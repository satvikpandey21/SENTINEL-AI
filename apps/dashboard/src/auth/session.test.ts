import { afterEach, describe, expect, it, vi } from 'vitest';
import { HttpClient, ApiError, type Fetcher } from '../api/http';
import { Session, type SessionEnvironment } from './session';
import { envelope, json } from '../tests/fixtures';
const sessions: Session[] = [];
function setup(fetcher = vi.fn<Fetcher>(), environment?: SessionEnvironment) {
  const session = new Session(
    new HttpClient('/api/admin', fetcher),
    environment ?? { lock: (work) => work() },
  );
  sessions.push(session);
  return { session, fetcher };
}
afterEach(() => sessions.splice(0).forEach((session) => session.destroy()));
describe('secure session lifecycle', () => {
  it('logs in with cookies and CSRF intent, keeping credentials out of browser storage', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValue(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    expect(session.getSnapshot().account?.username).toBe('operator');
    const options = fetcher.mock.calls[0]?.[1];
    expect(options).toMatchObject({
      credentials: 'include',
      method: 'POST',
      headers: { 'X-CSRF-Intent': 'sentinel-admin' },
    });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });
  it('rejects failed login without authenticating', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValue(json({ detail: 'Invalid credentials' }, 401));
    await expect(session.login({ username: 'operator', password: 'bad' })).rejects.toMatchObject({
      status: 401,
    });
    expect(session.getSnapshot().account).toBeNull();
  });
  it('restores once with a fresh nonce and rotating refresh cookie', async () => {
    const { session, fetcher } = setup();
    fetcher
      .mockResolvedValueOnce(json({ csrf_token: 'prepared' }))
      .mockResolvedValueOnce(json(envelope));
    await Promise.all([session.start(), session.start()]);
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1]).toMatchObject([
      '/api/admin/auth/refresh',
      { headers: { 'X-CSRF-Token': 'prepared' }, credentials: 'include' },
    ]);
    expect(session.getSnapshot().status).toBe('authenticated');
  });
  it('treats missing or revoked cookies as anonymous', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValue(json({}, 401));
    await session.start();
    expect(session.getSnapshot().status).toBe('anonymous');
  });
  it('exposes restoration outages for retry', async () => {
    const { session, fetcher } = setup();
    fetcher.mockRejectedValue(new TypeError('offline'));
    await session.start();
    expect(session.getSnapshot().status).toBe('unavailable');
  });
  it('deduplicates concurrent renewals and renews automatically', async () => {
    vi.useFakeTimers();
    const { session, fetcher } = setup();
    fetcher.mockResolvedValueOnce(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    fetcher.mockImplementation(async (path) =>
      String(path).endsWith('/csrf') ? json({ csrf_token: 'next' }) : json(envelope),
    );
    await Promise.all([session.refresh(), session.refresh(), session.refresh()]);
    expect(fetcher).toHaveBeenCalledTimes(3);
    await vi.advanceTimersByTimeAsync(270000);
    expect(fetcher).toHaveBeenCalledTimes(5);
  });
  it('refreshes a rejected request only once and revokes after a second 401', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValueOnce(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    fetcher
      .mockResolvedValueOnce(json({}, 401))
      .mockResolvedValueOnce(json({ csrf_token: 'next' }))
      .mockResolvedValueOnce(json(envelope))
      .mockResolvedValueOnce(json({}, 401));
    await expect(session.request('/events')).rejects.toMatchObject({ status: 401 });
    expect(fetcher).toHaveBeenCalledTimes(5);
    expect(session.getSnapshot().status).toBe('anonymous');
  });
  it('does not retry forbidden writes', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValueOnce(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    fetcher.mockResolvedValueOnce(json({}, 403));
    await expect(session.request('/policies', { method: 'PUT' })).rejects.toMatchObject({
      status: 403,
    });
    expect(fetcher).toHaveBeenCalledTimes(2);
    expect(fetcher.mock.calls[1]?.[1]).toMatchObject({
      credentials: 'omit',
      headers: { Authorization: 'Bearer unit-test-access', 'X-CSRF-Intent': 'sentinel-admin' },
    });
  });
  it('discards an old request after the operator signs out or switches accounts', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValueOnce(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    let resolve!: (value: Response) => void;
    fetcher.mockImplementationOnce(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    const request = session.request('/events');
    session.invalidate();
    resolve(json({ items: [] }));
    await expect(request).rejects.toBeInstanceOf(ApiError);
    expect(fetcher).toHaveBeenCalledTimes(2);
  });
  it('honors cancellation before sending anything', async () => {
    const { session, fetcher } = setup();
    const controller = new AbortController();
    controller.abort();
    await expect(session.request('/events', { signal: controller.signal })).rejects.toMatchObject({
      name: 'AbortError',
    });
    expect(fetcher).not.toHaveBeenCalled();
  });
  it('revokes server session and clears memory on logout', async () => {
    const { session, fetcher } = setup();
    fetcher.mockResolvedValueOnce(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    fetcher
      .mockResolvedValueOnce(json({ csrf_token: 'logout' }))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    expect(await session.logout()).toBe(true);
    expect(session.getSnapshot().status).toBe('anonymous');
    await expect(session.request('/events')).rejects.toMatchObject({ status: 401 });
  });
  it('reports unconfirmed server logout instead of claiming revocation', async () => {
    const { session, fetcher } = setup();
    fetcher.mockRejectedValue(new TypeError('offline'));
    expect(await session.logout()).toBe(false);
    expect(session.getSnapshot()).toMatchObject({ status: 'anonymous', logoutUnconfirmed: true });
  });
  it('broadcasts only notices and responds to cross-tab logout', async () => {
    const channel = {
      postMessage: vi.fn(),
      close: vi.fn(),
      onmessage: null as ((event: MessageEvent) => void) | null,
    };
    const { session, fetcher } = setup(undefined, { lock: (work) => work(), channel });
    fetcher.mockResolvedValue(json(envelope));
    await session.login({ username: 'operator', password: 'unit-password' });
    expect(channel.postMessage).toHaveBeenCalledWith({ type: 'signed-in' });
    channel.onmessage?.(new MessageEvent('message', { data: { type: 'signed-out' } }));
    expect(session.getSnapshot().status).toBe('anonymous');
    expect(JSON.stringify(channel.postMessage.mock.calls)).not.toContain(envelope.access_token);
  });
});
