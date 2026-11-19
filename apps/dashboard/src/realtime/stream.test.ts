import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Session, AuthState } from '../auth/session';
import { ApiError } from '../api/http';
import { SecurityStream, type Socket } from './stream';
import { parseNotification } from './types';
export class FakeSocket {
  onopen: Socket['onopen'] = null;
  onmessage: Socket['onmessage'] = null;
  onclose: Socket['onclose'] = null;
  onerror: Socket['onerror'] = null;
  send = vi.fn();
  close = vi.fn();
  message(data: unknown) {
    this.onmessage?.call(
      this as unknown as WebSocket,
      { data: JSON.stringify(data) } as MessageEvent,
    );
  }
  closed(code = 1006) {
    this.onclose?.call(this as unknown as WebSocket, { code } as CloseEvent);
  }
}
const id = '12345678-1234-4234-8234-123456789012';
export const activity = {
  schema_version: 1,
  notification_id: id,
  event_id: id,
  type: 'security.decision.created',
  occurred_at: '2026-11-14T12:00:00Z',
  committed_at: '2026-11-14T12:00:01Z',
  service: 'sentinel-demo-api',
  endpoint: '/api/demo/ping',
  status_code: 429,
  security_action: 'rate_limit',
  rule_ids: ['rate.default'],
  assessment_id: id,
  risk_score: 70,
  severity: 'high',
  classifications: ['excessive_api_requests'],
  experimental: false,
  degraded: false,
};
const stops: (() => void)[] = [];
afterEach(() => stops.splice(0).forEach((stop) => stop()));
function harness() {
  vi.useFakeTimers();
  let auth = { status: 'authenticated', account: { id: 'one' } } as AuthState;
  let epoch = 1;
  const listeners = new Set<() => void>();
  const request = vi
    .fn()
    .mockResolvedValue({ ticket: 't'.repeat(43), protocol: 'sentinel.security.v1' });
  const fake = {
    request,
    getSnapshot: () => auth,
    getEpoch: () => epoch,
    subscribe: (fn: () => void) => {
      listeners.add(fn);
      return () => listeners.delete(fn);
    },
    invalidate: vi.fn(() => {
      auth = { status: 'anonymous', account: null, expiresAt: null };
      epoch++;
      listeners.forEach((fn) => fn());
    }),
  };
  const sockets: FakeSocket[] = [];
  let visible = true;
  const factory = vi.fn(() => {
    const ws = new FakeSocket();
    sockets.push(ws);
    return ws;
  });
  const stream = new SecurityStream(fake as unknown as Session, {
    socket: factory,
    visible: () => visible,
    online: () => true,
    random: () => 1,
  });
  stops.push(stream.start());
  return {
    stream,
    sockets,
    factory,
    request,
    fake,
    account: () => {
      epoch++;
      listeners.forEach((fn) => fn());
    },
    visibility: (value: boolean) => {
      visible = value;
      document.dispatchEvent(new Event('visibilitychange'));
    },
  };
}
async function ready(h: ReturnType<typeof harness>) {
  await vi.advanceTimersByTimeAsync(0);
  h.sockets.at(-1)!.message({ schema_version: 1, type: 'connection.ready' });
}
describe('managed security stream', () => {
  it('acquires a fresh ticket, keeps credentials out of URLs and storage, heartbeats and reconciles', async () => {
    const storage = vi.spyOn(Storage.prototype, 'setItem');
    const h = harness();
    await ready(h);
    expect(h.request).toHaveBeenCalledWith(
      '/ws/v1/ticket',
      expect.objectContaining({ method: 'POST' }),
    );
    expect(h.factory).toHaveBeenCalledWith(
      expect.stringMatching(/^ws:\/\/.*\/api\/admin\/ws\/v1\/security$/),
      ['sentinel.security.v1', 'sentinel.ticket.' + 't'.repeat(43)],
    );
    expect(h.stream.getSnapshot().status).toBe('connected');
    expect(h.stream.getSnapshot().resyncVersion).toBe(1);
    h.sockets[0]!.message({ schema_version: 1, type: 'connection.heartbeat' });
    expect(h.sockets[0]!.send).toHaveBeenCalledWith('{"type":"connection.pong"}');
    expect(storage).not.toHaveBeenCalled();
  });
  it('deduplicates, batches analytics invalidation and bounds alert history', async () => {
    const h = harness();
    await ready(h);
    const ws = h.sockets[0]!;
    ws.message(activity);
    ws.message(activity);
    expect(h.stream.getSnapshot().notices).toHaveLength(1);
    expect(h.stream.getSnapshot().activityVersion).toBe(0);
    for (let n = 0; n < 100; n++)
      ws.message({
        ...activity,
        event_id: id.slice(0, -3) + String(n).padStart(3, '0'),
        notification_id: id.slice(0, -3) + String(n).padStart(3, '0'),
        endpoint: '/api/demo/' + n,
      });
    await vi.advanceTimersByTimeAsync(1500);
    expect(h.stream.getSnapshot().activityVersion).toBe(1);
    expect(h.stream.getSnapshot().assessmentVersion).toBe(1);
    expect(h.stream.getSnapshot().notices).toHaveLength(50);
    h.stream.markRead();
    expect(h.stream.getSnapshot().notices.every((n) => n.read)).toBe(true);
    h.stream.clear();
    expect(h.stream.getSnapshot().notices).toHaveLength(0);
  });
  it('suppresses repeated alerts and requires opt-in for routine information', async () => {
    const h = harness();
    await ready(h);
    const ws = h.sockets[0]!;
    ws.message(activity);
    ws.message({
      ...activity,
      event_id: id.replace('12345678', '99999999'),
      notification_id: id.replace('12345678', '99999999'),
    });
    expect(h.stream.getSnapshot().notices).toHaveLength(1);
    const info = {
      ...activity,
      security_action: null,
      risk_score: 0,
      severity: 'low',
      classifications: [],
      event_id: id.replace('12345678', '88888888'),
      notification_id: id.replace('12345678', '88888888'),
    };
    ws.message(info);
    expect(h.stream.getSnapshot().notices).toHaveLength(1);
    h.stream.informational(true);
    ws.message({
      ...info,
      event_id: id.replace('12345678', '77777777'),
      notification_id: id.replace('12345678', '77777777'),
    });
    expect(h.stream.getSnapshot().notices[0]!.actionable).toBe(false);
  });
  it('uses capped exponential backoff with bounded retries and manual recovery', async () => {
    const h = harness();
    await ready(h);
    for (const delay of [1000, 2000, 4000, 8000, 16000, 30000, 30000, 30000]) {
      h.sockets.at(-1)!.closed();
      const before = h.sockets.length;
      await vi.advanceTimersByTimeAsync(delay - 1);
      expect(h.sockets.length).toBe(before);
      await vi.advanceTimersByTimeAsync(1);
      expect(h.sockets.length).toBe(before + 1);
    }
    h.sockets.at(-1)!.closed();
    expect(h.stream.getSnapshot().status).toBe('unavailable');
    await vi.advanceTimersByTimeAsync(100000);
    expect(h.sockets).toHaveLength(9);
    h.stream.retry();
    await ready(h);
    expect(h.stream.getSnapshot().status).toBe('connected');
  });
  it('stops immediately on logout, including the subscription used for cross-tab sign-out', async () => {
    const h = harness();
    await ready(h);
    h.sockets[0]!.message(activity);
    h.fake.invalidate();
    expect(h.sockets[0]!.close).toHaveBeenCalled();
    h.sockets[0]!.message(activity);
    h.sockets[0]!.closed();
    await vi.advanceTimersByTimeAsync(100000);
    expect(h.stream.getSnapshot().status).toBe('disconnected');
    expect(h.stream.getSnapshot().notices).toHaveLength(0);
    expect(h.sockets).toHaveLength(1);
  });
  it('stops retrying after confirmed authorization failure', async () => {
    const h = harness();
    await ready(h);
    h.sockets[0]!.closed(4401);
    expect(h.fake.invalidate).toHaveBeenCalledOnce();
    await vi.advanceTimersByTimeAsync(100000);
    expect(h.sockets).toHaveLength(1);
  });
  it('isolates callbacks and ticket responses from an old account', async () => {
    const h = harness();
    await ready(h);
    const old = h.sockets[0]!;
    h.account();
    await ready(h);
    old.message(activity);
    old.closed(4401);
    expect(h.stream.getSnapshot().notices).toHaveLength(0);
    expect(h.fake.invalidate).not.toHaveBeenCalled();
    let resolve!: (v: unknown) => void;
    h.request.mockImplementationOnce(
      () =>
        new Promise((r) => {
          resolve = r;
        }),
    );
    h.stream.retry();
    h.fake.invalidate();
    resolve({ ticket: 't'.repeat(43), protocol: 'sentinel.security.v1' });
    await vi.advanceTimersByTimeAsync(0);
    expect(h.sockets).toHaveLength(2);
  });
  it('receives background activity and reconciles authoritative state on return', async () => {
    const h = harness();
    await ready(h);
    h.visibility(false);
    expect(h.stream.getSnapshot().status).toBe('connected');
    h.sockets[0]!.message(activity);
    expect(h.stream.getSnapshot().notices).toHaveLength(1);
    expect(h.stream.getSnapshot().lastNotification).toBe(activity.committed_at);
    h.visibility(true);
    expect(h.stream.getSnapshot().resyncVersion).toBe(2);
    expect(h.sockets).toHaveLength(1);
  });
  it('handles failed ticket acquisition and silent server restart', async () => {
    const h = harness();
    await ready(h);
    await vi.advanceTimersByTimeAsync(50000);
    expect(h.stream.getSnapshot().status).toBe('reconnecting');
    h.request.mockRejectedValueOnce(new ApiError(403, 'Revoked'));
    await vi.advanceTimersByTimeAsync(1000);
    expect(h.fake.invalidate).toHaveBeenCalledOnce();
  });
  it('rejects malformed frames without replacing existing data', async () => {
    const h = harness();
    await ready(h);
    h.sockets[0]!.message({ ...activity, endpoint: '/api?secret=value' });
    h.sockets[0]!.message({ ...activity, risk_score: 500 });
    expect(h.stream.getSnapshot().notices).toHaveLength(0);
    expect(parseNotification({})).toBeNull();
  });
});
