import { describe, expect, it, vi } from 'vitest';
import { HttpClient, type Fetcher } from './http';
import { validateApiBase } from './config';
import { DashboardApi } from './client';
import { Session } from '../auth/session';
import { json } from '../tests/fixtures';
describe('HTTP and OpenAPI client boundary', () => {
  it('preserves safe errors, validation locations, retry hints and request IDs', async () => {
    const fetcher = vi.fn<Fetcher>().mockResolvedValue(
      json(
        {
          detail: 'Invalid filter',
          errors: [{ location: ['query', 'limit'], type: 'out_of_range' }],
        },
        429,
        { 'X-Request-ID': 'ref', 'Retry-After': '3' },
      ),
    );
    await expect(new HttpClient('/api/admin', fetcher).send('/events')).rejects.toMatchObject({
      status: 429,
      message: 'Invalid filter',
      requestId: 'ref',
      retryAfter: '3',
      issues: [{ type: 'out_of_range' }],
    });
  });
  it('normalizes network errors and unreadable success bodies', async () => {
    const fetcher = vi
      .fn<Fetcher>()
      .mockRejectedValueOnce(new Error('private network detail'))
      .mockResolvedValueOnce(new Response('not json'));
    const client = new HttpClient('/api/admin', fetcher);
    await expect(client.send('/events')).rejects.toMatchObject({ status: 0 });
    await expect(client.send('/events')).rejects.toMatchObject({ status: 502 });
  });
  it('completes empty logout responses and disables caching and redirects', async () => {
    const fetcher = vi.fn<Fetcher>().mockResolvedValue(new Response(null, { status: 204 }));
    await expect(
      new HttpClient('/api/admin', fetcher).send('/auth/logout'),
    ).resolves.toBeUndefined();
    expect(fetcher.mock.calls[0]?.[1]).toMatchObject({ cache: 'no-store', redirect: 'error' });
  });
  it('bounds stalled requests with a timeout', async () => {
    vi.useFakeTimers();
    const fetcher = vi
      .fn<Fetcher>()
      .mockImplementation(
        (_path, options) =>
          new Promise((_resolve, reject) =>
            options?.signal?.addEventListener('abort', () => reject(options.signal?.reason)),
          ),
      );
    const request = new HttpClient('/api/admin', fetcher).send('/events');
    const rejected = expect(request).rejects.toMatchObject({ status: 0 });
    await vi.advanceTimersByTimeAsync(15000);
    await rejected;
  });
  it.each([
    'http://evil.example/api/admin',
    'https://user:password@example.com/api/admin',
    'https://example.com/api/admin?token=x',
    'https://example.com/other',
    '//example.com/api/admin',
  ])('rejects unsafe API base %s', (value) => {
    expect(() => validateApiBase(value)).toThrow();
  });
  it('accepts the development proxy and explicit HTTPS API', () => {
    expect(validateApiBase('/api/admin')).toBe('/api/admin');
    expect(validateApiBase('https://console.example.com/api/admin/')).toBe(
      'https://console.example.com/api/admin',
    );
  });
  it('uses encoded filters and bounded page requests', async () => {
    const session = new Session(new HttpClient('/api/admin', vi.fn()), { lock: (work) => work() });
    const request = vi.spyOn(session, 'request').mockResolvedValue({});
    const api = new DashboardApi(session);
    const controller = new AbortController();
    await api.events({ endpoint: '/api/items/{id}', limit: 25, offset: 25 }, controller.signal);
    expect(request).toHaveBeenCalledWith(
      '/events?endpoint=%2Fapi%2Fitems%2F%7Bid%7D&limit=25&offset=25',
      { signal: controller.signal },
    );
    session.destroy();
  });
});
