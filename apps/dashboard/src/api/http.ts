import type { ApiErrorBody } from './types';
export class ApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public issues: ApiErrorBody['errors'] = [],
    public requestId?: string,
    public retryAfter?: string,
  ) {
    super(message);
    this.name = 'ApiError';
  }
}
export type Fetcher = typeof fetch;
export function isAbort(error: unknown): boolean {
  return error instanceof Error && error.name === 'AbortError';
}
export function errorMessage(error: unknown): string {
  return error instanceof ApiError
    ? error.message
    : 'The request could not be completed. Please try again.';
}
export class HttpClient {
  constructor(
    public readonly base: string,
    private readonly fetcher: Fetcher = (...args) => fetch(...args),
  ) {}
  async send<T>(path: string, options: RequestInit = {}): Promise<T> {
    const controller = new AbortController();
    const abort = () => controller.abort(options.signal?.reason);
    if (options.signal?.aborted) abort();
    options.signal?.addEventListener('abort', abort, { once: true });
    const timeout = setTimeout(
      () => controller.abort(new DOMException('Timeout', 'TimeoutError')),
      15000,
    );
    try {
      const response = await this.fetcher(this.base + path, {
        ...options,
        signal: controller.signal,
        cache: 'no-store',
        redirect: 'error',
      });
      if (response.status === 204) return undefined as T;
      const body: unknown = await response.json().catch(() => null);
      if (!response.ok) {
        const safe = body && typeof body === 'object' ? (body as Partial<ApiErrorBody>) : {};
        throw new ApiError(
          response.status,
          typeof safe.detail === 'string' ? safe.detail : 'The API rejected this request.',
          safe.errors,
          response.headers.get('X-Request-ID') ?? undefined,
          response.headers.get('Retry-After') ?? undefined,
        );
      }
      if (body === null) throw new ApiError(502, 'The API returned an unreadable response.');
      return body as T;
    } catch (error) {
      if (error instanceof ApiError || options.signal?.aborted) throw error;
      throw new ApiError(0, 'Unable to reach the API. Check the connection and try again.');
    } finally {
      clearTimeout(timeout);
      options.signal?.removeEventListener('abort', abort);
    }
  }
}
export const jsonBody = (value: unknown) => ({
  body: JSON.stringify(value),
  headers: { 'Content-Type': 'application/json' },
});
