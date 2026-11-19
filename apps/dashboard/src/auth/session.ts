import { ApiError, HttpClient, jsonBody } from '../api/http';
import type { Account, LoginInput, TokenEnvelope } from '../api/types';

export type AuthState = {
  status: 'restoring' | 'authenticated' | 'anonymous' | 'unavailable';
  account: Account | null;
  expiresAt: number | null;
  message?: string;
  logoutUnconfirmed?: boolean;
  signingOut?: boolean;
};
type Notice = { type: 'signed-in' | 'signed-out' | 'renewed' };
type Channel = Pick<BroadcastChannel, 'postMessage' | 'close' | 'onmessage'>;
export type SessionEnvironment = {
  lock: <T>(work: () => Promise<T>) => Promise<T>;
  channel?: Channel;
  now?: () => number;
  visible?: () => boolean;
};

export function browserSessionEnvironment(base: string): SessionEnvironment {
  return {
    async lock<T>(work: () => Promise<T>) {
      if (!navigator.locks) {
        throw new ApiError(
          503,
          'Secure session coordination requires a current browser on HTTPS or localhost.',
        );
      }
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 20000);
      try {
        return await navigator.locks.request(
          `sentinel-session:${base}`,
          { signal: controller.signal },
          work,
        );
      } finally {
        clearTimeout(timeout);
      }
    },
    channel:
      typeof BroadcastChannel === 'undefined'
        ? undefined
        : new BroadcastChannel(`sentinel-session:${base}`),
    now: () => Date.now(),
    visible: () => document.visibilityState === 'visible',
  };
}

/** All credentials are private process memory. Cookie operations share a cross-tab lock. */
export class Session {
  private state: AuthState = { status: 'restoring', account: null, expiresAt: null };
  private accessToken: string | null = null;
  private renewal: Promise<void> | null = null;
  private startup: Promise<void> | null = null;
  private listeners = new Set<() => void>();
  private timer: ReturnType<typeof setTimeout> | undefined;
  private generation = 0;
  private readonly now: () => number;
  constructor(
    private readonly http: HttpClient,
    private readonly environment: SessionEnvironment = browserSessionEnvironment(http.base),
  ) {
    this.now = environment.now ?? Date.now;
    if (environment.channel)
      environment.channel.onmessage = (event: MessageEvent<Notice>) => {
        if (event.data?.type === 'signed-out')
          this.invalidate('Your session was signed out in another tab.', false);
        if (event.data?.type === 'signed-in') {
          this.clearCredentials();
          this.update({ status: 'restoring', account: null, expiresAt: null });
          void (this.renewal ?? Promise.resolve())
            .catch(() => undefined)
            .then(() => this.restore());
        }
        // Refresh completion is informational. Each tab prepares a new nonce under the
        // shared lock before its next rotation; credentials are never broadcast.
      };
  }
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  getSnapshot = () => this.state;
  getEpoch = () => this.generation;
  private update(state: AuthState) {
    this.state = state;
    this.listeners.forEach((listener) => listener());
  }
  private notice(type: Notice['type']) {
    this.environment.channel?.postMessage({ type } satisfies Notice);
  }
  private clearCredentials() {
    this.generation++;
    this.accessToken = null;
    clearTimeout(this.timer);
  }
  invalidate(
    message = 'Your session has ended. Sign in again.',
    broadcast = true,
    logoutUnconfirmed = false,
  ) {
    this.clearCredentials();
    this.update({
      status: 'anonymous',
      account: null,
      expiresAt: null,
      message,
      logoutUnconfirmed,
    });
    if (broadcast) this.notice('signed-out');
  }
  private accept(data: TokenEnvelope) {
    this.accessToken = data.access_token;
    const expiresAt = this.now() + data.expires_in * 1000;
    this.update({ status: 'authenticated', account: data.account, expiresAt });
    clearTimeout(this.timer);
    this.timer = setTimeout(
      () => {
        if (this.environment.visible?.() !== false) void this.refresh().catch(() => undefined);
      },
      Math.max(1000, expiresAt - this.now() - 30000),
    );
  }
  private auth<T>(path: string, body?: unknown, csrf?: string) {
    return this.http.send<T>(`/auth/${path}`, {
      method: 'POST',
      credentials: 'include',
      ...(body === undefined ? {} : jsonBody(body)),
      headers: {
        ...(body === undefined ? {} : { 'Content-Type': 'application/json' }),
        'X-CSRF-Intent': 'sentinel-admin',
        ...(csrf ? { 'X-CSRF-Token': csrf } : {}),
      },
    });
  }
  start(): Promise<void> {
    this.startup ??= this.restore();
    return this.startup;
  }
  async restore() {
    try {
      await this.refresh();
    } catch (error) {
      if (this.state.status === 'anonymous') return;
      if (error instanceof ApiError && [401, 403].includes(error.status))
        this.invalidate(undefined, false);
      else
        this.update({
          status: 'unavailable',
          account: null,
          expiresAt: null,
          message: 'Session restoration is unavailable. Check the API connection, then retry.',
        });
    }
  }
  async login(input: LoginInput) {
    await this.environment.lock(async () => {
      const data = await this.auth<TokenEnvelope>('login', input);
      this.generation++;
      this.accept(data);
      this.notice('signed-in');
    });
  }
  refresh(): Promise<void> {
    if (this.renewal) return this.renewal;
    const generation = this.generation;
    this.renewal = this.environment
      .lock(async () => {
        if (generation !== this.generation) return;
        const prepared = await this.auth<{ csrf_token: string }>('csrf');
        const data = await this.auth<TokenEnvelope>('refresh', undefined, prepared.csrf_token);
        if (generation === this.generation) {
          this.accept(data);
          this.notice('renewed');
        }
      })
      .catch((error) => {
        if (
          generation === this.generation &&
          error instanceof ApiError &&
          [401, 403].includes(error.status)
        ) {
          this.invalidate('Your session expired or was revoked. Sign in again.', false);
        } else if (generation === this.generation && this.state.status === 'authenticated') {
          this.update({
            ...this.state,
            message: 'Session renewal failed. Check the connection and retry.',
          });
        }
        throw error;
      })
      .finally(() => {
        this.renewal = null;
      });
    return this.renewal;
  }
  async logout(): Promise<boolean> {
    this.clearCredentials();
    this.update({ ...this.state, signingOut: true });
    this.notice('signed-out');
    let confirmed = false;
    try {
      await this.environment.lock(async () => {
        const prepared = await this.auth<{ csrf_token: string }>('csrf');
        await this.auth<void>('logout', undefined, prepared.csrf_token);
        confirmed = true;
      });
    } catch (error) {
      // A 401 means the server no longer accepts this cookie, so local clearing is sufficient.
      confirmed = error instanceof ApiError && error.status === 401;
    } finally {
      this.invalidate(
        confirmed
          ? 'You have been signed out.'
          : 'Signed out locally. Server revocation could not be confirmed; retry server sign-out when connected.',
        true,
        !confirmed,
      );
    }
    return confirmed;
  }
  async request<T>(path: string, options: RequestInit = {}): Promise<T> {
    const generation = this.generation;
    const ensureSession = () => {
      if (generation !== this.generation || !this.accessToken)
        throw new ApiError(401, 'The session changed. Retry from the current account.');
    };
    options.signal?.throwIfAborted();
    if (!this.accessToken) throw new ApiError(401, 'Sign in to continue.');
    if ((this.state.expiresAt ?? 0) - this.now() < 30000) await this.refresh();
    ensureSession();
    options.signal?.throwIfAborted();
    const perform = () =>
      this.http.send<T>(path, {
        ...options,
        credentials: 'omit',
        headers: {
          ...options.headers,
          Authorization: `Bearer ${this.accessToken}`,
          ...(options.method && options.method !== 'GET'
            ? { 'X-CSRF-Intent': 'sentinel-admin' }
            : {}),
        },
      });
    try {
      const result = await perform();
      ensureSession();
      return result;
    } catch (error) {
      ensureSession();
      if (!(error instanceof ApiError) || error.status !== 401 || options.signal?.aborted)
        throw error;
      await this.refresh();
      ensureSession();
      options.signal?.throwIfAborted();
      try {
        const result = await perform();
        ensureSession();
        return result;
      } catch (retryError) {
        ensureSession();
        if (retryError instanceof ApiError && retryError.status === 401) this.invalidate();
        throw retryError;
      }
    }
  }
  watchVisibility() {
    const listener = () => {
      if (
        document.visibilityState === 'visible' &&
        this.state.status === 'authenticated' &&
        (this.state.expiresAt ?? 0) - this.now() < 30000
      )
        void this.refresh().catch(() => undefined);
    };
    document.addEventListener('visibilitychange', listener);
    return () => document.removeEventListener('visibilitychange', listener);
  }
  destroy() {
    this.invalidate(undefined, false);
    clearTimeout(this.timer);
    this.environment.channel?.close();
    this.listeners.clear();
  }
}
