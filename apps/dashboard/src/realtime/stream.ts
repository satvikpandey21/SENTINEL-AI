import type { Session } from '../auth/session';
import { ApiError } from '../api/http';
import { API_BASE } from '../api/config';
import { initialLiveState, parseNotification, type LiveState } from './types';
export type Socket = Pick<
  WebSocket,
  'onopen' | 'onmessage' | 'onclose' | 'onerror' | 'send' | 'close'
>;
export type LiveEnvironment = {
  socket: (url: string, protocols: string[]) => Socket;
  visible: () => boolean;
  online: () => boolean;
  random: () => number;
};
export const alertPolicy = { cooldownMs: 30000, historyLimit: 50, maxRetries: 8, batchMs: 1500 };
export class SecurityStream {
  private state: LiveState = { ...initialLiveState };
  private listeners = new Set<() => void>();
  private unsubscribe?: () => void;
  private socket?: Socket;
  private controller?: AbortController;
  private retryTimer?: ReturnType<typeof setTimeout>;
  private deadline?: ReturnType<typeof setTimeout>;
  private batchTimer?: ReturnType<typeof setTimeout>;
  private epoch = 0;
  private identity = '';
  private attempts = 0;
  private seen = new Set<string>();
  private cooldown = new Map<string, number>();
  private assessmentPending = false;
  constructor(
    private session: Session,
    private env: LiveEnvironment = {
      socket: (url, protocols) => new WebSocket(url, protocols),
      visible: () => document.visibilityState === 'visible',
      online: () => navigator.onLine,
      random: Math.random,
    },
    private policy = alertPolicy,
  ) {}
  subscribe = (listener: () => void) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  getSnapshot = () => this.state;
  private update(patch: Partial<LiveState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach((listener) => listener());
  }
  private disconnect() {
    this.epoch++;
    clearTimeout(this.batchTimer);
    this.batchTimer = undefined;
    this.assessmentPending = false;
    this.controller?.abort();
    clearTimeout(this.retryTimer);
    clearTimeout(this.deadline);
    this.socket?.close();
    this.socket = undefined;
  }
  start() {
    this.unsubscribe = this.session.subscribe(this.sync);
    document.addEventListener('visibilitychange', this.visibility);
    window.addEventListener('online', this.visibility);
    window.addEventListener('offline', this.visibility);
    this.sync();
    return () => this.stop();
  }
  stop() {
    this.unsubscribe?.();
    document.removeEventListener('visibilitychange', this.visibility);
    window.removeEventListener('online', this.visibility);
    window.removeEventListener('offline', this.visibility);
    this.disconnect();
    clearTimeout(this.batchTimer);
    this.batchTimer = undefined;
    this.identity = '';
  }
  private sync = () => {
    const auth = this.session.getSnapshot();
    const identity =
      auth.status === 'authenticated' && !auth.signingOut
        ? `${auth.account?.id}:${this.session.getEpoch()}`
        : '';
    if (identity === this.identity) return;
    this.disconnect();
    clearTimeout(this.batchTimer);
    this.batchTimer = undefined;
    this.assessmentPending = false;
    this.identity = identity;
    this.attempts = 0;
    this.seen.clear();
    this.cooldown.clear();
    this.update({ ...initialLiveState });
    if (identity && this.env.online()) void this.connect();
  };
  private visibility = () => {
    if (!this.identity || !this.env.online()) {
      this.disconnect();
      this.update({ status: 'disconnected' });
      return;
    }
    // A terminal or background tab must not silently discard live security activity.
    // Return to the page still reconciles REST, including after browser suspension.
    if (!this.env.visible()) return;
    if (this.socket) {
      this.update({ resyncVersion: this.state.resyncVersion + 1 });
      return;
    }
    this.disconnect();
    this.attempts = 0;
    void this.connect();
  };
  retry = () => {
    if (!this.identity || !this.env.online()) return;
    this.disconnect();
    this.attempts = 0;
    void this.connect();
  };
  private failed() {
    this.disconnect();
    if (!this.identity || !this.env.online()) {
      this.update({ status: 'disconnected' });
      return;
    }
    if (this.attempts >= this.policy.maxRetries) {
      this.update({ status: 'unavailable' });
      return;
    }
    const delay = Math.min(30000, 1000 * 2 ** this.attempts++) * (0.5 + this.env.random() * 0.5);
    this.update({ status: 'reconnecting' });
    this.retryTimer = setTimeout(() => void this.connect(), delay);
  }
  private watch(epoch: number) {
    clearTimeout(this.deadline);
    this.deadline = setTimeout(() => {
      if (epoch === this.epoch) this.failed();
    }, 50000);
  }
  private async connect() {
    const epoch = this.epoch;
    this.update({ status: this.attempts ? 'reconnecting' : 'connecting' });
    this.controller = new AbortController();
    try {
      const ticket = await this.session.request<{ ticket: string; protocol: string }>(
        '/ws/v1/ticket',
        {
          method: 'POST',
          signal: this.controller.signal,
        },
      );
      if (epoch !== this.epoch) return;
      if (ticket.protocol !== 'sentinel.security.v1' || !/^[A-Za-z0-9_-]{43}$/.test(ticket.ticket))
        throw new Error('Invalid stream authorization');
      const url = new URL(API_BASE + '/ws/v1/security', window.location.origin);
      url.protocol = url.protocol === 'https:' ? 'wss:' : 'ws:';
      const socket = this.env.socket(url.toString(), [
        ticket.protocol,
        'sentinel.ticket.' + ticket.ticket,
      ]);
      this.socket = socket;
      this.deadline = setTimeout(() => {
        if (epoch === this.epoch) this.failed();
      }, 10000);
      socket.onopen = () => {
        if (epoch === this.epoch) this.watch(epoch);
      };
      socket.onerror = () => undefined; // The close/deadline path owns retry coordination.
      socket.onclose = (event) => {
        if (epoch !== this.epoch) return;
        if ([4401, 4403].includes(event.code)) {
          this.session.invalidate('Streaming authorization ended. Sign in again.');
          return;
        }
        this.failed();
      };
      socket.onmessage = (event) => {
        if (epoch !== this.epoch || typeof event.data !== 'string' || event.data.length > 4096)
          return;
        try {
          const frame = JSON.parse(event.data);
          if (frame.schema_version !== 1) return;
          this.watch(epoch);
          if (frame.type === 'connection.ready') {
            this.attempts = 0;
            this.update({ status: 'connected', resyncVersion: this.state.resyncVersion + 1 });
            return;
          }
          if (frame.type === 'connection.heartbeat') {
            socket.send('{"type":"connection.pong"}');
            return;
          }
          if (frame.type === 'connection.resync_required') {
            this.update({ resyncVersion: this.state.resyncVersion + 1 });
            return;
          }
          const n = parseNotification(frame);
          if (!n || this.seen.has(n.notification_id)) return;
          this.seen.add(n.notification_id);
          if (this.seen.size > 2048) this.seen.delete(this.seen.values().next().value!);
          this.assessmentPending ||= !!n.assessment_id;
          if (!this.batchTimer)
            this.batchTimer = setTimeout(() => {
              this.batchTimer = undefined;
              if (epoch !== this.epoch) {
                this.assessmentPending = false;
                return;
              }
              this.update({
                activityVersion: this.state.activityVersion + 1,
                assessmentVersion: this.state.assessmentVersion + (this.assessmentPending ? 1 : 0),
              });
              this.assessmentPending = false;
            }, this.policy.batchMs);
          const actionable =
            !n.degraded &&
            (['high', 'critical'].includes(n.severity ?? '') ||
              ['rate_limit', 'temporary_block'].includes(n.security_action ?? '') ||
              n.classifications.includes('possible_brute_force') ||
              n.classifications.includes('repeated_authentication_failures'));
          const group = [
            n.service,
            n.endpoint,
            n.security_action,
            n.severity,
            ...n.classifications,
          ].join('|');
          const now = Date.now();
          const present =
            (actionable || this.state.includeInformational) &&
            now - (this.cooldown.get(group) ?? -Infinity) >= this.policy.cooldownMs;
          if (present) {
            this.cooldown.set(group, now);
            if (this.cooldown.size > 256) this.cooldown.delete(this.cooldown.keys().next().value!);
          }
          this.update({
            lastNotification: n.committed_at,
            ...(present
              ? {
                  notices: [{ ...n, read: false, actionable }, ...this.state.notices].slice(
                    0,
                    this.policy.historyLimit,
                  ),
                }
              : {}),
          });
        } catch {
          /* Malformed frames never replace authoritative dashboard data. */
        }
      };
    } catch (error) {
      if (epoch !== this.epoch) return;
      if (error instanceof ApiError && [401, 403].includes(error.status)) {
        this.session.invalidate('Streaming authorization ended. Sign in again.');
        return;
      }
      this.failed();
    }
  }
  markRead = () => this.update({ notices: this.state.notices.map((n) => ({ ...n, read: true })) });
  clear = () => this.update({ notices: [] });
  informational = (value: boolean) => this.update({ includeInformational: value });
}
