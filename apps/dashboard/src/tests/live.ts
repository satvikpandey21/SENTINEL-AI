import { vi } from 'vitest';
import type { Socket } from '../realtime/stream';
export class TestLiveSocket {
  static instances: TestLiveSocket[] = [];
  onopen: Socket['onopen'] = null;
  onclose: Socket['onclose'] = null;
  onmessage: Socket['onmessage'] = null;
  onerror: Socket['onerror'] = null;
  send = vi.fn();
  close = vi.fn();
  constructor() {
    TestLiveSocket.instances.push(this);
  }
  message(value: unknown) {
    this.onmessage?.call(
      this as unknown as WebSocket,
      { data: JSON.stringify(value) } as MessageEvent,
    );
  }
}
export const liveTicket = { ticket: 't'.repeat(43), protocol: 'sentinel.security.v1' };
export const liveActivity = {
  schema_version: 1,
  type: 'security.decision.created',
  notification_id: '22222222-2222-4222-8222-222222222222',
  event_id: '22222222-2222-4222-8222-222222222222',
  occurred_at: '2026-11-14T00:00:00Z',
  committed_at: '2026-11-14T00:00:01Z',
  service: 'sentinel-demo-api',
  endpoint: '/api/demo/ping',
  status_code: 429,
  security_action: 'rate_limit',
  rule_ids: ['demo.rate'],
  assessment_id: '33333333-3333-4333-8333-333333333333',
  risk_score: 65,
  severity: 'high',
  classifications: ['excessive_api_requests'],
  experimental: false,
  degraded: false,
};
