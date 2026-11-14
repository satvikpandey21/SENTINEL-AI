import type {
  Account,
  Analytics,
  Assessment,
  PolicyDocument,
  SecurityEvent,
  TokenEnvelope,
} from '../api/types';
export const account: Account = {
  id: '11111111-1111-4111-8111-111111111111',
  username: 'operator',
  role: 'ADMIN',
  active: true,
  created_at: '2026-11-14T00:00:00Z',
};
export const envelope: TokenEnvelope = {
  access_token: 'unit-test-access',
  token_type: 'Bearer',
  csrf_token: 'unit-test-csrf',
  expires_in: 300,
  account,
};
export const event: SecurityEvent = {
  event_id: '22222222-2222-4222-8222-222222222222',
  schema_version: 1,
  event_type: 'http.request.completed',
  occurred_at: '2026-11-14T00:00:00Z',
  service: 'sentinel-demo-api',
  method: 'GET',
  endpoint: '/api/demo/ping',
  status_code: 200,
  duration_ms: 2.5,
  request_id: 'a'.repeat(32),
  client_identifier: 'b'.repeat(64),
  severity: 'info',
  authentication_outcome: 'not_provided',
  response_completed: true,
  rule_id: null,
  security_action: null,
  counter_value: null,
  threshold: null,
  window_seconds: null,
  retry_after_seconds: null,
  restriction_expires_at: null,
  degraded: null,
};
export const assessment: Assessment = {
  assessment_id: '33333333-3333-4333-8333-333333333333',
  event_id: event.event_id,
  client_identifier: event.client_identifier,
  service: event.service,
  risk_score: 65,
  severity: 'high',
  analyzed_at: event.occurred_at,
  rule_version: 'risk-v1',
  feature_schema: 'behavior-v1',
  model_version: null,
  evidence: {
    aggregation_status: 'complete',
    window_seconds: 60,
    contributions: { authentication: 65, behavior: 0, policy: 0, volume: 0 },
    statistics: { status: 'warming_up', baseline_windows: 2, flags: [] },
    ml: { status: 'disabled', experimental: true },
    threats: [
      {
        risk_score: 65,
        timestamp: event.occurred_at,
        category: 'possible_brute_force',
        detection_method: 'deterministic',
        severity: 'high',
        rule_ids: ['auth.failures'],
        evidence: { failures: 10 },
      },
    ],
  },
};
export const analytics: Analytics = {
  start: '2026-11-13T00:00:00Z',
  end: '2026-11-14T00:00:00Z',
  bucket: 'hour',
  monitored_requests: 12,
  security_decisions: 3,
  rate_limit_violations: 2,
  temporary_blocks: 1,
  requests_over_time: [],
  status_distribution: [],
  threats_by_severity: [],
  threats_by_classification: [],
  risk_distribution: [],
  targeted_routes: [],
  recent_alerts: [],
  suspicious_clients: [],
};
export const policies: PolicyDocument = {
  version: 7,
  created_at: event.occurred_at,
  enforcement_synchronized: true,
  policies: [
    {
      id: 'demo-read',
      path_prefix: '/api/demo',
      enabled: true,
      failure_mode: 'closed',
      methods: [],
      rate: { requests: 600, window_seconds: 60, block_seconds: 60, exceed_action: 'rate_limit' },
      authentication: null,
    },
  ],
};
export const page = <T>(items: T[], total = items.length) => ({
  items,
  total,
  offset: 0,
  limit: 25,
});
export const json = (body: unknown, status = 200, headers?: HeadersInit) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...headers },
  });
