export type SecurityNotification = {
  schema_version: 1;
  notification_id: string;
  type: 'security.event.created' | 'security.decision.created';
  event_id: string;
  occurred_at: string;
  committed_at: string;
  service: string;
  endpoint: string;
  status_code: number;
  security_action: 'record' | 'rate_limit' | 'temporary_block' | 'deny' | null;
  rule_ids: string[];
  assessment_id: string | null;
  risk_score: number | null;
  severity: 'low' | 'moderate' | 'high' | 'critical' | null;
  classifications: string[];
  experimental: boolean;
  degraded: boolean;
};
export type LiveNotice = SecurityNotification & { read: boolean; actionable: boolean };
export type LiveState = {
  status: 'connected' | 'connecting' | 'reconnecting' | 'disconnected' | 'unavailable';
  lastNotification: string | null;
  activityVersion: number;
  assessmentVersion: number;
  resyncVersion: number;
  notices: LiveNotice[];
  includeInformational: boolean;
};
export const initialLiveState: LiveState = {
  status: 'disconnected',
  lastNotification: null,
  activityVersion: 0,
  assessmentVersion: 0,
  resyncVersion: 0,
  notices: [],
  includeInformational: false,
};

const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const classifications = new Set([
  'possible_brute_force',
  'repeated_authentication_failures',
  'excessive_api_requests',
  'repeated_policy_violations',
  'suspicious_behavioral_deviation',
  'experimental_behavioral_anomaly',
]);
/** Reject malformed/unbounded frames before they reach UI state. */
export function parseNotification(value: unknown): SecurityNotification | null {
  if (!value || typeof value !== 'object') return null;
  const n = value as SecurityNotification;
  if (
    n.schema_version !== 1 ||
    !['security.event.created', 'security.decision.created'].includes(n.type) ||
    !uuid.test(n.notification_id) ||
    n.event_id !== n.notification_id ||
    typeof n.service !== 'string' ||
    !/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/.test(n.service) ||
    typeof n.endpoint !== 'string' ||
    n.endpoint.length > 256 ||
    !/^(unmatched|\/[a-zA-Z0-9_./{}:~-]*)$/.test(n.endpoint) ||
    !Number.isInteger(n.status_code) ||
    n.status_code < 100 ||
    n.status_code > 599 ||
    ![null, 'record', 'rate_limit', 'temporary_block', 'deny'].includes(n.security_action) ||
    !Array.isArray(n.rule_ids) ||
    n.rule_ids.length > 16 ||
    n.rule_ids.some((r) => typeof r !== 'string' || !/^[a-zA-Z0-9_.-]{1,96}$/.test(r)) ||
    !Array.isArray(n.classifications) ||
    n.classifications.length > 6 ||
    n.classifications.some((c) => !classifications.has(c)) ||
    !(
      n.assessment_id === null ||
      (typeof n.assessment_id === 'string' && uuid.test(n.assessment_id))
    ) ||
    !(
      n.risk_score === null ||
      (Number.isFinite(n.risk_score) && n.risk_score >= 0 && n.risk_score <= 100)
    ) ||
    ![null, 'low', 'moderate', 'high', 'critical'].includes(n.severity) ||
    typeof n.experimental !== 'boolean' ||
    typeof n.degraded !== 'boolean' ||
    typeof n.occurred_at !== 'string' ||
    !Number.isFinite(Date.parse(n.occurred_at)) ||
    typeof n.committed_at !== 'string' ||
    !Number.isFinite(Date.parse(n.committed_at))
  )
    return null;
  return n;
}
