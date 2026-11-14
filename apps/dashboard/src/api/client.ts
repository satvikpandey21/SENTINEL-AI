import type { Session } from '../auth/session';
import { jsonBody } from './http';
import type {
  Account,
  AccountQuery,
  Analytics,
  AnalyticsQuery,
  Assessment,
  AssessmentQuery,
  AuditQuery,
  AuditRecord,
  ClientActivity,
  ClientQuery,
  CreateAccountInput,
  EventQuery,
  Page,
  PolicyDocument,
  PolicyUpdate,
  SecurityEvent,
  UpdateAccountInput,
} from './types';

function queryString(query: object): string {
  const values = new URLSearchParams();
  for (const [key, value] of Object.entries(query))
    if (value !== undefined && value !== null && value !== '') values.set(key, String(value));
  const result = values.toString();
  return result ? `?${result}` : '';
}
export class DashboardApi {
  constructor(private readonly session: Session) {}
  analytics = (query: AnalyticsQuery, signal?: AbortSignal) =>
    this.session.request<Analytics>('/analytics' + queryString(query), { signal });
  events = (query: EventQuery, signal?: AbortSignal) =>
    this.session.request<Page<SecurityEvent>>('/events' + queryString(query), { signal });
  event = (id: string, signal?: AbortSignal) =>
    this.session.request<SecurityEvent>('/events/' + encodeURIComponent(id), { signal });
  assessments = (query: AssessmentQuery, signal?: AbortSignal) =>
    this.session.request<Page<Assessment>>('/assessments' + queryString(query), { signal });
  assessment = (id: string, signal?: AbortSignal) =>
    this.session.request<Assessment>('/assessments/' + encodeURIComponent(id), { signal });
  client = (id: string, query: ClientQuery, signal?: AbortSignal) =>
    this.session.request<ClientActivity>(
      '/clients/' + encodeURIComponent(id) + '/activity' + queryString(query),
      { signal },
    );
  policies = (signal?: AbortSignal) =>
    this.session.request<PolicyDocument>('/policies', { signal });
  updatePolicies = (input: PolicyUpdate) =>
    this.session.request<PolicyDocument>('/policies', { method: 'PUT', ...jsonBody(input) });
  reconcilePolicies = () =>
    this.session.request<PolicyDocument>('/policies/reconcile', { method: 'POST' });
  audit = (query: AuditQuery, signal?: AbortSignal) =>
    this.session.request<Page<AuditRecord>>('/audit' + queryString(query), { signal });
  me = (signal?: AbortSignal) => this.session.request<Account>('/auth/me', { signal });
  accounts = (query: AccountQuery, signal?: AbortSignal) =>
    this.session.request<Page<Account>>('/accounts' + queryString(query), { signal });
  createAccount = (input: CreateAccountInput) =>
    this.session.request<Account>('/accounts', { method: 'POST', ...jsonBody(input) });
  updateAccount = (id: string, input: UpdateAccountInput) =>
    this.session.request<Account>('/accounts/' + encodeURIComponent(id), {
      method: 'PATCH',
      ...jsonBody(input),
    });
}
