import type { components, paths } from './generated';
export type Account = components['schemas']['AccountOut'];
export type LoginInput = components['schemas']['Login'];
export type TokenEnvelope = components['schemas']['TokenOut'];
export type Analytics = components['schemas']['AnalyticsOut'];
export type SecurityEvent = components['schemas']['EventOut'];
export type Assessment = components['schemas']['AssessmentOut'];
export type Threat = components['schemas']['Threat'];
export type ClientActivity = components['schemas']['ClientActivity'];
export type Policy = components['schemas']['EndpointPolicy'];
export type PolicyDocument = components['schemas']['PolicyOut'];
export type PolicyUpdate = components['schemas']['PolicyUpdate'];
export type AuditRecord = components['schemas']['AuditOut'];
export type CreateAccountInput = components['schemas']['CreateAccount'];
export type UpdateAccountInput = components['schemas']['UpdateAccount'];
export type ApiErrorBody = components['schemas']['ErrorOut'];
export type EventQuery = NonNullable<paths['/api/admin/events']['get']['parameters']['query']>;
export type AssessmentQuery = NonNullable<
  paths['/api/admin/assessments']['get']['parameters']['query']
>;
export type AnalyticsQuery = NonNullable<
  paths['/api/admin/analytics']['get']['parameters']['query']
>;
export type ClientQuery = NonNullable<
  paths['/api/admin/clients/{client_identifier}/activity']['get']['parameters']['query']
>;
export type AuditQuery = NonNullable<paths['/api/admin/audit']['get']['parameters']['query']>;
export type AccountQuery = NonNullable<paths['/api/admin/accounts']['get']['parameters']['query']>;
export type Page<T> = { items: T[]; total: number; limit: number; offset: number };
export type TimeWindow = { start: string; end: string };
