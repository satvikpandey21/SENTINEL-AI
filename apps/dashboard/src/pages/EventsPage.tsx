import { NewActivity, useLiveRefresh } from '../realtime/LiveActivity';
import { useState } from 'react';
import { useLocation } from 'react-router';
import type { EventQuery } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import { useWindow, windowFor, dateTime } from '../utils/format';
import { CustomWindow, Field, FilterBar, TimeFilter, validWindow } from '../components/Filters';
import { EventTable } from '../components/EventTable';
import { EventDetail } from '../components/Details';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { PageHeading, Pagination, Panel, RefreshControl } from '../components/UI';
export default function EventsPage() {
  const { search } = useLocation();
  return <EventsExplorer key={search} search={search} />;
}
function EventsExplorer({ search }: { search: string }) {
  const { api } = useAuth();
  const params = new URLSearchParams(search);
  const initial: EventQuery = {
    request_id: params.get('request_id') || undefined,
    client_identifier: params.get('client') || undefined,
  };
  const [draft, setDraft] = useState<EventQuery>(initial);
  const scope = useWindow();
  const [applied, setApplied] = useState<EventQuery>({ ...initial, ...scope.window });
  const [appliedRange, setAppliedRange] = useState<import('../utils/format').Range | null>('24h');
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(params.get('event'));
  const [invalid, setInvalid] = useState('');
  const query = { ...applied, offset, limit: 25 };
  const result = useResource('events:' + JSON.stringify(query), (signal) =>
    api.events(query, signal),
  );
  const liveRefresh = () => {
    if (appliedRange) setApplied((old) => ({ ...old, ...windowFor(appliedRange) }));
    else result.refresh();
  };
  const live = useLiveRefresh(liveRefresh, false, false);
  const refreshLive = () => {
    live.acknowledge();
    liveRefresh();
  };
  const field = <K extends keyof EventQuery>(key: K, value: EventQuery[K]) =>
    setDraft((old) => ({ ...old, [key]: value || undefined }));
  return (
    <>
      <PageHeading
        eyebrow="Investigate / events"
        title="Security events"
        description="Explore sanitized HTTP observations and independently emitted security decisions."
      >
        <RefreshControl
          loading={result.loading}
          updatedAt={result.updatedAt}
          onRefresh={refreshLive}
        />
      </PageHeading>
      <NewActivity pending={live.pending} refresh={refreshLive} assessments={false} />
      <FilterBar
        onSubmit={(event) => {
          event.preventDefault();
          if (!validWindow(scope.window)) {
            setInvalid('Choose a positive time window of at most 31 days.');
            return;
          }
          setInvalid('');
          setAppliedRange(scope.custom ? null : scope.range);
          live.acknowledge();
          setApplied({ ...draft, ...scope.window });
          setOffset(0);
        }}
        onReset={() => {
          setAppliedRange('24h');
          live.acknowledge();
          setDraft({});
          scope.changeRange('24h');
          setApplied({ ...defaultWindow() });
          setOffset(0);
          setInvalid('');
        }}
      >
        <div className="filter-grid">
          <Field label="Service">
            <input
              value={draft.service ?? ''}
              onChange={(event) => field('service', event.target.value)}
              placeholder="All services"
              maxLength={64}
              pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]*"
            />
          </Field>
          <Field label="Event type">
            <select
              value={draft.event_type ?? ''}
              onChange={(event) =>
                field('event_type', event.target.value as EventQuery['event_type'])
              }
            >
              <option value="">All event types</option>
              <option value="http.request.completed">HTTP completion · v1</option>
              <option value="security.decision">Security decision · v2</option>
            </select>
          </Field>
          <Field label="Severity">
            <select
              value={draft.severity ?? ''}
              onChange={(event) => field('severity', event.target.value as EventQuery['severity'])}
            >
              <option value="">All severities</option>
              {['info', 'warning', 'error'].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </Field>
          <TimeFilter
            range={scope.range}
            window={scope.window}
            onChange={(range) => scope.changeRange(range)}
          />
        </div>
        <details className="advanced-filters">
          <summary>Advanced filters &amp; custom window</summary>
          <div className="filter-grid">
            <Field label="Security action">
              <select
                value={draft.security_action ?? ''}
                onChange={(event) =>
                  field('security_action', event.target.value as EventQuery['security_action'])
                }
              >
                <option value="">All actions</option>
                {['record', 'rate_limit', 'temporary_block', 'deny'].map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </Field>
            <Field label="Sanitized endpoint">
              <input
                value={draft.endpoint ?? ''}
                onChange={(event) => field('endpoint', event.target.value)}
                maxLength={256}
                placeholder="/api/demo/items/{item_id}"
                pattern="(unmatched|\/[a-zA-Z0-9_.\/\{\}:~\-]*)"
              />
            </Field>
            <Field label="Request ID">
              <input
                className="mono"
                value={draft.request_id ?? ''}
                onChange={(event) => field('request_id', event.target.value)}
                pattern="[0-9a-f]{32}"
                maxLength={32}
                placeholder="32-character correlation ID"
              />
            </Field>
            <Field label="Client identifier">
              <input
                className="mono"
                value={draft.client_identifier ?? ''}
                onChange={(event) => field('client_identifier', event.target.value)}
                pattern="[0-9a-f]{64}"
                maxLength={64}
                placeholder="64-character HMAC identifier"
              />
            </Field>
            <CustomWindow window={scope.window} onChange={scope.setWindow} />
          </div>
        </details>
      </FilterBar>
      {invalid && (
        <p className="notice danger" role="alert">
          {invalid}
        </p>
      )}
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}
      <Panel
        title="Event stream"
        subtitle={`${dateTime(applied.start)} — ${dateTime(applied.end)} · newest first`}
      >
        {!result.data && result.loading ? (
          <LoadingState />
        ) : result.data?.items.length ? (
          <EventTable events={result.data.items} onSelect={(row) => setSelected(row.event_id)} />
        ) : (
          !result.error && <EmptyState search />
        )}
        {result.data && (
          <Pagination
            total={result.data.total}
            offset={offset}
            limit={25}
            disabled={result.loading}
            onOffset={setOffset}
          />
        )}
      </Panel>
      <p className="data-note">
        This explorer returns a bounded snapshot. Event metadata never includes raw IPs, bodies,
        credentials, or query values.
      </p>
      {selected && <EventDetail id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
function defaultWindow() {
  const end = new Date();
  return { start: new Date(end.getTime() - 86400000).toISOString(), end: end.toISOString() };
}
