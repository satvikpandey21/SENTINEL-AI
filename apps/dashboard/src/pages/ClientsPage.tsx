import { useState } from 'react';
import { useLocation } from 'react-router';
import { Fingerprint, Search, ShieldBan } from 'lucide-react';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import { clientPattern, dateTime, useWindow } from '../utils/format';
import type { ClientQuery, TimeWindow } from '../api/types';
import { CustomWindow, Field, TimeFilter, validWindow } from '../components/Filters';
import { Badge, KeyValues, PageHeading, Panel, RefreshControl } from '../components/UI';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { EventTable } from '../components/EventTable';
import { AssessmentTable } from '../components/AssessmentTable';
import { AssessmentDetail, EventDetail } from '../components/Details';
import { RiskHistory } from '../components/Charts';
export default function ClientsPage() {
  const { search } = useLocation();
  return <Investigation key={search} search={search} />;
}
function Investigation({ search }: { search: string }) {
  const initial = new URLSearchParams(search).get('client') ?? '';
  const scope = useWindow();
  const [draft, setDraft] = useState(initial);
  const [service, setService] = useState('');
  const [lookup, setLookup] = useState<{ id: string; window: TimeWindow; service: string } | null>(
    clientPattern.test(initial) ? { id: initial, window: scope.window, service: '' } : null,
  );
  const [tab, setTab] = useState('requests');
  const [selectedEvent, setSelectedEvent] = useState<string | null>(null);
  const [selectedRisk, setSelectedRisk] = useState<string | null>(null);
  const { api } = useAuth();
  const query: ClientQuery = lookup
    ? { ...lookup.window, service: lookup.service || undefined }
    : scope.window;
  const result = useResource(
    'client:' + JSON.stringify(lookup),
    (signal) => api.client(lookup?.id ?? '', query, signal),
    { enabled: !!lookup },
  );
  const data = result.data;
  return (
    <>
      <PageHeading
        eyebrow="Investigate / client activity"
        title="Client investigation"
        description="Trace API activity through a pseudonymous HMAC identifier."
      >
        <RefreshControl
          loading={result.loading}
          updatedAt={result.updatedAt}
          onRefresh={result.refresh}
        />
      </PageHeading>
      <div className="notice info">
        <Fingerprint size={20} />
        <p>
          One identifier may be shared by users behind a NAT or proxy. It represents a network
          context, not a uniquely identified person. Raw IP addresses are never shown.
        </p>
      </div>
      <form
        className="filter-panel"
        onSubmit={(event) => {
          event.preventDefault();
          if (clientPattern.test(draft) && validWindow(scope.window))
            setLookup({ id: draft, window: scope.window, service });
        }}
      >
        <div className="investigation-form">
          <Field label="Pseudonymous client identifier">
            <input
              className="mono"
              required
              pattern="[0-9a-f]{64}"
              maxLength={64}
              value={draft}
              onChange={(event) => setDraft(event.target.value)}
              placeholder="Paste the 64-character identifier from an event"
              autoComplete="off"
            />
          </Field>
          <Field label="Service">
            <input
              placeholder="All services"
              maxLength={64}
              pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]*"
              value={service}
              onChange={(event) => setService(event.target.value)}
            />
          </Field>
          <TimeFilter
            range={scope.range}
            window={scope.window}
            onChange={(range) => scope.changeRange(range)}
          />
          <button className="button primary" type="submit" disabled={result.loading}>
            <Search size={17} />
            Investigate
          </button>
        </div>
        <details className="advanced-filters">
          <summary>Custom investigation window</summary>
          <div className="filter-grid">
            <CustomWindow window={scope.window} onChange={scope.setWindow} />
          </div>
        </details>
        {!validWindow(scope.window) && (
          <p className="notice danger" role="alert">
            Choose a positive time window of at most 31 days.
          </p>
        )}
      </form>
      {!lookup && (
        <Panel
          title="Follow the evidence"
          subtitle="Start from a security event or paste an existing identifier."
        >
          <EmptyState
            title="Ready to investigate"
            description="Select a client from Security Events, Threat Intelligence, or the overview to inspect its real activity."
            search
          />
        </Panel>
      )}
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!data && result.loading && <LoadingState label="Retrieving client activity" />}
      {data && (
        <>
          <Panel title="Investigation context" subtitle={data.client_identifier}>
            <KeyValues
              values={[
                ['First observed in window', dateTime(data.first_seen)],
                ['Last observed in window', dateTime(data.last_seen)],
                ['Window start', dateTime(data.start)],
                ['Window end (exclusive)', dateTime(data.end)],
              ]}
            />
          </Panel>
          <Panel
            title="Active restriction snapshot"
            subtitle="Current managed-policy TTLs, observed at the last refresh"
          >
            {(data.active_restrictions ?? []).length ? (
              <div className="restriction-grid">
                {(data.active_restrictions ?? []).map((row) => (
                  <div className="restriction-card" key={row.service + row.policy_id}>
                    <ShieldBan size={21} />
                    <div>
                      <strong>{row.policy_id}</strong>
                      <small>{row.service}</small>
                      <span>
                        {row.remaining_seconds}s remaining at {dateTime(row.observed_at)}
                      </span>
                    </div>
                    <Badge value="temporary-block">TTL snapshot</Badge>
                  </div>
                ))}
              </div>
            ) : (
              <EmptyState
                title="No active restrictions found"
                description="Checks cover current policy fingerprints for up to 20 observed services."
              />
            )}
          </Panel>
          <Panel
            title="Observed risk history"
            subtitle="Up to 50 persisted assessments in the selected window"
          >
            {data.assessments.length ? (
              <RiskHistory assessments={data.assessments} />
            ) : (
              <EmptyState title="No risk history in this window" />
            )}
          </Panel>
          <section className="panel">
            <div className="tab-list" role="tablist" aria-label="Client activity records">
              {[
                ['requests', `Recent requests (${data.recent_requests.length})`],
                ['decisions', `Policy violations (${data.violations.length})`],
                ['assessments', `Assessments (${data.assessments.length})`],
                ['restrictions', `Restriction history (${data.temporary_restrictions.length})`],
              ].map(([key, text]) => (
                <button
                  role="tab"
                  key={key}
                  id={'tab-' + key}
                  aria-selected={tab === key}
                  aria-controls="client-records"
                  tabIndex={tab === key ? 0 : -1}
                  onKeyDown={(event) => {
                    const keys = ['requests', 'decisions', 'assessments', 'restrictions'];
                    if (event.key === 'ArrowRight' || event.key === 'ArrowLeft') {
                      event.preventDefault();
                      const next =
                        keys[(keys.indexOf(tab) + (event.key === 'ArrowRight' ? 1 : 3)) % 4] ??
                        'requests';
                      setTab(next);
                      document.getElementById('tab-' + next)?.focus();
                    }
                  }}
                  onClick={() => setTab(key ?? 'requests')}
                >
                  {text}
                </button>
              ))}
            </div>
            <div id="client-records" role="tabpanel" aria-labelledby={'tab-' + tab}>
              {tab === 'assessments' ? (
                data.assessments.length ? (
                  <AssessmentTable
                    assessments={data.assessments}
                    onSelect={(row) => setSelectedRisk(row.assessment_id)}
                  />
                ) : (
                  <EmptyState />
                )
              ) : (
                (() => {
                  const rows =
                    tab === 'requests'
                      ? data.recent_requests
                      : tab === 'decisions'
                        ? data.violations
                        : data.temporary_restrictions;
                  return rows.length ? (
                    <EventTable events={rows} onSelect={(row) => setSelectedEvent(row.event_id)} />
                  ) : (
                    <EmptyState />
                  );
                })()
              )}
            </div>
          </section>
          <p className="data-note">
            Each record list is capped at 50 by the backend. Narrow the time window or use the event
            and assessment explorers for paginated investigations.
          </p>
        </>
      )}
      {selectedEvent && <EventDetail id={selectedEvent} onClose={() => setSelectedEvent(null)} />}{' '}
      {selectedRisk && <AssessmentDetail id={selectedRisk} onClose={() => setSelectedRisk(null)} />}
    </>
  );
}
