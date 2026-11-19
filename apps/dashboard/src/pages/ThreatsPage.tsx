import { NewActivity, useLiveRefresh } from '../realtime/LiveActivity';
import { useState } from 'react';
import { useLocation } from 'react-router';
import type { AssessmentQuery } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import { useWindow, windowFor, dateTime, label } from '../utils/format';
import { CustomWindow, Field, FilterBar, TimeFilter, validWindow } from '../components/Filters';
import { AssessmentTable } from '../components/AssessmentTable';
import { AssessmentDetail } from '../components/Details';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { Badge, PageHeading, Pagination, Panel, RefreshControl } from '../components/UI';
const classifications: NonNullable<AssessmentQuery['classification']>[] = [
  'possible_brute_force',
  'repeated_authentication_failures',
  'excessive_api_requests',
  'repeated_policy_violations',
  'suspicious_behavioral_deviation',
  'experimental_behavioral_anomaly',
];
export default function ThreatsPage() {
  const { search } = useLocation();
  return <ThreatExplorer key={search} search={search} />;
}
function ThreatExplorer({ search }: { search: string }) {
  const { api } = useAuth();
  const params = new URLSearchParams(search);
  const initial: AssessmentQuery = { event_id: params.get('event_id') || undefined };
  const [draft, setDraft] = useState<AssessmentQuery>(initial);
  const scope = useWindow();
  const [applied, setApplied] = useState<AssessmentQuery>({ ...initial, ...scope.window });
  const [appliedRange, setAppliedRange] = useState<import('../utils/format').Range | null>('24h');
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<string | null>(params.get('assessment'));
  const [invalid, setInvalid] = useState('');
  const query = { ...applied, offset, limit: 25 };
  const result = useResource('threats:' + JSON.stringify(query), (signal) =>
    api.assessments(query, signal),
  );
  const liveRefresh = () => {
    if (appliedRange) setApplied((old) => ({ ...old, ...windowFor(appliedRange) }));
    else result.refresh();
  };
  const live = useLiveRefresh(liveRefresh, false, true);
  const refreshLive = () => {
    live.acknowledge();
    liveRefresh();
  };
  const field = <K extends keyof AssessmentQuery>(key: K, value: AssessmentQuery[K]) =>
    setDraft((old) => ({ ...old, [key]: value === '' ? undefined : value }));
  return (
    <>
      <PageHeading
        eyebrow="Investigate / threat intelligence"
        title="Threat intelligence"
        description="Investigate persisted risk assessments and the evidence behind each decision."
      >
        <RefreshControl
          loading={result.loading}
          updatedAt={result.updatedAt}
          onRefresh={refreshLive}
        />
      </PageHeading>
      <div className="method-strip">
        <span>
          <i className="dot cyan" />
          Deterministic rules
        </span>
        <span>
          <i className="dot amber" />
          Statistical deviations
        </span>
        <span>
          <i className="dot purple" />
          Experimental ML evidence
        </span>
        <small>Risk is an assessment score, not an attack probability.</small>
      </div>
      <NewActivity pending={live.pending} refresh={refreshLive} assessments={true} />
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
          setApplied(windowFor('24h'));
          setOffset(0);
          setInvalid('');
        }}
      >
        <div className="filter-grid">
          <Field label="Service">
            <input
              maxLength={64}
              pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]*"
              placeholder="All services"
              value={draft.service ?? ''}
              onChange={(event) => field('service', event.target.value)}
            />
          </Field>
          <Field label="Severity">
            <select
              value={draft.severity ?? ''}
              onChange={(event) =>
                field('severity', event.target.value as AssessmentQuery['severity'])
              }
            >
              <option value="">All severities</option>
              {['low', 'moderate', 'high', 'critical'].map((value) => (
                <option key={value}>{value}</option>
              ))}
            </select>
          </Field>
          <Field label="Detection method">
            <select
              value={draft.detection_method ?? ''}
              onChange={(event) =>
                field('detection_method', event.target.value as AssessmentQuery['detection_method'])
              }
            >
              <option value="">All methods</option>
              <option value="deterministic">Deterministic</option>
              <option value="robust_statistics">Robust statistics</option>
              <option value="isolation_forest">Isolation Forest · experimental</option>
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
            <Field label="Classification">
              <select
                value={draft.classification ?? ''}
                onChange={(event) =>
                  field('classification', event.target.value as AssessmentQuery['classification'])
                }
              >
                <option value="">All classifications</option>
                {classifications.map((value) => (
                  <option key={value} value={value}>
                    {label(value)}
                  </option>
                ))}
              </select>
            </Field>
            <Field label="Minimum risk score">
              <input
                type="number"
                min={0}
                max={100}
                step="any"
                value={draft.min_risk ?? 0}
                onChange={(event) => field('min_risk', Number(event.target.value))}
              />
            </Field>
            <Field label="Event ID">
              <input
                placeholder="Correlated event UUID"
                value={draft.event_id ?? ''}
                onChange={(event) => field('event_id', event.target.value)}
                pattern="[0-9a-fA-F\-]{36}"
                maxLength={36}
              />
            </Field>
            <Field label="Client identifier">
              <input
                className="mono"
                pattern="[0-9a-f]{64}"
                maxLength={64}
                value={draft.client_identifier ?? ''}
                onChange={(event) => field('client_identifier', event.target.value)}
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
        title="Persisted assessments"
        subtitle={`${dateTime(applied.start)} — ${dateTime(applied.end)}`}
        actions={<Badge value="experimental">ML adds evidence only</Badge>}
      >
        {!result.data && result.loading ? (
          <LoadingState />
        ) : result.data?.items.length ? (
          <AssessmentTable
            assessments={result.data.items}
            onSelect={(row) => setSelected(row.assessment_id)}
          />
        ) : (
          !result.error && <EmptyState title="No assessments match your filters" />
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
      {selected && <AssessmentDetail id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
