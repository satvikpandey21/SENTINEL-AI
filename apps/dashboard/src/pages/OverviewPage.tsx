import { useLiveRefresh } from '../realtime/LiveActivity';
import { useState } from 'react';
import { Link } from 'react-router';
import { Activity, ArrowUpRight, Fingerprint, Gauge, ShieldAlert, ShieldBan } from 'lucide-react';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import {
  windowFor,
  dateTime,
  number,
  label,
  compactId,
  servicePattern,
  type Range,
} from '../utils/format';
import { Badge, PageHeading, Panel, RangeSelect, RefreshControl } from '../components/UI';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { DistributionChart, RequestChart } from '../components/Charts';
import { AssessmentTable } from '../components/AssessmentTable';
import { AssessmentDetail } from '../components/Details';
export default function OverviewPage() {
  const { api } = useAuth();
  const [range, setRange] = useState<Range>('24h');
  const [service, setService] = useState('');
  const [draft, setDraft] = useState('');
  const [selected, setSelected] = useState<string | null>(null);
  const result = useResource(
    `overview:${range}:${service}`,
    (signal) =>
      api.analytics(
        {
          ...windowFor(range),
          service: service || undefined,
          bucket: range === '30d' ? 'day' : 'hour',
        },
        signal,
      ),
    { pollMs: 60000 },
  );
  useLiveRefresh(result.refresh, true);
  const data = result.data;
  const metrics = data
    ? [
        {
          title: 'Monitored requests',
          value: data.monitored_requests,
          description: 'HTTP completion records',
          icon: Activity,
          color: 'cyan',
        },
        {
          title: 'Security decisions',
          value: data.security_decisions,
          description: 'Independent decision records',
          icon: Gauge,
          color: 'blue',
        },
        {
          title: 'Rate-limit violations',
          value: data.rate_limit_violations,
          description: 'Rate-limit decisions',
          icon: ShieldAlert,
          color: 'amber',
        },
        {
          title: 'Temporary restrictions',
          value: data.temporary_blocks,
          description: 'Blocking decisions, including repeats',
          icon: ShieldBan,
          color: 'rose',
        },
      ]
    : [];
  return (
    <>
      <PageHeading
        eyebrow="Monitor / overview"
        title="Security overview"
        description="A clear view of API traffic, protection decisions, and observed risk."
      >
        <RangeSelect value={range} onChange={setRange} />
        <RefreshControl
          loading={result.loading}
          onRefresh={result.refresh}
          updatedAt={result.updatedAt}
          polling
        />
      </PageHeading>
      <form
        className="scope-bar"
        onSubmit={(event) => {
          event.preventDefault();
          if (!draft || servicePattern.test(draft)) setService(draft);
        }}
      >
        <span className="scope-label">Monitoring scope</span>
        <label>
          <span className="sr-only">Service</span>
          <input
            placeholder="All services"
            aria-label="Service"
            maxLength={64}
            pattern="[a-zA-Z0-9][a-zA-Z0-9_.\-]*"
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
          />
        </label>
        <button className="button small secondary" type="submit">
          Apply service
        </button>
        <span className="scope-window">
          {data ? `${dateTime(data.start)} — ${dateTime(data.end)}` : 'Time window selected above'}
        </span>
      </form>
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!!result.error && data && (
        <p className="muted">Showing the last successfully received snapshot.</p>
      )}
      {!data && result.loading && <LoadingState label="Loading security overview" />}
      {data && (
        <>
          <div className="metric-grid">
            {metrics.map((metric) => (
              <section className="metric-card" key={metric.title}>
                <div>
                  <span>{metric.title}</span>
                  <metric.icon className={'metric-icon ' + metric.color} size={21} />
                </div>
                <strong>{number(metric.value)}</strong>
                <small>{metric.description}</small>
              </section>
            ))}
          </div>
          <div className="overview-grid">
            <Panel
              className="span-8"
              title="Request activity"
              subtitle="Monitored HTTP requests · UTC buckets"
              actions={<Badge value="neutral">{data.bucket === 'day' ? 'Daily' : 'Hourly'}</Badge>}
            >
              <RequestChart data={data} />
            </Panel>
            <Panel
              className="span-4"
              title="Threat severity"
              subtitle="Assessments containing classified threats"
            >
              <DistributionChart
                title="Threat severity distribution"
                items={data.threats_by_severity}
                doughnut
              />
            </Panel>
            <Panel
              className="span-6"
              title="HTTP response distribution"
              subtitle="Status codes from HTTP completion records"
            >
              <DistributionChart
                title="HTTP status distribution"
                items={data.status_distribution}
              />
            </Panel>
            <Panel
              className="span-6"
              title="Risk score distribution"
              subtitle="All assessments · grouped risk scores, not probabilities"
            >
              <DistributionChart title="Risk score distribution" items={data.risk_distribution} />
            </Panel>
            <Panel
              className="span-8"
              title="Recent alerts"
              subtitle="Latest 20 assessments with nonzero risk"
              actions={
                <Link className="text-link" to="/threats">
                  Threat intelligence
                  <ArrowUpRight size={15} />
                </Link>
              }
            >
              {data.recent_alerts.length ? (
                <AssessmentTable
                  assessments={data.recent_alerts}
                  onSelect={(row) => setSelected(row.assessment_id)}
                />
              ) : (
                <EmptyState
                  title="No nonzero-risk alerts"
                  description="Observed assessments remain available in Threat Intelligence."
                />
              )}
            </Panel>
            <Panel
              className="span-4"
              title="Frequently targeted routes"
              subtitle="Top sanitized routes by monitored request volume"
            >
              {data.targeted_routes.length ? (
                <ol className="route-ranking">
                  {data.targeted_routes.map((route, index) => (
                    <li key={route.key}>
                      <span className="rank">{String(index + 1).padStart(2, '0')}</span>
                      <div>
                        <code>{route.key}</code>
                        <span className="mini-bar">
                          <i
                            style={{
                              width: `${(route.count / Math.max(...data.targeted_routes.map((item) => item.count))) * 100}%`,
                            }}
                          />
                        </span>
                      </div>
                      <strong>{number(route.count)}</strong>
                    </li>
                  ))}
                </ol>
              ) : (
                <EmptyState title="No route activity" />
              )}
            </Panel>
            <Panel
              className="span-6"
              title="Observed classifications"
              subtitle="Assessments may contain more than one category"
            >
              {data.threats_by_classification.length ? (
                <ul className="classification-list">
                  {data.threats_by_classification.map((row) => (
                    <li key={row.key}>
                      <ShieldAlert size={17} />
                      <span>
                        {label(row.key)}
                        {row.key === 'experimental_behavioral_anomaly' && (
                          <small>Experimental evidence only</small>
                        )}
                      </span>
                      <strong>{number(row.count)}</strong>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No classifications observed" />
              )}
            </Panel>
            <Panel
              className="span-6"
              title="Suspicious client activity"
              subtitle="Pseudonymous service/client groups with nonzero risk"
            >
              {data.suspicious_clients.length ? (
                <ul className="client-list">
                  {data.suspicious_clients.map((row) => (
                    <li key={row.service + row.client_identifier}>
                      <Fingerprint size={20} />
                      <div>
                        <Link className="mono" to={'/clients?client=' + row.client_identifier}>
                          {compactId(row.client_identifier)}
                        </Link>
                        <small>
                          {row.service} · {number(row.assessment_count)} assessments
                        </small>
                      </div>
                      <div>
                        <strong>
                          {row.max_risk.toFixed(0)}
                          <small>max risk</small>
                        </strong>
                      </div>
                    </li>
                  ))}
                </ul>
              ) : (
                <EmptyState title="No suspicious groups observed" />
              )}
            </Panel>
          </div>
          <p className="data-note">
            HTTP requests and security decisions are counted separately. Telemetry is processed
            asynchronously. Shared client identifiers do not uniquely identify a person.
          </p>
        </>
      )}
      {selected && <AssessmentDetail id={selected} onClose={() => setSelected(null)} />}
    </>
  );
}
