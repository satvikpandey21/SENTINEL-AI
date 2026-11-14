import { useState } from 'react';
import type { AuditQuery, AuditRecord } from '../api/types';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import { dateTime, compactId, label, useWindow, windowFor } from '../utils/format';
import { CustomWindow, Field, FilterBar, TimeFilter, validWindow } from '../components/Filters';
import { Badge, KeyValues, PageHeading, Panel, Pagination, RefreshControl } from '../components/UI';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { Modal } from '../components/Modal';
function summary(record: AuditRecord) {
  return (
    Object.entries(record.summary)
      .filter(([, value]) => value !== null && value !== undefined)
      .map(
        ([key, value]) =>
          `${label(key)}: ${Array.isArray(value) ? value.join(', ') : String(value)}`,
      )
      .join(' · ') || 'No additional changes'
  );
}
export default function AuditPage() {
  const { api } = useAuth();
  const scope = useWindow();
  const [draft, setDraft] = useState<AuditQuery>({});
  const [applied, setApplied] = useState<AuditQuery>(scope.window);
  const [offset, setOffset] = useState(0);
  const [selected, setSelected] = useState<AuditRecord | null>(null);
  const [invalid, setInvalid] = useState('');
  const query = { ...applied, offset, limit: 25 };
  const result = useResource('audit:' + JSON.stringify(query), (signal) =>
    api.audit(query, signal),
  );
  return (
    <>
      <PageHeading
        eyebrow="Control / administrative history"
        title="Audit logs"
        description="Review security-sensitive administrative activity and rejected operations."
      >
        <RefreshControl
          loading={result.loading}
          updatedAt={result.updatedAt}
          onRefresh={result.refresh}
        />
      </PageHeading>
      <FilterBar
        onSubmit={(event) => {
          event.preventDefault();
          if (!validWindow(scope.window)) {
            setInvalid('Choose a positive time window of at most 31 days.');
            return;
          }
          setInvalid('');
          setApplied({ ...draft, ...scope.window });
          setOffset(0);
        }}
        onReset={() => {
          setDraft({});
          scope.changeRange('24h');
          setApplied(windowFor('24h'));
          setOffset(0);
        }}
      >
        <div className="filter-grid">
          <Field label="Actor ID">
            <input
              className="mono"
              maxLength={36}
              pattern="[0-9a-fA-F\-]{36}"
              placeholder="Administrator UUID"
              value={draft.actor_id ?? ''}
              onChange={(event) =>
                setDraft({ ...draft, actor_id: event.target.value || undefined })
              }
            />
          </Field>
          <Field label="Action">
            <input
              maxLength={48}
              pattern="[a-z_.]+"
              placeholder="For example: policy.update"
              value={draft.action ?? ''}
              onChange={(event) => setDraft({ ...draft, action: event.target.value || undefined })}
            />
          </Field>
          <Field label="Outcome">
            <select
              value={draft.outcome ?? ''}
              onChange={(event) =>
                setDraft({
                  ...draft,
                  outcome: (event.target.value as AuditQuery['outcome']) || undefined,
                })
              }
            >
              <option value="">All outcomes</option>
              <option value="success">Success</option>
              <option value="rejected">Rejected</option>
            </select>
          </Field>
          <TimeFilter
            range={scope.range}
            window={scope.window}
            onChange={(range) => scope.changeRange(range)}
          />
        </div>
        <details className="advanced-filters">
          <summary>Custom time window</summary>
          <div className="filter-grid">
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
        title="Administrative activity"
        subtitle={`${dateTime(applied.start)} — ${dateTime(applied.end)}`}
      >
        {!result.data && result.loading ? (
          <LoadingState />
        ) : result.data?.items.length ? (
          <div
            className="table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Administrative audit records"
          >
            <table>
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Actor</th>
                  <th>Action</th>
                  <th>Target</th>
                  <th>Outcome</th>
                  <th>Change summary</th>
                  <th>
                    <span className="sr-only">Details</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {result.data.items.map((record) => (
                  <tr key={record.id}>
                    <td>
                      <time dateTime={record.occurred_at}>{dateTime(record.occurred_at)}</time>
                    </td>
                    <td>
                      <code title={record.actor_id ?? 'System or unknown'}>
                        {record.actor_id ? compactId(record.actor_id) : 'System / unknown'}
                      </code>
                    </td>
                    <td>
                      <code>{record.action}</code>
                    </td>
                    <td className="break">{record.target}</td>
                    <td>
                      <Badge value={record.outcome === 'success' ? 'low' : 'warning'}>
                        {record.outcome}
                      </Badge>
                    </td>
                    <td className="summary-cell">{summary(record)}</td>
                    <td>
                      <button className="text-button" onClick={() => setSelected(record)}>
                        Details<span className="sr-only"> for audit {record.id}</span>
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          !result.error && <EmptyState title="No administrative activity in this window" />
        )}
        {result.data && (
          <Pagination
            total={result.data.total}
            offset={offset}
            limit={25}
            onOffset={setOffset}
            disabled={result.loading}
          />
        )}
      </Panel>
      {selected && (
        <Modal
          title="Administrative audit record"
          description="An allowlisted, persisted change record."
          onClose={() => setSelected(null)}
        >
          <KeyValues
            values={[
              ['Record ID', <code>{selected.id}</code>],
              ['Actor', <code>{selected.actor_id ?? 'System or unknown'}</code>],
              ['Action', selected.action],
              ['Target', selected.target],
              [
                'Outcome',
                <Badge value={selected.outcome === 'success' ? 'low' : 'warning'}>
                  {selected.outcome}
                </Badge>,
              ],
              ['Timestamp', dateTime(selected.occurred_at)],
              ['Summary', summary(selected)],
            ]}
          />
        </Modal>
      )}
    </>
  );
}
