import { useRef, useState } from 'react';
import { Check, LockKeyhole, Pencil, ShieldCheck } from 'lucide-react';
import { useAuth } from '../auth/AuthProvider';
import { ApiError } from '../api/http';
import type { Policy, PolicyDocument } from '../api/types';
import { useResource } from '../hooks/useResource';
import { policyChanges, policyErrors } from '../utils/policies';
import { dateTime, label, number } from '../utils/format';
import { Badge, KeyValues, PageHeading, Panel, RefreshControl } from '../components/UI';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { Modal } from '../components/Modal';
import { Field } from '../components/Filters';
export default function PoliciesPage() {
  const { api, state } = useAuth();
  const admin = state.account?.role === 'ADMIN';
  const result = useResource('policies', (signal) => api.policies(signal));
  const [editing, setEditing] = useState<Policy | null>(null);
  const [success, setSuccess] = useState('');
  const [reconcile, setReconcile] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const data = result.data;
  return (
    <>
      <PageHeading
        eyebrow="Control / protection policies"
        title="Protection policies"
        description="View shared enforcement rules and manage reviewed, versioned changes."
      >
        <RefreshControl
          loading={result.loading}
          updatedAt={result.updatedAt}
          onRefresh={result.refresh}
        />
      </PageHeading>
      {success && (
        <div className="notice success" role="status">
          <Check size={19} />
          <p>{success}</p>
        </div>
      )}
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!data && result.loading && <LoadingState label="Retrieving effective policies" />}
      {data && (
        <>
          <div
            className={
              'policy-status ' + (data.enforcement_synchronized ? 'synchronized' : 'pending')
            }
          >
            <ShieldCheck size={25} />
            <div>
              <strong>
                Revision {data.version} ·{' '}
                {data.enforcement_synchronized
                  ? 'Enforcement synchronized'
                  : 'Activation not confirmed'}
              </strong>
              <span>Committed {dateTime(data.created_at)}</span>
            </div>
            <Badge value={data.enforcement_synchronized ? 'low' : 'warning'}>
              {data.enforcement_synchronized ? 'Server confirmed' : 'Review required'}
            </Badge>
          </div>
          {!data.enforcement_synchronized && (
            <div className="notice danger" role="alert">
              <div>
                <strong>Saved configuration is not confirmed active.</strong>
                <p>
                  A policy update may be pending. Reload the current revision before any further
                  edits.
                </p>
              </div>
              {admin && (
                <button className="button secondary small" onClick={() => setReconcile(true)}>
                  Reconcile latest revision
                </button>
              )}
            </div>
          )}
          {!admin && (
            <div className="notice info">
              <LockKeyhole size={19} />
              <p>
                Your ANALYST role has read-only policy access. Administrative changes are also
                authorized by the server.
              </p>
            </div>
          )}
          {!data.policies.length && (
            <EmptyState
              title="No managed policies"
              description="No policy groups are configured on this deployment."
            />
          )}
          <div className="policy-grid">
            {data.policies.map((policy) => (
              <Panel
                key={policy.id}
                title={policy.id}
                subtitle={policy.path_prefix}
                actions={
                  admin ? (
                    <button
                      className="button small secondary"
                      disabled={result.loading || !data.enforcement_synchronized}
                      onClick={() => {
                        setSuccess('');
                        setEditing(policy);
                      }}
                    >
                      <Pencil size={14} />
                      Edit policy
                    </button>
                  ) : (
                    <Badge value="neutral">Read only</Badge>
                  )
                }
              >
                <div className="policy-methods">
                  <Badge value="low">{policy.enabled !== false ? 'Enabled' : 'Disabled'}</Badge>
                  <span>
                    {policy.methods?.length ? policy.methods.join(', ') : 'All HTTP methods'}
                  </span>
                  <span>{label(policy.failure_mode)} on enforcement error</span>
                </div>
                <KeyValues
                  values={[
                    [
                      'Rate limit',
                      policy.rate
                        ? `${number(policy.rate.requests ?? 600)} requests / ${policy.rate.window_seconds ?? 60}s`
                        : 'No rate rule',
                    ],
                    [
                      'Rate action',
                      policy.rate
                        ? label(policy.rate.exceed_action ?? 'rate_limit')
                        : 'Not applicable',
                    ],
                    [
                      'Rate block duration',
                      policy.rate ? `${policy.rate.block_seconds ?? 60}s` : 'Not applicable',
                    ],
                    [
                      'Authentication threshold',
                      policy.authentication
                        ? `${policy.authentication.failures ?? 5} failures / ${policy.authentication.window_seconds ?? 60}s`
                        : 'No authentication rule',
                    ],
                    [
                      'Authentication action',
                      policy.authentication
                        ? label(policy.authentication.exceed_action ?? 'block')
                        : 'Not applicable',
                    ],
                    [
                      'Authentication block',
                      policy.authentication
                        ? `${policy.authentication.block_seconds ?? 60}s`
                        : 'Not applicable',
                    ],
                    [
                      'Clear failures after verified success',
                      policy.authentication
                        ? policy.authentication.clear_on_success !== false
                          ? 'Yes'
                          : 'No'
                        : 'Not applicable',
                    ],
                  ]}
                />
              </Panel>
            ))}
          </div>
          <p className="data-note">
            Existing protected scopes and closed failure modes are preserved. Edits start fresh rule
            counters. A committed revision is only shown as active when Redis synchronization is
            confirmed.
          </p>
        </>
      )}
      {editing && data && (
        <PolicyEditor
          document={data}
          original={editing}
          onClose={() => setEditing(null)}
          onReload={() => {
            setEditing(null);
            result.refresh();
          }}
          onSaved={(saved) => {
            setEditing(null);
            setSuccess(
              saved.enforcement_synchronized
                ? `Server acknowledged activation of revision ${saved.version}. Reloading the current enforcement state.`
                : `Revision ${saved.version} was saved; activation is not confirmed.`,
            );
            result.refresh();
          }}
        />
      )}
      {reconcile && (
        <Modal
          title="Reconcile enforcement"
          description="Activate the latest committed configuration in shared Redis."
          onClose={() => {
            if (!busy) setReconcile(false);
          }}
        >
          {!!error && <ErrorState error={error} />}
          <p>
            This can change active request enforcement. Review the current revision and confirm that
            it is the intended policy set.
          </p>
          <div className="modal-actions">
            <button
              className="button secondary"
              disabled={busy}
              onClick={() => setReconcile(false)}
            >
              Cancel
            </button>
            <button
              className="button primary"
              disabled={busy}
              onClick={async () => {
                if (busy) return;
                setBusy(true);
                setError(null);
                try {
                  const saved = await api.reconcilePolicies();
                  setSuccess(
                    `Revision ${saved.version} reconciliation ${saved.enforcement_synchronized ? 'confirmed' : 'pending'}.`,
                  );
                  setReconcile(false);
                  result.refresh();
                } catch (error) {
                  setError(error);
                } finally {
                  setBusy(false);
                }
              }}
            >
              {busy ? 'Reconciling…' : 'Confirm reconciliation'}
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
function PolicyEditor({
  document,
  original,
  onClose,
  onSaved,
  onReload,
}: {
  document: PolicyDocument;
  original: Policy;
  onClose: () => void;
  onSaved: (data: PolicyDocument) => void;
  onReload: () => void;
}) {
  const { api } = useAuth();
  const [draft, setDraft] = useState<Policy>(() => structuredClone(original));
  const [review, setReview] = useState(false);
  const [validation, setValidation] = useState<string[]>([]);
  const [error, setError] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const changes = policyChanges(original, draft);
  const setRate = (patch: Partial<NonNullable<Policy['rate']>>) =>
    setDraft((old) => ({ ...old, rate: old.rate ? { ...old.rate, ...patch } : old.rate }));
  const setAuthentication = (patch: Partial<NonNullable<Policy['authentication']>>) =>
    setDraft((old) => ({
      ...old,
      authentication: old.authentication ? { ...old.authentication, ...patch } : old.authentication,
    }));
  const save = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const saved = await api.updatePolicies({
        expected_version: document.version,
        policies: document.policies.map((policy) => (policy.id === draft.id ? draft : policy)),
      });
      onSaved(saved);
    } catch (error) {
      setError(error);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <Modal
      wide
      title={review ? 'Review protection change' : 'Edit protection policy'}
      description={`${original.id} · ${original.path_prefix} · based on revision ${document.version}`}
      onClose={() => {
        if (!busy) onClose();
      }}
    >
      {!!error && <ErrorState error={error} />}{' '}
      {error instanceof ApiError && [409, 503].includes(error.status) && (
        <div className="notice warning">
          <p>
            {error.status === 409
              ? 'Another operator changed the policies.'
              : 'A revision may have committed without activation.'}{' '}
            Reload the latest revision before trying again.
          </p>
          <button className="button secondary small" onClick={onReload}>
            Reload latest revision
          </button>
        </div>
      )}
      {review ? (
        <>
          <p className="muted">
            Confirm the exact changes below. Rule counters restart for the changed configuration;
            requests already in flight can finish under their selected rules.
          </p>
          <ul className="change-list">
            {changes.map((change) => (
              <li key={change}>{change}</li>
            ))}
          </ul>
          <div className="modal-actions">
            <button disabled={busy} className="button secondary" onClick={() => setReview(false)}>
              Back to editing
            </button>
            <button
              className="button primary"
              disabled={busy || (error instanceof ApiError && [409, 503].includes(error.status))}
              onClick={() => void save()}
            >
              {busy ? 'Applying…' : 'Confirm and apply'}
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const errors = policyErrors(draft);
            setValidation(errors);
            if (!errors.length) setReview(true);
          }}
        >
          {validation.length > 0 && (
            <div className="notice danger" role="alert">
              <ul>
                {validation.map((message) => (
                  <li key={message}>{message}</li>
                ))}
              </ul>
            </div>
          )}
          <Field label="Enforcement error behavior">
            <select
              value={draft.failure_mode ?? 'open'}
              disabled={original.failure_mode === 'closed'}
              onChange={(event) =>
                setDraft({ ...draft, failure_mode: event.target.value as Policy['failure_mode'] })
              }
            >
              <option value="open">Open · observe degradation</option>
              <option value="closed">Closed · reject with 503</option>
            </select>
          </Field>
          {draft.rate && (
            <fieldset>
              <legend>Request rate rule</legend>
              <div className="filter-grid">
                <Field label="Allowed requests">
                  <input
                    type="number"
                    required
                    min={1}
                    max={10000}
                    step={1}
                    value={draft.rate.requests ?? 600}
                    onChange={(event) => setRate({ requests: Number(event.target.value) })}
                  />
                </Field>
                <Field label="Rate window (seconds)">
                  <input
                    type="number"
                    required
                    min={0.1}
                    max={3600}
                    step="any"
                    value={draft.rate.window_seconds ?? 60}
                    onChange={(event) => setRate({ window_seconds: Number(event.target.value) })}
                  />
                </Field>
                <Field label="Rate exceed action">
                  <select
                    value={draft.rate.exceed_action ?? 'rate_limit'}
                    onChange={(event) =>
                      setRate({
                        exceed_action: event.target.value as 'record' | 'rate_limit' | 'block',
                      })
                    }
                  >
                    <option value="record">Record only</option>
                    <option value="rate_limit">Rate limit</option>
                    <option value="block">Temporary block</option>
                  </select>
                </Field>
                <Field label="Rate block (seconds)">
                  <input
                    type="number"
                    required
                    min={0.1}
                    max={3600}
                    step="any"
                    value={draft.rate.block_seconds ?? 60}
                    onChange={(event) => setRate({ block_seconds: Number(event.target.value) })}
                  />
                </Field>
              </div>
            </fieldset>
          )}
          {draft.authentication && (
            <fieldset>
              <legend>Verified authentication failures</legend>
              <div className="filter-grid">
                <Field label="Failure threshold">
                  <input
                    type="number"
                    required
                    min={2}
                    max={100}
                    step={1}
                    value={draft.authentication.failures ?? 5}
                    onChange={(event) =>
                      setAuthentication({ failures: Number(event.target.value) })
                    }
                  />
                </Field>
                <Field label="Failure window (seconds)">
                  <input
                    type="number"
                    required
                    min={0.1}
                    max={3600}
                    step="any"
                    value={draft.authentication.window_seconds ?? 60}
                    onChange={(event) =>
                      setAuthentication({ window_seconds: Number(event.target.value) })
                    }
                  />
                </Field>
                <Field label="Authentication action">
                  <select
                    value={draft.authentication.exceed_action ?? 'block'}
                    onChange={(event) =>
                      setAuthentication({ exceed_action: event.target.value as 'record' | 'block' })
                    }
                  >
                    <option value="record">Record only</option>
                    <option value="block">Temporary block</option>
                  </select>
                </Field>
                <Field label="Authentication block (seconds)">
                  <input
                    type="number"
                    required
                    min={0.1}
                    max={3600}
                    step="any"
                    value={draft.authentication.block_seconds ?? 60}
                    onChange={(event) =>
                      setAuthentication({ block_seconds: Number(event.target.value) })
                    }
                  />
                </Field>
              </div>
              <label className="checkbox-field">
                <input
                  type="checkbox"
                  checked={draft.authentication.clear_on_success !== false}
                  onChange={(event) =>
                    setAuthentication({ clear_on_success: event.target.checked })
                  }
                />
                Clear failure counter after verified authentication succeeds
              </label>
            </fieldset>
          )}
          <div className="modal-actions">
            <button type="button" className="button secondary" onClick={onClose}>
              Cancel
            </button>
            <button className="button primary" type="submit" disabled={!changes.length}>
              Review changes
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
