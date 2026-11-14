import { useRef, useState } from 'react';
import { LockKeyhole, Plus, ShieldCheck, UserRound } from 'lucide-react';
import { useAuth } from '../auth/AuthProvider';
import { useResource } from '../hooks/useResource';
import type { Account, CreateAccountInput, UpdateAccountInput } from '../api/types';
import { dateTime } from '../utils/format';
import { Badge, KeyValues, PageHeading, Pagination, Panel } from '../components/UI';
import { EmptyState, ErrorState, LoadingState } from '../components/States';
import { Modal } from '../components/Modal';
import { Field } from '../components/Filters';
export default function SettingsPage() {
  const { state, api, session } = useAuth();
  const profile = useResource('profile', (signal) => api.me(signal));
  return (
    <>
      <PageHeading
        eyebrow="Account / settings"
        title="Account & session"
        description="Review your account, server permissions, and active session."
      />
      {!!profile.error && <ErrorState error={profile.error} retry={profile.refresh} />}
      <div className="settings-grid">
        <Panel
          title="Your profile"
          subtitle="Account information confirmed by the API"
          actions={<UserRound size={20} />}
        >
          {!profile.data ? (
            profile.loading ? (
              <LoadingState />
            ) : (
              <EmptyState
                title="Profile unavailable"
                description="Retry the API request to retrieve your account."
              />
            )
          ) : (
            <KeyValues
              values={[
                ['Username', profile.data.username],
                ['Account ID', <code>{profile.data.id}</code>],
                ['Role', <Badge value="neutral">{profile.data.role}</Badge>],
                ['Account status', profile.data.active ? 'Active' : 'Disabled'],
                ['Created', dateTime(profile.data.created_at)],
              ]}
            />
          )}
        </Panel>
        <Panel
          title="Session security"
          subtitle="Credentials stay out of browser storage"
          actions={<LockKeyhole size={20} />}
        >
          <ul className="security-facts">
            <li>
              <ShieldCheck size={18} />
              <span>Access renews automatically while the console is in use.</span>
            </li>
            <li>
              <ShieldCheck size={18} />
              <span>Refresh credentials are protected by an HttpOnly cookie.</span>
            </li>
            <li>
              <ShieldCheck size={18} />
              <span>Logout revokes the current server session.</span>
            </li>
          </ul>
          <p className="muted">
            Current access renewal deadline:{' '}
            {dateTime(state.expiresAt ? new Date(state.expiresAt) : null)}. The server controls
            absolute session expiry.
          </p>
          <button className="button secondary" onClick={() => void session.logout()}>
            Sign out of this session
          </button>
        </Panel>
      </div>
      {state.account?.role === 'ADMIN' ? (
        <AccountManagement />
      ) : (
        <div className="notice info">
          <LockKeyhole size={19} />
          <p>
            Your role permits read-only investigation. Account creation and changes require an
            administrator.
          </p>
        </div>
      )}
    </>
  );
}
function AccountManagement() {
  const { api, state, session } = useAuth();
  const [offset, setOffset] = useState(0);
  const result = useResource('accounts:' + offset, (signal) =>
    api.accounts({ offset, limit: 10 }, signal),
  );
  const [editing, setEditing] = useState<Account | 'new' | null>(null);
  const [message, setMessage] = useState('');
  return (
    <Panel
      title="Authorized accounts"
      subtitle="Provision and manage access. Changes revoke the target account’s active sessions."
      actions={
        <button className="button primary small" onClick={() => setEditing('new')}>
          <Plus size={15} />
          Provision account
        </button>
      }
    >
      {message && (
        <p className="notice success" role="status">
          {message}
        </p>
      )}
      {!!result.error && <ErrorState error={result.error} retry={result.refresh} />}{' '}
      {!result.data && result.loading ? (
        <LoadingState />
      ) : result.data?.items.length ? (
        <div className="table-scroll" tabIndex={0} role="region" aria-label="Authorized accounts">
          <table>
            <thead>
              <tr>
                <th>Account</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>
                  <span className="sr-only">Manage</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {result.data.items.map((account) => (
                <tr key={account.id}>
                  <td>
                    <strong>{account.username}</strong>
                    <small className="mono">{account.id}</small>
                  </td>
                  <td>
                    <Badge value="neutral">{account.role}</Badge>
                  </td>
                  <td>
                    <Badge value={account.active ? 'low' : 'warning'}>
                      {account.active ? 'Active' : 'Disabled'}
                    </Badge>
                  </td>
                  <td>{dateTime(account.created_at)}</td>
                  <td>
                    <button className="text-button" onClick={() => setEditing(account)}>
                      Manage<span className="sr-only"> {account.username}</span>
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState />
      )}
      {result.data && (
        <Pagination
          total={result.data.total}
          offset={offset}
          limit={10}
          disabled={result.loading}
          onOffset={setOffset}
        />
      )}
      {editing && (
        <AccountEditor
          original={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(account) => {
            setEditing(null);
            if (account.id === state.account?.id) {
              session.invalidate('Your account was changed. Sign in again.');
              return;
            }
            setMessage(`Account ${account.username} confirmed by the server.`);
            result.refresh();
          }}
        />
      )}
    </Panel>
  );
}
function AccountEditor({
  original,
  onClose,
  onSaved,
}: {
  original: Account | null;
  onClose: () => void;
  onSaved: (account: Account) => void;
}) {
  const { api, state } = useAuth();
  const [username, setUsername] = useState(original?.username ?? '');
  const [role, setRole] = useState<'ADMIN' | 'ANALYST'>(original?.role ?? 'ANALYST');
  const [active, setActive] = useState(original?.active ?? true);
  const [password, setPassword] = useState('');
  const [review, setReview] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const inFlight = useRef(false);
  const submit = async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    try {
      const input: UpdateAccountInput = { role, active, ...(password ? { password } : {}) };
      const account = original
        ? await api.updateAccount(original.id, input)
        : await api.createAccount({ username, password, role } satisfies CreateAccountInput);
      setPassword('');
      onSaved(account);
    } catch (error) {
      setError(error);
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  };
  return (
    <Modal
      title={
        review
          ? 'Confirm account change'
          : original
            ? 'Manage account'
            : 'Provision authorized account'
      }
      description={
        original
          ? 'Role, password, and activation changes revoke all target sessions.'
          : 'Create access for an authorized operator. No public registration is available.'
      }
      onClose={() => {
        if (!busy) {
          setPassword('');
          onClose();
        }
      }}
    >
      {!!error && <ErrorState error={error} />}{' '}
      {review ? (
        <>
          <KeyValues
            values={[
              ['Username', username],
              ['Role', role],
              ['Status', active ? 'Active' : 'Disabled'],
              ['Password', password ? 'A new password will be set' : 'Unchanged'],
            ]}
          />
          {original?.id === state.account?.id && (
            <p className="notice warning">
              Changing your own account ends this session. You will need to sign in again.
            </p>
          )}
          <div className="modal-actions">
            <button className="button secondary" disabled={busy} onClick={() => setReview(false)}>
              Back
            </button>
            <button className="button primary" disabled={busy} onClick={() => void submit()}>
              {busy ? 'Saving…' : 'Confirm account change'}
            </button>
          </div>
        </>
      ) : (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            setReview(true);
          }}
        >
          <div className="form-stack">
            <Field label="Username">
              <input
                required
                minLength={3}
                maxLength={64}
                pattern="[a-z0-9][a-z0-9_.\-]*"
                autoComplete="off"
                value={username}
                disabled={!!original}
                onChange={(event) => setUsername(event.target.value)}
              />
            </Field>
            <Field label="Role">
              <select
                value={role}
                onChange={(event) => setRole(event.target.value as 'ADMIN' | 'ANALYST')}
              >
                <option value="ANALYST">ANALYST · read-only investigation</option>
                <option value="ADMIN">ADMIN · full administrative control</option>
              </select>
            </Field>
            <Field
              label={original ? 'New password (optional)' : 'Initial password'}
              hint="15–128 characters. Share the credential only through your approved secure channel."
            >
              <input
                type="password"
                autoComplete="new-password"
                required={!original}
                minLength={15}
                maxLength={128}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
              />
            </Field>
            {original && (
              <label className="checkbox-field">
                <input
                  type="checkbox"
                  checked={active}
                  onChange={(event) => setActive(event.target.checked)}
                />
                Account is active
              </label>
            )}
          </div>
          <div className="modal-actions">
            <button
              type="button"
              className="button secondary"
              onClick={() => {
                setPassword('');
                onClose();
              }}
            >
              Cancel
            </button>
            <button className="button primary" type="submit">
              Review account change
            </button>
          </div>
        </form>
      )}
    </Modal>
  );
}
