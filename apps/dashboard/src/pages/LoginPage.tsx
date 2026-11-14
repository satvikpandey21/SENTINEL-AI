import { useState } from 'react';
import { Navigate, useLocation } from 'react-router';
import {
  ArrowRight,
  Eye,
  EyeOff,
  Fingerprint,
  LockKeyhole,
  Radar,
  ShieldCheck,
} from 'lucide-react';
import { useAuth } from '../auth/AuthProvider';
import { ErrorState } from '../components/States';
import { Field } from '../components/Filters';
export default function LoginPage() {
  const { state, session } = useAuth();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [visible, setVisible] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<unknown>(null);
  if (state.status === 'authenticated') {
    const from = (location.state as { from?: unknown } | null)?.from;
    return (
      <Navigate
        replace
        to={
          typeof from === 'string' &&
          from.startsWith('/') &&
          !from.startsWith('//') &&
          from != '/login'
            ? from
            : '/'
        }
      />
    );
  }
  return (
    <div className="login-layout">
      <section className="login-story" aria-label="Sentinel security console">
        <a href="/" className="brand">
          <span className="brand-mark">
            <ShieldCheck size={27} />
          </span>
          <span>
            SENTINEL<span className="brand-ai"> AI</span>
            <small>SECURITY OPERATIONS</small>
          </span>
        </a>
        <div className="login-intro">
          <span className="eyebrow">Visibility. Evidence. Control.</span>
          <h1>
            Clarity for your
            <br />
            <span>API security.</span>
          </h1>
          <p>
            Connect the signals. Investigate the evidence.
            <br />
            Keep protection decisions under your control.
          </p>
          <div className="radar-art" aria-hidden="true">
            <span />
            <span />
            <span />
            <i />
            <ShieldCheck size={48} />
            <b className="radar-point p1" />
            <b className="radar-point p2" />
            <b className="radar-point p3" />
          </div>
          <ul className="login-capabilities">
            <li>
              <Radar size={19} />
              <span>
                Traffic visibility<small>Observed requests and security events</small>
              </span>
            </li>
            <li>
              <Fingerprint size={19} />
              <span>
                Evidence-led investigation<small>Explainable risk and pseudonymous activity</small>
              </span>
            </li>
            <li>
              <ShieldCheck size={19} />
              <span>
                Controlled protection<small>Reviewed, versioned policy enforcement</small>
              </span>
            </li>
          </ul>
        </div>
        <footer>
          Sentinel AI<span>Administrative control plane</span>
        </footer>
      </section>
      <main className="login-main">
        <div className="login-card">
          <span className="login-lock">
            <LockKeyhole size={24} />
          </span>
          <span className="eyebrow">Authorized operators only</span>
          <h2>Welcome to Sentinel</h2>
          <p>Sign in to your security workspace.</p>
          {state.message && (
            <div className="notice info" role="status">
              <p>{state.message}</p>
            </div>
          )}
          {state.status === 'unavailable' && (
            <button className="text-button" onClick={() => void session.restore()}>
              Retry session restoration
            </button>
          )}
          {state.logoutUnconfirmed && (
            <button className="button secondary" onClick={() => void session.logout()}>
              Retry server sign-out
            </button>
          )}
          {!!error && <ErrorState error={error} />}
          <form
            onSubmit={async (event) => {
              event.preventDefault();
              if (busy) return;
              setBusy(true);
              setError(null);
              try {
                await session.login({ username, password });
                setPassword('');
              } catch (error) {
                setError(error);
                setPassword('');
              } finally {
                setBusy(false);
              }
            }}
            className="form-stack"
          >
            <Field label="Username">
              <input
                autoComplete="username"
                name="username"
                required
                minLength={3}
                maxLength={64}
                pattern="[a-z0-9][a-z0-9_.\-]*"
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                placeholder="Your administrator-provisioned username"
                disabled={busy}
              />
            </Field>
            <Field label="Password">
              <span className="password-input">
                <input
                  autoComplete="current-password"
                  name="password"
                  required
                  type={visible ? 'text' : 'password'}
                  maxLength={128}
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                  disabled={busy}
                />
                <button
                  type="button"
                  className="icon-only button ghost"
                  aria-label={visible ? 'Hide password' : 'Show password'}
                  onClick={() => setVisible((value) => !value)}
                >
                  {visible ? <EyeOff size={17} /> : <Eye size={17} />}
                </button>
              </span>
            </Field>
            <button
              className="button primary login-submit"
              disabled={busy || state.status === 'restoring'}
              type="submit"
            >
              {busy
                ? 'Authenticating…'
                : state.status === 'restoring'
                  ? 'Restoring session…'
                  : 'Sign in securely'}
              <ArrowRight size={17} />
            </button>
          </form>
          <p className="login-help">
            Need access? Contact your administrator. Accounts are provisioned through an authorized
            administrative workflow.
          </p>
          <div className="login-assurance">
            <LockKeyhole size={14} />
            <span>HttpOnly sessions · Role-based access · Audited changes</span>
          </div>
        </div>
        <footer>Access is restricted to authorized personnel.</footer>
      </main>
    </div>
  );
}
