import { afterEach, describe, expect, it, vi } from 'vitest';
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter, Outlet, Route, Routes } from 'react-router';
import type { ReactNode } from 'react';
import { AppRoutes } from '../App';
import { Session } from '../auth/session';
import { HttpClient } from '../api/http';
import { AuthProvider } from '../auth/AuthProvider';
import { AdminRoute, ProtectedRoute } from '../auth/ProtectedRoute';
import AppLayout from '../layouts/AppLayout';
import LoginPage from '../pages/LoginPage';
import OverviewPage from '../pages/OverviewPage';
import EventsPage from '../pages/EventsPage';
import ThreatsPage from '../pages/ThreatsPage';
import PoliciesPage from '../pages/PoliciesPage';
import AuditPage from '../pages/AuditPage';
import SettingsPage from '../pages/SettingsPage';
import ClientsPage from '../pages/ClientsPage';
import { account, analytics, assessment, envelope, event, json, page, policies } from './fixtures';
vi.mock('react-chartjs-2', () => ({
  Line: () => <div aria-label="Line chart" />,
  Bar: () => <div aria-label="Bar chart" />,
  Doughnut: () => <div aria-label="Doughnut chart" />,
}));
const sessions: Session[] = [];
afterEach(() => sessions.splice(0).forEach((session) => session.destroy()));
async function mount(
  node: ReactNode,
  options: {
    role?: 'ADMIN' | 'ANALYST';
    anonymous?: boolean;
    path?: string;
    handle?: (path: string, options: RequestInit) => Response | Promise<Response>;
  } = {},
) {
  const user = { ...account, role: options.role ?? 'ADMIN' };
  const token = { ...envelope, account: user };
  const fetcher = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = String(input);
    if (path.endsWith('/auth/csrf'))
      return options.anonymous ? json({}, 401) : json({ csrf_token: 'fresh' });
    if (path.endsWith('/auth/refresh')) return json(token);
    if (path.endsWith('/auth/login') && (!options.anonymous || !options.handle)) return json(token);
    if (path.endsWith('/auth/me')) return json(user);
    return options.handle?.(path, init ?? {}) ?? json({ detail: 'Unexpected test request' }, 404);
  });
  const session = new Session(new HttpClient('/api/admin', fetcher), { lock: (work) => work() });
  sessions.push(session);
  if (!options.anonymous)
    await session.login({ username: account.username, password: 'component-password' });
  await session.start();
  const result = render(
    <AuthProvider session={session}>
      <MemoryRouter initialEntries={[options.path ?? '/']}>{node}</MemoryRouter>
    </AuthProvider>,
  );
  return { ...result, session, fetcher };
}
describe('authentication and route UI', () => {
  it('submits login and reports authentication failure', async () => {
    await mount(<LoginPage />, {
      anonymous: true,
      handle: () => json({ detail: 'Invalid credentials' }, 401),
    });
    await userEvent.type(screen.getByLabelText('Username'), 'operator');
    await userEvent.type(screen.getByLabelText('Password'), 'wrong');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in securely' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('Invalid credentials');
    expect(screen.getByLabelText('Password')).toHaveValue('');
  });
  it('navigates to the protected destination after login success', async () => {
    await mount(
      <Routes>
        <Route path="/login" element={<LoginPage />} />
        <Route path="/" element={<p>Authorized workspace</p>} />
      </Routes>,
      { anonymous: true, path: '/login' },
    );
    await userEvent.type(screen.getByLabelText('Username'), 'operator');
    await userEvent.type(screen.getByLabelText('Password'), 'correct');
    await userEvent.click(screen.getByRole('button', { name: 'Sign in securely' }));
    expect(await screen.findByText('Authorized workspace')).toBeInTheDocument();
  });
  it('redirects anonymous visitors to login', async () => {
    await mount(
      <Routes>
        <Route element={<ProtectedRoute />}>
          <Route path="/events" element={<p>Private events</p>} />
        </Route>
        <Route path="/login" element={<p>Login required</p>} />
      </Routes>,
      { anonymous: true, path: '/events' },
    );
    expect(screen.getByText('Login required')).toBeInTheDocument();
  });
  it('rejects analyst navigation to administrator routes', async () => {
    await mount(
      <Routes>
        <Route element={<AdminRoute />}>
          <Route path="/audit" element={<p>Private audit</p>} />
        </Route>
        <Route path="/" element={<p>Permitted overview</p>} />
      </Routes>,
      { role: 'ANALYST', path: '/audit' },
    );
    expect(screen.getByText('Permitted overview')).toBeInTheDocument();
    expect(screen.queryByText('Private audit')).not.toBeInTheDocument();
  });
  it('supports mobile navigation and role-aware links', async () => {
    await mount(
      <Routes>
        <Route element={<AppLayout />}>
          <Route path="/" element={<Outlet />} />
        </Route>
      </Routes>,
      { role: 'ANALYST' },
    );
    expect(screen.queryByRole('link', { name: 'Audit Logs' })).not.toBeInTheDocument();
    await userEvent.click(screen.getByRole('button', { name: 'Open navigation' }));
    const dialog = screen.getByRole('dialog');
    expect(within(dialog).getByRole('link', { name: 'Security Events' })).toBeInTheDocument();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close dialog' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
});
describe('complete lazy route tree', () => {
  it('loads the protected overview through the application routes', async () => {
    await mount(<AppRoutes />, { handle: () => json(analytics) });
    expect(await screen.findByRole('heading', { name: 'Security overview' })).toBeInTheDocument();
    expect(await screen.findByText('Monitored requests', { exact: true })).toBeInTheDocument();
  });
});
describe('actual-contract page rendering', () => {
  it('renders independent backend counters without combining requests and decisions', async () => {
    await mount(<OverviewPage />, { handle: () => json(analytics) });
    expect(await screen.findByText('12')).toBeInTheDocument();
    expect(screen.getByText('3')).toBeInTheDocument();
    expect(screen.getByText('2')).toBeInTheDocument();
    expect(screen.getByText('1')).toBeInTheDocument();
    expect(screen.getByText('No nonzero-risk alerts')).toBeInTheDocument();
  });
  it('renders empty analytics and zero totals', async () => {
    await mount(<OverviewPage />, {
      handle: () =>
        json({
          ...analytics,
          monitored_requests: 0,
          security_decisions: 0,
          rate_limit_violations: 0,
          temporary_blocks: 0,
        }),
    });
    expect(await screen.findAllByText('0')).toHaveLength(4);
    expect(screen.getByText('No route activity')).toBeInTheDocument();
  });
  it('shows API errors instead of fabricated dashboard totals', async () => {
    await mount(<OverviewPage />, { handle: () => json({ detail: 'Analytics unavailable' }, 503) });
    expect(await screen.findByRole('alert')).toHaveTextContent('Analytics unavailable');
    expect(screen.queryByText('Monitored requests', { exact: true })).not.toBeInTheDocument();
  });
  it('applies event filters and server-side pagination', async () => {
    const { fetcher } = await mount(<EventsPage />, { handle: () => json(page([event], 51)) });
    await screen.findByText('/api/demo/ping');
    fireEvent.change(screen.getByLabelText('Service'), { target: { value: 'sentinel-demo-api' } });
    await userEvent.click(screen.getByRole('button', { name: 'Apply filters' }));
    await waitFor(() =>
      expect(
        fetcher.mock.calls.some(([url]) => String(url).includes('service=sentinel-demo-api')),
      ).toBe(true),
    );
    await waitFor(() => expect(screen.getByRole('button', { name: 'Next' })).toBeEnabled());
    await userEvent.click(screen.getByRole('button', { name: 'Next' }));
    await waitFor(() =>
      expect(fetcher.mock.calls.some(([url]) => String(url).includes('offset=25'))).toBe(true),
    );
  });
  it('renders risk, deterministic evidence and experimental ML limitations', async () => {
    await mount(<ThreatsPage />, {
      handle: (path) => json(path.includes('/assessments/') ? assessment : page([assessment])),
    });
    expect(await screen.findByText('possible brute force')).toBeInTheDocument();
    expect(screen.getByRole('meter')).toHaveAttribute('aria-valuenow', '65');
    await userEvent.click(screen.getByRole('button', { name: /Evidence for/ }));
    expect(await screen.findByText('auth.failures')).toBeInTheDocument();
    expect(screen.getByText(/ML does not raise risk scores/)).toBeInTheDocument();
  });
  it('shows analysts effective policies without edit controls', async () => {
    await mount(<PoliciesPage />, { role: 'ANALYST', handle: () => json(policies) });
    expect(await screen.findByText('demo-read')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: 'Edit policy' })).not.toBeInTheDocument();
    expect(screen.getByText(/Revision 7/)).toHaveTextContent('Enforcement synchronized');
  });
  it('validates a policy, confirms changes and handles a stale revision', async () => {
    const { fetcher } = await mount(<PoliciesPage />, {
      handle: (_path, init) =>
        init.method === 'PUT' ? json({ detail: 'Policy version conflict' }, 409) : json(policies),
    });
    await userEvent.click(await screen.findByRole('button', { name: 'Edit policy' }));
    fireEvent.change(screen.getByLabelText('Rate exceed action'), { target: { value: 'block' } });
    fireEvent.change(screen.getByLabelText('Rate block (seconds)'), { target: { value: '1' } });
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }));
    expect(screen.getByRole('alert')).toHaveTextContent('Rate block duration must cover');
    fireEvent.change(screen.getByLabelText('Rate block (seconds)'), { target: { value: '60' } });
    fireEvent.change(screen.getByLabelText('Allowed requests'), { target: { value: '30' } });
    await userEvent.click(screen.getByRole('button', { name: 'Review changes' }));
    await userEvent.click(screen.getByRole('button', { name: 'Confirm and apply' }));
    expect(await screen.findByText('Policy version conflict')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Confirm and apply' })).toBeDisabled();
    const write = fetcher.mock.calls.find(([, init]) => init?.method === 'PUT');
    expect(JSON.parse(String(write?.[1]?.body))).toMatchObject({
      expected_version: 7,
      policies: [{ id: 'demo-read', rate: { requests: 30 } }],
    });
  });
  it('shows saved-but-unsynchronized policies as pending and disallows editing', async () => {
    await mount(<PoliciesPage />, {
      handle: () => json({ ...policies, enforcement_synchronized: false }),
    });
    expect(
      await screen.findByText('Saved configuration is not confirmed active.'),
    ).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit policy' })).toBeDisabled();
  });
  it('renders persisted audit records and non-sensitive summaries', async () => {
    await mount(<AuditPage />, {
      handle: () =>
        json(
          page([
            {
              id: 'audit-id',
              actor_id: account.id,
              action: 'policy.update',
              target: 'policy-set',
              outcome: 'success',
              occurred_at: event.occurred_at,
              summary: { version: 8 },
            },
          ]),
        ),
    });
    expect(await screen.findByText('policy.update')).toBeInTheDocument();
    expect(screen.getByText('policy-set')).toBeInTheDocument();
    expect(screen.getByText('version: 8')).toBeInTheDocument();
  });
  it('provides only server-supported profile and account settings', async () => {
    await mount(<SettingsPage />, { handle: () => json(page([account])) });
    expect((await screen.findAllByText('operator')).length).toBeGreaterThan(0);
    expect(screen.getByRole('button', { name: 'Provision account' })).toBeInTheDocument();
  });
  it('shows the client lookup and privacy explanation without requesting a fake client', async () => {
    const { fetcher } = await mount(<ClientsPage />);
    expect(screen.getByText('Ready to investigate')).toBeInTheDocument();
    expect(screen.getByText(/One identifier may be shared/)).toBeInTheDocument();
    expect(fetcher.mock.calls.some(([url]) => String(url).includes('/clients/'))).toBe(false);
  });
});
