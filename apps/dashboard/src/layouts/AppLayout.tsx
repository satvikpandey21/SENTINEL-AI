import { useState } from 'react';
import { NavLink, Outlet, useLocation } from 'react-router';
import {
  Activity,
  ChevronLeft,
  ChevronRight,
  Fingerprint,
  LayoutDashboard,
  LogOut,
  Menu,
  Radar,
  Settings2,
  ShieldCheck,
  ShieldEllipsis,
  ScrollText,
} from 'lucide-react';
import { NotificationCenter } from '../realtime/NotificationCenter';
import { useAuth } from '../auth/AuthProvider';
import { Modal } from '../components/Modal';
import { Badge } from '../components/UI';
const navigation = [
  { path: '/', label: 'Security Overview', icon: LayoutDashboard, section: 'MONITOR' },
  { path: '/events', label: 'Security Events', icon: Activity, section: '' },
  { path: '/threats', label: 'Threat Intelligence', icon: Radar, section: 'INVESTIGATE' },
  { path: '/clients', label: 'Client Investigation', icon: Fingerprint, section: '' },
  { path: '/policies', label: 'Protection Policies', icon: ShieldEllipsis, section: 'CONTROL' },
  { path: '/audit', label: 'Audit Logs', icon: ScrollText, section: '', admin: true },
  { path: '/settings', label: 'Settings', icon: Settings2, section: '' },
];
function Navigation({ close }: { close?: () => void }) {
  const { state } = useAuth();
  return (
    <nav aria-label="Main navigation">
      {navigation
        .filter((item) => !item.admin || state.account?.role === 'ADMIN')
        .map((item) => (
          <div key={item.path}>
            {item.section && <span className="nav-section">{item.section}</span>}
            <NavLink end={item.path === '/'} to={item.path} onClick={close} title={item.label}>
              <item.icon size={19} />
              <span className="nav-label">{item.label}</span>
            </NavLink>
          </div>
        ))}
    </nav>
  );
}
export default function AppLayout() {
  const { state, session } = useAuth();
  const location = useLocation();
  const [collapsed, setCollapsed] = useState(false);
  const [mobile, setMobile] = useState(false);
  const [signingOut, setSigningOut] = useState(false);
  const page =
    navigation.find((item) => item.path === location.pathname)?.label ?? 'Security Console';
  return (
    <div className={'app-shell ' + (collapsed ? 'is-collapsed' : '')}>
      <a href="#main-content" className="skip-link">
        Skip to content
      </a>
      <aside className="sidebar">
        <NavLink className="brand" to="/" title="Sentinel AI overview">
          <span className="brand-mark">
            <ShieldCheck size={25} />
          </span>
          <span className="brand-name">
            SENTINEL<span className="brand-ai"> AI</span>
            <small>SECURITY CONSOLE</small>
          </span>
        </NavLink>
        <Navigation />
        <div className="sidebar-footer">
          <div className="workspace-label">
            <span className="workspace-icon">S</span>
            <div>
              <strong>Sentinel workspace</strong>
              <small>Administrative control plane</small>
            </div>
          </div>
          <button
            className="collapse-button"
            onClick={() => setCollapsed((value) => !value)}
            aria-expanded={!collapsed}
            aria-label={collapsed ? 'Expand navigation' : 'Collapse navigation'}
          >
            {collapsed ? (
              <ChevronRight size={17} />
            ) : (
              <>
                <ChevronLeft size={17} />
                <span>Collapse navigation</span>
              </>
            )}
          </button>
        </div>
      </aside>
      <div className="app-workspace">
        <header className="topbar">
          <div className="topbar-title">
            <button
              className="button icon-only ghost mobile-menu"
              aria-label="Open navigation"
              aria-expanded={mobile}
              onClick={() => setMobile(true)}
            >
              <Menu size={21} />
            </button>
            <span className="breadcrumb">
              Workspace<span>/</span>
              <strong>{page}</strong>
            </span>
          </div>
          <div className="topbar-account">
            <NotificationCenter />
            <span className="account-avatar">
              {state.account?.username.slice(0, 2).toUpperCase()}
            </span>
            <div className="account-details">
              <strong>{state.account?.username}</strong>
              <small>
                {state.account?.role === 'ADMIN' ? 'Administrator' : 'Security analyst'}
              </small>
            </div>
            <Badge value="neutral">{state.account?.role}</Badge>
            <button
              className="button icon-only ghost"
              aria-label="Sign out"
              disabled={signingOut}
              onClick={async () => {
                setSigningOut(true);
                await session.logout();
                setSigningOut(false);
              }}
            >
              <LogOut size={18} />
            </button>
          </div>
        </header>
        <main id="main-content" className="main-content" tabIndex={-1}>
          {state.message && (
            <div className="notice warning" role="alert">
              <p>{state.message}</p>
              <button
                className="button secondary small"
                onClick={() => void session.refresh().catch(() => undefined)}
              >
                Retry renewal
              </button>
            </div>
          )}
          <Outlet />
        </main>
        <footer className="workspace-footer">
          <span>Sentinel AI</span>
          <span>Observe with context. Act with evidence.</span>
        </footer>
      </div>
      {mobile && (
        <Modal title="Navigation" onClose={() => setMobile(false)}>
          <Navigation close={() => setMobile(false)} />
        </Modal>
      )}
    </div>
  );
}
