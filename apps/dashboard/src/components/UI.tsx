import { ChevronLeft, ChevronRight, RefreshCw } from 'lucide-react';
import type { ReactNode } from 'react';
import { rangeOptions, type Range, dateTime, number } from '../utils/format';
export function Badge({ value, children }: { value?: string | null; children?: ReactNode }) {
  return (
    <span className={`badge ${value ? value.toLowerCase().replaceAll('_', '-') : 'neutral'}`}>
      {children ?? value ?? 'None'}
    </span>
  );
}
export function PageHeading({
  eyebrow = 'Security operations',
  title,
  description,
  children,
}: {
  eyebrow?: string;
  title: string;
  description: string;
  children?: ReactNode;
}) {
  return (
    <div className="page-heading">
      <div>
        <span className="eyebrow">{eyebrow}</span>
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {children && <div className="heading-actions">{children}</div>}
    </div>
  );
}
export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = '',
}: {
  title: string;
  subtitle?: string;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel ${className}`}>
      <header className="panel-heading">
        <div>
          <h2>{title}</h2>
          {subtitle && <p>{subtitle}</p>}
        </div>
        {actions}
      </header>
      {children}
    </section>
  );
}
export function RefreshControl({
  loading,
  onRefresh,
  updatedAt,
  polling = false,
}: {
  loading: boolean;
  onRefresh: () => void;
  updatedAt: Date | null;
  polling?: boolean;
}) {
  return (
    <div className="refresh-control">
      <span>
        {updatedAt ? `Updated ${dateTime(updatedAt)}` : 'Waiting for API'}
        {polling && <small>60s polling · pauses in background</small>}
      </span>
      <button
        className="button secondary icon-only"
        aria-label="Refresh data"
        onClick={onRefresh}
        disabled={loading}
      >
        <RefreshCw size={17} className={loading ? 'spin' : ''} />
      </button>
    </div>
  );
}
export function RangeSelect({
  value,
  onChange,
}: {
  value: Range;
  onChange: (value: Range) => void;
}) {
  return (
    <label className="range-select">
      <span className="sr-only">Time range</span>
      <select value={value} onChange={(event) => onChange(event.target.value as Range)}>
        {rangeOptions.map(([key, text]) => (
          <option key={key} value={key}>
            {text}
          </option>
        ))}
      </select>
    </label>
  );
}
export function Pagination({
  total,
  offset,
  limit,
  onOffset,
  disabled = false,
}: {
  total: number;
  offset: number;
  limit: number;
  onOffset: (value: number) => void;
  disabled?: boolean;
}) {
  const last = Math.min(10000, Math.max(0, Math.ceil(total / limit) * limit - limit));
  return (
    <nav className="pagination" aria-label="Table pagination">
      <span>
        {total
          ? `${number(offset + 1)}–${number(Math.min(offset + limit, total))} of ${number(total)}`
          : '0 records'}
        <small>{offset >= 10000 && ' · Query limit reached; narrow the window.'}</small>
      </span>
      <div>
        <button
          className="button small secondary"
          disabled={disabled || offset === 0}
          onClick={() => onOffset(Math.max(0, offset - limit))}
        >
          <ChevronLeft size={15} />
          Previous
        </button>
        <button
          className="button small secondary"
          disabled={disabled || offset >= last}
          onClick={() => onOffset(Math.min(10000, offset + limit))}
        >
          Next
          <ChevronRight size={15} />
        </button>
      </div>
    </nav>
  );
}
export function KeyValues({ values }: { values: [string, ReactNode][] }) {
  return (
    <dl className="key-values">
      {values.map(([key, value]) => (
        <div key={key}>
          <dt>{key}</dt>
          <dd>{value ?? 'Not available'}</dd>
        </div>
      ))}
    </dl>
  );
}
