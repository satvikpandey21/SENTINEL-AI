import type { FormEvent, ReactNode } from 'react';
import { Filter, RotateCcw } from 'lucide-react';
import { RangeSelect } from './UI';
import { dateTime, type Range, windowFor } from '../utils/format';
import type { TimeWindow } from '../api/types';
export function FilterBar({
  children,
  onSubmit,
  onReset,
}: {
  children: ReactNode;
  onSubmit: (event: FormEvent<HTMLFormElement>) => void;
  onReset: () => void;
}) {
  return (
    <form className="filter-panel" onSubmit={onSubmit}>
      {children}
      <div className="filter-actions">
        <button type="submit" className="button primary small">
          <Filter size={15} />
          Apply filters
        </button>
        <button type="button" className="button ghost small" onClick={onReset}>
          <RotateCcw size={14} />
          Reset
        </button>
      </div>
    </form>
  );
}
export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: ReactNode;
  hint?: string;
}) {
  return (
    <label className="field">
      <span>{label}</span>
      {children}
      {hint && <small>{hint}</small>}
    </label>
  );
}
export function TimeFilter({
  range,
  window,
  onChange,
}: {
  range: Range;
  window: TimeWindow;
  onChange: (range: Range, window: TimeWindow) => void;
}) {
  return (
    <div className="field">
      <span>Time range</span>
      <RangeSelect value={range} onChange={(value) => onChange(value, windowFor(value))} />
      <small title={dateTime(window.start) + ' — ' + dateTime(window.end)}>
        Anchored when applied · UTC
      </small>
    </div>
  );
}
export function CustomWindow({
  window,
  onChange,
}: {
  window: TimeWindow;
  onChange: (window: TimeWindow) => void;
}) {
  const local = (value: string) => {
    const date = new Date(value);
    return new Date(date.getTime() - date.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
  };
  return (
    <>
      <Field label="From (your local time)">
        <input
          type="datetime-local"
          required
          value={local(window.start)}
          onChange={(event) => {
            if (event.target.value)
              onChange({ ...window, start: new Date(event.target.value).toISOString() });
          }}
        />
      </Field>
      <Field label="Until (your local time)">
        <input
          type="datetime-local"
          required
          value={local(window.end)}
          onChange={(event) => {
            if (event.target.value)
              onChange({ ...window, end: new Date(event.target.value).toISOString() });
          }}
        />
      </Field>
    </>
  );
}
export function validWindow(window: TimeWindow) {
  const length = new Date(window.end).getTime() - new Date(window.start).getTime();
  return length > 0 && length <= 31 * 86400000;
}
