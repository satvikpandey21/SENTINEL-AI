import { useState } from 'react';
import type { TimeWindow } from '../api/types';
export const rangeOptions = [
  ['1h', 'Last hour'],
  ['6h', 'Last 6 hours'],
  ['24h', 'Last 24 hours'],
  ['7d', 'Last 7 days'],
  ['30d', 'Last 30 days'],
] as const;
export type Range = (typeof rangeOptions)[number][0];
const durations: Record<Range, number> = {
  '1h': 3600000,
  '6h': 21600000,
  '24h': 86400000,
  '7d': 604800000,
  '30d': 2592000000,
};
export function windowFor(range: Range, now = new Date()): TimeWindow {
  return {
    start: new Date(now.getTime() - durations[range]).toISOString(),
    end: now.toISOString(),
  };
}
export function useWindow(initial: Range = '24h') {
  const [range, setRange] = useState<Range>(initial);
  const [window, setWindow] = useState(() => windowFor(initial));
  const [custom, setCustom] = useState(false);
  return {
    range,
    window,
    custom,
    setWindow: (value: TimeWindow) => {
      setCustom(true);
      setWindow(value);
    },
    changeRange: (next: Range) => {
      setCustom(false);
      setRange(next);
      setWindow(windowFor(next));
    },
    renew: () => setWindow(windowFor(range)),
  };
}
export const dateTime = (value: string | Date | null | undefined) =>
  value
    ? new Intl.DateTimeFormat(undefined, {
        dateStyle: 'medium',
        timeStyle: 'medium',
        timeZone: 'UTC',
      }).format(new Date(value)) + ' UTC'
    : 'Not observed';
export const shortTime = (value: string) =>
  new Intl.DateTimeFormat(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
    timeZone: 'UTC',
  }).format(new Date(value));
export const number = (value: number) => new Intl.NumberFormat().format(value);
export const label = (value: string | null | undefined) =>
  value ? value.replaceAll('_', ' ').replaceAll('.', ' ') : 'None';
export const compactId = (value: string) =>
  value.length > 18 ? value.slice(0, 8) + '…' + value.slice(-6) : value;
export const clientPattern = /^[0-9a-f]{64}$/;
export const requestPattern = /^[0-9a-f]{32}$/;
export const servicePattern = /^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/;
export const endpointPattern = /^(unmatched|\/[a-zA-Z0-9_./{}:~-]*)$/;
