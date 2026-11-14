import { describe, expect, it } from 'vitest';
import { policyChanges, policyErrors } from './policies';
import { validWindow } from '../components/Filters';
import { windowFor } from './format';
import { policies } from '../tests/fixtures';
const original = policies.policies[0]!;
describe('policy validation and time windows', () => {
  it('accepts the backend policy and reports exact changes', () => {
    expect(policyErrors(original)).toEqual([]);
    expect(
      policyChanges(original, { ...original, rate: { ...original.rate!, requests: 20 } }),
    ).toEqual(['rate requests: 600 \u2192 20']);
  });
  it.each([0, 10001, 1.5, NaN])('rejects invalid rate count %s', (requests) => {
    expect(policyErrors({ ...original, rate: { ...original.rate!, requests } })).not.toHaveLength(
      0,
    );
  });
  it('requires block actions to cover windows', () => {
    expect(
      policyErrors({
        ...original,
        rate: { ...original.rate!, exceed_action: 'block', window_seconds: 60, block_seconds: 2 },
      }),
    ).toContain('Rate block duration must cover its rate window.');
  });
  it('rejects unsafe authentication windows and thresholds', () => {
    expect(
      policyErrors({
        ...original,
        authentication: {
          failures: 1,
          window_seconds: 60,
          block_seconds: 2,
          exceed_action: 'block',
          clear_on_success: true,
        },
      }),
    ).toHaveLength(2);
  });
  it('accepts bounded UTC intervals and rejects reversed or oversized ranges', () => {
    const now = new Date('2026-11-14T00:00:00Z');
    expect(windowFor('24h', now)).toEqual({
      start: '2026-11-13T00:00:00.000Z',
      end: now.toISOString(),
    });
    expect(validWindow(windowFor('30d', now))).toBe(true);
    expect(validWindow({ start: now.toISOString(), end: now.toISOString() })).toBe(false);
    expect(validWindow({ start: '2026-01-01', end: now.toISOString() })).toBe(false);
  });
});
