import type { Policy } from '../api/types';
export function policyErrors(policy: Policy): string[] {
  const errors: string[] = [];
  const within = (value: number, min: number, max: number) =>
    Number.isFinite(value) && value >= min && value <= max;
  if (policy.rate) {
    const r = policy.rate;
    if (!Number.isInteger(r.requests ?? 600) || !within(r.requests ?? 600, 1, 10000))
      errors.push('Rate requests must be an integer from 1 to 10,000.');
    if (!within(r.window_seconds ?? 60, 0.1, 3600))
      errors.push('Rate window must be between 0.1 and 3,600 seconds.');
    if (!within(r.block_seconds ?? 60, 0.1, 3600))
      errors.push('Rate block duration must be between 0.1 and 3,600 seconds.');
    if (r.exceed_action === 'block' && (r.block_seconds ?? 60) < (r.window_seconds ?? 60))
      errors.push('Rate block duration must cover its rate window.');
  }
  if (policy.authentication) {
    const r = policy.authentication;
    if (!Number.isInteger(r.failures ?? 5) || !within(r.failures ?? 5, 2, 100))
      errors.push('Authentication threshold must be an integer from 2 to 100.');
    if (!within(r.window_seconds ?? 60, 0.1, 3600))
      errors.push('Authentication window must be between 0.1 and 3,600 seconds.');
    if (!within(r.block_seconds ?? 60, 0.1, 3600))
      errors.push('Authentication block duration must be between 0.1 and 3,600 seconds.');
    if ((r.block_seconds ?? 60) < (r.window_seconds ?? 60))
      errors.push('Authentication block duration must cover its failure window.');
  }
  return errors;
}
export function policyChanges(before: Policy, after: Policy): string[] {
  const changes: string[] = [];
  if (before.failure_mode !== after.failure_mode)
    changes.push(`Failure mode: ${before.failure_mode} → ${after.failure_mode}`);
  for (const group of ['rate', 'authentication'] as const) {
    const previous = before[group];
    const next = after[group];
    if (previous && next)
      for (const [key, value] of Object.entries(next)) {
        if (value !== previous[key as keyof typeof previous])
          changes.push(
            `${group} ${key.replaceAll('_', ' ')}: ${String(previous[key as keyof typeof previous])} → ${String(value)}`,
          );
      }
  }
  return changes;
}
