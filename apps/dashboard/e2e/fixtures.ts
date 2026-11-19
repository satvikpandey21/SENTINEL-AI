import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test as base, expect, type Page } from '@playwright/test';
type Credentials = {
  username: string;
  analyst: string;
  password: string;
  request_id: string;
  prefix: string;
  policies: unknown[];
};
export const deploymentArgs =
  process.env.SENTINEL_E2E_PRODUCTION === '1'
    ? [
        '--env-file',
        '.env.production-test',
        '-p',
        'sentinel-production-test',
        '-f',
        'compose.yaml',
        '-f',
        'compose.production.yaml',
        '-f',
        'compose.production-test.yaml',
      ]
    : [];
const root = fileURLToPath(new URL('../../../', import.meta.url));
const script = readFileSync(
  new URL('../../../scripts/dashboard_test_accounts.py', import.meta.url),
  'utf8',
);
export const test = base.extend<object, { credentials: Credentials }>({
  // Playwright requires a destructured first fixture argument.
  credentials: [
    // eslint-disable-next-line no-empty-pattern
    async ({}, use) => {
      const run = (args: string[] = []) =>
        execFileSync(
          'docker',
          ['compose', ...deploymentArgs, 'exec', '-T', 'admin-api', 'python', '-', ...args],
          {
            cwd: root,
            input: script,
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
          },
        );
      const credentials = JSON.parse(run()) as Credentials;
      try {
        await use(credentials);
      } finally {
        execFileSync(
          'docker',
          [
            'compose',
            ...deploymentArgs,
            'exec',
            '-T',
            'admin-api',
            'python',
            '-',
            '--cleanup',
            credentials.prefix,
          ],
          {
            cwd: root,
            input: script.replace(
              'ORIGINAL_POLICIES = None',
              'ORIGINAL_POLICIES = json.loads(' +
                JSON.stringify(JSON.stringify(credentials.policies)) +
                ')',
            ),
            encoding: 'utf8',
            stdio: ['pipe', 'pipe', 'pipe'],
          },
        );
      }
    },
    { scope: 'worker' },
  ],
});
export { expect };
export async function signIn(
  page: Page,
  credentials: Credentials,
  role: 'ADMIN' | 'ANALYST' = 'ADMIN',
) {
  await page.goto('/login');
  await page
    .getByLabel('Username', { exact: true })
    .fill(role === 'ADMIN' ? credentials.username : credentials.analyst);
  await page.getByLabel('Password', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
}
