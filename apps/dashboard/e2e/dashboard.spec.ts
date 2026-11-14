import AxeBuilder from '@axe-core/playwright';
import { test, expect, signIn } from './fixtures';
test('login, protected redirect, HttpOnly cookie, reload restoration and logout', async ({
  page,
  context,
  credentials,
}) => {
  await page.clock.install();
  await page.goto('/events');
  await expect(page).toHaveURL(/\/login$/);
  await page.getByLabel('Username', { exact: true }).fill(credentials.username);
  await page.getByLabel('Password', { exact: true }).fill('intentionally-incorrect');
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page.getByRole('alert')).toBeVisible();
  await page.getByLabel('Password', { exact: true }).fill(credentials.password);
  await page.getByRole('button', { name: 'Sign in securely' }).click();
  await expect(page).toHaveURL(/\/events$/);
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  const cookies = await context.cookies();
  expect(
    cookies.some(
      (cookie) =>
        cookie.name.includes('sentinel-refresh') && cookie.httpOnly && cookie.sameSite === 'Strict',
    ),
  ).toBe(true);
  expect(
    await page.evaluate(() => ({ local: localStorage.length, session: sessionStorage.length })),
  ).toEqual({ local: 0, session: 0 });
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  const renewal = page.waitForResponse(
    (response) => response.url().endsWith('/auth/refresh') && response.status() === 200,
  );
  await page.clock.fastForward(271000);
  await renewal;
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page).toHaveURL(/\/login$/);
  await page.reload();
  await expect(page.getByRole('button', { name: 'Sign in securely' })).toBeEnabled();
});
test('real analytics, persisted demo event, assessment evidence and client investigation', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  await expect(page.getByText('Monitored requests', { exact: true })).toBeVisible();
  const metrics = page.waitForResponse(
    (response) => response.url().includes('/analytics') && response.status() === 200,
  );
  await page.getByRole('button', { name: 'Refresh data' }).click();
  const actual = await (await metrics).json();
  expect(actual.monitored_requests).toBeGreaterThanOrEqual(0);
  await expect(page.locator('.metric-card').first().locator('strong')).toHaveText(
    new Intl.NumberFormat('en-US').format(actual.monitored_requests),
  );
  await page.goto('/events?request_id=' + credentials.request_id);
  await expect(page.getByText('/api/demo/ping', { exact: true })).toBeVisible();
  await page
    .getByRole('button', { name: /Inspect event/ })
    .first()
    .click();
  const dialog = page.getByRole('dialog');
  await expect(dialog.getByText(credentials.request_id, { exact: true })).toBeVisible();
  await dialog.getByRole('link', { name: 'Related assessments' }).click();
  await page
    .getByRole('button', { name: /Evidence for/ })
    .first()
    .click();
  await expect(page.getByRole('dialog').getByText(/ML does not raise risk scores/)).toBeVisible();
  await page
    .getByRole('dialog')
    .getByRole('link', { name: /^[0-9a-f]{64}$/ })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Client investigation', exact: true }),
  ).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Investigation context' })).toBeVisible();
});
test('administrator policies, reviewed update, audit and account provisioning', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  await page.getByRole('link', { name: 'Protection Policies' }).click();
  await expect(page.getByText(/Enforcement synchronized/)).toBeVisible();
  await page.getByRole('button', { name: 'Edit policy' }).first().click();
  const dialog = page.getByRole('dialog');
  const requests = dialog.getByLabel('Allowed requests', { exact: true });
  const before = Number(await requests.inputValue());
  await requests.fill(String(before === 10000 ? 9999 : before + 1));
  await dialog.getByRole('button', { name: 'Review changes' }).click();
  await dialog.getByRole('button', { name: 'Confirm and apply' }).click();
  await expect(page.getByText(/Server acknowledged activation/)).toBeVisible();
  // Restore the exact original threshold using the newly confirmed revision.
  await page.getByRole('button', { name: 'Edit policy' }).first().click();
  await page
    .getByRole('dialog')
    .getByLabel('Allowed requests', { exact: true })
    .fill(String(before));
  await page.getByRole('button', { name: 'Review changes' }).click();
  await page.getByRole('button', { name: 'Confirm and apply' }).click();
  await expect(page.getByText(/Server acknowledged activation/)).toBeVisible();
  await page.getByRole('link', { name: 'Audit Logs' }).click();
  await expect(page.getByText('policy.update', { exact: true }).first()).toBeVisible();
  await page.getByRole('link', { name: 'Settings', exact: true }).click();
  await page.getByRole('button', { name: 'Provision account' }).click();
  await page
    .getByRole('dialog')
    .getByLabel('Username', { exact: true })
    .fill(credentials.prefix + '-created');
  await page.getByRole('dialog').getByLabel('Initial password').fill(credentials.password);
  await page.getByRole('button', { name: 'Review account change' }).click();
  await page.getByRole('button', { name: 'Confirm account change' }).click();
  await expect(
    page.getByText('Account ' + credentials.prefix + '-created confirmed by the server.'),
  ).toBeVisible();
});
test('analyst restrictions, concurrent cross-tab refresh and cross-tab sign-out', async ({
  page,
  context,
  credentials,
}) => {
  await signIn(page, credentials, 'ANALYST');
  await expect(page.getByRole('link', { name: 'Audit Logs' })).toHaveCount(0);
  await page.getByRole('link', { name: 'Protection Policies' }).click();
  await expect(page.getByText(/Your ANALYST role has read-only/)).toBeVisible();
  await expect(page.getByRole('button', { name: 'Edit policy' })).toHaveCount(0);
  await page.goto('/audit');
  await expect(page.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
  const other = await context.newPage();
  await Promise.all([page.reload(), other.goto('/')]);
  await expect(page.getByRole('heading', { name: 'Security overview', exact: true })).toBeVisible();
  await expect(
    other.getByRole('heading', { name: 'Security overview', exact: true }),
  ).toBeVisible();
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(other).toHaveURL(/\/login$/);
  await other.close();
});
test('desktop and mobile navigation, overflow and automated accessibility', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  for (const width of [1440, 1024, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto('/');
    await expect(page.getByText('Monitored requests', { exact: true })).toBeVisible();
    await expect
      .poll(() => page.evaluate(() => document.documentElement.scrollWidth), {
        message: `Page overflow at ${width}px`,
      })
      .toBe(width);
  }
  await page.getByRole('button', { name: 'Open navigation' }).click();
  await page.getByRole('dialog').getByRole('link', { name: 'Security Events' }).click();
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  for (const path of ['/', '/events', '/threats', '/clients', '/policies', '/audit', '/settings']) {
    await page.goto(path);
    await expect(page.locator('main h1')).toBeVisible();
    await expect(page.getByRole('status').filter({ hasText: /Retrieving/ })).toHaveCount(0);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
      true,
    );
    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21aa'])
      .analyze();
    expect(
      results.violations.map((row) => ({
        id: row.id,
        targets: row.nodes.map((node) => node.target),
      })),
    ).toEqual([]);
  }
});
