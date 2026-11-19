import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test, expect, signIn } from './fixtures';
const root = fileURLToPath(new URL('../../../', import.meta.url));
function demo(path: string, count = 1) {
  return execFileSync(
    'docker',
    [
      'compose',
      'exec',
      '-T',
      'demo-api',
      'python',
      '-c',
      `import urllib.request, urllib.error\nfor _ in range(${count}):\n try:\n  urllib.request.urlopen('http://127.0.0.1:8000${path}',timeout=10).close()\n except urllib.error.HTTPError as e:\n  assert e.code == 429`,
    ],
    { cwd: root, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
  );
}
test('real live notifications, analyst fan-out, local read state, reconnect and logout', async ({
  page,
  context,
  browser,
  credentials,
}) => {
  const analystContext = await browser.newContext();
  const analyst = await analystContext.newPage();
  const frames: Record<string, unknown>[] = [];
  page.on('websocket', (ws) =>
    ws.on('framereceived', (event) => {
      try {
        const value = JSON.parse(String(event.payload));
        if (value.type?.startsWith('security.')) frames.push(value);
      } catch {
        /* Control frames. */
      }
    }),
  );
  try {
    await signIn(page, credentials);
    await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
    await signIn(analyst, credentials, 'ANALYST');
    await expect(analyst.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
    for (const target of [page, analyst]) {
      await target.getByRole('button', { name: /Notifications,/ }).click();
      await target.getByLabel('Include informational activity').check();
      await target.getByRole('button', { name: 'Close dialog' }).click();
    }
    demo('/api/demo/limited', 8);
    for (const target of [page, analyst]) {
      await expect(target.getByRole('button', { name: /Notifications, [1-9]/ })).toBeVisible();
      await target.getByRole('button', { name: /Notifications,/ }).click();
      const dialog = target.getByRole('dialog', { name: 'Security notifications' });
      await expect(dialog.getByText(/temporary block/).first()).toBeVisible();
      await dialog.getByRole('button', { name: 'Mark all as read' }).click();
      await expect(target.getByRole('button', { name: 'Notifications, 0 unread' })).toBeVisible();
      await dialog.getByRole('button', { name: 'Close dialog' }).click();
    }
    expect(frames.length).toBeGreaterThan(0);
    expect(new Set(frames.map((f) => f.notification_id)).size).toBe(frames.length);
    expect(JSON.stringify(frames)).not.toMatch(
      /authorization|refresh_token|cookie|client_ip|request_body/i,
    );
    const metric = await page.locator('.metric-card').first().locator('strong').innerText();
    await context.setOffline(true);
    await expect(page.getByRole('status', { name: 'Security stream: Disconnected' })).toBeVisible();
    await expect(page.locator('.metric-card').first().locator('strong')).toHaveText(metric);
    await context.setOffline(false);
    await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
    await page.getByRole('button', { name: /Notifications,/ }).click();
    await page.getByRole('button', { name: 'Clear history' }).click();
    await expect(page.getByText('No notifications received in this tab.')).toBeVisible();
    await page.getByRole('button', { name: 'Close dialog' }).click();
    expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page).toHaveURL(/\/login$/);
  } finally {
    await analystContext.close();
  }
});

test('server restart restores streaming and preserves the event investigation', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  // Preserve the authenticated stream; full reload restoration has separate coverage.
  await page
    .getByRole('navigation', { name: 'Main navigation' })
    .getByRole('link', { name: 'Security Events', exact: true })
    .click();
  await expect(page.getByRole('heading', { name: 'Security events', exact: true })).toBeVisible();
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  await page.getByLabel('Service', { exact: true }).fill('sentinel-demo-api');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await page
    .getByRole('button', { name: /Inspect event/ })
    .first()
    .click();
  await expect(page.getByRole('dialog').getByText('Event ID', { exact: true })).toBeVisible();
  const eventId = await page.getByRole('dialog').locator('dd').first().innerText();
  execFileSync('docker', ['compose', 'restart', 'admin-api'], {
    cwd: root,
    stdio: ['pipe', 'pipe', 'pipe'],
  });
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible({
    timeout: 30000,
  });
  await expect(page.getByRole('dialog').getByText(eventId, { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Close dialog' }).click();
  await expect(page.getByLabel('Service', { exact: true })).toHaveValue('sentinel-demo-api');
  demo('/api/demo/ping');
  await expect(page.getByRole('button', { name: 'Refresh selected window' })).toBeVisible();
});
