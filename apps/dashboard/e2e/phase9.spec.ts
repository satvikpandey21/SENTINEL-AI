import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test, expect, signIn } from './fixtures';
const root = fileURLToPath(new URL('../../../', import.meta.url));
function traffic(path: string, count = 1): number[] {
  return JSON.parse(
    execFileSync(
      'docker',
      [
        'compose',
        'exec',
        '-T',
        'demo-api',
        'python',
        '-c',
        `import json,urllib.request,urllib.error\nrows=[]\nfor _ in range(${count}):\n try:\n  r=urllib.request.urlopen('http://127.0.0.1:8000${path}',timeout=10)\n except urllib.error.HTTPError as e:\n  r=e\n rows.append(r.code)\n r.close()\nprint(json.dumps(rows))`,
      ],
      { cwd: root, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
    ),
  );
}

test('real activity reaches the notification center while the operator uses another app', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  await page.getByRole('button', { name: /Notifications,/ }).click();
  await page.getByLabel('Include informational activity').check();
  await page.getByRole('button', { name: 'Close dialog' }).click();
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', { configurable: true, get: () => 'hidden' });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  expect(traffic('/api/demo/ping')).toEqual([200]);
  expect(traffic('/api/demo/limited', 12)).toContain(429);
  await page.evaluate(() => {
    Object.defineProperty(document, 'visibilityState', {
      configurable: true,
      get: () => 'visible',
    });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  await page.getByRole('button', { name: /Notifications,/ }).click();
  const dialog = page.getByRole('dialog', { name: 'Security notifications' });
  await expect(dialog.getByText('Persisted API activity', { exact: true }).first()).toBeVisible();
  await expect(dialog.getByText(/temporary block/).first()).toBeVisible();
  await expect(dialog.getByText(/Last activity: Not observed/)).toHaveCount(0);
  await expect(page.getByRole('button', { name: /Notifications, [1-9]/ })).toBeVisible();
  await dialog.getByRole('button', { name: 'Mark all as read' }).click();
  await expect(page.getByRole('button', { name: 'Notifications, 0 unread' })).toBeVisible();
  await dialog.getByRole('button', { name: 'Clear history' }).click();
  await expect(dialog.getByText('No notifications received in this tab.')).toBeVisible();
  await dialog.getByRole('button', { name: 'Close dialog' }).click();
  await page.reload();
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  await page.getByRole('button', { name: /Notifications,/ }).click();
  await expect(page.getByText('No notifications received in this tab.')).toBeVisible();
});

test('mobile bell, badge, focus and panel work at every supported width and page', async ({
  page,
  credentials,
}) => {
  await signIn(page, credentials);
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  expect(traffic('/api/demo/limited', 12)).toContain(429);
  await expect(page.getByRole('button', { name: /Notifications, [1-9]/ })).toBeVisible();
  for (const width of [320, 375, 390, 400, 768, 1440]) {
    await page.setViewportSize({ width, height: 900 });
    for (const label of [
      'Security Overview',
      'Security Events',
      'Threat Intelligence',
      'Client Investigation',
      'Protection Policies',
      'Audit Logs',
      'Settings',
    ]) {
      if (width < 901) {
        await page.getByRole('button', { name: 'Open navigation' }).click();
        await page
          .getByRole('dialog', { name: 'Navigation' })
          .getByRole('link', { name: label, exact: true })
          .click();
      } else
        await page
          .getByRole('navigation', { name: 'Main navigation' })
          .getByRole('link', { name: label, exact: true })
          .click();
      const bell = page.getByRole('button', { name: /Notifications,/ });
      await expect(bell).toBeVisible();
      await expect(bell.locator('.unread-count')).toBeVisible();
      const badge = await bell.locator('.unread-count').boundingBox();
      expect(badge!.x).toBeGreaterThanOrEqual(0);
      expect(badge!.x + badge!.width).toBeLessThanOrEqual(width);
      await bell.click();
      const dialog = page.getByRole('dialog', { name: 'Security notifications' });
      await expect(dialog).toBeVisible();
      await page.keyboard.press('Shift+Tab');
      expect(await dialog.evaluate((element) => element.contains(document.activeElement))).toBe(
        true,
      );
      const box = await dialog.boundingBox();
      expect(box!.x).toBeGreaterThanOrEqual(0);
      expect(box!.x + box!.width).toBeLessThanOrEqual(width);
      await expect(dialog.getByRole('button', { name: 'Clear history' })).toBeVisible();
      if (width === 400 && label === 'Security Overview')
        await page.screenshot({
          path: fileURLToPath(new URL('../../../.artifacts/day9-mobile400.png', import.meta.url)),
        });
      await page.keyboard.press('Escape');
      await expect(bell).toBeFocused();
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
        true,
      );
    }
  }
});
