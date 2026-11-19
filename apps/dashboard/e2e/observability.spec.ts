import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { test, expect } from '@playwright/test';

test.use({ viewport: { width: 1440, height: 1000 } });

test('Grafana renders all five provisioned operational dashboards', async ({ page, context }) => {
  const password = readFileSync(
    new URL('../../../.secrets/observability/grafana_password', import.meta.url),
    'utf8',
  ).trim();
  const login = await context.request.post('http://localhost:3000/login', {
    data: { user: 'sentinel-ops', password },
  });
  expect(login.status()).toBe(200);
  const dashboards = [
    ['system', 'Scrape target availability'],
    ['enforcement', 'Security decision checks'],
    ['pipeline', 'Queue messages ready'],
    ['streaming', 'Active authenticated WebSockets'],
    ['analysis', 'Committed assessments'],
  ];
  for (const [uid, panel] of dashboards) {
    await page.goto('http://localhost:3000/d/sentinel-' + uid);
    await expect(page.getByText(panel, { exact: true })).toBeVisible();
    await expect(page.getByText('Data source not found', { exact: true })).toHaveCount(0);
    if (uid === 'system') {
      await expect(page.getByText('admin-api:9100', { exact: true })).toBeVisible();
      await expect(page.getByText('demo-api:9100', { exact: true })).toBeVisible();
      await page.screenshot({
        path: fileURLToPath(
          new URL('../../../.artifacts/day8-grafana-system.png', import.meta.url),
        ),
        fullPage: true,
      });
    }
  }
});
