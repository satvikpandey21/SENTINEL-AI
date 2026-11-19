import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { test, expect, signIn, deploymentArgs } from './fixtures';
const root = fileURLToPath(new URL('../../../', import.meta.url));
test.skip(
  process.env.SENTINEL_E2E_PRODUCTION !== '1',
  'Runs only against isolated production HTTPS ingress',
);

test('production same-origin HTTPS, secure rotation, WSS delivery, reconnect and server revocation', async ({
  page,
  context,
  credentials,
}) => {
  const sockets: string[] = [];
  const decisions: Record<string, unknown>[] = [];
  page.on('websocket', (ws) => {
    sockets.push(ws.url());
    ws.on('framereceived', (event) => {
      try {
        const frame = JSON.parse(String(event.payload));
        if (frame.type === 'security.decision.created') decisions.push(frame);
      } catch {
        /* Ignore non-JSON control bytes. */
      }
    });
  });
  const login = page.waitForResponse((r) => r.url().endsWith('/auth/login') && r.status() === 200);
  await signIn(page, credentials);
  const token = (await (await login).json()).access_token;
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  expect(
    sockets.every((url) => url.startsWith('wss://localhost:8443/') && !url.includes('?')),
  ).toBe(true);
  const before = (await context.cookies()).find((c) => c.name === '__Secure-sentinel-refresh')!;
  expect(before).toMatchObject({
    secure: true,
    httpOnly: true,
    sameSite: 'Strict',
    path: '/api/admin/auth',
  });
  await page.reload();
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  const after = (await context.cookies()).find((c) => c.name === before.name)!;
  expect(after.value !== before.value).toBe(true);
  expect(
    (
      await context.request.post('https://localhost:8443/api/admin/auth/csrf', {
        headers: { Origin: 'https://evil.invalid', 'X-CSRF-Intent': 'sentinel-admin' },
      })
    ).status(),
  ).toBe(403);
  for (const path of ['/metrics', '/api/admin/metrics', '/api/demo/ping', '/health/ready'])
    expect((await context.request.get('https://localhost:8443' + path)).status()).toBe(404);
  const traffic = () =>
    execFileSync(
      'docker',
      [
        'compose',
        ...deploymentArgs,
        'exec',
        '-T',
        'demo-api',
        'python',
        '-c',
        "import urllib.request,urllib.error\nfor _ in range(12):\n try:\n  urllib.request.urlopen('http://127.0.0.1:8000/api/demo/limited').close()\n except urllib.error.HTTPError as e:\n  assert e.code==429",
      ],
      { cwd: root, stdio: ['pipe', 'pipe', 'pipe'] },
    );
  traffic();
  await expect(page.getByRole('button', { name: /Notifications, [1-9]/ })).toBeVisible();
  await expect
    .poll(() => decisions.some((n) => n.security_action === 'temporary_block'))
    .toBe(true);
  const authorization = { Authorization: 'Bearer ' + token };
  for (const path of ['/events?event_type=security.decision', '/assessments']) {
    const response = await context.request.get('https://localhost:8443/api/admin' + path, {
      headers: authorization,
    });
    expect(response.status()).toBe(200);
    expect((await response.json()).items.length).toBeGreaterThan(0);
  }
  await context.setOffline(true);
  await expect(page.getByRole('status', { name: 'Security stream: Disconnected' })).toBeVisible();
  traffic();
  await context.setOffline(false);
  await expect(page.getByRole('status', { name: 'Security stream: Connected' })).toBeVisible();
  expect(sockets.length).toBeGreaterThanOrEqual(3);
  const headers = { Origin: 'https://localhost:8443', 'X-CSRF-Intent': 'sentinel-admin' };
  const csrf = await context.request.post('https://localhost:8443/api/admin/auth/csrf', {
    headers,
  });
  const logout = await context.request.post('https://localhost:8443/api/admin/auth/logout', {
    headers: { ...headers, 'X-CSRF-Token': (await csrf.json()).csrf_token },
  });
  expect(logout.status()).toBe(204);
  // Revoke on the server without notifying React; periodic WSS session validation must close it.
  await expect(page).toHaveURL(/\/login$/, { timeout: 25000 });
  expect(
    (
      await context.request.get('https://localhost:8443/api/admin/events', {
        headers: authorization,
      })
    ).status(),
  ).toBe(401);
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
});
