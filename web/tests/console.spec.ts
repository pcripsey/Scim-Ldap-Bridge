import { expect, test, type Page } from '@playwright/test';
import type { Settings, Status } from '../src/api';

const token = 'console-test-admin-token-at-least-24';
const defaults: Settings = {
  scim_url: 'https://identity.example.org/scim/v2',
  ldap_url: 'ldaps://directory.example.org:636',
  ldap_bind_dn: 'cn=bridge,dc=example,dc=org',
  ldap_base_dn: 'ou=people,dc=example,dc=org',
  attribute_mappings: [
    { scim_path: 'userName', ldap_attribute: 'uid', direction: 'both' },
    { scim_path: 'name.givenName', ldap_attribute: 'givenName', direction: 'both' },
    { scim_path: 'name.familyName', ldap_attribute: 'sn', direction: 'both' },
    { scim_path: 'displayName', ldap_attribute: 'displayName', direction: 'both' },
    { scim_path: 'emails.value', ldap_attribute: 'mail', direction: 'both' },
  ],
  ldap_start_tls: true,
  ldap_allow_insecure: false,
  direction: 'bidirectional',
  conflict_policy: 'manual',
  interval_seconds: 300,
  enabled: false,
  dry_run: true,
  scim_token_configured: true,
  ldap_password_configured: true,
};
const initialStatus: Status = {
  running: false, next_run: null, enabled: false, dry_run: true,
  configured: true, inbound_enabled: true, linked_users: 1,
  database: { engine: 'sqlite', inventory: [{ source: 'scim', resource_type: 'Users', count: 26 }], operations: { preview: 1 } },
  runs: [{ id: 7, started: '2026-10-16T10:00:00Z', finished: '2026-10-16T10:01:00Z', status: 'completed', dry_run: 1, processed: 26, changed: 1, conflicts: 0, errors: 0 }],
  events: [{ id: 1, time: '2026-10-16T10:01:00Z', run_id: 7, level: 'info', username: 'ada', message: 'Run finished.' }],
};

async function environment(page: Page, overrides: Partial<Settings> = {}) {
  let settings = { ...defaults, ...overrides };
  let status = { ...initialStatus, enabled: settings.enabled, dry_run: settings.dry_run };
  const writes: Record<string, unknown>[] = [];
  const calls: string[] = [];
  await page.route('**/api/**', async route => {
    const req = route.request();
    const url = new URL(req.url());
    calls.push(`${req.method()} ${url.pathname}${url.search}`);
    if (req.headers()['authorization'] !== `Bearer ${token}`) {
      await route.fulfill({ status: 401, json: { detail: 'A valid bearer token is required.' } }); return;
    }
    if (url.pathname === '/api/status') { await route.fulfill({ json: status }); return; }
    if (url.pathname === '/api/settings') {
      if (req.method() === 'PUT') {
        const payload: Record<string, unknown> = req.postDataJSON();
        writes.push(payload);
        const { scim_token, ldap_password, ...rest } = payload;
        settings = { ...settings, ...rest };
        if (scim_token !== undefined) settings.scim_token_configured = Boolean(scim_token);
        if (ldap_password !== undefined) settings.ldap_password_configured = Boolean(ldap_password);
        status = { ...status, dry_run: settings.dry_run, enabled: settings.enabled };
        await route.fulfill({ json: { saved: true } }); return;
      }
      await route.fulfill({ json: settings }); return;
    }
    if (url.pathname.startsWith('/api/test/')) { await route.fulfill({ json: { ok: true, users: 26 } }); return; }
    if (url.pathname.startsWith('/api/discovery/')) {
      const connector = url.pathname.split('/').at(-1);
      await route.fulfill({ json: {
        schemas: [], resource_types: [], users: 1,
        attributes: connector === 'scim'
          ? [{ name: 'name.givenName', samples: ['Ada'] }, { name: 'employeeNumber', samples: ['42'] }]
          : [{ name: 'givenName', samples: ['Ada'] }, { name: 'employeeNumber', samples: ['42'] }],
      } });
      return;
    }
    if (url.pathname === '/api/mappings/validate') {
      await route.fulfill({ json: { valid: true, errors: [], scim_attributes: 20, ldap_attributes: 20 } });
      return;
    }
    if (url.pathname === '/api/sync') { await route.fulfill({ status: 202, json: { run_id: 8 } }); return; }
    if (url.pathname === '/api/data/resources') {
      const offset = Number(url.searchParams.get('offset') ?? 0);
      const source = url.searchParams.get('source') ?? 'scim';
      const resources = Array.from({ length: offset === 0 ? 25 : 1 }, (_, index) => ({
        source, resource_type: url.searchParams.get('resource_type'), resource_key: `user-${index + offset}`,
        observed_at: '2026-10-16T10:00:00Z', present: index === 1 ? 0 : 1,
      }));
      await route.fulfill({ json: { resources } }); return;
    }
    if (url.pathname === '/api/data/resource') {
      await route.fulfill({ json: { data: { userName: url.searchParams.get('key'), extensions: { department: 'Engineering' } } } }); return;
    }
    if (url.pathname === '/api/data/operations') {
      await route.fulfill({ json: { operations: [{ id: 1, run_id: 7, resource_type: 'Users', resource_key: 'ada', target: 'ldap', operation: 'create', status: 'preview', created_at: '2026-10-16T10:00:00Z', updated_at: '2026-10-16T10:00:00Z', error: null }] } }); return;
    }
    await route.fulfill({ status: 404, json: { detail: 'Not found' } });
  });
  return { writes, calls };
}

async function login(page: Page) {
  await page.goto('/');
  await page.getByLabel('Administrator token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Open console' }).click();
  await expect(page.getByRole('heading', { name: 'Overview', exact: true })).toBeVisible();
}

test('authenticates, navigates every page, and never persists the token', async ({ page }) => {
  await environment(page);
  await login(page);
  for (const name of ['Connections', 'Synchronization', 'Inventory', 'Activity', 'System']) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
  }
  expect(await page.evaluate(() => ({ local: { ...localStorage }, session: { ...sessionStorage } }))).toEqual({ local: {}, session: {} });
  await page.reload();
  await expect(page.getByRole('heading', { name: 'Welcome to your console' })).toBeVisible();
  await expect(page.getByLabel('Administrator token', { exact: true })).toHaveValue('');
});

test('rejects a bad token and surfaces the API message', async ({ page }) => {
  await environment(page);
  await page.goto('/');
  await page.getByLabel('Administrator token', { exact: true }).fill('wrong-token');
  await page.getByRole('button', { name: 'Open console' }).click();
  await expect(page.getByRole('alert')).toContainText('valid bearer token');
});

test('saves configuration, preserves omitted secrets, and reloads persisted values', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await page.getByLabel('Synchronization direction').selectOption('ldap_to_scim');
  await page.getByLabel('Interval (seconds)').fill('600');
  await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes).toHaveLength(1);
  expect(env.writes[0]).toMatchObject({ direction: 'ldap_to_scim', interval_seconds: 600 });
  expect(env.writes[0]).not.toHaveProperty('scim_token');
  expect(env.writes[0]).not.toHaveProperty('ldap_password');
  expect(env.writes[0]).not.toHaveProperty('scim_token_configured');
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
});

test('replaces and explicitly clears connector credentials', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByLabel('SCIM bearer token', { exact: true }).selectOption('replace');
  await page.getByLabel('New scim bearer token', { exact: true }).fill('new-connector-secret');
  await page.getByLabel('LDAP bind password', { exact: true }).selectOption('clear');
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({ scim_token: 'new-connector-secret', ldap_password: '' });
  await expect(page.getByLabel('New scim bearer token', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('button', { name: 'Test LDAP connection' })).toBeDisabled();
});

test('connection tests use saved settings and report success and failures', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByRole('button', { name: 'Test SCIM connection' }).click();
  await expect(page.getByText('SCIM connection verified. Read 26 users using saved settings.')).toBeVisible();
  expect(env.calls).toContain('POST /api/test/scim');
  await page.route('**/api/test/ldap', route => route.fulfill({ status: 502, json: { detail: 'Connection failed. Check TLS.' } }));
  await page.getByRole('button', { name: 'Test LDAP connection' }).click();
  await expect(page.getByRole('alert')).toContainText('Check TLS');
  await page.getByLabel('Base distinguished name', { exact: true }).fill('dc=changed');
  await expect(page.getByRole('button', { name: 'Test SCIM connection' })).toBeDisabled();
});

test('discovers attributes and saves editable mappings', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByRole('button', { name: 'Discover SCIM attributes' }).click();
  await expect(page.getByText('employeeNumber', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Discover LDAP attributes' }).click();
  await expect(page.getByText('givenName', { exact: true }).last()).toBeVisible();
  await page.getByRole('button', { name: 'Validate mappings' }).click();
  await expect(page.getByText(/All mappings validated against 20 SCIM paths/)).toBeVisible();
  await page.getByRole('button', { name: 'Preview mapping' }).click();
  await expect(page.getByRole('table').getByText('Ada', { exact: true }).first()).toBeVisible();
  await page.getByLabel('SCIM path 5').fill('employeeNumber');
  await page.getByLabel('LDAP attribute 5').fill('employeeNumber');
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({
    attribute_mappings: expect.arrayContaining([
      { scim_path: 'employeeNumber', ldap_attribute: 'employeeNumber', direction: 'both' },
    ]),
  });
});

test('live settings and live runs require confirmation', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await page.getByLabel('Dry-run mode', { exact: true }).uncheck();
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByRole('button', { name: 'Run sync', exact: true }).click();
  expect(env.calls).not.toContain('POST /api/sync');
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Run sync', exact: true }).click();
  await expect(page.getByText('Run #8 started in live mode. Follow its progress in Activity.')).toBeVisible();
});

test('identity reset can be cancelled and drafts survive navigation', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByLabel('SCIM endpoint URL').fill('https://new.example.org/scim/v2');
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByLabel('SCIM endpoint URL')).toHaveValue('https://new.example.org/scim/v2');
  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('identity baselines');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  await page.getByRole('button', { name: 'Discard', exact: true }).click();
  await expect(page.getByLabel('SCIM endpoint URL')).toHaveValue(defaults.scim_url);
});

test('shows validation errors without discarding the draft', async ({ page }) => {
  await environment(page);
  await login(page);
  await page.route('**/api/settings', async route => {
    if (route.request().method() === 'PUT') await route.fulfill({ status: 400, json: { detail: 'Configure both connectors before enabling the schedule.' } });
    else await route.fallback();
  });
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await page.getByLabel('Enable scheduled synchronization').check();
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByRole('alert')).toContainText('Configure both connectors');
  await expect(page.getByLabel('Enable scheduled synchronization')).toBeChecked();
});

test('inventory supports filtering, pagination, and attribute inspection', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Inventory', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'user-0', exact: true })).toBeVisible();
  await expect(page.getByText('Absent', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: 'Next page' }).click();
  await expect(page.getByRole('cell', { name: 'user-25', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Next page' })).toBeDisabled();
  await page.getByLabel('Source', { exact: true }).selectOption('ldap');
  await page.getByLabel('Resource type', { exact: true }).fill('Groups');
  await page.getByRole('button', { name: 'Apply filters' }).click();
  await expect(page.getByRole('cell', { name: 'user-0', exact: true })).toBeVisible();
  expect(env.calls).toContain('GET /api/data/resources?resource_type=Groups&limit=25&offset=0&source=ldap');
  await page.getByRole('button', { name: 'Inspect' }).first().click();
  await expect(page.getByRole('dialog')).toContainText('Engineering');
  await page.getByRole('button', { name: 'Close resource details' }).click();
  await expect(page.getByRole('dialog')).toHaveCount(0);
});

test('inventory fetch failures are visible and retryable', async ({ page }) => {
  await environment(page);
  await login(page);
  await page.route('**/api/data/resources?**', route => route.fulfill({ status: 502, json: { detail: 'Storage unavailable' } }));
  await page.getByRole('button', { name: 'Inventory', exact: true }).click();
  await expect(page.getByRole('alert')).toContainText('Storage unavailable');
  await expect(page.getByText('No resources found')).toHaveCount(0);
  await page.unroute('**/api/data/resources?**');
  await page.getByRole('button', { name: 'Refresh inventory' }).click();
  await expect(page.getByRole('cell', { name: 'user-0', exact: true })).toBeVisible();
});

test('polling reports stale data, recovers, and expires a rejected session', async ({ page }) => {
  await environment(page);
  await page.clock.install();
  await login(page);
  await page.route('**/api/status', route => route.fulfill({ status: 503, json: { detail: 'Temporarily unavailable' } }));
  await page.clock.fastForward(6000);
  await expect(page.getByRole('alert')).toContainText('Displayed data may be stale');
  await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeDisabled();
  await page.unroute('**/api/status');
  await page.clock.fastForward(6000);
  await expect(page.getByRole('alert')).toHaveCount(0);
  await page.route('**/api/status', route => route.fulfill({ status: 401, json: { detail: 'Token rotated' } }));
  await page.clock.fastForward(6000);
  await expect(page.getByRole('heading', { name: 'Welcome to your console' })).toBeVisible();
  await expect(page.getByRole('alert')).toContainText('token was rejected');
});

test('activity shows runs, operations, and events', async ({ page }) => {
  await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Activity', exact: true }).click();
  await expect(page.getByRole('cell', { name: 'preview', exact: true })).toBeVisible();
  await expect(page.getByRole('cell', { name: 'completed', exact: true })).toBeVisible();
  await expect(page.getByText('Run finished.', { exact: true })).toBeVisible();
});

test('mobile pages fit without document-level horizontal overflow', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await environment(page);
  await login(page);
  for (const name of ['Overview', 'Connections', 'Synchronization', 'Inventory', 'Activity', 'System']) {
    await page.getByRole('button', { name, exact: true }).click();
    await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true);
  }
});
