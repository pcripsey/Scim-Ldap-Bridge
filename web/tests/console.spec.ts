import { expect, test, type Page } from '@playwright/test';
import type { Settings, Status } from '../src/api';

const token = 'console-test-admin-token-at-least-24';
const defaults: Settings = {
  scim_provider: 'generic',
  scim_url: 'https://identity.example.org/scim/v2',
  entra_tenant_id: '',
  entra_client_id: '',
  scim_filter: '',
  entra_client_secret_configured: false,
  ldap_url: 'ldaps://directory.example.org:636',
  ldap_service: 'generic',
  ad_enable_new_accounts: false,
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
  ignore_unsupported_fields: false,
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
        const { scim_token, ldap_password, entra_client_secret, confirm_scope_reset, ...rest } = payload;
        settings = { ...settings, ...rest };
        if (scim_token !== undefined) settings.scim_token_configured = Boolean(scim_token);
        if (ldap_password !== undefined) settings.ldap_password_configured = Boolean(ldap_password);
        if (entra_client_secret !== undefined) settings.entra_client_secret_configured = Boolean(entra_client_secret);
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

test('separates inbound push setup from Entra OAuth and explains password limitations', async ({ page }) => {
  await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  const push = page.locator('section').filter({ has: page.getByRole('heading', { name: 'SCIM push — inbound provisioning', exact: true }) });
  await expect(push).toContainText('/scim/v2');
  await expect(push).toContainText('BRIDGE_SCIM_TOKEN');
  await expect(push.getByLabel('Entra client ID')).toHaveCount(0);
  await page.getByLabel('Provider and authentication').selectOption('entra');
  await expect(page.getByRole('heading', { name: 'Microsoft Entra ID — OAuth pull', exact: true })).toBeVisible();
  await expect(push).toBeVisible();
  await expect(page.getByLabel('Entra client ID')).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Password synchronization', exact: true })).toBeVisible();
  await expect(page.getByText('SCIM passwords are write-only', { exact: false })).toBeVisible();
});

test('LDAP service selection confirms replacement, persists defaults, and highlights requirements', async ({ page }) => {
  const env = await environment(page, {
    enabled: true, dry_run: false,
    attribute_mappings: [...defaults.attribute_mappings, { scim_path: 'title', ldap_attribute: 'title', direction: 'both' }],
  });
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByLabel('LDAP service', { exact: true }).selectOption('active_directory');
  await expect(page.getByLabel('LDAP service', { exact: true })).toHaveValue('generic');
  await expect(page.getByLabel('LDAP attribute 6', { exact: true })).toHaveValue('title');
  page.once('dialog', dialog => dialog.accept());
  await page.getByLabel('LDAP service', { exact: true }).selectOption('active_directory');
  await expect(page.getByLabel('LDAP attribute 1', { exact: true })).toHaveValue('sAMAccountName');
  await expect(page.getByLabel('LDAP attribute 6', { exact: true })).toHaveCount(0);
  await expect(page.getByRole('heading', { name: 'Required attributes — Microsoft Active Directory Domain Services' })).toBeVisible();
  await expect(page.getByText('Required by bridge', { exact: true })).toBeVisible();
  await expect(page.getByText('New accounts are disabled', { exact: false })).toBeVisible();
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await expect(page.getByLabel('Dry-run mode', { exact: true })).toBeChecked();
  await expect(page.getByLabel('Enable scheduled synchronization')).not.toBeChecked();
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({ ldap_service: 'active_directory', dry_run: true, enabled: false });
  await page.reload();
  await page.getByLabel('Administrator token', { exact: true }).fill(token);
  await page.getByRole('button', { name: 'Open console' }).click();
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByLabel('LDAP service', { exact: true })).toHaveValue('active_directory');
  await expect(page.getByLabel('LDAP attribute 1', { exact: true })).toHaveValue('sAMAccountName');
  for (const service of ['openldap', '389ds', 'generic']) {
    page.once('dialog', dialog => dialog.accept());
    await page.getByLabel('LDAP service', { exact: true }).selectOption(service);
    await expect(page.getByLabel('LDAP attribute 1', { exact: true })).toHaveValue('uid');
    await expect(page.getByLabel('LDAP attribute 3', { exact: true })).toHaveValue('sn');
  }
});

test('legacy settings keep generic LDAP defaults and missing surnames are highlighted', async ({ page }) => {
  await environment(page, { ldap_service: undefined });
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByLabel('LDAP service', { exact: true })).toHaveValue('generic');
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  await page.getByRole('button', { name: 'Remove mapping 3', exact: true }).click();
  await expect(page.getByText('Add a name.familyName mapping:', { exact: false })).toBeVisible();
});

test('AD activation is opt-in, confirmed on save, and cleared when switching LDAP service', async ({ page }) => {
  const env = await environment(page, { ldap_service: 'active_directory' });
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByLabel('Enable new AD accounts', { exact: true })).not.toBeChecked();
  await page.getByLabel('Enable new AD accounts', { exact: true }).check();
  await expect(page.getByText('Users need a separate password-reset process to sign in.', { exact: false })).toBeVisible();
  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('generated, undisclosed password');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({ ad_enable_new_accounts: true });
  await expect(page.getByLabel('Enable new AD accounts', { exact: true })).toBeChecked();
  page.once('dialog', dialog => dialog.accept());
  await page.getByLabel('LDAP service', { exact: true }).selectOption('openldap');
  await expect(page.getByLabel('Enable new AD accounts', { exact: true })).toHaveCount(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByLabel('LDAP service', { exact: true }).selectOption('active_directory');
  await expect(page.getByLabel('Enable new AD accounts', { exact: true })).not.toBeChecked();
});

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

const tenantId = '11111111-2222-3333-4444-555555555555';
const clientId = 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee';
const entraSettings: Partial<Settings> = {
  scim_provider: 'entra', scim_url: 'https://graph.microsoft.com/rp/scim',
  entra_tenant_id: tenantId, entra_client_id: clientId,
  entra_client_secret_configured: true, scim_token_configured: false, direction: 'scim_to_ldap',
};

test('opts into Entra safely, validates IDs, confirms source identity, and sends OAuth settings', async ({ page }) => {
  const env = await environment(page, { enabled: true, dry_run: false });
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByLabel('SCIM bearer token', { exact: true }).selectOption('replace');
  await page.getByLabel('New scim bearer token', { exact: true }).fill('discard-this-static-secret');
  await page.getByLabel('Provider and authentication').selectOption('entra');
  await expect(page.getByLabel('SCIM endpoint URL')).toHaveValue('https://graph.microsoft.com/rp/scim');
  await expect(page.getByLabel('SCIM endpoint URL')).toHaveAttribute('readonly', '');
  await expect(page.getByLabel('SCIM bearer token', { exact: true })).toHaveCount(0);
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  expect(await page.getByLabel('Entra tenant ID', { exact: true }).evaluate((input: HTMLInputElement) => input.validity.valueMissing)).toBe(true);
  await page.getByLabel('Entra tenant ID', { exact: true }).fill('not-a-guid');
  await page.getByLabel('Entra client ID', { exact: true }).fill(clientId);
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  expect(await page.getByLabel('Entra tenant ID', { exact: true }).evaluate((input: HTMLInputElement) => input.validity.patternMismatch)).toBe(true);
  await page.getByLabel('Entra tenant ID', { exact: true }).fill(tenantId);
  await page.getByLabel('Entra client secret', { exact: true }).selectOption('replace');
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  await page.getByLabel('New entra client secret', { exact: true }).fill('new-entra-client-secret');
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await expect(page.getByLabel('Synchronization direction')).toHaveValue('scim_to_ldap');
  await expect(page.getByLabel('Synchronization direction').locator('option[value="bidirectional"]')).toBeDisabled();
  await expect(page.getByLabel('Synchronization direction').locator('option[value="ldap_to_scim"]')).toBeDisabled();
  await expect(page.getByLabel('Enable scheduled synchronization')).not.toBeChecked();
  await expect(page.getByLabel('Dry-run mode', { exact: true })).toBeChecked();
  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('tenant, client, and source filter');
    await dialog.dismiss();
  });
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({
    scim_provider: 'entra', scim_url: 'https://graph.microsoft.com/rp/scim',
    entra_tenant_id: tenantId, entra_client_id: clientId, direction: 'scim_to_ldap',
    entra_client_secret: 'new-entra-client-secret', enabled: false, dry_run: true,
    confirm_scope_reset: true,
  });
  expect(env.writes[0]).not.toHaveProperty('scim_token');
  expect(env.writes[0]).not.toHaveProperty('entra_client_secret_configured');
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
});

test('Entra preserves, replaces, and clears its secret with provider-aware readiness', async ({ page }) => {
  const env = await environment(page, entraSettings);
  await login(page);
  await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByRole('button', { name: 'Test SCIM connection' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Discover SCIM attributes' })).toBeEnabled();
  await expect(page.getByRole('button', { name: 'Validate mappings' })).toBeEnabled();
  await page.getByLabel('Base distinguished name', { exact: true }).fill('ou=changed,dc=example,dc=org');
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).not.toHaveProperty('entra_client_secret');
  await page.getByLabel('Entra client secret', { exact: true }).selectOption('replace');
  await page.getByLabel('New entra client secret', { exact: true }).fill('replacement-entra-secret');
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  expect(env.writes[1]).toHaveProperty('entra_client_secret', 'replacement-entra-secret');
  expect(env.writes[1]).not.toHaveProperty('confirm_scope_reset');
  await page.getByLabel('Entra client secret', { exact: true }).selectOption('clear');
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  expect(env.writes[2]).toHaveProperty('entra_client_secret', '');
  for (const name of ['Test SCIM connection', 'Discover SCIM attributes', 'Validate mappings', 'Run sync']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  }
});

test('returning to generic mode never leaves the Graph endpoint or a pending OAuth replacement', async ({ page }) => {
  const env = await environment(page, entraSettings);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByLabel('Entra client secret', { exact: true }).selectOption('replace');
  await page.getByLabel('New entra client secret', { exact: true }).fill('discard-this-oauth-secret');
  await page.getByLabel('Provider and authentication').selectOption('generic');
  await expect(page.getByLabel('SCIM endpoint URL')).toHaveValue('');
  await expect(page.getByLabel('SCIM endpoint URL')).not.toHaveAttribute('readonly', '');
  await page.getByLabel('SCIM endpoint URL').fill(defaults.scim_url);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  expect(env.writes[0]).toMatchObject({ scim_provider: 'generic', scim_url: defaults.scim_url, confirm_scope_reset: true });
  expect(env.writes[0]).not.toHaveProperty('entra_client_secret');
});

test('legacy settings without provider fields default to generic bearer authentication', async ({ page }) => {
  await environment(page);
  const legacy: Record<string, unknown> = { ...defaults };
  for (const key of ['scim_provider', 'entra_tenant_id', 'entra_client_id', 'scim_filter', 'entra_client_secret_configured']) delete legacy[key];
  await page.route('**/api/settings', route => route.fulfill({ json: legacy }));
  await login(page);
  await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeEnabled();
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByLabel('Provider and authentication')).toHaveValue('generic');
  await expect(page.getByRole('button', { name: 'Test SCIM connection' })).toBeEnabled();
});

test('Entra requires its own saved OAuth secret even when a bearer token exists', async ({ page }) => {
  await environment(page, { ...entraSettings, entra_client_secret_configured: false, scim_token_configured: true });
  await login(page);
  await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeDisabled();
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  for (const name of ['Test SCIM connection', 'Discover SCIM attributes', 'Validate mappings']) {
    await expect(page.getByRole('button', { name, exact: true })).toBeDisabled();
  }
});

for (const label of ['Entra tenant ID', 'Entra client ID']) {
  test(`changing ${label} requires explicit source scope confirmation`, async ({ page }) => {
    const env = await environment(page, entraSettings);
    await login(page);
    await page.getByRole('button', { name: 'Connections', exact: true }).click();
    await page.getByLabel(label, { exact: true }).fill('99999999-8888-7777-6666-555555555555');
    page.once('dialog', dialog => dialog.dismiss());
    await page.getByRole('button', { name: 'Save configuration' }).click();
    expect(env.writes).toHaveLength(0);
    page.once('dialog', dialog => dialog.accept());
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
    expect(env.writes[0]).toHaveProperty('confirm_scope_reset', true);
    expect(env.writes[0]).not.toHaveProperty('entra_client_secret');
  });
}

test('Entra filter scope changes require confirmation and invalid filters retain the draft', async ({ page }) => {
  const env = await environment(page, entraSettings);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await page.getByLabel('Entra source filter', { exact: true }).fill('userName eq "person@example.org"');
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  page.once('dialog', dialog => dialog.accept());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  expect(env.writes[0]).toMatchObject({ scim_filter: 'userName eq "person@example.org"', confirm_scope_reset: true });
  expect(env.writes[0]).not.toHaveProperty('entra_client_secret');
  for (const filter of [
    'userName eq', 'userName eq "unterminated', 'userName eq "\\q"', 'userName eq ""',
    'userName eq "line\\nfeed"', 'userName eq true', 'active eq "true"', 'active ew true',
    'groups.value ew "group-id"', 'displayName eq "Ada"', 'not active eq true',
    'active eq true and userName ew "@example.org"', 'active eq true or active eq false',
  ]) {
    await page.getByLabel('Entra source filter', { exact: true }).fill(filter);
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await expect(page.getByRole('alert')).toContainText('Invalid Entra source filter.');
    await expect(page.getByLabel('Entra source filter', { exact: true })).toHaveValue(filter);
    await expect(page.getByRole('button', { name: 'Run sync', exact: true })).toBeDisabled();
    expect(env.writes).toHaveLength(1);
  }
});

test('Entra accepts the documented single predicate subset including direct group scope', async ({ page }) => {
  const env = await environment(page, entraSettings);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByText(/Grant application permissions User.Read.All and Group.Read.All/)).toBeVisible();
  await expect(page.getByText(/selects direct members only, not transitive membership/)).toBeVisible();
  const filters = [
    'active eq true', 'active eq false', 'userName ew "@example.org"',
    `groups.value eq "${tenantId}"`, 'id eq "source-user-id"', 'externalId eq "external-user-id"',
    'userName eq "person@example.org"', 'externalId eq "escaped \\"quote\\" and \\\\ slash"',
    'externalId eq "\\u0041da"', '',
  ];
  for (const [index, filter] of filters.entries()) {
    await page.getByLabel('Entra source filter', { exact: true }).fill(filter);
    page.once('dialog', dialog => dialog.accept());
    await page.getByRole('button', { name: 'Save configuration' }).click();
    await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
    expect(env.writes[index]).toMatchObject({ scim_filter: filter, confirm_scope_reset: true });
  }
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

test('ignoring unsupported fields is an explicit, persisted, reversible choice', async ({ page }) => {
  const env = await environment(page);
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  const checkbox = page.getByRole('checkbox', { name: 'Ignore unsupported or unmapped fields' });
  await expect(checkbox).not.toBeChecked();
  await expect(checkbox).toHaveAccessibleDescription(/active:false does not disable the LDAP account/);
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  await checkbox.check();
  await expect(page.getByText('You have unsaved changes')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeEnabled();
  page.once('dialog', dialog => dialog.dismiss());
  await page.getByRole('button', { name: 'Save configuration' }).click();
  expect(env.writes).toHaveLength(0);
  await expect(checkbox).toBeChecked();
  page.once('dialog', async dialog => {
    expect(dialog.message()).toContain('active:false will not disable the LDAP account');
    await dialog.accept();
  });
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({ ignore_unsupported_fields: true });
  expect(env.writes[0]).not.toHaveProperty('scim_token');
  expect(env.calls.filter(call => call === 'GET /api/settings')).toHaveLength(2);
  await expect(checkbox).toBeChecked();
  await expect(page.getByText('All changes saved')).toBeVisible();
  await checkbox.uncheck();
  await expect(page.getByRole('button', { name: 'Discard' })).toBeEnabled();
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('All changes saved')).toBeVisible();
  expect(env.writes[1]).toMatchObject({ ignore_unsupported_fields: false });
  await expect(checkbox).not.toBeChecked();
});

test('legacy settings without the ignore policy default to strict validation', async ({ page }) => {
  const env = await environment(page);
  const legacy: Record<string, unknown> = { ...defaults };
  delete legacy.ignore_unsupported_fields;
  await page.route('**/api/settings', route => route.request().method() === 'GET'
    ? route.fulfill({ json: legacy }) : route.fallback());
  await login(page);
  await page.getByRole('button', { name: 'Connections', exact: true }).click();
  await expect(page.getByRole('checkbox', { name: 'Ignore unsupported or unmapped fields' })).not.toBeChecked();
  await expect(page.getByRole('button', { name: 'Save configuration' })).toBeDisabled();
  await page.getByRole('button', { name: 'Synchronization', exact: true }).click();
  await page.getByLabel('Interval (seconds)').fill('600');
  await page.getByRole('button', { name: 'Save configuration' }).click();
  await expect(page.getByText('Configuration saved. Your next run will use these settings.')).toBeVisible();
  expect(env.writes[0]).toMatchObject({ ignore_unsupported_fields: false, interval_seconds: 600 });
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
