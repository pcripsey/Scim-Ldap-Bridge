import { cloneElement, useCallback, useEffect, useId, useRef, useState, type FormEvent, type ReactElement, type ReactNode } from 'react';
import {
  Activity, ArrowDownUp, ArrowRight, Check, ChevronLeft, ChevronRight, CircleHelp,
  Database, ExternalLink, GitCompareArrows, LayoutDashboard, LoaderCircle, LogOut, Network,
  Play, RefreshCw, Save, Server, Settings2, ShieldCheck, X,
} from 'lucide-react';
import {
  ApiError, ldapDefaultMappings, ldapServices, message, normalizeSettings, request, settingsPayload,
  type AttributeDiscovery, type Event, type MappingValidation, type Operation, type Resource, type Run, type SecretEdit,
  type Secrets, type Settings, type Status,
} from './api';

type Page = 'Overview' | 'Connections' | 'Attribute mapping' | 'Synchronization' | 'Inventory' | 'Activity' | 'System';
const navigation = [
  { name: 'Overview', icon: LayoutDashboard, description: 'Your identity infrastructure, at a glance.' },
  { name: 'Connections', icon: Network, description: 'Connect your SCIM provider and LDAP directory.' },
  { name: 'Attribute mapping', icon: GitCompareArrows, description: 'Map SCIM paths to LDAP attributes for your directory service.' },
  { name: 'Synchronization', icon: ArrowDownUp, description: 'Decide how identities move between your systems.' },
  { name: 'Inventory', icon: Database, description: 'Explore the last observed state of your directory resources.' },
  { name: 'Activity', icon: Activity, description: 'Follow synchronization runs, operations, and events.' },
  { name: 'System', icon: Server, description: 'Deployment information and operational safeguards.' },
] as const;
const emptySecrets = (): Secrets => ({
  scim_token: { mode: 'keep', value: '' }, ldap_password: { mode: 'keep', value: '' },
  entra_client_secret: { mode: 'keep', value: '' },
});
const entraUrl = 'https://graph.microsoft.com/rp/scim';
const guidPattern = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}';
function validEntraFilter(value: string) {
  if (!value) return true;
  if (value.length > 2048) return false;
  const match = /^(?:(userName|id|externalId|groups\.value|active) eq (.+)|userName ew (.+))$/.exec(value);
  if (!match || match[0] !== value) return false;
  if (match[1] === 'active') return /^(true|false)$/i.test(match[2]);
  try {
    const operand: unknown = JSON.parse(match[2] ?? match[3]);
    return typeof operand === 'string' && operand.length > 0 && !Array.from(operand).some(char => char.charCodeAt(0) < 32);
  } catch { return false; }
}
const date = (value: string | number | null) =>
  value === null ? 'Not scheduled' : new Date(typeof value === 'number' ? value * 1000 : value).toLocaleString();
const settingsPages: Page[] = ['Connections', 'Attribute mapping', 'Synchronization'];
const direction = { bidirectional: 'Bidirectional', scim_to_ldap: 'SCIM to LDAP', ldap_to_scim: 'LDAP to SCIM' };

function Badge({ children, tone = '' }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

function Panel({ title, subtitle, children, action }: { title: string; subtitle?: string; children: ReactNode; action?: ReactNode }) {
  return <section className="panel"><div className="panel-heading"><div><h2>{title}</h2>{subtitle && <p>{subtitle}</p>}</div>{action}</div>{children}</section>;
}

function Field({ label, hint, children }: {
  label: string; hint?: string; children: ReactElement<{ id?: string; 'aria-describedby'?: string }>;
}) {
  const id = useId();
  return <div className="field"><label htmlFor={id}>{label}</label>
    {cloneElement(children, { id, 'aria-describedby': hint ? `${id}-hint` : undefined })}
    {hint && <small id={`${id}-hint`}>{hint}</small>}</div>;
}

function Notice({ children, kind = 'error', dismiss }: { children: ReactNode; kind?: string; dismiss?: () => void }) {
  return <div className={`notice ${kind}`} role={kind === 'error' ? 'alert' : 'status'}><span>{children}</span>
    {dismiss && <button className="icon-button" aria-label="Dismiss message" onClick={dismiss}><X size={16} /></button>}
  </div>;
}

function SecretField({ label, configured, edit, onChange }: {
  label: string; configured: boolean; edit: SecretEdit; onChange: (value: SecretEdit) => void;
}) {
  return <div className="secret-field">
    <Field label={label} hint={configured ? 'A credential is saved. Its value is never returned to the browser.' : 'No credential saved.'}>
      <select value={edit.mode} onChange={event => {
        const mode = event.target.value;
        if (mode === 'keep' || mode === 'replace' || mode === 'clear') onChange({ mode, value: '' });
      }}>
        <option value="keep">{configured ? 'Keep saved credential' : 'Leave unset'}</option>
        <option value="replace">Set a new credential</option>
        <option value="clear">Clear saved credential</option>
      </select>
    </Field>
    {edit.mode === 'replace' && <Field label={`New ${label.toLowerCase()}`}>
      <input type="password" autoComplete="new-password" required value={edit.value}
        onChange={event => onChange({ mode: 'replace', value: event.target.value })} />
    </Field>}
    {edit.mode === 'clear' && <p className="warning-text">This credential will be removed when you save.</p>}
  </div>;
}

function Runs({ runs }: { runs: Run[] }) {
  return runs.length ? <div className="table-scroll"><table><thead><tr>
    <th>Run</th><th>Started</th><th>Status</th><th>Mode</th><th>Users</th><th>Changes</th><th>Conflicts</th><th>Errors</th>
  </tr></thead><tbody>{runs.map(run => <tr key={run.id}>
    <td className="strong">#{run.id}</td><td>{date(run.started)}</td><td><State value={run.status} /></td>
    <td>{run.dry_run ? 'Dry run' : 'Live'}</td><td>{run.processed}</td><td>{run.changed}</td>
    <td>{run.conflicts}</td><td>{run.errors}</td>
  </tr>)}</tbody></table></div> : <Empty title="No runs yet" text="Configure your connectors, then start a dry run to preview changes." />;
}

function State({ value }: { value: string }) {
  const tone = ['failed', 'error', 'interrupted'].includes(value) ? 'red'
    : ['conflict', 'conflicts', 'warning', 'cancelled'].includes(value) ? 'amber'
      : ['completed', 'applied', 'success'].includes(value) ? 'green' : 'blue';
  return <Badge tone={tone}>{value.replaceAll('_', ' ')}</Badge>;
}

function Empty({ title, text }: { title: string; text: string }) {
  return <div className="empty"><Database size={28} /><h3>{title}</h3><p>{text}</p></div>;
}

function Events({ events }: { events: Event[] }) {
  return events.length ? <ol className="events">{events.map(event => <li key={event.id}>
    <span className={`event-dot ${event.level}`} /><div><p>{event.message}</p>
      <small>{date(event.time)}{event.run_id !== null && ` / Run #${event.run_id}`}{event.username && ` / ${event.username}`}</small></div>
    <State value={event.level} />
  </li>)}</ol> : <Empty title="All quiet here" text="Connection checks, configuration changes, and sync activity appear here." />;
}

export function App() {
  const [session, setSession] = useState<{ token: string; status: Status; settings: Settings } | null>(null);
  const [token, setToken] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const logout = useCallback((reason = '') => { setSession(null); setError(reason); }, []);

  async function login(event: FormEvent) {
    event.preventDefault();
    setBusy(true); setError('');
    try {
      const [status, settings] = await Promise.all([
        request<Status>(token, '/api/status'), request<Settings>(token, '/api/settings'),
      ]);
      setSession({ token, status, settings: normalizeSettings(settings) }); setToken('');
    } catch (error) { setError(message(error)); }
    finally { setBusy(false); }
  }

  if (session) return <Console key={session.token} session={session} onLogout={logout} />;
  return <main className="login-shell"><div className="login-intro">
    <div className="brand"><span className="brand-icon"><ArrowDownUp /></span><span>bridge<span className="brand-period">.</span></span></div>
    <Badge tone="blue">SCIM + LDAP</Badge>
    <h1>Two systems.<br />One connected<br /><span>identity layer.</span></h1>
    <p>A clear view of your directories. A safer way to keep them in sync.</p>
    <div className="login-points"><span><ShieldCheck size={18} /> Dry-run first</span><span><Database size={18} /> Encrypted storage</span></div>
  </div><section className="login-card"><div className="section-icon"><ShieldCheck /></div>
    <h2>Welcome to your console</h2><p>Sign in to manage your bridge environment.</p>
    {error && <Notice>{error}</Notice>}
    <form onSubmit={login}>
      <Field label="Administrator token" hint="Use the BRIDGE_ADMIN_TOKEN configured on your server.">
        <input autoFocus type="password" autoComplete="off" required value={token} onChange={event => setToken(event.target.value)} disabled={busy} />
      </Field>
      <button className="primary full" disabled={busy || !token}>{busy ? <LoaderCircle className="spin" size={18} /> : <ArrowRight size={18} />} {busy ? 'Connecting...' : 'Open console'}</button>
    </form><p className="login-note"><ShieldCheck size={16} /> Your token stays in memory, not browser storage. Reloading signs you out. Use HTTPS for remote access.</p>
  </section><span className="login-footer">SCIM LDAP Bridge / Administration</span></main>;
}

function Console({ session, onLogout }: {
  session: { token: string; status: Status; settings: Settings }; onLogout: (reason?: string) => void;
}) {
  const [page, setPage] = useState<Page>('Overview');
  const [status, setStatus] = useState(session.status);
  const [saved, setSaved] = useState(session.settings);
  const [draft, setDraft] = useState(session.settings);
  const [secrets, setSecrets] = useState(emptySecrets);
  const [discovery, setDiscovery] = useState<Partial<Record<'scim' | 'ldap', AttributeDiscovery>>>({});
  const [showMappingPreview, setShowMappingPreview] = useState(false);
  const [busy, setBusy] = useState('');
  const [notice, setNotice] = useState<{ text: string; kind: string } | null>(null);
  const [pollError, setPollError] = useState('');
  const [updated, setUpdated] = useState(new Date());
  const dirty = JSON.stringify(draft) !== JSON.stringify(saved) ||
    Object.values(secrets).some(secret => secret.mode !== 'keep');
  const currentPage = navigation.find(item => item.name === page)!;
  const entra = draft.scim_provider === 'entra';
  const activeDirectory = draft.ldap_service === 'active_directory';
  const usernameAttribute = draft.attribute_mappings.find(mapping => mapping.scim_path === 'userName')?.ldap_attribute;
  const scimReady = Boolean(saved.scim_url && (saved.scim_provider === 'entra'
    ? new RegExp(`^${guidPattern}$`).test(saved.entra_tenant_id) &&
      new RegExp(`^${guidPattern}$`).test(saved.entra_client_id) && saved.entra_client_secret_configured &&
      /^https:\/\/graph\.microsoft\.com\/rp\/scim\/?$/.test(saved.scim_url) && saved.direction === 'scim_to_ldap' &&
      validEntraFilter(saved.scim_filter)
    : saved.scim_token_configured));
  const connected = Boolean(scimReady && saved.ldap_url && saved.ldap_base_dn &&
    saved.ldap_bind_dn && saved.ldap_password_configured);

  const api = useCallback(async <T,>(path: string, init?: RequestInit): Promise<T> => {
    try { return await request<T>(session.token, path, init); }
    catch (error) {
      if (error instanceof ApiError && error.status === 401) onLogout('Your administrator token was rejected. Sign in again.');
      throw error;
    }
  }, [session.token, onLogout]);

  const refresh = useCallback(async (signal?: AbortSignal) => {
    const latest = await api<Status>('/api/status', { signal });
    setStatus(latest); setUpdated(new Date()); setPollError('');
  }, [api]);

  useEffect(() => {
    const controller = new AbortController();
    let timer: ReturnType<typeof setTimeout>;
    const poll = async () => {
      try { await refresh(controller.signal); }
      catch (error) { if (!controller.signal.aborted) setPollError(`Status refresh failed: ${message(error)}`); }
      if (!controller.signal.aborted) timer = setTimeout(poll, 5000);
    };
    timer = setTimeout(poll, 5000);
    return () => { controller.abort(); clearTimeout(timer); };
  }, [refresh]);

  useEffect(() => {
    const warn = (event: BeforeUnloadEvent) => { event.preventDefault(); };
    if (dirty) window.addEventListener('beforeunload', warn);
    return () => window.removeEventListener('beforeunload', warn);
  }, [dirty]);

  async function action(name: string, callback: () => Promise<string>, refreshAfter = true) {
    setBusy(name); setNotice(null);
    try {
      const text = await callback();
      setNotice({ text, kind: 'success' });
      if (refreshAfter) {
        try { await refresh(); }
        catch (error) { setPollError(`Status refresh failed: ${message(error)}`); }
      }
    } catch (error) { setNotice({ text: message(error), kind: 'error' }); }
    finally { setBusy(''); }
  }

  function update<K extends keyof Settings>(key: K, value: Settings[K]) {
    setDraft(previous => ({ ...previous, [key]: value }));
  }

  function selectProvider(provider: Settings['scim_provider']) {
    if (provider === draft.scim_provider) return;
    setDraft(previous => ({
      ...previous, scim_provider: provider, enabled: false, dry_run: true,
      ...(provider === 'entra'
        ? { scim_url: entraUrl, direction: 'scim_to_ldap' as const }
        : { scim_url: saved.scim_provider === 'generic' ? saved.scim_url : '', scim_filter: '' }),
    }));
    setSecrets(previous => ({
      ...previous,
      scim_token: previous.scim_token.mode === 'replace' ? { mode: 'keep', value: '' } : previous.scim_token,
      entra_client_secret: previous.entra_client_secret.mode === 'replace' ? { mode: 'keep', value: '' } : previous.entra_client_secret,
    }));
    setDiscovery({}); setShowMappingPreview(false);
  }

  function selectLdapService(service: Settings['ldap_service']) {
    if (service === draft.ldap_service) return;
    if (!window.confirm('Changing LDAP service replaces all attribute mappings with service defaults, pauses the schedule, and enables dry run. Continue?')) return;
    setDraft(previous => ({
      ...previous, ldap_service: service, attribute_mappings: ldapDefaultMappings(service),
      ad_enable_new_accounts: false,
      enabled: false, dry_run: true,
    }));
    setDiscovery({});
    setShowMappingPreview(false);
  }

  const plainLdap = draft.ldap_url.toLowerCase().startsWith('ldap://') ? true
    : draft.ldap_url.toLowerCase().startsWith('ldaps://') ? false : undefined;

  function save(event: FormEvent) {
    event.preventDefault();
    if (Object.values(secrets).some(secret => secret.mode === 'replace' && !secret.value)) {
      setNotice({ text: 'Enter a value for each credential being replaced.', kind: 'error' });
      return;
    }
    if (entra && (!new RegExp(`^${guidPattern}$`).test(draft.entra_tenant_id) ||
        !new RegExp(`^${guidPattern}$`).test(draft.entra_client_id) || draft.direction !== 'scim_to_ldap' ||
        !/^https:\/\/graph\.microsoft\.com\/rp\/scim\/?$/.test(draft.scim_url))) {
      setNotice({ text: 'Entra requires GUID tenant and client IDs, the official Graph SCIM endpoint, and SCIM to LDAP direction.', kind: 'error' });
      return;
    }
    if (entra && !validEntraFilter(draft.scim_filter)) {
      setNotice({ text: 'Invalid Entra source filter. Use one predicate: userName/id/externalId/groups.value eq "value", userName ew "suffix", or active eq true/false. Compound and not filters are not supported.', kind: 'error' });
      return;
    }
    const paths = draft.attribute_mappings.map(mapping => mapping.scim_path.trim().toLowerCase());
    const attributes = draft.attribute_mappings.map(mapping => mapping.ldap_attribute.trim().toLowerCase());
    if (paths.some(path => !path) || attributes.some(attribute => !attribute) ||
        new Set(paths).size !== paths.length || new Set(attributes).size !== attributes.length ||
        !draft.attribute_mappings.some(mapping => mapping.scim_path.trim() === 'userName' && mapping.direction === 'both')) {
      setNotice({ text: 'Mappings must be complete and unique, and userName must be mapped in both directions.', kind: 'error' });
      return;
    }
    const warnings: string[] = [];
    if (draft.ad_enable_new_accounts && !saved.ad_enable_new_accounts) {
      warnings.push('New AD accounts will receive a generated, undisclosed password and be enabled after successful password initialization. Existing accounts are unchanged. Users need a separate password-reset process.');
    }
    const scopeChanged = (['scim_provider', 'entra_tenant_id', 'entra_client_id', 'scim_filter'] as const)
      .some(key => draft[key] !== saved[key]);
    if (!draft.dry_run && (saved.dry_run || (!saved.enabled && draft.enabled))) {
      warnings.push(`Live mode allows writes to your directories, including inbound SCIM provisioning. Enabling the schedule will run automatically.${
        Object.values(status.database.pending_users ?? {}).reduce((sum, count) => sum + count, 0)
          ? ' Users waiting to be synchronised to LDAP will be created automatically.' : ''}`);
    }
    if (scopeChanged || (['scim_url', 'ldap_url', 'ldap_base_dn', 'ldap_bind_dn', 'ldap_service'] as const).some(key => draft[key] !== saved[key])) {
      warnings.push('Changing source scope or connector identity clears cached inventory and identity baselines. Confirm the provider, endpoint, tenant, client, and source filter identify the intended source before continuing.');
      warnings.push(`Source: ${draft.scim_provider}\nEndpoint: ${draft.scim_url || '(unset)'}${entra
        ? `\nTenant: ${draft.entra_tenant_id}\nClient: ${draft.entra_client_id}\nSource filter: ${draft.scim_filter || '(all users)'}` : ''}`);
    }
    if (Object.values(secrets).some(secret => secret.mode === 'clear')) warnings.push('Selected saved credentials will be removed.');
    if (draft.ignore_unsupported_fields && !saved.ignore_unsupported_fields) {
      warnings.push('Inbound SCIM requests will drop unsupported or unmapped fields instead of being rejected. Ignored account status, password, and group changes are not applied: active:false will not disable the LDAP account.');
    }
    if (plainLdap && !draft.ldap_start_tls && draft.ldap_allow_insecure && !(saved.ldap_allow_insecure && !saved.ldap_start_tls)) {
      warnings.push('Unencrypted LDAP sends the bind password and directory data in clear text.');
    }
    if (warnings.length && !window.confirm(`${warnings.join('\n\n')}\n\nSave these settings?`)) return;
    void action('save', async () => {
      await api('/api/settings', { method: 'PUT', body: JSON.stringify({
        ...settingsPayload(draft, secrets), ...(scopeChanged ? { confirm_scope_reset: true } : {}),
      }) });
      // The saved response is authoritative, including whether credentials are configured.
      let latest: Settings;
      try { latest = normalizeSettings(await api<Settings>('/api/settings')); }
      catch (error) { throw new Error(`Configuration was saved, but could not be reloaded: ${message(error)}. Sign out and reconnect to reload saved settings.`); }
      setSaved(latest); setDraft(latest); setSecrets(emptySecrets()); setDiscovery({}); setShowMappingPreview(false);
      return 'Configuration saved. Your next run will use these settings.';
    });
  }

  function test(connector: 'scim' | 'ldap') {
    void action(`test-${connector}`, async () => {
      const result = await api<{ users: number }>(`/api/test/${connector}`, { method: 'POST' });
      return `${connector.toUpperCase()} connection verified. Read ${result.users} users using saved settings.`;
    });
  }

  function discover(connector: 'scim' | 'ldap') {
    void action(`discover-${connector}`, async () => {
      const result = await api<AttributeDiscovery>(`/api/discovery/${connector}`, { method: 'POST' });
      setDiscovery(previous => ({ ...previous, [connector]: result }));
      return `Discovered ${result.attributes.length} ${connector.toUpperCase()} attributes from ${result.users} users.`;
    });
  }

  function validateMappings() {
    void action('validate-mappings', async () => {
      const result = await api<MappingValidation>('/api/mappings/validate', {
        method: 'POST', body: JSON.stringify({ attribute_mappings: draft.attribute_mappings }),
      });
      if (!result.valid) {
        throw new Error(result.errors.map(item => `${item.scim_path ?? item.ldap_attribute}: ${item.message}`).join('; '));
      }
      return `All mappings validated against ${result.scim_attributes} SCIM paths and ${result.ldap_attributes} LDAP attributes.`;
    });
  }

  function sync() {
    if (!status.dry_run && !window.confirm('Start a live synchronization? This can write changes to your configured directories.')) return;
    void action('sync', async () => {
      const result = await api<{ run_id: number }>('/api/sync', { method: 'POST' });
      return `Run #${result.run_id} started${status.dry_run ? ' in dry-run mode' : ' in live mode'}. Follow its progress in Activity.`;
    });
  }

  const saveBar = <div className="save-bar"><span>{dirty ? 'You have unsaved changes' : 'All changes saved'}<small>Connection tests and syncs always use saved settings.</small></span>
    <div className="button-row"><button type="button" disabled={!dirty || Boolean(busy)} onClick={() => { setDraft(saved); setSecrets(emptySecrets()); }}>Discard</button>
      <button className="primary" type="submit" disabled={!dirty || Boolean(busy) || status.running}><Save size={16} />{busy === 'save' ? 'Saving...' : 'Save configuration'}</button></div></div>;

  return <div className="app-shell"><aside className="sidebar">
    <div className="brand"><span className="brand-icon"><ArrowDownUp /></span><span>bridge<span className="brand-period">.</span></span></div>
    <span className="nav-label">WORKSPACE</span><nav aria-label="Main navigation">{navigation.map(item =>
      <button key={item.name} className={page === item.name ? 'active' : ''} aria-current={page === item.name ? 'page' : undefined}
        onClick={() => setPage(item.name)}><item.icon size={19} />{item.name}{page === item.name && <span className="nav-indicator" />}</button>,
    )}</nav>
    <div className="sidebar-bottom"><div className="sidebar-note"><ShieldCheck size={19} /><strong>{status.dry_run ? 'Safety first' : 'Live environment'}</strong>
      <p>{status.dry_run ? 'Dry-run mode is on. Preview changes before going live.' : 'Live writes are enabled. Changes can reach your directories.'}</p></div>
      <button className="logout" onClick={() => { if (!dirty || window.confirm('Discard unsaved configuration and sign out?')) onLogout(); }}><LogOut size={17} />Sign out</button>
      <small>SCIM LDAP Bridge</small></div>
  </aside><div className="workspace"><header className="topbar"><span><span className="workspace-mark">B</span> Bridge environment <span className="slash">/</span> <strong>{page}</strong></span>
    <div className="topbar-right"><span className={`status-dot ${pollError ? 'offline' : ''}`} />{pollError ? 'Connection interrupted' : 'Console connected'}<span className="avatar">A</span></div></header>
    <main className="main"><div className="page-heading"><div><div className="eyebrow">ENVIRONMENT MANAGEMENT</div><h1>{page}</h1><p>{currentPage.description}</p></div>
      <div className="button-row"><button aria-label="Refresh status" disabled={Boolean(busy)} onClick={() => { void action('refresh', async () => {
        try { await refresh(); }
        catch (error) { setPollError(`Status refresh failed: ${message(error)}`); throw error; }
        return 'Status refreshed.';
      }, false); }}><RefreshCw size={16} className={busy === 'refresh' ? 'spin' : ''} /></button>
        <button className="primary" disabled={Boolean(busy) || status.running || !connected || dirty || Boolean(pollError)} onClick={sync}><Play size={16} />{status.running ? 'Sync in progress' : 'Run sync'}</button></div></div>
    {notice && <Notice kind={notice.kind} dismiss={() => setNotice(null)}>{notice.text}</Notice>}
    {pollError && <Notice>{pollError} Displayed data may be stale. Retrying automatically.</Notice>}
    {dirty && !settingsPages.includes(page) && <Notice kind="warning">You have unsaved configuration changes. Save or discard them in Connections, Attribute mapping, or Synchronization before running a sync.</Notice>}
    {page === 'Overview' && <>
      <div className={`environment-banner ${status.dry_run ? '' : 'live'}`}><div className="banner-icon"><ShieldCheck size={24} /></div>
        <div><strong>{status.dry_run ? 'A safe place to get in sync.' : 'Your bridge is in live mode.'}</strong><p>{status.dry_run ? 'Dry-run mode is enabled. Runs preview changes without writing to your directories.' : 'Synchronization and inbound provisioning can write to your directory systems.'}</p></div>
        <button onClick={() => setPage('Synchronization')}>Review policy <ArrowRight size={16} /></button></div>
      <div className="metrics">
        <Metric label="SCIM USERS" value={status.database.inventory.filter(row => row.source === 'scim' && row.resource_type === 'Users').reduce((sum, row) => sum + row.count, 0)} icon={<Network />} note="Present in last inventory" />
        <Metric label="LDAP USERS" value={status.database.inventory.filter(row => row.source === 'ldap' && row.resource_type === 'Users').reduce((sum, row) => sum + row.count, 0)} icon={<Database />}
          note={status.database.pending_users?.pending ? `${status.database.pending_users.pending} waiting to be synchronised to LDAP` : 'Present in last inventory'} />
        <Metric label="LINKED IDENTITIES" value={status.linked_users} icon={<ArrowDownUp />} note="Matching identity baselines" />
        <Metric label="SYNC STATUS" value={status.running ? 'Running' : 'Idle'} icon={<Activity />} note={status.enabled ? `Next: ${date(status.next_run)}` : 'Automatic schedule paused'} />
      </div>
      <div className="two-columns"><Panel title="Your connections" subtitle="The two sides of your identity bridge" action={<button className="text-button" onClick={() => setPage('Connections')}>Configure <ArrowRight size={15} /></button>}>
        <ConnectionSummary name="SCIM provider" endpoint={saved.scim_url} ready={scimReady} icon={<Network />} />
        <div className="connection-link"><span /><ArrowDownUp size={16} /><span /></div>
        <ConnectionSummary name="LDAP directory" endpoint={saved.ldap_url} ready={Boolean(saved.ldap_url && saved.ldap_base_dn && saved.ldap_bind_dn && saved.ldap_password_configured)} icon={<Database />} />
        <p className="panel-footnote">Configured does not mean verified. Test each saved connection before syncing.</p>
      </Panel><Panel title="Synchronization policy" subtitle="The rules behind your next run">
        <dl className="details"><dt>Direction</dt><dd>{direction[saved.direction]}</dd><dt>Conflict resolution</dt><dd>{saved.conflict_policy === 'manual' ? 'Manual review' : saved.conflict_policy === 'scim_wins' ? 'SCIM wins' : 'LDAP wins'}</dd>
          <dt>Execution mode</dt><dd><Badge tone={status.dry_run ? 'blue' : 'amber'}>{status.dry_run ? 'Dry run' : 'Live writes'}</Badge></dd>
          <dt>Schedule</dt><dd>{status.enabled ? `Every ${saved.interval_seconds} seconds` : 'Paused'}</dd>
          <dt>Inbound SCIM</dt><dd>{status.inbound_enabled ? 'Enabled' : 'Disabled'}</dd></dl>
        <button className="text-button panel-link" onClick={() => setPage('Synchronization')}>Manage synchronization <ArrowRight size={15} /></button>
      </Panel></div>
      <Panel title="Recent synchronization runs" subtitle="A record of what changed, and what didn't" action={<button className="text-button" onClick={() => setPage('Activity')}>View activity <ArrowRight size={15} /></button>}><Runs runs={status.runs.slice(0, 5)} /></Panel>
      <Panel title="Latest events"><Events events={status.events.slice(0, 5)} /></Panel>
    </>}
    {settingsPages.includes(page) && <form onSubmit={save}>
      <fieldset disabled={Boolean(busy) || status.running} className="settings-fields">
      {page === 'Connections' ? <>
        <Notice kind="info">Credentials are encrypted at rest. Leave a credential unchanged to keep its saved value. Changing an endpoint or LDAP identity resets inventory and baselines.</Notice>
        <Panel title="SCIM push — inbound provisioning" subtitle="Entra or another identity provider pushes users into this bridge. No Entra app registration is needed for this connection.">
          <dl className="details"><dt>Status</dt><dd><Badge tone={status.inbound_enabled ? 'green' : 'amber'}>{status.inbound_enabled ? 'Enabled' : 'Disabled'}</Badge></dd>
            <dt>Tenant URL</dt><dd><code>{window.location.origin}/scim/v2</code></dd>
            <dt>Secret token</dt><dd>BRIDGE_SCIM_TOKEN (set on the server; never displayed here)</dd></dl>
          <p className="body-copy">Use the externally reachable HTTPS URL, including any reverse-proxy prefix. In Entra, configure Enterprise applications → Provisioning → Automatic with this tenant URL and the inbound secret token. The administrator token and outbound connector credentials are not interchangeable.</p>
          <p className="panel-footnote">Push uses the saved LDAP connection and the mappings on the Attribute mapping page, independently of the outbound provider and schedule. Pushed users are stored in the bridge database until they are created in LDAP; they appear in Inventory as waiting to be synchronised to LDAP while dry run is on, LDAP is unavailable, or another operation is running, and are retried automatically. Configure BRIDGE_SCIM_TOKEN and disable dry run only when ready.</p>
        </Panel>
        <Panel title="Outbound source" subtitle="Optional remote connector for scheduled or manual reconciliation; not needed for inbound SCIM push.">
          <Field label="Provider and authentication"><select value={draft.scim_provider} onChange={event => {
            if (event.target.value === 'generic' || event.target.value === 'entra') selectProvider(event.target.value);
          }}><option value="generic">Generic SCIM — static bearer token</option><option value="entra">Microsoft Entra pull — OAuth client secret</option></select></Field>
        </Panel>
        <div className="two-columns connection-forms">
          <Panel title={entra ? 'Microsoft Entra ID — OAuth pull' : 'Generic SCIM — outbound connector'} subtitle={entra ? 'App registration credentials for reading Entra; not SCIM push credentials.' : 'Your remote SCIM 2.0 API; not this bridge’s inbound endpoint.'} action={<span className="section-icon"><Network size={20} /></span>}>
            {entra && <Notice kind="warning">Opt-in Entra pull reads users into LDAP only. Switching providers pauses the schedule and enables dry run. Verify your tenant, application, and source scope before saving. Direct group membership filtering is supported, but group provisioning, deletion, and deactivation are not. Grant application permissions User.Read.All and Group.Read.All with administrator consent.</Notice>}
            <Field label="SCIM endpoint URL" hint={entra ? 'Official Microsoft Graph SCIM endpoint. This URL cannot be changed in Entra mode.' : 'Include the base API path, for example https://identity.example.org/scim/v2. Use HTTPS outside isolated development.'}><input type="url" required={entra} readOnly={entra} placeholder="https://identity.example.org/scim/v2" value={draft.scim_url} onChange={event => update('scim_url', event.target.value)} /></Field>
            {entra ? <>
              <Field label="Entra tenant ID" hint="Directory (tenant) ID, in GUID format."><input required pattern={guidPattern} value={draft.entra_tenant_id} onChange={event => update('entra_tenant_id', event.target.value)} /></Field>
              <Field label="Entra client ID" hint="Application (client) ID, in GUID format."><input required pattern={guidPattern} value={draft.entra_client_id} onChange={event => update('entra_client_id', event.target.value)} /></Field>
              <SecretField label="Entra client secret" configured={saved.entra_client_secret_configured} edit={secrets.entra_client_secret} onChange={edit => setSecrets(previous => ({ ...previous, entra_client_secret: edit }))} />
              <Field label="Entra source filter" hint={'Optional single predicate: userName, id, externalId, or groups.value eq a JSON-quoted string; active eq true/false; or userName ew a JSON-quoted suffix. Examples: active eq true or userName ew "@example.org". groups.value eq "group-id" selects direct members only, not transitive membership. No compound/not filters, group provisioning, deletion, or deactivation.'}><input maxLength={2048} value={draft.scim_filter} onChange={event => update('scim_filter', event.target.value)} /></Field>
            </> : <SecretField label="SCIM bearer token" configured={saved.scim_token_configured} edit={secrets.scim_token} onChange={edit => setSecrets(previous => ({ ...previous, scim_token: edit }))} />}
            <div className="test-row"><button type="button" disabled={dirty || !scimReady} onClick={() => test('scim')}><Network size={16} />{busy === 'test-scim' ? 'Testing...' : 'Test SCIM connection'}</button></div>
          </Panel>
          <Panel title="LDAP directory" subtitle="A certificate-verified directory connection" action={<span className="section-icon"><Database size={20} /></span>}>
            <Field label="LDAP service" hint="Selecting a different service replaces custom attribute mappings with matching defaults and resets to dry run.">
              <select value={draft.ldap_service} onChange={event => {
                const service = event.target.value as Settings['ldap_service'];
                if (service in ldapServices) selectLdapService(service);
              }}>{Object.entries(ldapServices).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>
            </Field>
            {activeDirectory && <>
              <Notice kind="warning">Uses AD user objects, sAMAccountName by default, and cn-based distinguished names. New accounts are disabled by default (userAccountControl=514). This is AD DS, not Entra ID.</Notice>
              <label className="check-row"><input type="checkbox" aria-label="Enable new AD accounts" checked={draft.ad_enable_new_accounts} onChange={event => update('ad_enable_new_accounts', event.target.checked)} /><span><strong>Enable new AD accounts</strong><small>Opt in to generating a strong random password, setting it over verified LDAPS or StartTLS, then enabling each new account. Passwords are never saved or displayed. Existing accounts are unchanged. Requires delegated password-reset and account-control permissions.</small></span></label>
              {draft.ad_enable_new_accounts && <Notice kind="warning">Users need a separate password-reset process to sign in. A failed password initialization leaves the account disabled; failed activation requires administrator review. Retries do not activate already-created accounts.</Notice>}
            </>}
            <Field label="LDAP endpoint URL" hint="Use ldaps:// (port 636, implicit TLS) or ldap:// (port 389) with StartTLS. The server must trust the directory certificate."><input type="url" placeholder="ldaps://directory.example.org:636" value={draft.ldap_url} onChange={event => update('ldap_url', event.target.value)} /></Field>
            <Field label="Bind distinguished name"><input placeholder="cn=bridge,ou=services,dc=example,dc=org" value={draft.ldap_bind_dn} onChange={event => update('ldap_bind_dn', event.target.value)} /></Field>
            <SecretField label="LDAP bind password" configured={saved.ldap_password_configured} edit={secrets.ldap_password} onChange={edit => setSecrets(previous => ({ ...previous, ldap_password: edit }))} />
            <Field label="Base distinguished name"><input placeholder="ou=people,dc=example,dc=org" value={draft.ldap_base_dn} onChange={event => update('ldap_base_dn', event.target.value)} /></Field>
            <label className="check-row"><input type="checkbox" aria-label="StartTLS" disabled={plainLdap === false} checked={draft.ldap_start_tls} onChange={event => update('ldap_start_tls', event.target.checked)} /><span><strong>StartTLS</strong><small>Upgrades an ldap:// (port 389) connection to TLS before binding. Not used with ldaps://, which is already encrypted.</small></span></label>
            {plainLdap && !draft.ldap_start_tls && <label className="check-row"><input type="checkbox" aria-label="Allow unencrypted LDAP" checked={draft.ldap_allow_insecure} onChange={event => update('ldap_allow_insecure', event.target.checked)} /><span><strong>Allow unencrypted LDAP (insecure)</strong><small>Sends the bind password and directory data in clear text. Use only on a trusted, isolated network.</small></span></label>}
            {plainLdap && !draft.ldap_start_tls && draft.ldap_allow_insecure && <Notice kind="warning">Unencrypted LDAP is enabled. Credentials and user data can be intercepted on the network.</Notice>}
            <div className="test-row"><button type="button" disabled={dirty || !saved.ldap_url || !saved.ldap_bind_dn || !saved.ldap_base_dn || !saved.ldap_password_configured} onClick={() => test('ldap')}><Database size={16} />{busy === 'test-ldap' ? 'Testing...' : 'Test LDAP connection'}</button></div>
          </Panel>
        </div>
        <Panel title="Password synchronization" subtitle="Not supported — attribute provisioning does not synchronize credentials.">
          <p className="body-copy">The AD-only “Enable new AD accounts” option initializes a fresh, undisclosed random password for new accounts. It does not synchronize a source password or change existing accounts.</p>
          <Notice kind="info">SCIM passwords are write-only and cannot be read back for reconciliation. Entra OAuth pull cannot retrieve existing user passwords, and Entra application provisioning is not a password-sync channel. There is no safe password-sync switch for these connectors.</Notice>
          <p className="body-copy">For AD DS → Entra password hash synchronization, use Microsoft Entra Connect Sync or Cloud Sync where supported. That is not Entra → LDAP password export. For LDAP users, use the directory’s native password reset or a dedicated, separately secured password-change integration. The LDAP bind password above authenticates the bridge service account only.</p>
          <p className="panel-footnote">Password mappings remain blocked. Inbound password fields are rejected by default, or dropped when “Ignore unsupported or unmapped fields” is enabled; dropping a field never changes a password.</p>
        </Panel>
      </> : page === 'Attribute mapping' ? <>
        <Panel title="SCIM to LDAP attribute mappings" subtitle="Map SCIM paths to LDAP attributes. Discovery uses saved, read-only connections." action={<button type="button" className="text-button" onClick={() => setPage('Connections')}>LDAP service <ArrowRight size={15} /></button>}>
          <h3>Required attributes — {ldapServices[draft.ldap_service]}</h3>
          <dl className="details"><dt>{usernameAttribute || 'User identifier'}</dt><dd><Badge tone="amber">Required identity</Badge> Mapped from userName in both directions; must be unique.</dd>
            <dt>cn</dt><dd><Badge tone="amber">Required by schema</Badge> {activeDirectory ? 'Generated from userName for new account DNs.' : 'Generated from displayName, falling back to userName, unless explicitly mapped.'}</dd>
            <dt>sn</dt><dd><Badge tone="amber">{activeDirectory ? 'Required by bridge' : 'Required by schema'}</Badge> Supplied by name.familyName; never fabricated.</dd></dl>
          {!draft.attribute_mappings.some(mapping => mapping.scim_path === 'name.familyName') &&
            <Notice kind="warning">Add a name.familyName mapping: the bridge requires a surname to create or update users.</Notice>}
          <p className="panel-footnote">Defaults target {activeDirectory ? 'AD DS user' : 'inetOrgPerson'} objects. Custom object classes, POSIX accounts, or local schema extensions may require additional attributes. Discovery samples are not a complete schema validation.</p>
          <p className="body-copy">The userName mapping identifies accounts. Passwords and other sensitive attributes are excluded from discovery. Validation uses saved connector settings.</p>
          <div className="button-row mapping-discovery">
            <button type="button" disabled={dirty || !scimReady || Boolean(busy)}
              onClick={() => discover('scim')}>{busy === 'discover-scim' ? 'Discovering SCIM...' : 'Discover SCIM attributes'}</button>
            <button type="button" disabled={dirty || !saved.ldap_url || !saved.ldap_base_dn || !saved.ldap_bind_dn || !saved.ldap_password_configured || Boolean(busy)}
              onClick={() => discover('ldap')}>{busy === 'discover-ldap' ? 'Discovering LDAP...' : 'Discover LDAP attributes'}</button>
          </div>
          {draft.attribute_mappings.map((mapping, index) => <div className="mapping-row" key={`${index}-${mapping.scim_path}`}>
            <Field label={`SCIM path ${index + 1}`} hint="Use dotted paths for nested scalar attributes, such as name.givenName.">
              <input required list="scim-attribute-options" value={mapping.scim_path} onChange={event => update('attribute_mappings', draft.attribute_mappings.map((item, row) => row === index ? { ...item, scim_path: event.target.value } : item))} />
            </Field>
            <Field label={`LDAP attribute ${index + 1}`} hint={mapping.scim_path === 'userName' ? 'Required account identity.' : mapping.ldap_attribute.toLowerCase() === 'sn' ? 'Required surname (name.familyName).' : mapping.ldap_attribute.toLowerCase() === 'cn' ? 'Required common name; generated if not mapped.' : undefined}>
              <input required list="ldap-attribute-options" value={mapping.ldap_attribute} onChange={event => update('attribute_mappings', draft.attribute_mappings.map((item, row) => row === index ? { ...item, ldap_attribute: event.target.value } : item))} />
            </Field>
            <Field label={`Direction ${index + 1}`}>
              <select value={mapping.direction} onChange={event => {
                const value = event.target.value;
                if (value === 'both' || value === 'scim_to_ldap' || value === 'ldap_to_scim') {
                  update('attribute_mappings', draft.attribute_mappings.map((item, row) => row === index ? { ...item, direction: value } : item));
                }
              }}><option value="both">Both directions</option><option value="scim_to_ldap">SCIM to LDAP</option><option value="ldap_to_scim">LDAP to SCIM</option></select>
            </Field>
            <button type="button" aria-label={`Remove mapping ${index + 1}`} disabled={draft.attribute_mappings.length === 1}
              onClick={() => update('attribute_mappings', draft.attribute_mappings.filter((_, row) => row !== index))}>Remove</button>
          </div>)}
          <datalist id="scim-attribute-options">{(discovery.scim?.attributes ?? []).map(attribute => <option key={attribute.name} value={attribute.name} />)}</datalist>
          <datalist id="ldap-attribute-options">{(discovery.ldap?.attributes ?? []).map(attribute => <option key={attribute.name} value={attribute.name} />)}</datalist>
          <div className="button-row mapping-discovery"><button type="button" onClick={() => update('attribute_mappings', [...draft.attribute_mappings, { scim_path: '', ldap_attribute: '', direction: 'both' }])}>Add mapping</button></div>
          <label className="check-row"><input type="checkbox" aria-label="Ignore unsupported or unmapped fields" aria-describedby="ignore-unsupported-fields-hint" checked={draft.ignore_unsupported_fields} onChange={event => update('ignore_unsupported_fields', event.target.checked)} /><span><strong>Ignore unsupported or unmapped fields</strong><small id="ignore-unsupported-fields-hint">Applies to inbound SCIM user create, replace, and patch requests. When off (default), requests containing account status, password, or group fields are rejected. When on, fields that cannot be provisioned through the SCIM to LDAP mappings above, including account status (active), password, and group fields, are dropped instead. This does not add account enable/disable, password, or group support: an ignored active:false does not disable the LDAP account. userName and name.familyName are still required.</small></span></label>
          <div className="button-row mapping-discovery"><button type="button" disabled={!connected || Boolean(busy)}
            onClick={validateMappings}>{busy === 'validate-mappings' ? 'Validating...' : 'Validate mappings'}</button></div>
          <div className="button-row mapping-discovery"><button type="button" disabled={!discovery.scim || !discovery.ldap}
            onClick={() => setShowMappingPreview(value => !value)}>{showMappingPreview ? 'Hide mapping preview' : 'Preview mapping'}</button></div>
          {showMappingPreview && <div className="table-scroll"><table><thead><tr><th>SCIM path</th><th>SCIM sample</th><th>LDAP attribute</th><th>LDAP sample</th><th>Direction</th><th>Projected value</th></tr></thead>
            <tbody>{draft.attribute_mappings.map((mapping, index) => {
              const scimSample = discovery.scim?.attributes.find(attribute => attribute.name === mapping.scim_path)?.samples[0] ?? 'No sample';
              const ldapSample = discovery.ldap?.attributes.find(attribute => attribute.name.toLowerCase() === mapping.ldap_attribute.toLowerCase())?.samples[0] ?? 'No sample';
              const projected = mapping.direction === 'ldap_to_scim' ? `LDAP → SCIM: ${ldapSample}`
                : mapping.direction === 'scim_to_ldap' ? `SCIM → LDAP: ${scimSample}`
                  : `SCIM → LDAP: ${scimSample}; LDAP → SCIM: ${ldapSample}`;
              return <tr key={`${mapping.scim_path}-${index}`}><td><code>{mapping.scim_path}</code></td><td>{scimSample}</td>
                <td><code>{mapping.ldap_attribute}</code></td><td>{ldapSample}</td><td>{mapping.direction.replaceAll('_', ' ')}</td><td>{projected}</td></tr>;
            })}</tbody></table></div>}
          {(discovery.scim || discovery.ldap) && <div className="mapping-discovery-results">
            {(['scim', 'ldap'] as const).map(source => discovery[source] && <div key={source}>
              <strong>{source.toUpperCase()} discovered attributes</strong>
              <ul>{discovery[source]!.attributes.map(attribute => <li key={attribute.name}><code>{attribute.name}</code>
                <small>{attribute.type ?? 'type unavailable'} / {attribute.multi_valued === undefined || attribute.multi_valued === null ? 'multiplicity unavailable' : attribute.multi_valued ? 'multi-valued' : 'single-valued'}</small>
                {attribute.samples.length > 0 && <small>Sample: {attribute.samples.join(', ')}</small>}</li>)}</ul>
            </div>)}
          </div>}
        </Panel>
      </> : <>
        <div className="two-columns"><Panel title="Reconciliation policy" subtitle="Choose the source of truth for your identities">
          <Field label="Synchronization direction"><select value={draft.direction} onChange={event => {
            const value = event.target.value;
            if (value === 'scim_to_ldap' || (!entra && (value === 'bidirectional' || value === 'ldap_to_scim'))) update('direction', value);
          }}><option value="bidirectional" disabled={entra}>Bidirectional</option><option value="scim_to_ldap">SCIM to LDAP</option><option value="ldap_to_scim" disabled={entra}>LDAP to SCIM</option></select></Field>
          <Field label="Conflict policy" hint="Manual review records conflicts without overwriting either side. Renames and missing linked users require manual intervention."><select value={draft.conflict_policy} onChange={event => {
            const value = event.target.value;
            if (value === 'manual' || value === 'scim_wins' || value === 'ldap_wins') update('conflict_policy', value);
          }}><option value="manual">Manual review (recommended)</option><option value="scim_wins">SCIM wins</option><option value="ldap_wins">LDAP wins</option></select></Field>
          <label className="check-row"><input type="checkbox" aria-label="Dry-run mode" checked={draft.dry_run} onChange={event => update('dry_run', event.target.checked)} /><span><strong>Dry-run mode</strong><small>Preview planned changes. Blocks outbound and inbound directory writes; pushed SCIM users are stored and wait to be synchronised to LDAP.</small></span></label>
          {!draft.dry_run && <Notice kind="warning">Live mode permits writes to your directories. Review a dry run before turning this on.</Notice>}
        </Panel><Panel title="Automatic schedule" subtitle="Keep identities in sync without manual runs">
          <label className="check-row"><input type="checkbox" aria-label="Enable scheduled synchronization" checked={draft.enabled} onChange={event => update('enabled', event.target.checked)} /><span><strong>Enable scheduled synchronization</strong><small>Both connectors must be fully configured before enabling.</small></span></label>
          <Field label="Interval (seconds)" hint="Between 30 and 86,400 seconds. The interval restarts when settings are saved."><input type="number" required min={30} max={86400} step={1} value={Number.isNaN(draft.interval_seconds) ? '' : draft.interval_seconds} onChange={event => update('interval_seconds', event.target.valueAsNumber)} /></Field>
          <dl className="details"><dt>Current schedule</dt><dd>{status.enabled ? 'Enabled' : 'Paused'}</dd><dt>Next run</dt><dd>{date(status.next_run)}</dd></dl>
        </Panel></div>
        <Panel title="Supported mapping" subtitle="What this bridge synchronizes today"><p className="body-copy">Users are matched by username. Default mappings cover username, given name, family name, display name, and primary email using the selected LDAP service profile ({ldapServices[draft.ldap_service]}).</p><p className="body-copy">Groups, deletion, passwords, lifecycle provisioning, and arbitrary custom schema synchronization are not implemented. Conflicts are recorded for review, not editable here. The inventory is a cache, not the authoritative directory.</p></Panel>
      </>}
      {saveBar}</fieldset>
    </form>}
    {page === 'Inventory' && <Inventory api={api} report={text => setNotice({ text, kind: 'error' })}
      notify={text => setNotice({ text, kind: 'success' })} />}
    {page === 'Activity' && <>
      <Panel title="Synchronization runs" subtitle="Most recent 30 runs. Operation history is retained for the latest 200."><Runs runs={status.runs} /></Panel>
      <Operations api={api} />
      <Panel title="Event log" subtitle="Most recent 100 events. The service retains up to 2,000."><Events events={status.events} /></Panel>
    </>}
    {page === 'System' && <System status={status} />}
    <footer className="main-footer"><span><ShieldCheck size={14} /> Encrypted configuration & inventory</span><span>Last status update {updated.toLocaleTimeString()} / refreshes every 5s</span></footer>
    </main></div></div>;
}

type DataProps = { api: <T>(path: string, init?: RequestInit) => Promise<T>; report: (text: string) => void };

function Pager({ offset, count, busy, setOffset }: { offset: number; count: number; busy: boolean; setOffset: (offset: number) => void }) {
  return <div className="pager"><small>{count ? `${offset + 1}-${offset + count}` : 'No records'} / 25 per page</small><div className="button-row">
    <button aria-label="Previous page" disabled={busy || offset === 0} onClick={() => setOffset(Math.max(0, offset - 25))}><ChevronLeft size={16} />Previous</button>
    <button aria-label="Next page" disabled={busy || count < 25} onClick={() => setOffset(offset + 25)}>Next<ChevronRight size={16} /></button>
  </div></div>;
}

const resourceStates: Record<NonNullable<Resource['status']>, { label: string; tone: string }> = {
  present: { label: 'Present', tone: 'green' },
  absent: { label: 'Absent', tone: 'amber' },
  waiting_for_ldap: { label: 'Waiting to be synchronised to LDAP', tone: 'blue' },
  conflict: { label: 'Conflict: exists in LDAP', tone: 'red' },
};
const sourceLabels: Record<Resource['source'], string> = { scim: 'SCIM', ldap: 'LDAP', inbound: 'SCIM push' };

function Inventory({ api, report, notify }: DataProps & { notify: (text: string) => void }) {
  const [source, setSource] = useState('');
  const [resourceType, setResourceType] = useState('Users');
  const [filter, setFilter] = useState({ source: '', resourceType: 'Users' });
  const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<Resource[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  const [detail, setDetail] = useState<{ resource: Resource; data: unknown } | null>(null);
  const [inspecting, setInspecting] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const inspection = useRef(0);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(''); setRows([]); setInspecting(false);
    const query = new URLSearchParams({ resource_type: filter.resourceType, limit: '25', offset: String(offset) });
    if (filter.source) query.set('source', filter.source);
    api<{ resources: Resource[] }>(`/api/data/resources?${query}`, { signal: controller.signal })
      .then(result => { if (!controller.signal.aborted) setRows(result.resources); })
      .catch(error => { if (!controller.signal.aborted) setError(message(error)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => { controller.abort(); inspection.current += 1; };
  }, [api, filter, offset, revision]);

  useEffect(() => { if (detail) dialog.current?.showModal(); }, [detail]);

  async function discard(resource: Resource) {
    if (!window.confirm(`Discard ${resource.resource_key}? It will not be created in LDAP.`)) return;
    setInspecting(true);
    try {
      await api(`/api/data/pending?${new URLSearchParams({ key: resource.resource_key })}`, { method: 'DELETE' });
      notify(`${resource.resource_key} was discarded from the LDAP queue.`);
      setRevision(value => value + 1);
    } catch (error) { report(message(error)); }
    finally { setInspecting(false); }
  }

  async function inspect(resource: Resource) {
    const id = ++inspection.current;
    setInspecting(true);
    try {
      const query = new URLSearchParams({ source: resource.source, resource_type: resource.resource_type, key: resource.resource_key });
      const result = await api<{ data: unknown }>(`/api/data/resource?${query}`);
      if (id === inspection.current) setDetail({ resource, data: result.data });
    } catch (error) { if (id === inspection.current) report(message(error)); }
    finally { if (id === inspection.current) setInspecting(false); }
  }

  return <><Notice kind="info">Read-only inventory from the last complete connector read. Absent resources remain cached. Run synchronization to refresh it; editing cached data would not update your directories. Users pushed through inbound SCIM are listed as SCIM push while they wait to be synchronised to LDAP, and are retried automatically when dry run is off.</Notice>
    <Panel title="Resource inventory" subtitle="Select a record to inspect its decrypted attributes" action={<button aria-label="Refresh inventory" onClick={() => setRevision(value => value + 1)} disabled={loading}><RefreshCw size={16} /></button>}>
      <form className="filters" onSubmit={event => { event.preventDefault(); setOffset(0); setFilter({ source, resourceType }); }}>
        <Field label="Source"><select value={source} onChange={event => setSource(event.target.value)}><option value="">All sources</option><option value="scim">SCIM</option><option value="ldap">LDAP</option><option value="inbound">SCIM push (waiting for LDAP)</option></select></Field>
        <Field label="Resource type"><input required maxLength={100} value={resourceType} onChange={event => setResourceType(event.target.value)} /></Field>
        <button type="submit">Apply filters</button>
      </form>
      {error ? <Notice>{error} Use refresh to retry.</Notice> : loading ? <Loading /> : rows.length ?
        <div className="table-scroll"><table><thead><tr><th>Resource key</th><th>Source</th><th>Type</th><th>State</th><th>Last observed</th><th>Details</th></tr></thead>
          <tbody>{rows.map(row => {
            const status = row.status ?? (row.present ? 'present' : 'absent');
            const state = resourceStates[status] ?? { label: status.replaceAll('_', ' '), tone: '' };
            return <tr key={`${row.source}:${row.resource_type}:${row.resource_key}`}><td className="strong">{row.resource_key}</td><td><Badge>{sourceLabels[row.source] ?? row.source}</Badge></td><td>{row.resource_type}</td>
              <td><Badge tone={state.tone}>{state.label}</Badge>{row.error && <small className="state-detail">Last attempt failed ({row.error}){row.attempts ? ` / ${row.attempts} attempt${row.attempts === 1 ? '' : 's'}` : ''}</small>}</td><td>{date(row.observed_at)}</td>
              <td><div className="button-row"><button className="text-button" disabled={inspecting} onClick={() => { void inspect(row); }}>Inspect <ExternalLink size={14} /></button>
                {row.source === 'inbound' && <button className="text-button" disabled={inspecting} onClick={() => { void discard(row); }}>Discard</button>}</div></td></tr>;
          })}</tbody></table></div>
        : <Empty title="No resources found" text="Your inventory will appear after a successful sync. Check the filters if you expected records." />}
      <Pager offset={offset} count={rows.length} busy={loading || Boolean(error)} setOffset={setOffset} />
    </Panel>
    {detail && <dialog ref={dialog} onClose={() => setDetail(null)} aria-labelledby="resource-title"><div className="dialog-heading"><div><h2 id="resource-title">{detail.resource.resource_key}</h2><p>{sourceLabels[detail.resource.source] ?? detail.resource.source} / {detail.resource.resource_type}</p></div><button aria-label="Close resource details" onClick={() => dialog.current?.close()}><X size={18} /></button></div>
      <p className="body-copy">Decrypted, cached attributes. Password attributes are excluded from storage.</p><pre>{JSON.stringify(detail.data, null, 2)}</pre></dialog>}
  </>;
}

function Operations({ api }: Pick<DataProps, 'api'>) {
  const [offset, setOffset] = useState(0);
  const [rows, setRows] = useState<Operation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true); setError(''); setRows([]);
    api<{ operations: Operation[] }>(`/api/data/operations?limit=25&offset=${offset}`, { signal: controller.signal })
      .then(result => { if (!controller.signal.aborted) setRows(result.operations); })
      .catch(error => { if (!controller.signal.aborted) setError(message(error)); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [api, offset, revision]);
  return <Panel title="Operation history" subtitle="Previewed, applied, failed, and conflicting changes" action={<button aria-label="Refresh operations" disabled={loading} onClick={() => setRevision(value => value + 1)}><RefreshCw size={16} /></button>}>
    {error ? <Notice>{error} Use refresh to retry.</Notice> : loading ? <Loading /> : rows.length ? <div className="table-scroll"><table><thead><tr>
      <th>Run</th><th>Resource</th><th>Type</th><th>Target</th><th>Operation</th><th>Status</th><th>Updated</th><th>Error</th>
    </tr></thead><tbody>{rows.map(row => <tr key={row.id}><td>#{row.run_id}</td><td className="strong">{row.resource_key}</td><td>{row.resource_type}</td><td>{row.target?.toUpperCase() ?? 'Review'}</td>
      <td>{row.operation}</td><td><State value={row.status} /></td><td>{date(row.updated_at)}</td><td>{row.error ?? '-'}</td></tr>)}</tbody></table></div>
      : <Empty title="No operations recorded" text="Planned changes and conflicts appear here after a synchronization run." />}
    <Pager offset={offset} count={rows.length} busy={loading || Boolean(error)} setOffset={setOffset} />
  </Panel>;
}

function Metric({ label, value, icon, note }: { label: string; value: ReactNode; icon: ReactNode; note: string }) {
  return <section className="metric"><div><span>{label}</span><span className="metric-icon">{icon}</span></div><strong>{value}</strong><small>{note}</small></section>;
}

function ConnectionSummary({ name, endpoint, ready, icon }: { name: string; endpoint: string; ready: boolean; icon: ReactNode }) {
  return <div className="connection-summary"><div className="section-icon">{icon}</div><div><h3>{name}</h3><p>{endpoint || 'No endpoint configured'}</p></div><Badge tone={ready ? 'green' : ''}>{ready ? <><Check size={12} />Configured</> : 'Not configured'}</Badge></div>;
}

function Loading() { return <div className="empty" role="status"><LoaderCircle className="spin" size={24} /><p>Loading records...</p></div>; }

function System({ status }: { status: Status }) {
  return <><div className="two-columns"><Panel title="Environment" subtitle="The service behind this console"><dl className="details">
    <dt>Console origin</dt><dd className="break">{window.location.origin}</dd><dt>Storage engine</dt><dd>{status.database.engine.toUpperCase()}</dd>
    <dt>Health endpoint</dt><dd><code>/healthz</code></dd><dt>Inbound SCIM base path</dt><dd><code>/scim/v2</code></dd>
    <dt>Inbound provisioning</dt><dd><Badge tone={status.inbound_enabled ? 'green' : ''}>{status.inbound_enabled ? 'Enabled' : 'Disabled'}</Badge></dd>
    <dt>Stored operations</dt><dd>{Object.entries(status.database.operations).map(([name, count]) => `${name}: ${count}`).join(', ') || 'None'}</dd>
  </dl></Panel><Panel title="Access & credentials" subtitle="Server-managed by design"><p className="body-copy">The administrator token authenticates this console. A distinct provisioning token enables inbound SCIM and cannot access management data.</p>
    <p className="body-copy">Set <code>BRIDGE_ADMIN_TOKEN</code> and optional <code>BRIDGE_SCIM_TOKEN</code> in the server environment, then restart to rotate them. Both must be at least 24 characters. Use randomly generated secrets, and HTTPS for remote access.</p>
    <p className="body-copy">Tokens, filesystem paths, TLS certificates, and container settings are managed on the host, not through this console.</p></Panel></div>
    <Panel title="Persistence & backups" subtitle="Protect the database and its encryption key"><div className="info-grid">
      <div><Database size={23} /><h3>One persistent data directory</h3><p>SQLite and the encryption key live in BRIDGE_DATA_DIR (locally ./data). Docker uses the bridge-data named volume at /data. Run one instance and one worker per volume.</p></div>
      <div><ShieldCheck size={23} /><h3>Back up the key with the data</h3><p>Stop the service and back up the entire data directory. Losing encryption.key makes encrypted records unrecoverable. Restrict volume and backup access.</p></div>
      <div><CircleHelp size={23} /><h3>Keep your volume</h3><p>Container replacement and normal restarts retain the database. Do not run docker compose down -v unless you intend to erase configuration, inventory, and keys.</p></div>
    </div></Panel></>;
}
