export interface Settings {
  scim_provider: 'generic' | 'entra';
  scim_url: string;
  entra_tenant_id: string;
  entra_client_id: string;
  scim_filter: string;
  entra_client_secret_configured: boolean;
  ldap_url: string;
  ldap_service: 'generic' | 'openldap' | '389ds' | 'active_directory';
  ad_enable_new_accounts: boolean;
  ldap_bind_dn: string;
  ldap_base_dn: string;
  attribute_mappings: AttributeMapping[];
  ldap_start_tls: boolean;
  ldap_allow_insecure: boolean;
  direction: 'bidirectional' | 'scim_to_ldap' | 'ldap_to_scim';
  conflict_policy: 'manual' | 'scim_wins' | 'ldap_wins';
  interval_seconds: number;
  enabled: boolean;
  dry_run: boolean;
  ignore_unsupported_fields: boolean;
  scim_token_configured: boolean;
  ldap_password_configured: boolean;
}

export interface AttributeMapping {
  scim_path: string;
  ldap_attribute: string;
  direction: 'both' | 'scim_to_ldap' | 'ldap_to_scim';
}

export const ldapServices = {
  generic: 'Generic LDAP (inetOrgPerson)',
  openldap: 'OpenLDAP',
  '389ds': '389 Directory Server / Red Hat Directory Server',
  active_directory: 'Microsoft Active Directory Domain Services',
};

export function ldapDefaultMappings(service: Settings['ldap_service']): AttributeMapping[] {
  return [
    { scim_path: 'userName', ldap_attribute: service === 'active_directory' ? 'sAMAccountName' : 'uid', direction: 'both' },
    { scim_path: 'name.givenName', ldap_attribute: 'givenName', direction: 'both' },
    { scim_path: 'name.familyName', ldap_attribute: 'sn', direction: 'both' },
    { scim_path: 'displayName', ldap_attribute: 'displayName', direction: 'both' },
    { scim_path: 'emails.value', ldap_attribute: 'mail', direction: 'both' },
  ];
}

export interface AttributeDiscovery {
  schemas: unknown[];
  resource_types: unknown[];
  attributes: { name: string; type?: string; multi_valued?: boolean | null; samples: string[] }[];
  users: number;
}

export interface MappingValidation {
  valid: boolean;
  errors: { scim_path?: string; ldap_attribute?: string; message: string }[];
  scim_attributes: number;
  ldap_attributes: number;
}

export interface Run {
  id: number;
  started: string;
  finished: string | null;
  status: string;
  dry_run: number;
  processed: number;
  changed: number;
  conflicts: number;
  errors: number;
}

export interface Event {
  id: number;
  time: string;
  run_id: number | null;
  level: string;
  username: string;
  message: string;
}

export interface Status {
  running: boolean;
  next_run: number | null;
  enabled: boolean;
  dry_run: boolean;
  configured: boolean;
  inbound_enabled: boolean;
  linked_users: number;
  database: {
    engine: string;
    inventory: { source: string; resource_type: string; count: number }[];
    operations: Record<string, number>;
  };
  runs: Run[];
  events: Event[];
}

export interface Resource {
  source: 'scim' | 'ldap';
  resource_type: string;
  resource_key: string;
  observed_at: string;
  present: number;
}

export interface Operation {
  id: number;
  run_id: number;
  resource_type: string;
  resource_key: string;
  target: string | null;
  operation: string;
  status: string;
  created_at: string;
  updated_at: string;
  error: string | null;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export async function request<T>(token: string, path: string, init: RequestInit = {}): Promise<T> {
  const response = await fetch(path, {
    ...init,
    cache: 'no-store',
    headers: {
      Authorization: `Bearer ${token}`,
      ...(init.body ? { 'Content-Type': 'application/json' } : {}),
    },
  });
  if (!response.ok) {
    const text = await response.text();
    let detail = `Request failed (HTTP ${response.status}).`;
    try {
      const body: unknown = JSON.parse(text);
      if (typeof body === 'object' && body !== null && 'detail' in body && typeof body.detail === 'string') {
        detail = body.detail;
      }
    } catch {
      // Reverse proxies may return HTML instead of an API error.
    }
    throw new ApiError(response.status, detail);
  }
  return response.json() as Promise<T>;
}

export const message = (error: unknown) =>
  error instanceof Error ? error.message : 'An unexpected error occurred.';

export type SecretEdit = { mode: 'keep' | 'replace' | 'clear'; value: string };
export type Secrets = { scim_token: SecretEdit; ldap_password: SecretEdit; entra_client_secret: SecretEdit };

export function normalizeSettings(settings: Settings): Settings {
  return Object.assign({
    scim_provider: 'generic', ldap_service: 'generic', ad_enable_new_accounts: false, entra_tenant_id: '', entra_client_id: '',
    scim_filter: '', entra_client_secret_configured: false, ignore_unsupported_fields: false,
  }, settings);
}

export function settingsPayload(settings: Settings, secrets: Secrets) {
  const { scim_token_configured, ldap_password_configured, entra_client_secret_configured, ...payload } = settings;
  const credentials: Partial<Record<keyof Secrets, string>> = {};
  for (const key of ['scim_token', 'ldap_password', 'entra_client_secret'] as const) {
    if (secrets[key].mode === 'replace') credentials[key] = secrets[key].value;
    if (secrets[key].mode === 'clear') credentials[key] = '';
  }
  return { ...payload, ...credentials };
}
