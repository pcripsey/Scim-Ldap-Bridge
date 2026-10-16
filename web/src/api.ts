export interface Settings {
  scim_url: string;
  ldap_url: string;
  ldap_bind_dn: string;
  ldap_base_dn: string;
  ldap_start_tls: boolean;
  ldap_allow_insecure: boolean;
  direction: 'bidirectional' | 'scim_to_ldap' | 'ldap_to_scim';
  conflict_policy: 'manual' | 'scim_wins' | 'ldap_wins';
  interval_seconds: number;
  enabled: boolean;
  dry_run: boolean;
  scim_token_configured: boolean;
  ldap_password_configured: boolean;
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
export type Secrets = { scim_token: SecretEdit; ldap_password: SecretEdit };

export function settingsPayload(settings: Settings, secrets: Secrets) {
  const { scim_token_configured, ldap_password_configured, ...payload } = settings;
  const credentials: Partial<Record<keyof Secrets, string>> = {};
  for (const key of ['scim_token', 'ldap_password'] as const) {
    if (secrets[key].mode === 'replace') credentials[key] = secrets[key].value;
    if (secrets[key].mode === 'clear') credentials[key] = '';
  }
  return { ...payload, ...credentials };
}
