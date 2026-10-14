// Generic gateway API client (PG-041 subscriber use; owner lane: import, don't rewrite).
// All routes per docs/API.md. Cookie session via credentials:include. Errors keep
// gateway { error: { code, message, request_id } } shape; never log bodies.

const BASE = (process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");

export interface ApiErrorShape {
  code: string;
  message: string;
  request_id?: string;
  http: number;
}

export class ApiError extends Error {
  code: string;
  http: number;
  requestId?: string;
  constructor(e: ApiErrorShape) {
    super(e.message);
    this.code = e.code;
    this.http = e.http;
    this.requestId = e.request_id;
  }
}

// snake_case DTOs match API.md exactly.
export interface EnvelopeV1 {
  delivery_id: string;
  schema_version: 1;
  resource_id: string;
  recipient_wallet: string;
  policy_version: number;
  key_epoch: number;
  ephemeral_public_key_b64: string;
  nonce_b64: string;
  aad_b64: string;
  ciphertext_b64: string;
}

export interface InsightV1 {
  event_id: string;
  event_type: "MACHINE_ANOMALY";
  severity: "LOW" | "MEDIUM" | "HIGH";
  observed_at: string;
  model_version: string;
}

export interface InsightsPage {
  items: EnvelopeV1[];
  next_cursor: string | null;
}

// Owner-dashboard DTOs (PG-040). snake_case matches API.md / gateway routes.
export interface DeviceRes {
  resource_id: string;
  device_id: string;
  name: string;
  registered_at: string;
  status: string;
}

export interface TelemetryRow {
  device_id: string;
  sequence: number;
  issued_at: string;
  temp_c: number;
  vibration_mm_s: number;
  rpm: number;
}

export interface PolicyCreateRes {
  policy_id: string;
  policy_revision: number;
  policy_digest: string;
  status: string;
  onchain_grant_required: boolean;
}

export interface PolicySyncRes {
  policy_id: string;
  status: string;
  contract_version: number;
  confirmed_block: number;
  transaction_hash: string;
}

export interface PolicyItem {
  policy_id: string;
  resource_id: string;
  recipient_wallet: string;
  policy_revision: number;
  policy_digest: string;
  status: string;
  contract_version?: number | null;
  confirmed_block?: number | null;
  expires_at_unix: number;
}

export interface PermissionEvent {
  event_type: string;
  block_number: number;
  tx_hash: string;
  contract_version: number;
  observed_at: string;
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const method = (init?.method ?? "GET").toUpperCase();
  const headers: Record<string, string> = {
    "content-type": "application/json",
    ...((init?.headers ?? {}) as Record<string, string>),
  };
  if (method !== "GET" && csrfToken) headers["X-CSRF-Token"] = csrfToken;
  const res = await fetch(`${BASE}${path}`, { credentials: "include", ...init, headers });
  const body = (await res.json().catch(() => null)) as {
    error?: { code: string; message: string; request_id?: string };
  } | T | null;
  if (!res.ok) {
    const e = (body as { error?: { code: string; message: string } })?.error;
    throw new ApiError({
      code: e?.code ?? (res.status === 401 ? "NOT_AUTHENTICATED" : "INVALID_INPUT"),
      message: e?.message ?? `Request failed (${res.status})`,
      http: res.status,
    });
  }
  return body as T;
}

const post = <T>(path: string, json: unknown) =>
  req<T>(path, { method: "POST", body: JSON.stringify(json) });

// ---- CSRF (memory only; login page sets it from verify response) ----
let csrfToken = "";
export function setCsrf(t: string): void {
  csrfToken = t;
}
export function clearCsrf(): void {
  csrfToken = "";
}

// ---- Owner DTOs (PG-040; subscriber lane does not use these) ----
export interface DeviceRes {
  resource_id: string;
  device_id: string;
  name: string;
  registered_at: string;
  status: string;
}
export interface PolicyItem {
  policy_id: string;
  policy_revision: number;
  policy_digest: string;
  recipient_wallet: string;
  status: string;
}
export interface TelemetryPage {
  items: import("./schemas").TelemetryRow[];
  next_cursor: string | null;
}

export const api = {
  challenge: (wallet_address: string) =>
    post<{ challenge_id: string; message_to_sign: string; expires_at: string }>(
      "/v1/auth/challenge",
      { wallet_address },
    ),
  verify: (challenge_id: string, signature_hex: string) =>
    post<{ wallet_address: string; expires_at: string; csrf_token: string }>(
      "/v1/auth/verify",
      { challenge_id, signature_hex },
    ),
  me: () => req<{ wallet_address: string; expires_at: string }>("/v1/me"),
  logout: () => post<{ ok: boolean }>("/v1/auth/logout", {}),
  registerKey: (x25519_public_key_b64: string) =>
    post<{ wallet_address: string; key_id: string; registered_at: string }>("/v1/keys", {
      x25519_public_key_b64,
    }),
  listInsights: (resource_id: string, limit = 50, cursor?: string) => {
    const q = new URLSearchParams({ resource_id, limit: String(Math.min(limit, 100)) });
    if (cursor) q.set("cursor", cursor);
    return req<InsightsPage>(`/v1/insights?${q.toString()}`);
  },
  // Owner lane (PG-040): device enroll, owner telemetry, policy draft/sync.
  enrollDevice: (d: {
    resource_id: string;
    device_id: string;
    name: string;
    ed25519_public_key_b64: string;
  }) => post<DeviceRes>("/v1/devices", d),
  listDevices: () => req<{ items: DeviceRes[] }>("/v1/devices"),
  telemetry: (resource_id: string, limit = 50, cursor?: string) => {
    const q = new URLSearchParams({ limit: String(Math.min(Math.max(limit, 1), 100)) });
    if (cursor) q.set("cursor", cursor);
    return req<{ items: TelemetryRow[]; next_cursor: string | null }>(
      `/v1/resources/${resource_id}/telemetry?${q.toString()}`,
    );
  },
  createPolicy: (d: {
    resource_id: string;
    recipient_wallet: string;
    scope: "READ_INSIGHT";
    allowed_event_types: string[];
    allowed_fields: string[];
    expires_at_unix: number;
  }) => post<PolicyCreateRes>("/v1/policies", d),
  syncPolicy: (policy_id: string, transaction_hash: string) =>
    post<PolicySyncRes>(`/v1/policies/${policy_id}/sync`, { transaction_hash }),
  listPolicies: (resource_id?: string) => {
    const q = new URLSearchParams();
    if (resource_id) q.set("resource_id", resource_id);
    const s = q.toString();
    return req<{ items: PolicyItem[] }>(`/v1/policies${s ? `?${s}` : ""}`);
  },
  permissionEvents: (resource_id: string, limit = 50) => {
    const q = new URLSearchParams({ resource_id, limit: String(Math.min(Math.max(limit, 1), 100)) });
    return req<{ items: PermissionEvent[]; next_cursor: string | null }>(
      `/v1/audit/permission-events?${q.toString()}`,
    );
  },
  health: () => req<{ status: string }>("/v1/health"),
};

// Verb-style aliases used by login/owner pages (same endpoints, same semantics).
export const postChallenge = (wallet_address: string) => api.challenge(wallet_address);
export const postVerify = (challenge_id: string, signature_hex: string) =>
  api.verify(challenge_id, signature_hex);
export const getMe = () => api.me();
export const postLogout = () => api.logout();
export const getTelemetry = (resource_id: string, limit = 50, cursor?: string) =>
  api.telemetry(resource_id, limit, cursor);
export const getPermissionEvents = (resource_id: string) => api.permissionEvents(resource_id);

// Bare-function aliases for owner dashboard named imports (same methods).
export function enrollDevice(d: Parameters<typeof api.enrollDevice>[0]) {
  return api.enrollDevice(d);
}
export function listDevices() {
  return api.listDevices();
}
export function listPolicies(resource_id?: string) {
  return api.listPolicies(resource_id);
}
export function createPolicy(d: Parameters<typeof api.createPolicy>[0]) {
  return api.createPolicy(d);
}
export function syncPolicy(policy_id: string, transaction_hash: string) {
  return api.syncPolicy(policy_id, transaction_hash);
}
