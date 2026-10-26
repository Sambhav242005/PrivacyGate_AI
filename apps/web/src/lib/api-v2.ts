"use client";

export const API_BASE = (process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
export type Role = "owner" | "reader";
export interface Session { account_id: string; username: string; role: Role; expires_at: number; csrf_token: string }
export interface Account { account_id: string; username: string; role: Role }
export interface Device { resource_id: string; device_id: string; name: string; ed25519_public_key_b64: string; last_sequence: number }
export interface Telemetry { device_id: string; sequence: number; issued_at: string; temp_c: number; vibration_mm_s: number; rpm: number }
export interface Receipt { transaction_id: string; block_height: number; block_hash: string; operation: string; resource_id: string; version: number }
export interface Policy { policy_id: string; policy_digest: string; resource_id: string; recipient_id: string; expires_at: number; status: string; version: number; receipt: Receipt | null }
export interface EnvelopeV2 { schema_version: 2; delivery_id: string; resource_id: string; recipient_id: string; policy_version: number; key_version: number; key_epoch: number; ephemeral_public_key_b64: string; nonce_b64: string; aad_b64: string; ciphertext_b64: string }
export interface Insight { event_id: string; event_type: "MACHINE_ANOMALY"; severity: "LOW"|"MEDIUM"|"HIGH"; observed_at: string; model_version: string }

export class ApiError extends Error { constructor(public code: string, message: string, public status: number) { super(message); this.name = "ApiError" } }
let csrf = "";
export function setCsrf(value: string) { csrf = value }
export function clearCsrf() { csrf = "" }
async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (init.body !== undefined) headers.set("Content-Type", "application/json");
  if (method !== "GET" && csrf) headers.set("X-CSRF-Token", csrf);
  const response = await fetch(`${API_BASE}${path}`, { ...init, headers, credentials: "include" });
  const body: any = await response.json().catch(() => null);
  if (!response.ok) throw new ApiError(body?.error?.code ?? (response.status === 401 ? "NOT_AUTHENTICATED" : "REQUEST_FAILED"), body?.error?.message ?? `Request failed (${response.status})`, response.status);
  return body as T;
}
const post = <T,>(path: string, data: unknown, operationId?: string) => request<T>(path, { method: "POST", body: JSON.stringify(data), headers: operationId ? { "X-Operation-ID": operationId } : undefined });
export const apiV2 = {
  login: (username: string, password: string) => post<Session>("/v2/auth/login", { username, password }),
  me: () => request<Session>("/v2/me"),
  logout: () => post<{ok:true}>("/v2/auth/logout", {}),
  accounts: () => request<{items:Account[]}>("/v2/accounts"),
  devices: () => request<{items:Device[]}>("/v2/devices"),
  createDevice: (name:string, operationId:string) => post<Device & {receipt:Receipt}>("/v2/devices", {name}, operationId),
  telemetry: (resourceId:string, cursor?:string, signal?:AbortSignal) => {
    const query = new URLSearchParams({ limit: "50" });
    if (cursor) query.set("cursor", cursor);
    return request<{items:Telemetry[];next_cursor:string|null}>(`/v2/resources/${encodeURIComponent(resourceId)}/telemetry?${query}`, {signal});
  },
  simulate: (resource_id:string, mode:"normal"|"anomaly"|"tampered"|"replayed"|"stale"|"malformed"|"wrong-device", count:number) => post<{accepted:number;rejected:number;deliveries:number}>("/v2/simulator", {resource_id,mode,count}),
  key: () => request<{key_id:string;key_version:number;x25519_public_key_b64:string}|null>("/v2/keys"),
  registerKey: (x25519_public_key_b64:string, replace=false) => post<{key_id:string;key_version:number;x25519_public_key_b64:string}>("/v2/keys", {x25519_public_key_b64,replace}),
  createPolicy: (resource_id:string,recipient_id:string,expires_at:number,operationId:string) => post<Policy>("/v2/policies", {resource_id,recipient_id,expires_at}, operationId),
  policies: (resource_id?:string) => request<{items:Policy[]}>(`/v2/policies${resource_id?`?resource_id=${encodeURIComponent(resource_id)}`:""}`),
  revoke: (id:string,operationId:string) => post<Policy>(`/v2/policies/${encodeURIComponent(id)}/revoke`, {}, operationId),
  operation: (id:string) => request<{transaction_id:string;status:string;code?:string;receipt:Receipt|null}>(`/v2/operations/${encodeURIComponent(id)}`),
  insights: (resource_id:string, signal?:AbortSignal) => request<{items:EnvelopeV2[];next_cursor:string|null}>(`/v2/insights?resource_id=${encodeURIComponent(resource_id)}&limit=50`, {signal}),
};
export async function logoutCurrentSession(): Promise<"ended" | "already-ended"> {
  try {
    const current = await apiV2.me();
    setCsrf(current.csrf_token);
  } catch (error) {
    if (error instanceof ApiError && error.status === 401) {
      clearCsrf();
      return "already-ended";
    }
    throw error;
  }
  await apiV2.logout();
  clearCsrf();
  return "ended";
}
export async function restoreSession(): Promise<Session|null> {
  try { const s = await apiV2.me(); setCsrf(s.csrf_token); return s; }
  catch (e) { if (e instanceof ApiError && e.status === 401) return null; throw e; }
}
