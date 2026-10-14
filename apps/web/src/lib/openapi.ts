// Read-only gateway API explorer model (api-docs page).
// Loads the live gateway /openapi.json when reachable, otherwise falls back to
// the checked-in snapshot (regenerate: python apps/web/scripts/dump-openapi.py).
// All field types come from real Pydantic schemas in that document -- nothing
// is hand-invented here. No auth, no requests other than the public spec fetch.

import snapshot from "./openapi.snapshot.json";

const LIVE_TIMEOUT_MS = 5000;

export function gatewayBase(): string {
  return (process.env.NEXT_PUBLIC_GATEWAY_URL ?? "http://127.0.0.1:8000").replace(/\/$/, "");
}

/** Subset of JSON Schema as emitted by Pydantic v2 / FastAPI. */
export interface JsonSchema {
  $ref?: string;
  type?: string;
  format?: string;
  title?: string;
  description?: string;
  properties?: Record<string, JsonSchema>;
  required?: string[];
  items?: JsonSchema;
  enum?: (string | number)[];
  const?: string | number | boolean;
  pattern?: string;
  default?: unknown;
  examples?: unknown[];
  anyOf?: JsonSchema[];
  allOf?: JsonSchema[];
  $defs?: Record<string, JsonSchema>;
  minLength?: number;
  maxLength?: number;
  minimum?: number;
  maximum?: number;
  exclusiveMinimum?: number;
  exclusiveMaximum?: number;
  minItems?: number;
  maxItems?: number;
  [k: string]: unknown;
}

export interface ApiParam {
  name: string;
  location: string;
  required: boolean;
  description: string;
  schema: JsonSchema | null;
}

export interface ApiResponseEntry {
  status: string;
  description: string;
  schema: JsonSchema | null;
}

export interface ApiEndpoint {
  method: string;
  path: string;
  summary: string;
  description: string;
  group: string;
  auth: string;
  requestDto: string | null;
  requestSchema: JsonSchema | null;
  params: ApiParam[];
  responses: ApiResponseEntry[];
  errors: string[];
  responseNote: string;
}

export interface ApiDocs {
  title: string;
  version: string;
  source: "live" | "snapshot";
  generatedAt: string | null;
  endpointCount: number;
  endpoints: ApiEndpoint[];
  /** All named schemas: OpenAPI components + real Pydantic domain DTOs. */
  schemas: Record<string, JsonSchema>;
}

interface SnapshotDoc {
  generated_at: string;
  openapi: { info?: { title?: string; version?: string }; paths?: Record<string, unknown>; components?: { schemas?: Record<string, JsonSchema> } };
  dto_schemas?: Record<string, JsonSchema>;
  endpoint_notes?: Record<string, { auth?: string; response_note?: string; errors?: string[] }>;
}

const SNAP = snapshot as unknown as SnapshotDoc;

export const GROUP_ORDER = ["auth", "devices", "policies", "insights", "audit", "health"] as const;

export function groupForPath(path: string): string {
  if (path.startsWith("/v1/auth") || path === "/v1/me") return "auth";
  if (path.startsWith("/v1/policies")) return "policies";
  if (path.startsWith("/v1/insights")) return "insights";
  if (path.startsWith("/v1/audit")) return "audit";
  if (path === "/v1/health" || path === "/v1/ready") return "health";
  return "devices";
}

function firstContentSchema(
  container: { content?: Record<string, { schema?: JsonSchema }> } | undefined,
): JsonSchema | null {
  const content = container?.content;
  if (!content) return null;
  const json = content["application/json"] ?? Object.values(content)[0];
  return json?.schema ?? null;
}

function refName(ref: string): string {
  return ref.split("/").pop() ?? ref;
}

/** Resolve local refs (#/components/schemas/X). $defs are flattened into schemas at load. */
export function resolveSchema(schema: JsonSchema, schemas: Record<string, JsonSchema>): JsonSchema {
  let cur = schema;
  const seen = new Set<string>();
  while (cur?.$ref && !seen.has(cur.$ref)) {
    seen.add(cur.$ref);
    cur = schemas[refName(cur.$ref)] ?? cur;
  }
  return cur;
}

/** Flatten nested $defs so every named schema resolves from one map. */
function collectSchemas(
  components: Record<string, JsonSchema>,
  dtos: Record<string, JsonSchema>,
): Record<string, JsonSchema> {
  const out: Record<string, JsonSchema> = { ...components };
  const absorb = (s: JsonSchema | undefined) => {
    if (!s) return;
    for (const [k, v] of Object.entries(s.$defs ?? {})) {
      if (!(k in out)) {
        out[k] = v;
        absorb(v);
      }
    }
    for (const v of Object.values(s.properties ?? {})) absorb(v);
    absorb(s.items);
    for (const v of [...(s.anyOf ?? []), ...(s.allOf ?? [])]) absorb(v);
  };
  for (const [k, v] of Object.entries(dtos)) {
    if (!(k in out)) out[k] = v;
  }
  for (const v of Object.values(out)) absorb(v);
  return out;
}

interface RawOperation {
  summary?: string;
  description?: string;
  parameters?: { name?: string; in?: string; required?: boolean; description?: string; schema?: JsonSchema }[];
  requestBody?: { content?: Record<string, { schema?: JsonSchema }> };
  responses?: Record<string, { description?: string; content?: Record<string, { schema?: JsonSchema }> }>;
}

const HTTP_METHODS = ["get", "post", "put", "patch", "delete"];

function normalizePaths(
  paths: Record<string, Record<string, RawOperation>>,
  schemas: Record<string, JsonSchema>,
  notes: Record<string, { auth?: string; response_note?: string; errors?: string[] }>,
): ApiEndpoint[] {
  const endpoints: ApiEndpoint[] = [];
  for (const [path, item] of Object.entries(paths)) {
    for (const method of HTTP_METHODS) {
      const op = item[method];
      if (!op) continue;
      const key = `${method.toUpperCase()} ${path}`;
      const note = notes[key] ?? {};
      const reqSchema = firstContentSchema(op.requestBody);
      const resolved = reqSchema ? resolveSchema(reqSchema, schemas) : null;
      endpoints.push({
        method: method.toUpperCase(),
        path,
        summary: op.summary ?? "",
        description: op.description ?? "",
        group: groupForPath(path),
        auth: note.auth ?? "pg_session cookie",
        requestDto: reqSchema?.$ref ? refName(reqSchema.$ref) : null,
        requestSchema: resolved,
        params: (op.parameters ?? []).map((p) => ({
          name: p.name ?? "",
          location: p.in ?? "",
          required: p.required ?? p.in === "path",
          description: p.description ?? "",
          schema: p.schema ? resolveSchema(p.schema, schemas) : null,
        })),
        responses: Object.entries(op.responses ?? {}).map(([status, r]) => ({
          status,
          description: r.description ?? "",
          schema: firstContentSchema(r) ? resolveSchema(firstContentSchema(r)!, schemas) : null,
        })),
        errors: note.errors ?? [],
        responseNote: note.response_note ?? "",
      });
    }
  }
  const groupRank = (g: string) => {
    const i = GROUP_ORDER.indexOf(g as (typeof GROUP_ORDER)[number]);
    return i < 0 ? 99 : i;
  };
  return endpoints.sort(
    (a, b) => groupRank(a.group) - groupRank(b.group) || a.path.localeCompare(b.path) || a.method.localeCompare(b.method),
  );
}

function normalizeDoc(
  openapi: SnapshotDoc["openapi"],
  dtoSchemas: Record<string, JsonSchema>,
  notes: SnapshotDoc["endpoint_notes"] | undefined,
  source: "live" | "snapshot",
  generatedAt: string | null,
): ApiDocs {
  const schemas = collectSchemas(openapi.components?.schemas ?? {}, dtoSchemas);
  const endpoints = normalizePaths(
    (openapi.paths ?? {}) as Record<string, Record<string, RawOperation>>,
    schemas,
    notes ?? {},
  );
  return {
    title: openapi.info?.title ?? "PrivacyGate AI gateway",
    version: openapi.info?.version ?? "",
    source,
    generatedAt,
    endpointCount: endpoints.length,
    endpoints,
    schemas,
  };
}

/**
 * Load explorer data. Tries the live gateway spec first (public, no auth),
 * falls back to the checked-in snapshot. Notes + DTO schemas always come
 * from the snapshot bundle.
 */
export async function loadApiDocs(): Promise<ApiDocs> {
  const notes = SNAP.endpoint_notes ?? {};
  const dtoSchemas = SNAP.dto_schemas ?? {};
  try {
    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), LIVE_TIMEOUT_MS);
    const res = await fetch(`${gatewayBase()}/openapi.json`, { signal: ctrl.signal });
    clearTimeout(timer);
    if (!res.ok) throw new Error(`gateway spec ${res.status}`);
    const live = (await res.json()) as SnapshotDoc["openapi"];
    if (!live.paths) throw new Error("gateway spec has no paths");
    return normalizeDoc(live, dtoSchemas, notes, "live", null);
  } catch {
    return normalizeDoc(SNAP.openapi, dtoSchemas, notes, "snapshot", SNAP.generated_at);
  }
}

/** Tiny generated example from a real schema (for the expandable sample). */
export function exampleForSchema(
  schema: JsonSchema,
  schemas: Record<string, JsonSchema>,
  depth = 0,
): unknown {
  const s = resolveSchema(schema, schemas);
  if (s.const !== undefined) return s.const;
  if (s.enum?.length) return s.enum[0];
  if (s.default !== undefined) return s.default;
  if (s.examples?.length) return s.examples[0];
  const types = s.anyOf?.map((v) => resolveSchema(v, schemas).type).filter(Boolean) as string[] | undefined;
  const type = s.type ?? types?.find((t) => t !== "null") ?? "string";
  if (depth > 3) return type === "array" ? [] : type === "object" ? {} : "…";
  if (type === "array") return [exampleForSchema(s.items ?? { type: "string" }, schemas, depth + 1)];
  if (type === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(s.properties ?? {})) out[k] = exampleForSchema(v, schemas, depth + 1);
    return out;
  }
  if (type === "integer" || type === "number") return s.minimum ?? 0;
  if (type === "boolean") return true;
  return s.pattern ? `(${s.pattern})` : "string";
}
