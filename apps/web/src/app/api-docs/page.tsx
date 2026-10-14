"use client";

import { useEffect, useMemo, useState } from "react";
import {
  GROUP_ORDER,
  exampleForSchema,
  loadApiDocs,
  resolveSchema,
  type ApiDocs,
  type ApiEndpoint,
  type JsonSchema,
} from "@/lib/openapi";

function methodPill(method: string): string {
  if (method === "GET") return "pill ok";
  if (method === "POST") return "pill low";
  if (method === "DELETE") return "pill high";
  return "pill medium";
}

function statusPill(status: string): string {
  if (status.startsWith("2")) return "pill ok";
  if (status.startsWith("4")) return "pill medium";
  if (status.startsWith("5")) return "pill high";
  return "pill";
}

function typeLabel(s: JsonSchema): string {
  const parts: string[] = [];
  if (s.const !== undefined) return `const ${JSON.stringify(s.const)}`;
  if (s.enum?.length) return `enum ${s.enum.map((e) => JSON.stringify(e)).join(" | ")}`;
  const anyTypes = s.anyOf?.map((v) => v.type ?? (v.$ref ? v.$ref.split("/").pop() : "?")).filter(Boolean);
  parts.push(s.type ?? (anyTypes?.length ? anyTypes.join(" | ") : s.$ref ? (s.$ref.split("/").pop() ?? "ref") : "object"));
  if (s.format) parts.push(s.format);
  if (s.pattern) parts.push(`/${s.pattern}/`);
  if (s.minimum !== undefined || s.maximum !== undefined) parts.push(`range ${s.minimum ?? "…"}..${s.maximum ?? "…"}`);
  if (s.minLength !== undefined || s.maxLength !== undefined) parts.push(`len ${s.minLength ?? "…"}..${s.maxLength ?? "…"}`);
  if (s.minItems !== undefined || s.maxItems !== undefined) parts.push(`items ${s.minItems ?? "…"}..${s.maxItems ?? "…"}`);
  return parts.join(" · ");
}

function SchemaView({ schema, schemas, depth = 0 }: { schema: JsonSchema; schemas: Record<string, JsonSchema>; depth?: number }) {
  const s = resolveSchema(schema, schemas);
  if (s.anyOf?.length && !s.type && !s.properties) {
    return (
      <>
        {s.anyOf.map((v, i) => (
          <details key={i}>
            <summary className="mono">option {i + 1}: {typeLabel(resolveSchema(v, schemas))}</summary>
            <SchemaView schema={v} schemas={schemas} depth={depth + 1} />
          </details>
        ))}
      </>
    );
  }
  if ((s.type === "array" || s.items) && !s.properties) {
    return (
      <details>
        <summary className="mono">array of {typeLabel(resolveSchema(s.items ?? { type: "string" }, schemas))}</summary>
        <SchemaView schema={s.items ?? { type: "string" }} schemas={schemas} depth={depth + 1} />
      </details>
    );
  }
  if (s.type === "object" || s.properties || (!s.type && !s.enum && s.const === undefined)) {
    const props = Object.entries(s.properties ?? {});
    if (!props.length) return <p className="mono">object (no declared properties)</p>;
    const required = new Set(s.required ?? []);
    return (
      <dl className="insight">
        {props.map(([name, prop]) => {
          const r = resolveSchema(prop, schemas);
          const nested = r.properties || r.items || r.anyOf;
          return (
            <div className="field" key={name}>
              <dt>{name} {required.has(name) ? <span className="pill ok">required</span> : <span className="pill">optional</span>}</dt>
              <dd>{typeLabel(r)}</dd>
              {r.description && <dd className="mono">{r.description}</dd>}
              {nested ? (
                <details>
                  <summary className="mono">expand</summary>
                  <SchemaView schema={prop} schemas={schemas} depth={depth + 1} />
                </details>
              ) : null}
            </div>
          );
        })}
      </dl>
    );
  }
  return <p className="mono">{typeLabel(s)}{s.description ? ` — ${s.description}` : ""}</p>;
}

function EndpointPanel({ ep, schemas }: { ep: ApiEndpoint; schemas: Record<string, JsonSchema> }) {
  const sample = useMemo(() => {
    if (!ep.requestSchema) return null;
    try {
      return JSON.stringify(exampleForSchema(ep.requestSchema, schemas), null, 2);
    } catch {
      return null;
    }
  }, [ep, schemas]);
  return (
    <section className="card">
      <h2>
        <span className={methodPill(ep.method)}>{ep.method}</span>
        <span className="addr">{ep.path}</span>
      </h2>
      {ep.summary && <p className="sub">{ep.summary}</p>}
      {ep.description && <p className="muted">{ep.description}</p>}
      <div className="row" style={{ marginBottom: 12 }}>
        <span className="pill">auth: {ep.auth}</span>
        {ep.requestDto && <span className="pill low">{ep.requestDto}</span>}
      </div>

      {ep.params.length > 0 && (
        <>
          <h2>Parameters</h2>
          <dl className="insight">
            {ep.params.map((p) => (
              <div className="field" key={`${p.location}:${p.name}`}>
                <dt>{p.name} <span className="pill">{p.location}</span> {p.required ? <span className="pill ok">required</span> : <span className="pill">optional</span>}</dt>
                <dd>{p.schema ? typeLabel(resolveSchema(p.schema, schemas)) : "—"}</dd>
                {p.description && <dd className="mono">{p.description}</dd>}
              </div>
            ))}
          </dl>
        </>
      )}

      {ep.requestSchema && (
        <details>
          <summary className="mono">request body{ep.requestDto ? ` (${ep.requestDto})` : ""} — expand</summary>
          <SchemaView schema={ep.requestSchema} schemas={schemas} />
        </details>
      )}

      <h2 style={{ marginTop: 14 }}>Responses</h2>
      {ep.responses.map((r) => (
        <details key={r.status}>
          <summary>
            <span className={statusPill(r.status)}>{r.status}</span>{" "}
            <span className="mono">{r.description}</span>
          </summary>
          {r.schema && Object.keys(r.schema).length > 1 ? (
            <SchemaView schema={r.schema} schemas={schemas} />
          ) : (
            <p className="mono">No typed schema in the gateway spec for this status.</p>
          )}
        </details>
      ))}
      {ep.responseNote && <div className="note">{ep.responseNote}</div>}
      {ep.errors.length > 0 && <p className="mono">errors: {ep.errors.join(" · ")}</p>}

      {sample && (
        <details>
          <summary className="mono">generated sample request — expand</summary>
          <pre className="mono">{sample}</pre>
        </details>
      )}
    </section>
  );
}

export default function ApiDocsPage() {
  const [docs, setDocs] = useState<ApiDocs | null>(null);
  const [failed, setFailed] = useState(false);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  useEffect(() => {
    loadApiDocs()
      .then((d) => {
        setDocs(d);
        setSelected((cur) => cur ?? (d.endpoints[0] ? `${d.endpoints[0].method} ${d.endpoints[0].path}` : null));
      })
      .catch(() => setFailed(true));
  }, []);

  const filtered = useMemo(() => {
    if (!docs) return [];
    const q = query.trim().toLowerCase();
    if (!q) return docs.endpoints;
    return docs.endpoints.filter((e) =>
      `${e.method} ${e.path} ${e.summary} ${e.description}`.toLowerCase().includes(q),
    );
  }, [docs, query]);

  const current = docs?.endpoints.find((e) => `${e.method} ${e.path}` === selected)
    ?? filtered[0] ?? docs?.endpoints[0] ?? null;

  return (
    <>
      <header className="hero">
        <h1>Gateway <em>API explorer</em></h1>
        <p>
          Every gateway endpoint with input/output types from the real gateway schemas.
          Read-only: this page never sends requests other than loading the public spec,
          and there is no try-it execution.
        </p>
      </header>

      <div className="row" style={{ marginBottom: 18 }}>
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Filter endpoints (method, path, text)…"
          aria-label="Filter endpoints"
        />
        {docs && (
          <span className="pill">{docs.source === "live" ? "LIVE gateway spec" : `SNAPSHOT ${docs.generatedAt ?? ""}`}</span>
        )}
      </div>

      {failed && <div className="err" role="alert"><code>!</code> Could not load the API spec.</div>}
      {!docs && !failed && <p className="muted">Loading spec…</p>}

      {docs && current && (
        <div style={{ display: "flex", gap: 18, alignItems: "flex-start", flexWrap: "wrap" }}>
          <nav className="card" style={{ flex: "1 1 240px", maxWidth: 320 }} aria-label="Endpoints">
            {GROUP_ORDER.map((g) => {
              const items = filtered.filter((e) => e.group === g);
              if (!items.length) return null;
              return (
                <div key={g} style={{ marginBottom: 12 }}>
                  <p className="mono">{g} ({items.length})</p>
                  {items.map((e) => {
                    const k = `${e.method} ${e.path}`;
                    const active = current.method === e.method && current.path === e.path;
                    return (
                      <div className="row" key={k} style={{ marginBottom: 6 }}>
                        <button className={active ? "" : "ghost"} onClick={() => setSelected(k)} style={{ padding: "6px 10px", fontSize: "0.8rem" }}>
                          <span className={methodPill(e.method)} style={{ marginRight: 6 }}>{e.method}</span>
                          <span className="mono">{e.path}</span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              );
            })}
            {filtered.length === 0 && <p className="muted">No endpoints match.</p>}
          </nav>
          <div style={{ flex: "3 1 420px", minWidth: 0 }}>
            <EndpointPanel ep={current} schemas={docs.schemas} />
            <section className="card">
              <h2><span className="step">§</span> Shared DTO schemas ({Object.keys(docs.schemas).length})</h2>
              <p className="sub">Named Pydantic models from the gateway spec plus domain DTOs bundled in the snapshot.</p>
              {Object.entries(docs.schemas)
                .filter(([, s]) => s.type === "object" || s.properties)
                .map(([name, s]) => (
                  <details key={name}>
                    <summary className="mono">{name} — expand</summary>
                    <SchemaView schema={s} schemas={docs.schemas} />
                  </details>
                ))}
            </section>
          </div>
        </div>
      )}

      <footer className="foot">
        Types come from the gateway OpenAPI/Pydantic schemas{docs ? ` (${docs.endpointCount} endpoints, source: ${docs.source})` : ""}.
        Regenerate the fallback snapshot with <code>python apps/web/scripts/dump-openapi.py</code> (gateway on PYTHONPATH).
      </footer>
    </>
  );
}
