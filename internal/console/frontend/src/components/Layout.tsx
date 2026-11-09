import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link, NavLink, useLocation, useNavigate } from "react-router-dom";
import { getJSON, api, ApiError } from "../api/client";
import type { SearchResults } from "../api/types";
import { scoped, useScope } from "../lib/scope";
import { applyTheme, loadTheme, type Theme } from "../lib/theme";
import { UseCaseHealth } from "./ui";
import type { Health } from "../api/types";

const NAV = [
  { to: "/overview", label: "Overview" },
  { to: "/use-cases", label: "AI Use Cases" },
  { to: "/sessions", label: "Sessions" },
  { to: "/costs", label: "Costs" },
  { to: "/configuration", label: "Configuration" },
  { to: "/system", label: "System" },
];

export function Layout({ children, onLogout }: { children: ReactNode; onLogout: () => void }) {
  const [open, setOpen] = useState(false);
  const [theme, setTheme] = useState<Theme>(loadTheme());
  const { tenant } = useScope();
  const loc = useLocation();
  useEffect(() => setOpen(false), [loc.pathname]);
  useEffect(() => applyTheme(theme), [theme]);
  return (
    <div className="app">
      <a className="skip-link" href="#main">Skip to content</a>
      <aside className={`sidebar${open ? " open" : ""}`} aria-label="Primary">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>
            Talon
            <small>Operations Console</small>
          </span>
        </div>
        <nav className="nav">
          {NAV.map((n) => (
            <NavLink key={n.to} to={scoped(n.to, tenant)} className={({ isActive }) => (isActive ? "active" : "")}>
              {n.label}
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-foot">
          <span>Read-only view of this installation.</span>
          <label className="row">
            Theme
            <select value={theme} onChange={(e) => setTheme(e.target.value as Theme)} aria-label="Theme">
              <option value="system">System</option>
              <option value="light">Light</option>
              <option value="dark">Dark</option>
            </select>
          </label>
        </div>
      </aside>
      <div className="main">
        <header className="topbar">
          <button type="button" className="menu-button" aria-expanded={open} aria-label="Open navigation" onClick={() => setOpen((o) => !o)}>
            Menu
          </button>
          <GlobalSearch tenant={tenant} />
          <span className="spacer" />
          <TenantScope />
          <button type="button" className="ghost" onClick={onLogout}>
            Log out
          </button>
        </header>
        <main id="main" className="content" tabIndex={-1}>
          {children}
        </main>
      </div>
    </div>
  );
}

function TenantScope() {
  const { tenant, set } = useScope();
  const [draft, setDraft] = useState(tenant);
  useEffect(() => setDraft(tenant), [tenant]);
  return (
    <form
      className="row"
      onSubmit={(e) => {
        e.preventDefault();
        set("tenant", draft.trim());
      }}
    >
      <label className="small muted" htmlFor="tenant-input">Tenant</label>
      <input id="tenant-input" value={draft} placeholder="all / default" size={12} onChange={(e) => setDraft(e.target.value)} />
    </form>
  );
}

function GlobalSearch({ tenant }: { tenant: string }) {
  const [q, setQ] = useState("");
  const [res, setRes] = useState<SearchResults | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [show, setShow] = useState(false);
  const nav = useNavigate();
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const term = q.trim();
    if (term.length < 2) {
      setRes(null);
      setErr(null);
      return;
    }
    const ctrl = new AbortController();
    const t = window.setTimeout(() => {
      getJSON<SearchResults>(api("/search"), { q: term, tenant }, ctrl.signal)
        .then((r) => {
          setRes(r);
          setErr(null);
        })
        .catch((e: unknown) => {
          if (!ctrl.signal.aborted) setErr(e instanceof ApiError ? e.message : String(e));
        });
    }, 200);
    return () => {
      ctrl.abort();
      window.clearTimeout(t);
    };
  }, [q, tenant]);
  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (box.current && !box.current.contains(e.target as Node)) setShow(false);
    };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  const go = (to: string) => {
    setShow(false);
    setQ("");
    nav(to);
  };
  const empty = res && res.use_cases.length + res.sessions.length + res.evidence.length === 0;
  return (
    <div className="search" ref={box} role="search">
      <label className="visually-hidden" htmlFor="global-search">Search use cases, session ids, evidence or correlation ids</label>
      <input
        id="global-search"
        type="search"
        placeholder="Search use case, session id, evidence id, correlation id"
        value={q}
        autoComplete="off"
        onFocus={() => setShow(true)}
        onChange={(e) => {
          setQ(e.target.value);
          setShow(true);
        }}
        onKeyDown={(e) => {
          if (e.key === "Escape") setShow(false);
        }}
      />
      {show && (res || err) ? (
        <div className="search-results" role="listbox" aria-label="Search results">
          {err ? <span className="none">Search unavailable: {err}</span> : null}
          {res && res.use_cases.length > 0 ? <h3>AI use cases</h3> : null}
          {res?.use_cases.map((u) => (
            <a key={`u${u.tenant_id}/${u.name}`} href="#" onClick={(e) => { e.preventDefault(); go(scoped(`/use-cases/${encodeURIComponent(u.name)}`, u.tenant_id)); }}>
              {u.name} <span className="muted small">{u.tenant_id}</span> <UseCaseHealth health={u.health as Health} />
            </a>
          ))}
          {res && res.sessions.length > 0 ? <h3>Sessions</h3> : null}
          {res?.sessions.map((s) => (
            <a key={`s${s.session_id}`} href="#" onClick={(e) => { e.preventDefault(); go(scoped(`/sessions/${encodeURIComponent(s.session_id)}`, s.tenant_id)); }}>
              <code>{s.session_id}</code> <span className="muted small">{s.managed ? "managed" : "observed in evidence"} · {s.record_count} records</span>
            </a>
          ))}
          {res && res.evidence.length > 0 ? <h3>Evidence</h3> : null}
          {res?.evidence.map((ev) => (
            <a key={`e${ev.id}`} href="#" onClick={(e) => { e.preventDefault(); go(scoped(`/evidence/${encodeURIComponent(ev.id)}`, ev.tenant_id)); }}>
              <code>{ev.id}</code> <span className="muted small">{ev.agent_id} · {ev.invocation_type}</span>
            </a>
          ))}
          {empty ? <span className="none muted">No exact match in this scope. Explanation-code search is not available.</span> : null}
        </div>
      ) : null}
    </div>
  );
}

export function PageHead({ title, lede, actions }: { title: string; lede?: ReactNode; actions?: ReactNode }) {
  useEffect(() => {
    document.title = `${title} · Talon Console`;
  }, [title]);
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {lede ? <p className="lede">{lede}</p> : null}
      </div>
      {actions ? <div className="actions">{actions}</div> : null}
    </div>
  );
}

export function BackLink({ to, label }: { to: string; label: string }) {
  return (
    <Link to={to} className="small">
      ← {label}
    </Link>
  );
}
