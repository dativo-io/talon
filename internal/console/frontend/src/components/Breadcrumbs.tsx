import { Link } from "react-router-dom";
import { scoped } from "../lib/scope";

export interface Crumb {
  label: string;
  to?: string;
}

// Breadcrumbs: the investigation path Installation/Tenant → AI use case →
// Session → Evidence, built from the URL and the record being shown (never
// from remembered state), so a deep link or a reload shows the same path.
export function Breadcrumbs({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="breadcrumbs">
      <ol>
        {items.map((c, i) => (
          <li key={`${i}-${c.label}`}>
            {c.to && i < items.length - 1 ? <Link to={c.to}>{c.label}</Link> : <span aria-current={i === items.length - 1 ? "page" : undefined}>{c.label}</span>}
          </li>
        ))}
      </ol>
    </nav>
  );
}

// scopeCrumb is the first crumb: the tenant scope the operator is in.
export function scopeCrumb(tenant: string): Crumb {
  return { label: tenant ? `Tenant ${tenant}` : "All tenants", to: scoped("/overview", tenant) };
}
