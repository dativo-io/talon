import { useEffect, useRef, useState } from "react";
import { postJSON, ApiError } from "../api/client";

// Pairing: the one-time code printed by the console process. The code is
// posted once and cleared from the field; the session is an HttpOnly cookie.
export function Pair({ expired, onPaired }: { expired: boolean; onPaired: () => void }) {
  const [code, setCode] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    document.title = "Pair this browser · Talon Console";
    input.current?.focus();
  }, []);
  return (
    <div className="pair-shell">
      <section className="card pair-card" id="pair" aria-labelledby="pair-title">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true" />
          <span>
            Talon
            <small>Operations Console</small>
          </span>
        </div>
        <h1 id="pair-title">Pair this browser</h1>
        {expired ? (
          <div className="notice info" role="status">
            Your console session ended. Pair again to continue where you were.
          </div>
        ) : null}
        <p className="muted">
          Enter the one-time pairing code printed by the console process (<code>docker compose logs talon-ui</code>, or the terminal running{" "}
          <code>talon ui</code>). Codes are single use and expire within ten minutes; <code>talon ui pair</code> prints a new one.
        </p>
        <form
          id="pair-form"
          autoComplete="off"
          onSubmit={(e) => {
            e.preventDefault();
            setBusy(true);
            setErr(null);
            postJSON("/console/auth/pair", { code })
              .then(() => {
                setCode("");
                onPaired();
              })
              .catch((e2: unknown) => {
                setCode("");
                setErr(e2 instanceof ApiError ? `${e2.message} (${e2.reason})` : String(e2));
              })
              .finally(() => setBusy(false));
          }}
        >
          <label htmlFor="code">Pairing code</label>
          <input
            id="code"
            ref={input}
            value={code}
            onChange={(e) => setCode(e.target.value)}
            placeholder="XXXXX-XXXXX-XXXXX-XXXXX"
            spellCheck={false}
            autoCapitalize="characters"
            required
          />
          <button type="submit" className="primary" disabled={busy}>
            Pair
          </button>
          {err ? (
            <p id="pair-error" className="notice error" role="alert">
              {err}
            </p>
          ) : null}
        </form>
      </section>
    </div>
  );
}
