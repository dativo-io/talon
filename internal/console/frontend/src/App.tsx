import { useCallback, useEffect, useState } from "react";
import { Navigate, Route, Routes } from "react-router-dom";
import { getJSON, onSessionEnded, postJSON } from "./api/client";
import type { AuthSession } from "./api/types";
import { Layout } from "./components/Layout";
import { Loading } from "./components/ui";
import { Pair } from "./pages/Pair";
import { Overview } from "./pages/Overview";
import { UseCases } from "./pages/UseCases";
import { UseCaseDetail } from "./pages/UseCaseDetail";
import { Sessions } from "./pages/Sessions";
import { SessionDetail } from "./pages/SessionDetail";
import { EvidencePage } from "./pages/Evidence";
import { Costs } from "./pages/Costs";
import { Configuration } from "./pages/Configuration";
import { System } from "./pages/System";
import { NotFound } from "./pages/NotFound";

type Auth = { state: "checking" } | { state: "paired"; expiresAt?: string } | { state: "unpaired"; expired: boolean } | { state: "error"; message: string };

// The app checks the browser session once, then renders the pages. When an
// API call reports the session ended, it shows pairing in place: the URL
// does not change, so pairing again returns to the same page.
export function App() {
  const [auth, setAuth] = useState<Auth>({ state: "checking" });
  const check = useCallback((expired = false) => {
    getJSON<AuthSession>("/console/auth/session")
      .then((s) => setAuth(s.paired ? { state: "paired", expiresAt: s.expires_at } : { state: "unpaired", expired }))
      .catch((e: unknown) => setAuth({ state: "error", message: String(e) }));
  }, []);
  useEffect(() => check(), [check]);
  useEffect(() => onSessionEnded(() => setAuth({ state: "unpaired", expired: true })), []);
  const logout = useCallback(() => {
    postJSON("/console/auth/logout", {}).finally(() => setAuth({ state: "unpaired", expired: false }));
  }, []);

  if (auth.state === "checking") return <Loading what="console" />;
  if (auth.state === "error")
    return (
      <div className="pair-shell">
        <div className="notice error" role="alert">
          The console process did not answer: {auth.message}
        </div>
      </div>
    );
  if (auth.state === "unpaired") return <Pair expired={auth.expired} onPaired={() => check()} />;
  return (
    <Layout onLogout={logout}>
      <Routes>
        <Route path="/" element={<Navigate to="/overview" replace />} />
        <Route path="/index.html" element={<Navigate to="/overview" replace />} />
        <Route path="/overview" element={<Overview />} />
        <Route path="/use-cases" element={<UseCases />} />
        <Route path="/use-cases/:name" element={<UseCaseDetail />} />
        <Route path="/sessions" element={<Sessions />} />
        <Route path="/sessions/:id" element={<SessionDetail />} />
        <Route path="/evidence/:id" element={<EvidencePage />} />
        <Route path="/costs" element={<Costs />} />
        <Route path="/configuration" element={<Configuration />} />
        <Route path="/system" element={<System expiresAt={auth.expiresAt} onLogout={logout} />} />
        <Route path="*" element={<NotFound />} />
      </Routes>
    </Layout>
  );
}
