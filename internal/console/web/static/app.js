// Console shell: pairing and a connection panel. No credential ever enters a
// URL, the DOM or browser storage; the session is an HttpOnly cookie the
// server validates on every request.
(function () {
  "use strict";
  var $ = function (id) { return document.getElementById(id); };
  var pair = $("pair"), connected = $("connected"), fatal = $("fatal");

  function show(el) { el.hidden = false; }
  function hide(el) { el.hidden = true; }
  function text(id, v) { $(id).textContent = v; }

  function api(path, opts) {
    opts = opts || {};
    opts.credentials = "same-origin";
    opts.headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
    return fetch(path, opts).then(function (res) {
      return res.text().then(function (body) {
        var data = null;
        try { data = body ? JSON.parse(body) : null; } catch (e) { data = null; }
        return { status: res.status, ok: res.ok, data: data };
      });
    });
  }

  function failure(r, fallback) {
    if (r.data && r.data.message) { return r.data.message + " (" + (r.data.error || r.status) + ")"; }
    return fallback + " (HTTP " + r.status + ")";
  }

  function renderSystem(expiresAt) {
    return api("/console/v1/system").then(function (r) {
      if (!r.ok) { throw new Error(failure(r, "system facts unavailable")); }
      var s = r.data;
      text("f-console", "v" + s.console.version + (s.console.commit ? " (" + s.console.commit.slice(0, 7) + ")" : "") + ", amounts in " + s.console.currency);
      var st = s.store;
      text("f-store", st.path + (st.read_only ? " (read-only)" : "") + (st.availability.state !== "ok" ? " — " + st.availability.state + (st.availability.error ? ": " + st.availability.error : "") : ""));
      text("f-records", st.availability.state === "ok" ? String(st.record_count) + (st.newest_record ? ", newest " + st.newest_record : "") : "unavailable");
      text("f-runtime", s.runtime.availability.state + (s.runtime.availability.note ? " — " + s.runtime.availability.note : ""));
      text("f-expires", expiresAt || "unknown");
    });
  }

  function boot() {
    api("/console/auth/session").then(function (r) {
      if (!r.ok) { throw new Error(failure(r, "console unreachable")); }
      if (r.data && r.data.paired) {
        hide(pair); show(connected);
        return renderSystem(r.data.expires_at);
      }
      hide(connected); show(pair); $("code").focus();
      return null;
    }).catch(function (e) { fatal.textContent = String(e.message || e); show(fatal); });
  }

  $("pair-form").addEventListener("submit", function (ev) {
    ev.preventDefault();
    var err = $("pair-error"), btn = ev.target.querySelector("button"), input = $("code");
    hide(err); btn.disabled = true;
    api("/console/auth/pair", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ code: input.value }) })
      .then(function (r) {
        input.value = "";
        if (!r.ok) { err.textContent = failure(r, "pairing failed"); show(err); return; }
        boot();
      })
      .catch(function (e) { err.textContent = String(e.message || e); show(err); })
      .then(function () { btn.disabled = false; });
  });

  $("logout").addEventListener("click", function () {
    api("/console/auth/logout", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" }).then(boot);
  });

  boot();
})();
