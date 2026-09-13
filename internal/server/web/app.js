// db-iam console.
//
// Plain ES modules-free JavaScript, loaded as an external file so the page can
// run under a Content-Security-Policy with no 'unsafe-inline'. Everything it
// builds goes through esc(): the values below are role names and object names
// read from somebody's database, which is exactly the kind of text that should
// never be interpolated into markup unescaped.

const $ = (id) => document.getElementById(id);

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const PANELS = ["caps", "summary", "roles", "grants", "objects", "audit"];

async function get(path) {
  const r = await fetch(path);
  const body = await r.json().catch(() => ({ error: `${r.status} ${r.statusText}` }));
  if (!r.ok) throw new Error(body.error || `${r.status} ${r.statusText}`);
  return body;
}

async function post(path, payload) {
  const r = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const body = await r.json().catch(() => ({ error: `${r.status} ${r.statusText}` }));
  if (!r.ok) {
    const e = new Error(body.error || `${r.status} ${r.statusText}`);
    e.body = body;
    throw e;
  }
  return body;
}

function fail(id, err) {
  $(id).innerHTML = `<p class="err">${esc(err.message)}</p>`;
}

// --- capabilities ----------------------------------------------------------

const supportClass = (v) =>
  ({ native: "native", substitute: "substitute", none: "none" }[v] || "muted");

function renderCaps(c) {
  const row = (label, value, cls) =>
    `<tr><td>${esc(label)}</td><td class="${cls || ""}">${esc(value)}</td></tr>`;
  const yn = (b) => (b ? "yes" : "no");

  let html = `<table><tbody>
    ${row("Engine", c.Engine)}
    ${row("Version", c.Version)}
    ${row("Managed flavour", c.Flavor || "vanilla")}
    ${row("Hierarchy", (c.Levels || []).join(" › "))}
    ${row("Column grants", c.ColumnGrants, supportClass(c.ColumnGrants))}
    ${row("Row filters", c.RowFilters, supportClass(c.RowFilters))}
    ${row("Masking", c.Masking, supportClass(c.Masking))}
    ${row("Persistent DENY", yn(c.NativeDeny), c.NativeDeny ? "" : "muted")}
    ${row("Future grants", yn(c.FutureGrants))}
    ${row("Transactional DDL", yn(c.TransactionalDDL))}
    ${row("Connected role is admin", yn(c.Superuser), c.Superuser ? "" : "substitute")}
  </tbody></table>`;

  if (!c.NativeDeny) {
    html += `<p class="note">No persistent DENY on this engine: an IAM-style deny is
      resolved when the plan is built, by withholding the grant. See ARCHITECTURE §7.</p>`;
  }
  for (const n of c.Notes || []) html += `<p class="note">${esc(n)}</p>`;
  $("caps").innerHTML = html;
}

// --- observed state --------------------------------------------------------

function renderSummary(s) {
  const st = (n, label) => `<div class="stat"><b>${esc(n)}</b><span>${esc(label)}</span></div>`;

  let html = `<div class="stats">
    ${st(s.summary.principals, "roles")}
    ${st(s.summary.objects, "objects")}
    ${st(s.summary.grants - s.summary.owner_grants, "manageable grants")}
    ${st(s.summary.owner_grants, "held by owners")}
    ${st(s.summary.public_grants, "held by PUBLIC")}
  </div>
  <dl class="kv mt-lg">
    <dt>snapshot</dt><dd class="mono">${esc(s.version)}</dd>
    <dt>taken at</dt><dd class="mono">${esc(s.taken_at)}</dd>
  </dl>`;

  if (s.summary.public_grants > 0) {
    html += `<p class="note">PUBLIC is an implicit grantee on newly created objects.
      Authoritative mode revokes these first.</p>`;
  }
  $("summary").innerHTML = html;
}

function renderRoles(s) {
  const rows = s.principals.map((p) => `<tr>
    <td class="mono">${esc(p.name)}</td>
    <td>${p.login ? "login" : '<span class="muted">no login</span>'}</td>
    <td>${p.inherit ? "inherit" : '<span class="muted">noinherit</span>'}</td>
    <td>${p.member_of.map((m) => `<span class="chip mono">${esc(m)}</span>`).join("") ||
      '<span class="muted">—</span>'}</td>
  </tr>`).join("");

  $("roles").innerHTML = `<table>
    <thead><tr><th>role</th><th>login</th><th>inheritance</th><th>member of</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="4" class="muted">none</td></tr>'}</tbody></table>`;
}

function renderGrants(s) {
  const rows = s.grants.map((g) => `<tr class="${g.implicit ? "dim" : ""}">
    <td class="mono">${esc(g.grantee)}${
      g.grantee === "PUBLIC" ? ' <span class="chip substitute">PUBLIC</span>'
        : g.implicit ? ' <span class="chip">owner</span>' : ""}</td>
    <td class="mono">${esc(g.action)}</td>
    <td class="mono">${esc(g.schema)}.${esc(g.object)}</td>
    <td>${g.columns.length
      ? g.columns.map((c) => `<span class="chip mono">${esc(c)}</span>`).join("")
      : '<span class="muted">all columns</span>'}</td>
  </tr>`).join("");

  $("grants").innerHTML = `<table>
    <thead><tr><th>grantee</th><th>action</th><th>object</th><th>columns</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="4" class="muted">no explicit grants</td></tr>'}</tbody></table>
    <p class="note">Rows marked <span class="chip">owner</span> are privileges held by owning the
    object. PostgreSQL materialises these into the ACL as soon as any grant is made, but revoking
    one breaks the owner, so no reconcile mode proposes it.</p>`;
}

function renderObjects(s) {
  const rows = s.objects.map((o) => `<tr>
    <td class="mono">${esc(o.schema)}.${esc(o.name)}</td>
    <td><span class="chip">${esc(o.kind)}</span></td>
    <td class="mono">${esc(o.owner)}</td>
    <td>${o.rls ? '<span class="native">enabled</span>' : '<span class="muted">off</span>'}</td>
    <td class="muted">${esc(o.columns.length || "—")}</td>
  </tr>`).join("");

  $("objects").innerHTML = `<table>
    <thead><tr><th>object</th><th>kind</th><th>owner</th><th>row security</th><th>columns</th></tr></thead>
    <tbody>${rows || '<tr><td colspan="5" class="muted">none</td></tr>'}</tbody></table>`;
}

// --- audit -----------------------------------------------------------------

function renderAudit(a) {
  if (!a.count) {
    $("audit").innerHTML = `<p class="muted mt-0">Nothing recorded yet.</p>`;
    return;
  }
  const rows = a.records.map((r) => `<tr>
    <td class="mono">${esc(r.seq)}</td>
    <td class="mono muted">${esc(String(r.at).replace("T", " ").slice(0, 19))}</td>
    <td class="mono">${esc(r.action)}</td>
    <td class="mono">${esc(r.intent && r.intent.name ? r.intent.name : "—")}</td>
    <td>${r.effect && r.effect.error
      ? '<span class="err">failed</span>'
      : `<span class="ok">${esc((r.effect && r.effect.executed) || 0)} statements</span>`}</td>
    <td class="mono muted">${esc(String(r.hash).slice(0, 12))}…</td>
  </tr>`).join("");

  $("audit").innerHTML = `
    <p class="${a.chain_valid ? "ok" : "err"} mt-0">
      ${a.chain_valid ? "✓ hash chain intact"
        : "✗ hash chain broken: " + esc(a.chain_error)}
      <span class="muted">· ${esc(a.count)} record(s)</span>
    </p>
    <table>
      <thead><tr><th>#</th><th>at</th><th>action</th><th>subject</th><th>effect</th><th>hash</th></tr></thead>
      <tbody>${rows}</tbody>
    </table>
    <p class="note">${esc(a.note)}</p>`;
}

// --- plans -----------------------------------------------------------------

function renderPlan(plan, heading) {
  const lines = plan.statements.map((st) =>
    `<span class="muted">-- ${esc(st.reason)}</span>\n${esc(st.sql)};`).join("\n\n");

  return `<p class="muted gap-head">${esc(heading)}
      · max risk <b>${esc(plan.max_risk)}</b>
      · <span class="mono">${esc(String(plan.hash).slice(0, 12))}…</span></p>
    <pre>${lines}</pre>`;
}

// --- main ------------------------------------------------------------------

async function main() {
  let target;
  try {
    const { targets } = await get("/api/v1/targets");
    if (!targets.length) throw new Error("no targets configured");
    target = targets[0];
    $("targetline").innerHTML =
      `<span class="mono">${esc(target.id)}</span> · ${esc(target.engine)} · ` +
      `<span class="mono muted">${esc(target.connection)}</span>`;
  } catch (e) {
    $("targetline").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    for (const id of PANELS) fail(id, e);
    return;
  }

  const base = `/api/v1/targets/${encodeURIComponent(target.id)}`;

  get(`${base}/capabilities`).then(renderCaps).catch((e) => fail("caps", e));

  const refreshSnapshot = () =>
    get(`${base}/snapshot`)
      .then((s) => {
        renderSummary(s); renderRoles(s); renderGrants(s); renderObjects(s);
        // Keep the "member of" choices in step with what actually exists.
        const sel = $("f-memberof");
        const chosen = new Set([...sel.selectedOptions].map((o) => o.value));
        sel.innerHTML = s.principals.map((p) =>
          `<option value="${esc(p.name)}"${chosen.has(p.name) ? " selected" : ""}>` +
          `${esc(p.name)}</option>`).join("");
      })
      .catch((e) => { for (const id of ["summary", "roles", "grants", "objects"]) fail(id, e); });

  const refreshAudit = () => get("/api/v1/audit").then(renderAudit).catch((e) => fail("audit", e));

  refreshSnapshot();
  refreshAudit();

  // --- create role ---------------------------------------------------------

  const form = $("roleform");
  const out = $("roleresult");

  const payload = (dryRun) => ({
    name: $("f-name").value.trim(),
    login: $("f-login").checked,
    inherit: $("f-inherit").checked,
    password: $("f-password").value, // empty asks the server to generate one
    connection_limit: parseInt($("f-limit").value, 10),
    member_of: [...$("f-memberof").selectedOptions].map((o) => o.value),
    dry_run: dryRun,
  });

  async function submit(dryRun) {
    const buttons = [$("f-plan"), $("f-create")];
    buttons.forEach((b) => { b.disabled = true; });
    out.innerHTML = `<p class="muted">working…</p>`;

    try {
      const res = await post(`${base}/users`, payload(dryRun));
      let html = renderPlan(res.plan, dryRun ? "Planned, nothing applied" : "Applied");

      if (res.generated_password) {
        // Shown once. db-iam keeps no copy and PostgreSQL stores only a
        // verifier, so there is nothing to read it back from.
        html += `<div class="reveal mt-md">
          <b>Generated password — shown once</b>
          <pre class="mt-sm">${esc(res.generated_password)}</pre>
          <span class="muted">Nothing stores this. Close the page and it is gone.</span>
        </div>`;
      }
      if (res.applied) {
        html += `<p class="${res.verified ? "ok" : "substitute"} mb-0">
          ${res.verified ? "✓ created and verified against the database"
            : "created, but could not be verified"}</p>`;
      }
      for (const w of res.warnings || []) html += `<p class="note">${esc(w)}</p>`;
      out.innerHTML = html;

      if (res.applied) { $("f-password").value = ""; refreshSnapshot(); }
      refreshAudit();
    } catch (e) {
      let html = `<p class="err">${esc(e.message)}</p>`;
      if (e.body && e.body.plan) html += renderPlan(e.body.plan, "Plan that failed");
      out.innerHTML = html;
      refreshAudit();
    } finally {
      buttons.forEach((b) => { b.disabled = false; });
    }
  }

  $("f-plan").addEventListener("click", () => submit(true));
  form.addEventListener("submit", (ev) => {
    // Without this the form navigates, the page reloads, and the browser
    // offers to save the password it just saw in a query string.
    ev.preventDefault();
    submit(false);
  });
}

main();
