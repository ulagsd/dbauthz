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

// --- forms -----------------------------------------------------------------

// fillSelect rebuilds a <select> from a list of names, preserving whatever was
// selected before so a background refresh does not wipe a half-finished form.
function fillSelect(sel, names, selected) {
  const keep = selected ?? new Set([...sel.selectedOptions].map((o) => o.value));
  sel.innerHTML = names.map((n) =>
    `<option value="${esc(n)}"${keep.has(n) ? " selected" : ""}>${esc(n)}</option>`).join("");
}

const selectedOf = (sel) => [...sel.selectedOptions].map((o) => o.value);

// runForm wraps the shared shape of all three flows: disable the buttons, post,
// render the plan, surface a generated password once, refresh what changed.
async function runForm(opts) {
  const { buttons, out, request, after } = opts;
  buttons.forEach((b) => { b.disabled = true; });
  out.innerHTML = `<p class="muted">working\u2026</p>`;

  try {
    const res = await request();
    let html = renderPlan(res.plan, res.applied ? "Applied" : "Planned, nothing applied");

    if (res.generated_password) {
      // Shown once. db-iam keeps no copy and PostgreSQL stores only a
      // verifier, so there is nothing to read it back from.
      html += `<div class="reveal mt-md">
        <b>Generated password \u2014 shown once</b>
        <pre class="mt-sm">${esc(res.generated_password)}</pre>
        <span class="muted">Nothing stores this. Close the page and it is gone.</span>
      </div>`;
    }
    if (res.applied) {
      html += `<p class="${res.verified ? "ok" : "substitute"} mb-0">
        ${res.verified ? "\u2713 applied and verified against the database"
          : "applied, but could not be verified"}</p>`;
    }
    for (const w of res.warnings || []) html += `<p class="note">${esc(w)}</p>`;
    out.innerHTML = html;

    if (res.applied && after) after();
  } catch (e) {
    let html = `<p class="err">${esc(e.message)}</p>`;
    if (e.body && e.body.warning) html += `<p class="note">${esc(e.body.warning)}</p>`;
    if (e.body && e.body.plan) html += renderPlan(e.body.plan, "Plan that failed");
    out.innerHTML = html;
  } finally {
    buttons.forEach((b) => { b.disabled = false; });
  }
}

// --- main ------------------------------------------------------------------

async function main() {
  let target;
  try {
    const { targets } = await get("/api/v1/targets");
    if (!targets.length) throw new Error("no targets configured");
    target = targets[0];
    $("targetline").innerHTML =
      `<span class="mono">${esc(target.id)}</span> \u00b7 ${esc(target.engine)} \u00b7 ` +
      `<span class="mono muted">${esc(target.connection)}</span>`;
  } catch (e) {
    $("targetline").innerHTML = `<span class="err">${esc(e.message)}</span>`;
    for (const id of PANELS) fail(id, e);
    return;
  }

  const base = `/api/v1/targets/${encodeURIComponent(target.id)}`;

  get(`${base}/capabilities`).then(renderCaps).catch((e) => fail("caps", e));

  // Principals drive three selects, so they are fetched once and shared.
  // membership maps a user to the roles it currently holds, which is what lets
  // the assign form send only a difference.
  let membership = new Map();

  const refreshPrincipals = async () => {
    const [users, roles] = await Promise.all([
      get(`${base}/users`), get(`${base}/roles`),
    ]);

    // The role db-iam connects as is excluded from every picker: a change that
    // locked it out could not be undone from here, and the server refuses it
    // anyway. Better not to offer it than to explain the refusal afterwards.
    const roleNames = roles.principals.filter((p) => !p.self).map((p) => p.name);
    const userNames = users.principals.filter((p) => !p.self).map((p) => p.name);

    membership = new Map(users.principals.map((p) => [p.name, new Set(p.member_of)]));

    fillSelect($("r-parents"), roleNames);
    fillSelect($("u-roles"), roleNames);

    const userSel = $("a-user");
    const chosen = userSel.value;
    userSel.innerHTML = userNames.map((n) =>
      `<option value="${esc(n)}"${n === chosen ? " selected" : ""}>${esc(n)}</option>`).join("");
    syncAssignRoles(roleNames);
  };

  let allRoleNames = [];
  function syncAssignRoles(roleNames) {
    if (roleNames) allRoleNames = roleNames;
    const held = membership.get($("a-user").value) || new Set();
    fillSelect($("a-roles"), allRoleNames, held);
  }

  const refreshSnapshot = () =>
    get(`${base}/snapshot`)
      .then((s) => { renderSummary(s); renderRoles(s); renderGrants(s); renderObjects(s); })
      .catch((e) => { for (const id of ["summary", "roles", "grants", "objects"]) fail(id, e); });

  const refreshAudit = () => get("/api/v1/audit").then(renderAudit).catch((e) => fail("audit", e));

  const refreshAll = () => { refreshPrincipals(); refreshSnapshot(); refreshAudit(); };
  refreshAll();

  $("a-user").addEventListener("change", () => syncAssignRoles());

  // --- 1. create role ------------------------------------------------------

  const roleForm = $("roleform");
  const roleRequest = (dryRun) => post(`${base}/roles`, {
    name: $("r-name").value.trim(),
    roles: selectedOf($("r-parents")),
    dry_run: dryRun,
  });
  const submitRole = (dryRun) => runForm({
    buttons: [$("r-plan"), $("r-create")],
    out: $("roleresult"),
    request: () => roleRequest(dryRun),
    after: () => { $("r-name").value = ""; refreshAll(); },
  });

  $("r-plan").addEventListener("click", () => submitRole(true));
  roleForm.addEventListener("submit", (ev) => { ev.preventDefault(); submitRole(false); });

  // --- 2. create user ------------------------------------------------------

  const userForm = $("userform");
  const userRequest = (dryRun) => post(`${base}/users`, {
    name: $("u-name").value.trim(),
    password: $("u-password").value, // empty asks the server to generate one
    roles: selectedOf($("u-roles")),
    inherit: $("u-inherit").checked,
    connection_limit: parseInt($("u-limit").value, 10),
    dry_run: dryRun,
  });
  const submitUser = (dryRun) => runForm({
    buttons: [$("u-plan"), $("u-create")],
    out: $("userresult"),
    request: () => userRequest(dryRun),
    after: () => { $("u-name").value = ""; $("u-password").value = ""; refreshAll(); },
  });

  $("u-plan").addEventListener("click", () => submitUser(true));
  userForm.addEventListener("submit", (ev) => { ev.preventDefault(); submitUser(false); });

  // --- 3. assign roles -----------------------------------------------------

  const assignForm = $("assignform");

  function membershipDiff() {
    const user = $("a-user").value;
    const held = membership.get(user) || new Set();
    const want = new Set(selectedOf($("a-roles")));
    return {
      user,
      grant: [...want].filter((r) => !held.has(r)),
      revoke: [...held].filter((r) => want.has(r) === false && allRoleNames.includes(r)),
    };
  }

  const submitAssign = (dryRun) => {
    const { user, grant, revoke } = membershipDiff();
    if (!user) return;
    if (!grant.length && !revoke.length) {
      $("assignresult").innerHTML =
        `<p class="muted mb-0">Nothing to change: that is already the membership.</p>`;
      return;
    }
    return runForm({
      buttons: [$("a-plan"), $("a-save")],
      out: $("assignresult"),
      request: () => post(`${base}/users/${encodeURIComponent(user)}/roles`,
        { grant, revoke, dry_run: dryRun }),
      after: refreshAll,
    });
  };

  $("a-plan").addEventListener("click", () => submitAssign(true));
  assignForm.addEventListener("submit", (ev) => { ev.preventDefault(); submitAssign(false); });
}

main();
