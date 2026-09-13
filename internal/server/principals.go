package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/ulagsd/db-iam/internal/audit"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/secret"
)

// db-iam separates the two things PostgreSQL keeps in one table.
//
// A user is a principal that authenticates. A role is a named bundle of
// privilege that users belong to. In pg_authid both are rows and the only
// difference is rolcanlogin, which is why a single "create role" form leads
// people to make login roles they meant as groups and vice versa. The split
// is enforced by the endpoint rather than a flag in the body: POST /roles
// cannot produce something that can log in, and POST /users cannot produce
// something that cannot.

type createRoleRequest struct {
	Name    string   `json:"name"`
	Roles   []string `json:"roles"` // roles this role is itself a member of
	Comment string   `json:"comment"`
	DryRun  bool     `json:"dry_run"`
}

type createUserRequest struct {
	Name string `json:"name"`

	// Password is optional. Omit it and one is generated and returned once;
	// there is no way to read it back, because db-iam keeps no copy.
	Password string `json:"password"`

	Roles           []string `json:"roles"`
	Inherit         *bool    `json:"inherit"`          // defaults to true
	ConnectionLimit *int     `json:"connection_limit"` // defaults to -1
	ValidUntil      string   `json:"valid_until"`      // RFC 3339, optional
	Comment         string   `json:"comment"`
	DryRun          bool     `json:"dry_run"`
}

type membershipRequest struct {
	Grant  []string `json:"grant"`
	Revoke []string `json:"revoke"`
	DryRun bool     `json:"dry_run"`
}

type principalView struct {
	Name     string   `json:"name"`
	Login    bool     `json:"login"`
	Inherit  bool     `json:"inherit"`
	MemberOf []string `json:"member_of"`
	Managed  bool     `json:"managed"`
	Builtin  bool     `json:"builtin"`
	Self     bool     `json:"self"` // the role db-iam connects as
}

// --- create ---------------------------------------------------------------

func (s *Server) handleCreateRole(w http.ResponseWriter, r *http.Request) {
	var req createRoleRequest
	if !decodeBody(w, r, &req) {
		return
	}
	s.createPrincipal(w, r, provider.RoleSpec{
		Name: req.Name,
		// A group role carries privilege and is never authenticated as, so it
		// gets no password and no way to use one.
		Login:           false,
		Inherit:         true,
		ConnectionLimit: -1,
		MemberOf:        req.Roles,
		Comment:         req.Comment,
	}, req.DryRun)
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if !decodeBody(w, r, &req) {
		return
	}

	spec := provider.RoleSpec{
		Name:            req.Name,
		Login:           true,
		Inherit:         boolOr(req.Inherit, true),
		ConnectionLimit: intOr(req.ConnectionLimit, -1),
		MemberOf:        req.Roles,
		Comment:         req.Comment,
	}
	if req.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, req.ValidUntil)
		if err != nil {
			badRequest(w, fmt.Errorf("valid_until must be RFC 3339: %w", err))
			return
		}
		spec.ValidUntil = t
	}

	if req.Password != "" {
		spec.Password = secret.Text(req.Password)
		s.createPrincipal(w, r, spec, req.DryRun)
		return
	}

	// A login role with no password can only authenticate by certificate,
	// cloud IAM or peer. Generating one is the safer default than quietly
	// creating a user that cannot connect.
	generated, err := secret.GeneratePassword()
	if err != nil {
		writeError(w, err)
		return
	}
	spec.Password = generated
	s.createPrincipalWithSecret(w, r, spec, req.DryRun, generated)
}

func (s *Server) createPrincipal(w http.ResponseWriter, r *http.Request, spec provider.RoleSpec, dryRun bool) {
	s.createPrincipalWithSecret(w, r, spec, dryRun, "")
}

func (s *Server) createPrincipalWithSecret(
	w http.ResponseWriter, r *http.Request,
	spec provider.RoleSpec, dryRun bool, generated secret.Text,
) {
	target, roles, prov, conn, caps, ok := s.resolveRoleManager(w, r)
	if !ok {
		return
	}

	plan, err := roles.PlanCreateRole(spec, caps)
	if err != nil {
		badRequest(w, err)
		return
	}

	kind := "role"
	if spec.Login {
		kind = "user"
	}
	intent := map[string]any{
		"kind": kind, "name": spec.Name, "login": spec.Login,
		"roles": spec.MemberOf, "dry_run": dryRun,
		"password_generated": !generated.Empty(),
	}

	resp := s.runPlan(w, r, runContext{
		target: target.ID, prov: prov, conn: conn,
		plan: plan, dryRun: dryRun, action: audit.ActionCreateRole, intent: intent,
	})
	if resp == nil {
		return
	}
	if !generated.Empty() && resp.Applied {
		resp.GeneratedPassword = generated.Reveal()
		resp.PasswordShownOnce = true
	}
	status := http.StatusCreated
	if dryRun {
		status = http.StatusOK
	}
	writeJSON(w, status, resp)
}

// --- membership ------------------------------------------------------------

func (s *Server) handleMembership(w http.ResponseWriter, r *http.Request) {
	var req membershipRequest
	if !decodeBody(w, r, &req) {
		return
	}
	target, roles, prov, conn, caps, ok := s.resolveRoleManager(w, r)
	if !ok {
		return
	}

	member := r.PathValue("name")
	plan, err := roles.PlanMembership(provider.MembershipChange{
		Member: member, Grant: req.Grant, Revoke: req.Revoke,
	}, caps)
	if err != nil {
		badRequest(w, err)
		return
	}

	resp := s.runPlan(w, r, runContext{
		target: target.ID, prov: prov, conn: conn,
		plan: plan, dryRun: req.DryRun, action: audit.ActionMembership,
		intent: map[string]any{
			"name": member, "grant": req.Grant, "revoke": req.Revoke, "dry_run": req.DryRun,
		},
	})
	if resp == nil {
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// --- list ------------------------------------------------------------------

func (s *Server) handleListUsers(w http.ResponseWriter, r *http.Request) {
	s.listPrincipals(w, r, func(p principalView) bool { return p.Login })
}

func (s *Server) handleListRoles(w http.ResponseWriter, r *http.Request) {
	s.listPrincipals(w, r, func(p principalView) bool { return !p.Login })
}

func (s *Server) listPrincipals(w http.ResponseWriter, r *http.Request, keep func(principalView) bool) {
	target, prov, conn, err := s.resolve(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}
	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()

	caps, err := prov.Capabilities(ctx, conn)
	if err != nil {
		writeError(w, fmt.Errorf("probing %s: %w", target.ID, err))
		return
	}
	snap, err := prov.Introspect(ctx, conn, scopeFor(target), "")
	if err != nil {
		writeError(w, fmt.Errorf("introspecting %s: %w", target.ID, err))
		return
	}

	out := make([]principalView, 0, len(snap.Principals))
	for _, p := range snap.Principals {
		v := principalToView(p, caps.ConnectedRole)
		if keep(v) {
			out = append(out, v)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"principals": out, "count": len(out)})
}

// --- shared ----------------------------------------------------------------

type runContext struct {
	target string
	prov   provider.Provider
	conn   TargetConn
	plan   *provider.Plan
	dryRun bool
	action audit.Action
	intent map[string]any
}

// runPlan records the plan, applies it unless this is a dry run, verifies the
// result and records the effect. It writes the error response itself and
// returns nil when the caller should stop.
func (s *Server) runPlan(w http.ResponseWriter, r *http.Request, rc runContext) *changeResponse {
	resp := &changeResponse{Plan: renderPlan(rc.plan)}

	if rc.dryRun {
		s.record(r, audit.ActionPlan, rc.target, rc.intent, map[string]any{
			"plan_hash": rc.plan.Hash, "statements": len(rc.plan.Statements), "applied": false,
		})
		return resp
	}

	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()

	applyRes, applyErr := rc.prov.Apply(ctx, rc.conn, rc.plan)
	effect := map[string]any{
		"plan_hash":     rc.plan.Hash,
		"statements":    redactedStatements(rc.plan),
		"executed":      applyRes.Executed,
		"failed":        applyRes.Failed,
		"indeterminate": applyRes.Indeterminate,
	}
	if applyErr != nil {
		effect["error"] = applyErr.Error()
	}
	s.record(r, rc.action, rc.target, rc.intent, effect)

	if applyErr != nil {
		status := http.StatusConflict
		if applyRes.Indeterminate {
			status = http.StatusInternalServerError
		}
		body := map[string]any{
			"error": applyErr.Error(), "plan": resp.Plan,
			"indeterminate": applyRes.Indeterminate,
		}
		if applyRes.Indeterminate {
			body["warning"] = "the target has no transaction to undo this and some statements " +
				"ran; its state is unknown until the next reconcile"
		}
		writeJSON(w, status, body)
		return nil
	}

	resp.Applied = true
	if v, err := rc.prov.Verify(ctx, rc.conn, rc.plan); err != nil {
		resp.Warnings = append(resp.Warnings, "could not verify the change: "+err.Error())
	} else if !v.Converged {
		resp.Warnings = append(resp.Warnings, v.Divergence...)
	} else {
		resp.Verified = true
	}
	return resp
}

type changeResponse struct {
	Applied  bool     `json:"applied"`
	Verified bool     `json:"verified"`
	Plan     planView `json:"plan"`

	GeneratedPassword string `json:"generated_password,omitempty"`
	PasswordShownOnce bool   `json:"password_shown_once,omitempty"`

	Warnings []string `json:"warnings,omitempty"`
}

func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	// An unknown field is rejected rather than ignored: silently dropping
	// something like "superuser": true would let a caller believe they asked
	// for what they did not get.
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		badRequest(w, fmt.Errorf("invalid request body: %w", err))
		return false
	}
	return true
}

func badRequest(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
}

func principalToView(p provider.ObservedPrincipal, connectedRole string) principalView {
	slices.Sort(p.MemberOf)
	return principalView{
		Name: p.Name, Login: p.Login, Inherit: p.Inherit,
		MemberOf: nonNil(p.MemberOf),
		Managed:  p.Managed,
		Builtin:  len(p.Name) > 3 && p.Name[:3] == "pg_",
		Self:     p.Name == connectedRole,
	}
}

func boolOr(p *bool, fallback bool) bool {
	if p == nil {
		return fallback
	}
	return *p
}

func intOr(p *int, fallback int) int {
	if p == nil {
		return fallback
	}
	return *p
}
