package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/ulagsd/db-iam/internal/audit"
	"github.com/ulagsd/db-iam/internal/provider"
	"github.com/ulagsd/db-iam/internal/secret"
)

// createUserRequest is the body of POST /api/v1/targets/{id}/users.
type createUserRequest struct {
	Name    string `json:"name"`
	Login   *bool  `json:"login"`   // defaults to true
	Inherit *bool  `json:"inherit"` // defaults to true

	// Password is optional. Omit it on a login role and one is generated and
	// returned once; there is no way to read it back afterwards, because
	// db-iam never holds it.
	Password string `json:"password"`

	ConnectionLimit *int     `json:"connection_limit"` // defaults to -1
	ValidUntil      string   `json:"valid_until"`      // RFC 3339, optional
	MemberOf        []string `json:"member_of"`

	// DryRun returns the plan without executing it. The default is false
	// because this endpoint exists to create a user, but every response
	// carries the plan either way, so nothing is applied unseen.
	DryRun bool `json:"dry_run"`
}

type statementView struct {
	SQL    string `json:"sql"` // redacted; never the executable form
	Risk   string `json:"risk"`
	Reason string `json:"reason"`
}

type planView struct {
	Hash       string          `json:"hash"`
	MaxRisk    string          `json:"max_risk"`
	Statements []statementView `json:"statements"`
}

type createUserResponse struct {
	Applied bool     `json:"applied"`
	Plan    planView `json:"plan"`

	// GeneratedPassword is present only when db-iam generated one. It is shown
	// exactly once: the server keeps the plaintext nowhere, and PostgreSQL
	// stores only a verifier it cannot reverse.
	GeneratedPassword string `json:"generated_password,omitempty"`
	PasswordShownOnce bool   `json:"password_shown_once,omitempty"`

	Verified bool     `json:"verified"`
	Warnings []string `json:"warnings,omitempty"`
}

func (s *Server) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	target, prov, conn, err := s.resolve(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, err)
		return
	}

	var req createUserRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64*1024))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": fmt.Sprintf("invalid request body: %s", err),
		})
		return
	}

	roles, ok := prov.(provider.RoleManager)
	if !ok {
		writeJSON(w, http.StatusNotImplemented, map[string]any{
			"error": fmt.Sprintf("the %s provider cannot create roles", target.Engine),
		})
		return
	}

	ctx, cancel := contextWithTimeout(r, 30*time.Second)
	defer cancel()

	caps, err := prov.Capabilities(ctx, conn)
	if err != nil {
		writeError(w, fmt.Errorf("probing %s: %w", target.ID, err))
		return
	}

	spec, generated, err := buildRoleSpec(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	plan, err := roles.PlanCreateRole(spec, caps)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}

	resp := createUserResponse{Plan: renderPlan(plan)}
	if !caps.Superuser {
		resp.Warnings = append(resp.Warnings,
			"the connected role is not a cluster admin; PostgreSQL may refuse to create roles")
	}

	// The plan is recorded whether or not it runs, so a dry run that is never
	// applied still leaves evidence that someone asked.
	intent := map[string]any{
		"name": spec.Name, "login": spec.Login, "inherit": spec.Inherit,
		"member_of": spec.MemberOf, "dry_run": req.DryRun,
		"password_set": !spec.Password.Empty(), "password_generated": generated != "",
	}

	if req.DryRun {
		s.record(r, audit.ActionPlan, target.ID, intent, map[string]any{
			"plan_hash": plan.Hash, "statements": len(plan.Statements), "applied": false,
		})
		writeJSON(w, http.StatusOK, resp)
		return
	}

	applyRes, applyErr := prov.Apply(ctx, conn, plan)
	effect := map[string]any{
		"plan_hash":  plan.Hash,
		"statements": redactedStatements(plan),
		"executed":   applyRes.Executed, "failed": applyRes.Failed,
		"indeterminate": applyRes.Indeterminate,
	}
	if applyErr != nil {
		effect["error"] = applyErr.Error()
	}
	s.record(r, audit.ActionCreateRole, target.ID, intent, effect)

	if applyErr != nil {
		status := http.StatusConflict // most failures here are "role exists"
		if applyRes.Indeterminate {
			status = http.StatusInternalServerError
			resp.Warnings = append(resp.Warnings,
				"the target has no transaction to undo this and some statements ran; "+
					"its state is unknown until the next reconcile")
		}
		writeJSON(w, status, map[string]any{
			"error": applyErr.Error(), "plan": resp.Plan,
			"indeterminate": applyRes.Indeterminate,
		})
		return
	}

	resp.Applied = true

	// Trust the observed database, not the absence of an error.
	if v, err := prov.Verify(ctx, conn, plan); err != nil {
		resp.Warnings = append(resp.Warnings, "could not verify the role was created: "+err.Error())
	} else if !v.Converged {
		resp.Warnings = append(resp.Warnings, v.Divergence...)
	} else {
		resp.Verified = true
	}

	if generated != "" {
		resp.GeneratedPassword = generated.Reveal()
		resp.PasswordShownOnce = true
	}
	writeJSON(w, http.StatusCreated, resp)
}

// buildRoleSpec validates the request and fills in the defaults.
//
// Returns the generated password separately from the spec so that the only way
// it reaches a response is an explicit assignment, rather than riding along
// inside a struct someone later marshals.
func buildRoleSpec(req createUserRequest) (provider.RoleSpec, secret.Text, error) {
	spec := provider.RoleSpec{
		Name:            req.Name,
		Login:           boolOr(req.Login, true),
		Inherit:         boolOr(req.Inherit, true),
		ConnectionLimit: intOr(req.ConnectionLimit, -1),
		MemberOf:        req.MemberOf,
	}

	if req.ValidUntil != "" {
		t, err := time.Parse(time.RFC3339, req.ValidUntil)
		if err != nil {
			return spec, "", fmt.Errorf("valid_until must be RFC 3339: %w", err)
		}
		spec.ValidUntil = t
	}

	var generated secret.Text
	switch {
	case req.Password != "":
		spec.Password = secret.Text(req.Password)
	case spec.Login:
		// A login role with no password can only authenticate another way.
		// Generating one is the safer default than creating a role that
		// quietly cannot connect.
		p, err := secret.GeneratePassword()
		if err != nil {
			return spec, "", err
		}
		spec.Password, generated = p, p
	}
	return spec, generated, nil
}

func renderPlan(p *provider.Plan) planView {
	out := planView{Hash: p.Hash, MaxRisk: p.MaxRisk().String()}
	for _, st := range p.Statements {
		out.Statements = append(out.Statements, statementView{
			SQL: st.Redacted(), Risk: st.Risk.String(), Reason: st.Reason,
		})
	}
	return out
}

func redactedStatements(p *provider.Plan) []string {
	out := make([]string, 0, len(p.Statements))
	for _, st := range p.Statements {
		out = append(out, st.Redacted())
	}
	return out
}

// record appends to the audit log. A failure to record is logged loudly rather
// than returned: the change has already happened, and losing the record is
// worse news than the request failing.
func (s *Server) record(r *http.Request, action audit.Action, target string, intent, effect map[string]any) {
	_, err := s.audit.Append(audit.Record{
		// There is no authentication yet, so there is no actor to name. Saying
		// so is better than inventing one.
		Actor:  "anonymous (no authentication in this build)",
		Action: action,
		Target: target,
		Intent: intent,
		Effect: effect,
	})
	if err != nil {
		s.log.Error("AUDIT RECORD LOST", "action", action, "target", target, "err", err)
	}
	_ = r
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	chainErr := s.audit.Verify()
	body := map[string]any{
		"records":     s.audit.List(100),
		"count":       s.audit.Len(),
		"chain_valid": chainErr == nil,
		"durable":     false,
		"note": "in-memory and lost on restart; the control-plane store is what " +
			"makes this durable",
	}
	if chainErr != nil {
		body["chain_error"] = chainErr.Error()
	}
	writeJSON(w, http.StatusOK, body)
	_ = r
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
