package server

import (
	"net/http"

	"github.com/ulagsd/db-iam/internal/audit"
	"github.com/ulagsd/db-iam/internal/provider"
)

// Plan rendering and audit. The handlers themselves live in principals.go.

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
func (s *Server) record(_ *http.Request, action audit.Action, target string, intent, effect map[string]any) {
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
}

func (s *Server) handleAudit(w http.ResponseWriter, _ *http.Request) {
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
}
