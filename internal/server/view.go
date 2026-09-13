package server

import (
	"sort"

	"github.com/ulagsd/db-iam/internal/core"
	"github.com/ulagsd/db-iam/internal/provider"
)

// The JSON shapes below are deliberately separate from the domain types. The
// console is a client like any other, and letting it read internal structs
// directly is how private fields end up in a browser.

type objectView struct {
	Path    string   `json:"path"`
	Kind    string   `json:"kind"`
	Schema  string   `json:"schema"`
	Name    string   `json:"name"`
	Owner   string   `json:"owner"`
	RLS     bool     `json:"rls"`
	Columns []string `json:"columns"`
}

type grantView struct {
	Grantee  string   `json:"grantee"`
	Action   string   `json:"action"`
	Path     string   `json:"path"`
	Schema   string   `json:"schema"`
	Object   string   `json:"object"`
	Columns  []string `json:"columns"`
	Implicit bool     `json:"implicit"`
}

type snapshotSummary struct {
	Principals int `json:"principals"`
	Objects    int `json:"objects"`
	Grants     int `json:"grants"`
	// PublicGrants counts privileges held by the PUBLIC pseudo-role. It is
	// surfaced on its own because PUBLIC is an implicit grantee on new objects
	// and is the most commonly overlooked path to unintended read access.
	PublicGrants int `json:"public_grants"`
	// OwnerGrants counts privileges held by virtue of owning the object.
	// Separating them keeps the count of grants a policy could actually manage
	// from being swamped by ownership.
	OwnerGrants int `json:"owner_grants"`
}

type snapshotResponse struct {
	Target     string          `json:"target"`
	Version    int64           `json:"version"`
	TakenAt    string          `json:"taken_at"`
	Summary    snapshotSummary `json:"summary"`
	Principals []principalView `json:"principals"`
	Objects    []objectView    `json:"objects"`
	Grants     []grantView     `json:"grants"`
}

func snapshotView(s *provider.Snapshot, connectedRole string) snapshotResponse {
	out := snapshotResponse{
		Target:     s.Target.Name,
		Version:    s.Version,
		TakenAt:    s.TakenAt.Format("2006-01-02T15:04:05Z"),
		Principals: make([]principalView, 0, len(s.Principals)),
		Objects:    make([]objectView, 0, len(s.Objects)),
		Grants:     make([]grantView, 0, len(s.Grants)),
	}

	for _, p := range s.Principals {
		out.Principals = append(out.Principals, principalToView(p, connectedRole))
	}

	for _, o := range s.Objects {
		schema, name, kind := describe(o.Path)
		out.Objects = append(out.Objects, objectView{
			Path: o.Path.String(), Kind: kind, Schema: schema, Name: name,
			Owner: o.Owner, RLS: o.RLS, Columns: nonNil(o.Columns),
		})
	}

	for _, g := range s.Grants {
		schema, name, _ := describe(g.Path)
		if g.Grantee == "PUBLIC" {
			out.Summary.PublicGrants++
		}
		if g.Implicit {
			out.Summary.OwnerGrants++
		}
		out.Grants = append(out.Grants, grantView{
			Grantee: g.Grantee, Action: string(g.Action), Path: g.Path.String(),
			Schema: schema, Object: name, Columns: nonNil(g.Columns),
			Implicit: g.Implicit,
		})
	}

	sort.Slice(out.Grants, func(i, j int) bool {
		if out.Grants[i].Grantee != out.Grants[j].Grantee {
			return out.Grants[i].Grantee < out.Grants[j].Grantee
		}
		if out.Grants[i].Path != out.Grants[j].Path {
			return out.Grants[i].Path < out.Grants[j].Path
		}
		return out.Grants[i].Action < out.Grants[j].Action
	})

	out.Summary.Principals = len(out.Principals)
	out.Summary.Objects = len(out.Objects)
	out.Summary.Grants = len(out.Grants)
	return out
}

// describe pulls the human-readable schema, object name and kind out of a
// resource path for display.
func describe(p core.ResourcePath) (schema, name, kind string) {
	if s, ok := p.SegmentAt(core.LevelSchema); ok {
		schema, _ = s.Literal()
	}
	if leaf, ok := p.Leaf(); ok {
		name, _ = leaf.Literal()
		kind = string(leaf.Kind)
	}
	return schema, name, kind
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
