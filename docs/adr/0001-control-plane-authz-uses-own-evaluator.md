# 0001. Control-plane authorization uses dbauthz's own evaluator

- **Status:** Accepted
- **Date:** 2026-10-09
- **Amends:** STACK.md section 7, row "dbauthz's own authorization"

## Context

STACK.md contradicted itself. Section 7 named **Cedar** for dbauthz's own
authorization, meaning who may approve or apply a plan. Section 3.3 froze
dbauthz's own policy format and solver, said the same engine handles control-plane
authorization, and removed `cedar-go`, OPA and Casbin from the dependency tree.

Section 3.3 is the later and more detailed decision. Its reasons still hold:
`cedar-go` lacks the schema validator, partial evaluation and Cedar Analysis,
and adding a second evaluator for roughly ten roles and thirty permissions buys
nothing.

## Decision

Control-plane authorization uses dbauthz's own evaluator, the same one that
evaluates database access policy. There is no runtime dependency on Cedar.

The policy format's semantics stay a subset of Cedar's, as section 3.3 requires,
so a later move to Cedar remains an upgrade rather than a rewrite.

## Consequences

- One evaluator to build, test and secure, used for both jobs.
- Control-plane authorization gets the solver's test coverage for free.
- Section 7 of STACK.md now matches section 3.3.
- Reversal cost is low while the policy format stays a Cedar subset.
