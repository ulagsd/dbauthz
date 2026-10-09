# Architecture Decision Records

Every change to a decision in [STACK.md](../STACK.md), or any new decision of
similar weight, gets a record here. A record states the decision, the reason
and what it replaces. It is not a fresh debate.

## How to add one

1. Copy [0000-template.md](0000-template.md) to the next number, for example
   `0002-short-title.md`.
2. Fill it in. Link the sources you relied on, including pages from
   [reference.md](../reference.md) for engine behaviour.
3. If it amends STACK.md, update the affected line there to point at the record.
4. Merge it in the same PR as the change it describes.

Records are never deleted. A reversed decision gets a new record that
supersedes the old one, and the old one's status changes to "Superseded".

## Index

| # | Title | Status |
|---|---|---|
| [0001](0001-control-plane-authz-uses-own-evaluator.md) | Control-plane authorization uses dbauthz's own evaluator | Accepted |
