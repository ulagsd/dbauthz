// Package audit records what db-iam did, in a form that shows tampering.
//
// This implementation keeps records in memory and is therefore not durable:
// restarting the server loses the chain. It exists now rather than later
// because the property it enforces — no privilege change without a record —
// is far harder to retrofit than to start with, and because the shape of a
// record is what the control-plane store will persist.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Action names what happened.
type Action string

// The recorded actions.
const (
	ActionCreateRole Action = "principal.create"
	ActionMembership Action = "membership.change"
	ActionPlan       Action = "plan.create"
)

// Record is one audited event.
//
// It carries both halves deliberately. Intent is what was asked for and by
// whom; Effect is what actually ran and what came back. A log with only one of
// them cannot answer the question an audit exists for — whether the thing that
// happened is the thing that was approved.
type Record struct {
	Seq    int64          `json:"seq"`
	At     time.Time      `json:"at"`
	Actor  string         `json:"actor"`
	Action Action         `json:"action"`
	Target string         `json:"target"`
	Intent map[string]any `json:"intent"`
	Effect map[string]any `json:"effect"`

	// PrevHash and Hash chain the records. Altering or removing any record
	// breaks every hash after it, so tampering is detectable even though the
	// store itself is not trusted.
	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Log is an append-only, hash-chained record store.
type Log struct {
	mu      sync.RWMutex
	records []Record
	seq     int64
}

// New returns an empty log.
func New() *Log { return &Log{} }

// Append adds a record and returns it with its sequence and hash filled in.
//
// Callers must not treat a privilege change as done until this has returned:
// in the control plane this write shares a transaction with the change it
// describes, so that an effect without a record is impossible rather than
// merely unlikely.
func (l *Log) Append(rec Record) (Record, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.seq++
	rec.Seq = l.seq
	if rec.At.IsZero() {
		rec.At = time.Now().UTC()
	}
	if n := len(l.records); n > 0 {
		rec.PrevHash = l.records[n-1].Hash
	}

	h, err := hashRecord(rec)
	if err != nil {
		return Record{}, err
	}
	rec.Hash = h

	l.records = append(l.records, rec)
	return rec, nil
}

// List returns the most recent records, newest first.
func (l *Log) List(limit int) []Record {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if limit <= 0 || limit > len(l.records) {
		limit = len(l.records)
	}
	out := make([]Record, 0, limit)
	for i := len(l.records) - 1; i >= len(l.records)-limit; i-- {
		out = append(out, l.records[i])
	}
	return out
}

// Verify walks the chain and reports the first record that does not match.
func (l *Log) Verify() error {
	l.mu.RLock()
	defer l.mu.RUnlock()

	prev := ""
	for _, rec := range l.records {
		if rec.PrevHash != prev {
			return fmt.Errorf("record %d: chain broken, expected previous hash %q, found %q",
				rec.Seq, prev, rec.PrevHash)
		}
		want, err := hashRecord(rec)
		if err != nil {
			return err
		}
		if rec.Hash != want {
			return fmt.Errorf("record %d: content does not match its hash", rec.Seq)
		}
		prev = rec.Hash
	}
	return nil
}

// Len reports how many records the log holds.
func (l *Log) Len() int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.records)
}

// hashRecord covers everything except the hash field itself. Using the JSON
// encoder keeps map keys sorted, so the same record always hashes the same
// way regardless of how it was built.
func hashRecord(rec Record) (string, error) {
	rec.Hash = ""
	body, err := json.Marshal(rec)
	if err != nil {
		return "", fmt.Errorf("canonicalising audit record: %w", err)
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:]), nil
}
