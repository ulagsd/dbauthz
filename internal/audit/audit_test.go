package audit

import "testing"

func TestChainLinksAndVerifies(t *testing.T) {
	l := New()
	for _, name := range []string{"alice", "bob", "carol"} {
		if _, err := l.Append(Record{
			Action: ActionCreateRole, Target: "demo-pg",
			Intent: map[string]any{"name": name},
		}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if l.Len() != 3 {
		t.Fatalf("Len = %d, want 3", l.Len())
	}
	if err := l.Verify(); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	recs := l.List(0) // newest first
	if recs[0].Seq != 3 || recs[2].Seq != 1 {
		t.Fatalf("List is not newest-first: %d, %d", recs[0].Seq, recs[2].Seq)
	}
	if recs[2].PrevHash != "" {
		t.Error("the first record should have no predecessor")
	}
	if recs[1].PrevHash != recs[2].Hash || recs[0].PrevHash != recs[1].Hash {
		t.Error("records are not chained to their predecessor")
	}
}

// The point of the chain: editing a record after the fact must be detectable
// even though the store itself is not trusted.
func TestVerifyDetectsTampering(t *testing.T) {
	l := New()
	for _, name := range []string{"alice", "bob", "carol"} {
		if _, err := l.Append(Record{Action: ActionCreateRole, Intent: map[string]any{"name": name}}); err != nil {
			t.Fatal(err)
		}
	}

	t.Run("edited content", func(t *testing.T) {
		l.records[1].Intent["name"] = "mallory"
		defer func() { l.records[1].Intent["name"] = "bob" }()

		if err := l.Verify(); err == nil {
			t.Fatal("Verify accepted an edited record")
		}
	})

	t.Run("removed record", func(t *testing.T) {
		saved := l.records
		l.records = append([]Record{saved[0]}, saved[2])
		defer func() { l.records = saved }()

		if err := l.Verify(); err == nil {
			t.Fatal("Verify accepted a log with a record removed")
		}
	})
}

func TestListLimit(t *testing.T) {
	l := New()
	for range 10 {
		if _, err := l.Append(Record{Action: ActionPlan}); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(l.List(3)); got != 3 {
		t.Errorf("List(3) returned %d records", got)
	}
	if got := len(l.List(100)); got != 10 {
		t.Errorf("List(100) returned %d records, want all 10", got)
	}
}
