package dedup

import "testing"

func TestFIFOSetDoesNotRefreshDuplicates(t *testing.T) {
	f := New(2)
	if !f.Add("a") || !f.Add("b") || f.Add("a") {
		t.Fatal("unexpected add result")
	}
	if !f.Add("c") {
		t.Fatal("c rejected")
	}
	if !f.Add("a") {
		t.Fatal("a should have been oldest and evicted")
	}
	if f.Add("c") {
		t.Fatal("c should still exist")
	}
}
