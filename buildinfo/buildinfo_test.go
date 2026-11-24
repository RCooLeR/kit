package buildinfo

import "testing"

func TestInfoReturnsTheLinkerVariables(t *testing.T) {
	restore := Info()
	t.Cleanup(func() { Version, Commit, Date = restore.Version, restore.Commit, restore.Date })

	if got := Info(); got != (Build{Version: "dev", Commit: "unknown", Date: "unknown"}) {
		t.Fatalf("a build without -ldflags reports %+v, want the dev defaults", got)
	}

	Version, Commit, Date = "1.4.0", "3f2a9c1", "2026-11-24T10:00:00Z"
	got := Info()
	if got.Version != "1.4.0" || got.Commit != "3f2a9c1" || got.Date != "2026-11-24T10:00:00Z" {
		t.Fatalf("Info() = %+v, want the stamped values", got)
	}
	if want := "1.4.0 (commit 3f2a9c1, built 2026-11-24T10:00:00Z)"; got.String() != want {
		t.Fatalf("String() = %q, want %q", got.String(), want)
	}
}
