package watchdog

import (
	"testing"
	"time"
)

func TestActiveTimeExcludesGapsAndPreservesBudgets(t *testing.T) {
	start := time.Now()
	c := DefaultConfig()
	c.FuzzingTimeout = 5 * time.Second
	c.NoProgressTimeout = 5 * time.Second
	p := newPolicy(c)
	p.resume(start)
	p.pause(start.Add(2 * time.Second))
	if p.active(start.Add(12*time.Second)) != 2*time.Second || p.reason(start.Add(12*time.Second)) != "" {
		t.Fatal("inactive work consumed a budget")
	}
	p.resume(start.Add(12 * time.Second))
	if p.reason(start.Add(15*time.Second-time.Nanosecond)) != "" {
		t.Fatal("limit fired too soon")
	}
	if p.reason(start.Add(15*time.Second)) != ReasonFuzzingTimeout {
		t.Fatal("active intervals were not accumulated")
	}
	p.pause(start.Add(15 * time.Second))
	if got := p.active(start.Add(time.Hour)); got != 5*time.Second {
		t.Fatalf("active time=%s", got)
	}
}

func TestProgressResetsOnlyItsActiveBudget(t *testing.T) {
	start := time.Now()
	c := DefaultConfig()
	c.FuzzingTimeout, c.NoProgressTimeout = 10*time.Second, 3*time.Second
	p := newPolicy(c)
	p.resume(start)
	p.observe(Observation{At: start.Add(2 * time.Second), Event: "REDUCE"})
	if p.reason(start.Add(3*time.Second)) != ReasonNoProgress {
		t.Fatal("reduction reset progress")
	}
	p.observe(Observation{At: start.Add(2 * time.Second), Progress: true})
	p.pause(start.Add(3 * time.Second))
	p.resume(start.Add(time.Hour))
	if p.reason(start.Add(time.Hour+time.Second)) != "" {
		t.Fatal("inactive time or restart reset the budget")
	}
	if p.reason(start.Add(time.Hour+2*time.Second)) != ReasonNoProgress {
		t.Fatal("idle time did not continue across attempts")
	}
	p.observe(Observation{At: start.Add(time.Hour + 6*time.Second), Progress: true})
	if p.reason(start.Add(time.Hour+7*time.Second)) != ReasonFuzzingTimeout {
		t.Fatal("progress extended the total budget")
	}
}

func TestLateObservationIsClampedToActualExit(t *testing.T) {
	start := time.Now()
	c := DefaultConfig()
	c.NoProgressTimeout = 3 * time.Second
	p := newPolicy(c)
	p.resume(start)
	p.pause(start.Add(2 * time.Second))
	p.observe(Observation{At: start.Add(20 * time.Second), Progress: true})
	if p.progressAt != 2*time.Second {
		t.Fatalf("late progress shifted the active clock: %s", p.progressAt)
	}
	p.resume(start.Add(30 * time.Second))
	if p.reason(start.Add(33*time.Second)) != ReasonNoProgress {
		t.Fatal("late output incorrectly extended the budget")
	}
}

func TestDisabledPoliciesHaveNoDeadline(t *testing.T) {
	p := newPolicy(DefaultConfig())
	p.resume(time.Now())
	if _, enabled := p.remaining(time.Now()); enabled || p.reason(time.Now().Add(24*time.Hour)) != "" {
		t.Fatal("disabled policies triggered")
	}
}
