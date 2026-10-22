package watchdog

import "time"

// policy runs on an active-time axis. start/end describe the current (or last)
// attempt so observations drained after exit can still update its progress.
type policy struct {
	total          time.Duration
	progressAt     time.Duration
	base           time.Duration
	start          time.Time
	end            time.Time
	fuzzingTimeout time.Duration
	noProgress     time.Duration
}

func newPolicy(c RunConfig) policy {
	return policy{fuzzingTimeout: c.FuzzingTimeout, noProgress: c.NoProgressTimeout}
}

func (p *policy) resume(at time.Time) {
	p.base, p.start, p.end = p.total, at, time.Time{}
}

func (p *policy) pause(at time.Time) {
	if p.start.IsZero() || !p.end.IsZero() {
		return
	}
	if at.Before(p.start) {
		at = p.start
	}
	p.total += at.Sub(p.start)
	p.end = at
}

func (p policy) active(now time.Time) time.Duration {
	if p.start.IsZero() || !p.end.IsZero() {
		return p.total
	}
	if now.Before(p.start) {
		return p.total
	}
	return p.total + now.Sub(p.start)
}

func (p *policy) observe(o Observation) {
	if !o.Progress || p.start.IsZero() {
		return
	}
	at := o.At
	if at.Before(p.start) {
		at = p.start
	}
	if !p.end.IsZero() && at.After(p.end) {
		at = p.end
	}
	position := p.base + at.Sub(p.start)
	if position > p.progressAt {
		p.progressAt = position
	}
}

func (p policy) remaining(now time.Time) (time.Duration, bool) {
	active := p.active(now)
	var next time.Duration
	enabled := false
	if p.fuzzingTimeout > 0 {
		next, enabled = p.fuzzingTimeout-active, true
	}
	if p.noProgress > 0 {
		idle := p.noProgress - (active - p.progressAt)
		if !enabled || idle < next {
			next, enabled = idle, true
		}
	}
	if next < 0 {
		next = 0
	}
	return next, enabled
}

func (p policy) reason(now time.Time) StopReason {
	active := p.active(now)
	if p.fuzzingTimeout > 0 && active >= p.fuzzingTimeout {
		return ReasonFuzzingTimeout
	}
	if p.noProgress > 0 && active-p.progressAt >= p.noProgress {
		return ReasonNoProgress
	}
	return ""
}
