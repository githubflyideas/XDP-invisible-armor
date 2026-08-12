package escalation

import "time"

var Ladder = []int64{600, 3600, 86400, 604800, 0}

const (
	ObserveWindow     = int64(3600)
	ActivityThreshold = uint64(5)
)

type Penalty struct {
	Target          string
	Level           int
	OffenseCount    int
	LastBannedAt    time.Time
	ObserveUntil    time.Time
	ExpiresAt       time.Time
	BaselinePackets uint64
	now             func() time.Time
}

func NewPenalty(target string) *Penalty {
	return &Penalty{Target: target, now: time.Now}
}

func (p *Penalty) CurrentTTL() int64 {
	i := p.Level
	if i > len(Ladder)-1 {
		i = len(Ladder) - 1
	}
	return Ladder[i]
}

func (p *Penalty) Permanent() bool { return p.CurrentTTL() == 0 }

func (p *Penalty) clock() time.Time {
	if p.now != nil {
		return p.now()
	}
	return time.Now()
}

func (p *Penalty) Observing() bool {
	return !p.ObserveUntil.IsZero() && p.clock().Before(p.ObserveUntil)
}

func (p *Penalty) RegisterBan(escalate bool) int64 {
	if escalate {
		p.Level++
		if p.Level > len(Ladder)-1 {
			p.Level = len(Ladder) - 1
		}
	}
	p.OffenseCount++
	now := p.clock()
	p.LastBannedAt = now
	ttl := p.CurrentTTL()
	if ttl > 0 {
		p.ExpiresAt = now.Add(time.Duration(ttl) * time.Second)

		p.ObserveUntil = p.ExpiresAt.Add(time.Duration(ObserveWindow) * time.Second)
	} else {
		p.ExpiresAt = time.Time{}
		p.ObserveUntil = time.Time{}
	}
	return ttl
}

func (p *Penalty) StillAttacking(nowPackets uint64) bool {
	if nowPackets < p.BaselinePackets {
		return false
	}
	return (nowPackets - p.BaselinePackets) > ActivityThreshold
}

func (p *Penalty) MaybeDecay() {
	if p.Observing() {
		return
	}
	if p.Level > 0 {
		p.Level--
	}
}
