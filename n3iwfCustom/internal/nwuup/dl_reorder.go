package nwuup

import (
	"runtime/debug"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
)

const (
	dlReorderQueueLen          = 65536
	dlReorderTickInterval      = 1 * time.Millisecond
	dlReorderTimeout           = 5 * time.Millisecond
	dlReorderMaxPendingPerTEID = 512
	dlReorderStateIdleTimeout  = 5 * time.Second

	// When the forward distance is greater than half the sequence space, treat the
	// packet as "behind" (late/old) and drop it.
	dlSeqBehindThreshold = 1 << 15
)

type dlReorderItem struct {
	teid   uint32
	seq    uint16
	hasSeq bool
	packet gtpQoSMsg.QoSTPDUPacket
}

type dlReorderState struct {
	expectedSeq  uint16
	expectedInit bool
	waitingSince time.Time
	lastSeen     time.Time
	pending      map[uint16]gtpQoSMsg.QoSTPDUPacket
}

type dlReorderer struct {
	log         *logrus.Entry
	states      map[uint32]*dlReorderState
	warnedNoSeq map[uint32]struct{}
}

func newDLReorderer(log *logrus.Entry) *dlReorderer {
	return &dlReorderer{
		log:         log,
		states:      make(map[uint32]*dlReorderState),
		warnedNoSeq: make(map[uint32]struct{}),
	}
}

func (s *Server) dlListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
		wg.Done()
	}()

	reorderer := newDLReorderer(nwuupLog)
	ticker := time.NewTicker(dlReorderTickInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.CancelContext().Done():
			return
		case item := <-s.dlCh:
			reorderer.handle(time.Now(), item, s.forwardDL)
		case <-ticker.C:
			reorderer.tick(time.Now(), s.forwardDL)
		}
	}
}

func (r *dlReorderer) handle(now time.Time, item dlReorderItem, forward func(gtpQoSMsg.QoSTPDUPacket)) {
	if !item.hasSeq {
		if _, ok := r.warnedNoSeq[item.teid]; !ok {
			r.warnedNoSeq[item.teid] = struct{}{}
			r.log.Warnf("Downlink GTP-U has no sequence number; cannot reorder TEID=%d", item.teid)
		}
		forward(item.packet)
		return
	}

	st := r.states[item.teid]
	if st == nil {
		st = &dlReorderState{
			pending: make(map[uint16]gtpQoSMsg.QoSTPDUPacket),
		}
		r.states[item.teid] = st
	}

	st.lastSeen = now

	if !st.expectedInit {
		st.expectedSeq = item.seq
		st.expectedInit = true
		st.waitingSince = now
	}

	if st.expectedInit {
		dist := seqForwardDistance(st.expectedSeq, item.seq)
		if dist > dlSeqBehindThreshold {
			// Too old/late; likely from a previous window after we already advanced.
			r.log.Tracef("Dropping late DL packet TEID=%d seq=%d expected=%d dist=%d", item.teid, item.seq, st.expectedSeq, dist)
			return
		}
	}

	if _, exists := st.pending[item.seq]; !exists {
		st.pending[item.seq] = item.packet
	}

	r.flush(now, st, forward)
	r.startGapTimerIfNeeded(now, st)
	if len(st.pending) >= dlReorderMaxPendingPerTEID {
		r.forceAdvance(now, item.teid, st, forward, "buffer-full")
	}
}

func (r *dlReorderer) tick(now time.Time, forward func(gtpQoSMsg.QoSTPDUPacket)) {
	for teid, st := range r.states {
		if now.Sub(st.lastSeen) > dlReorderStateIdleTimeout {
			delete(r.states, teid)
			delete(r.warnedNoSeq, teid)
			continue
		}

		if !st.expectedInit || len(st.pending) == 0 {
			continue
		}

		if st.waitingSince.IsZero() {
			continue
		}

		if now.Sub(st.waitingSince) >= dlReorderTimeout {
			r.forceAdvance(now, teid, st, forward, "timeout")
		}
	}
}

func (r *dlReorderer) flush(now time.Time, st *dlReorderState, forward func(gtpQoSMsg.QoSTPDUPacket)) {
	advanced := false
	for {
		pkt, ok := st.pending[st.expectedSeq]
		if !ok {
			break
		}
		delete(st.pending, st.expectedSeq)
		forward(pkt)
		st.expectedSeq++
		advanced = true
	}
	if advanced {
		st.waitingSince = time.Time{}
	}
}

func (r *dlReorderer) forceAdvance(now time.Time, teid uint32, st *dlReorderState, forward func(gtpQoSMsg.QoSTPDUPacket), reason string) {
	nextSeq, ok := chooseNextSeq(st.expectedSeq, st.pending)
	if !ok {
		return
	}
	if nextSeq == st.expectedSeq {
		r.flush(now, st, forward)
		return
	}

	r.log.Warnf(
		"DL reorder %s TEID=%d: missing seq=%d, jumping to seq=%d (pending=%d)",
		reason,
		teid,
		st.expectedSeq,
		nextSeq,
		len(st.pending),
	)
	st.expectedSeq = nextSeq
	st.waitingSince = now
	r.flush(now, st, forward)
	r.startGapTimerIfNeeded(now, st)
}

func seqForwardDistance(from, to uint16) uint16 {
	return to - from
}

func (r *dlReorderer) startGapTimerIfNeeded(now time.Time, st *dlReorderState) {
	if len(st.pending) == 0 || !st.expectedInit {
		st.waitingSince = time.Time{}
		return
	}
	if st.waitingSince.IsZero() {
		st.waitingSince = now
	}
}

func chooseNextSeq(expected uint16, pending map[uint16]gtpQoSMsg.QoSTPDUPacket) (uint16, bool) {
	var (
		chosen  uint16
		minDist = uint16(^uint16(0))
	)

	for seq := range pending {
		dist := seqForwardDistance(expected, seq)
		if dist < minDist {
			minDist = dist
			chosen = seq
		}
	}

	if minDist == uint16(^uint16(0)) {
		return 0, false
	}
	return chosen, true
}
