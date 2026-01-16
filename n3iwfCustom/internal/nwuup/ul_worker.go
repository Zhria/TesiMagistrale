package nwuup

import (
	"runtime/debug"
	"sync"
)

const (
	// Size of the uplink forwarding queue. Large enough to absorb bursts.
	ulQueueSize = 8192

	// Number of worker goroutines processing the UL queue.
	// This limits concurrent WriteTo calls to the GTP-U socket.
	ulWorkerCount = 32
)

// ulItem represents a packet to be forwarded from NWu to UPF.
type ulItem struct {
	ueInnerIP string
	ifIndex   int
	rawData   []byte
}

// ulWorker reads from the UL channel and forwards packets.
// Uses blocking receive, so backpressure naturally propagates to the GRE reader.
func (s *Server) ulWorker(wg *sync.WaitGroup, workerID int) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			nwuupLog.Fatalf("ulWorker[%d] panic: %v\n%s", workerID, p, string(debug.Stack()))
		}
		wg.Done()
	}()

	for {
		select {
		case <-s.CancelContext().Done():
			return
		case item, ok := <-s.ulCh:
			if !ok {
				return
			}
			s.forwardUL(item.ueInnerIP, item.ifIndex, item.rawData)
		}
	}
}
