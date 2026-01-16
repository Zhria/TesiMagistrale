package nwuup

import (
	"runtime/debug"
	"sync"

	"github.com/sirupsen/logrus"
)

const (
	ulForwardQueueLen = 65536
	ulWorkerCount     = 8 // parallel workers for UL forwarding
)

type ulForwardItem struct {
	ueInnerIP string
	ifIndex   int
	rawData   []byte
}

func (s *Server) ulListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
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

func (s *Server) dropUL(nwuupLog *logrus.Entry, ueInnerIP string, ifIndex int, n int) {
	nwuupLog.Warnf("Uplink forward queue full; dropping packet from %s ifindex=%d len=%d", ueInnerIP, ifIndex, n)
}
