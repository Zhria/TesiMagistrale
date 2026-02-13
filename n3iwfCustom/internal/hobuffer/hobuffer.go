// Package hobuffer provides a per-TEID downlink packet buffer used during
// N3IWF-to-N3IWF handover. Between the early UPF path switch and the
// completion of MOBIKE (when XFRM rules are updated with the UE's new outer
// IP), DL packets would otherwise be sent to the stale peer address.
// This buffer holds them in userspace until the tunnel is ready.
package hobuffer

import (
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/n3iwf/internal/logger"
)

// DefaultCapacity is the default per-TEID ring buffer capacity (2^16).
const DefaultCapacity = 65536

// DefaultTTL is the default time-to-live for an active buffer before it is
// considered orphaned and eligible for cleanup.
const DefaultTTL = 60 * time.Second

// buffer is a fixed-capacity ring buffer that stores raw packets (already
// GRE-encapsulated) for a single TEID during handover.
type buffer struct {
	packets [][]byte
	head    int
	count   int
	cap     int
	created time.Time
}

func newBuffer(capacity int) *buffer {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &buffer{
		packets: make([][]byte, capacity),
		cap:     capacity,
		created: time.Now(),
	}
}

// enqueue appends a packet. If the buffer is full the oldest packet is
// silently dropped (ring behaviour). Returns true if the packet was stored
// without dropping.
func (b *buffer) enqueue(pkt []byte) bool {
	cp := make([]byte, len(pkt))
	copy(cp, pkt)

	if b.count < b.cap {
		b.packets[(b.head+b.count)%b.cap] = cp
		b.count++
		return true
	}
	// Overwrite oldest
	b.packets[b.head] = cp
	b.head = (b.head + 1) % b.cap
	return false
}

// drain returns all buffered packets in FIFO order and resets the buffer.
func (b *buffer) drain() [][]byte {
	if b.count == 0 {
		return nil
	}
	out := make([][]byte, 0, b.count)
	for i := 0; i < b.count; i++ {
		idx := (b.head + i) % b.cap
		out = append(out, b.packets[idx])
		b.packets[idx] = nil // allow GC
	}
	b.count = 0
	b.head = 0
	return out
}

// Manager manages per-TEID handover DL buffers. It is safe for concurrent use.
type Manager struct {
	mu       sync.Mutex
	buffers  map[uint32]*buffer
	capacity int
	log      *logrus.Entry
}

// NewManager creates a new manager. capacity is the per-TEID ring buffer
// size; pass 0 to use DefaultCapacity.
func NewManager(capacity int) *Manager {
	if capacity <= 0 {
		capacity = DefaultCapacity
	}
	return &Manager{
		buffers:  make(map[uint32]*buffer),
		capacity: capacity,
		log:      logger.NWuUPLog,
	}
}

// Activate creates an empty buffer for the given TEID. If a buffer already
// exists it is silently replaced (drained & discarded).
func (m *Manager) Activate(teid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.buffers[teid]; ok {
		m.log.Warnf("HOBuffer: replacing existing buffer for TEID %d (%d packets dropped)", teid, old.count)
	}
	m.buffers[teid] = newBuffer(m.capacity)
	m.log.Infof("HOBuffer: activated for TEID %d (capacity=%d)", teid, m.capacity)
}

// IsActive returns true if a buffer exists for the given TEID.
func (m *Manager) IsActive(teid uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, ok := m.buffers[teid]
	return ok
}

// Enqueue stores a packet in the buffer for the given TEID. Returns true if
// the packet was buffered (buffer exists and was not full), false otherwise.
// If the buffer does not exist the call is a no-op and returns false.
func (m *Manager) Enqueue(teid uint32, pkt []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, ok := m.buffers[teid]
	if !ok {
		return false
	}
	return buf.enqueue(pkt)
}

// Flush returns all buffered packets for the given TEID in FIFO order, removes
// the buffer entry, and returns the packets. Returns nil if no buffer exists.
func (m *Manager) Flush(teid uint32) [][]byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	buf, ok := m.buffers[teid]
	if !ok {
		return nil
	}
	packets := buf.drain()
	delete(m.buffers, teid)
	m.log.Infof("HOBuffer: flushed %d packets for TEID %d", len(packets), teid)
	return packets
}

// Cancel discards any buffered packets for the given TEID and removes the
// buffer entry.
func (m *Manager) Cancel(teid uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if buf, ok := m.buffers[teid]; ok {
		m.log.Infof("HOBuffer: cancelled for TEID %d (%d packets discarded)", teid, buf.count)
		delete(m.buffers, teid)
	}
}

// CleanupExpired removes buffers that have been active longer than ttl. This
// catches orphaned buffers from abandoned handovers.
func (m *Manager) CleanupExpired(ttl time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for teid, buf := range m.buffers {
		if now.Sub(buf.created) > ttl {
			m.log.Warnf("HOBuffer: expired buffer for TEID %d (age=%s, %d packets discarded)",
				teid, now.Sub(buf.created).Round(time.Second), buf.count)
			delete(m.buffers, teid)
		}
	}
}

// Len returns the number of active buffers.
func (m *Manager) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.buffers)
}

// Flush retry parameters.
const (
	flushMaxRetries    = 8                   // max retries per packet on ENOBUFS
	flushInitBackoff   = 200 * time.Microsecond
	flushMaxBackoff    = 5 * time.Millisecond
	flushYieldInterval = 64 // yield to scheduler every N successful writes
)

// isENOBUFS returns true if the error is caused by a full kernel socket buffer.
func isENOBUFS(err error) bool {
	return err != nil && strings.Contains(err.Error(), "no buffer space available")
}

// FlushAndWrite flushes the buffer for the given TEID and writes each packet
// using the provided write function. This is intended to be called after XFRM
// rules have been updated so that packets are sent with the correct outer IP.
//
// When the kernel socket buffer is full (ENOBUFS), the write is retried with
// exponential backoff to let the kernel drain. Returns the number of packets
// successfully written.
func (m *Manager) FlushAndWrite(teid uint32, writeFn func(pkt []byte) error) int {
	packets := m.Flush(teid)
	if len(packets) == 0 {
		return 0
	}
	written := 0
	dropped := 0
	for i, pkt := range packets {
		ok := false
		backoff := flushInitBackoff
		for retry := 0; retry <= flushMaxRetries; retry++ {
			if err := writeFn(pkt); err != nil {
				if isENOBUFS(err) && retry < flushMaxRetries {
					time.Sleep(backoff)
					backoff *= 2
					if backoff > flushMaxBackoff {
						backoff = flushMaxBackoff
					}
					continue
				}
				// Non-ENOBUFS error or retries exhausted: drop packet
				dropped++
				break
			}
			ok = true
			break
		}
		if ok {
			written++
			// Yield periodically so the kernel can process queued packets
			if (i+1)%flushYieldInterval == 0 {
				runtime.Gosched()
			}
		}
	}
	if dropped > 0 {
		m.log.Warnf("HOBuffer: TEID %d flush: %d/%d written, %d dropped (ENOBUFS)",
			teid, written, len(packets), dropped)
	}
	return written
}
