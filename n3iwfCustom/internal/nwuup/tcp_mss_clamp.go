package nwuup

import (
	"encoding/binary"
)

const (
	ipv4MinHeaderLen = 20
	tcpMinHeaderLen  = 20

	// The GRE header built by this project is always 8 bytes when using the key
	// field (see internal/gre.GREHeaderFieldLength).
	greHeaderLen = 8
)

func (s *Server) maxSafeTCPMSS() (uint16, bool) {
	xfrmMTU := s.Config().GetXfrmMTU()
	if xfrmMTU <= 0 {
		return 0, false
	}

	// xfrmMTU is the MTU of the IPSec inner IP interface (10.0.0.0/24) that carries
	// GRE. The PDU IP packet is inside GRE, so we must subtract:
	// - outer (tunnel) IPv4 header
	// - GRE header
	// - inner IPv4 header
	// - TCP minimal header
	max := xfrmMTU - (ipv4MinHeaderLen + greHeaderLen + ipv4MinHeaderLen + tcpMinHeaderLen)
	if max <= 0 {
		return 0, false
	}
	if max > 0xFFFF {
		return 0xFFFF, true
	}
	return uint16(max), true
}

func clampIPv4TCPSYNMSS(pkt []byte, maxMSS uint16) (changed bool, oldMSS uint16) {
	if len(pkt) < ipv4MinHeaderLen {
		return false, 0
	}
	if pkt[0]>>4 != 4 {
		return false, 0
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < ipv4MinHeaderLen || len(pkt) < ihl {
		return false, 0
	}
	if pkt[9] != 6 { // TCP
		return false, 0
	}

	// Skip fragments (can't reliably rewrite TCP options).
	frag := binary.BigEndian.Uint16(pkt[6:8])
	if (frag&0x1FFF) != 0 || (frag&0x2000) != 0 { // offset != 0 || MF
		return false, 0
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	if totalLen <= 0 || totalLen > len(pkt) {
		totalLen = len(pkt)
	}

	tcpStart := ihl
	if totalLen < tcpStart+tcpMinHeaderLen {
		return false, 0
	}

	tcp := pkt[tcpStart:totalLen]
	dataOffset := int((tcp[12] >> 4) * 4)
	if dataOffset < tcpMinHeaderLen || len(tcp) < dataOffset {
		return false, 0
	}

	flags := tcp[13]
	if (flags & 0x02) == 0 { // SYN
		return false, 0
	}

	opts := tcp[tcpMinHeaderLen:dataOffset]
	for i := 0; i < len(opts); {
		kind := opts[i]
		switch kind {
		case 0: // End of options
			return false, 0
		case 1: // NOP
			i++
			continue
		}

		if i+1 >= len(opts) {
			return false, 0
		}
		optLen := int(opts[i+1])
		if optLen < 2 || i+optLen > len(opts) {
			return false, 0
		}

		// MSS option (kind=2, len=4)
		if kind == 2 && optLen == 4 {
			oldMSS = binary.BigEndian.Uint16(opts[i+2 : i+4])
			if oldMSS <= maxMSS {
				return false, oldMSS
			}

			binary.BigEndian.PutUint16(opts[i+2:i+4], maxMSS)
			// Recompute TCP checksum.
			tcp[16] = 0
			tcp[17] = 0
			binary.BigEndian.PutUint16(tcp[16:18], tcpChecksumIPv4(pkt[12:16], pkt[16:20], tcp))
			return true, oldMSS
		}

		i += optLen
	}

	return false, 0
}

func tcpChecksumIPv4(srcIP, dstIP []byte, tcpSegment []byte) uint16 {
	var sum uint32

	sum += checksum16(srcIP)
	sum += checksum16(dstIP)

	// Protocol and TCP length in pseudo-header.
	sum += uint32(6) // TCP
	sum += uint32(len(tcpSegment))

	sum += checksum16(tcpSegment)

	// Fold to 16 bits.
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

func checksum16(b []byte) uint32 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	return sum
}
