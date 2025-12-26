//go:build linux

package xfrm

import (
	"fmt"
	"net"
	"strings"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// ReplayState captures the kernel XFRM anti-replay/sequence state.
// It is required to continue ESP traffic without rekeying when SAs are migrated
// (e.g., N3IWF handover or MOBIKE address update that reinstalls XFRM rules).
type ReplayState struct {
	ReplayWindow uint32   `json:"replayWindow,omitempty"`
	OSeq         uint32   `json:"oseq,omitempty"`
	Seq          uint32   `json:"seq,omitempty"`
	OSeqHi       uint32   `json:"oseqHi,omitempty"`
	SeqHi        uint32   `json:"seqHi,omitempty"`
	Bitmap       []uint32 `json:"bitmap,omitempty"`
}

func (r *ReplayState) isZero() bool {
	return r == nil || (r.ReplayWindow == 0 && r.OSeq == 0 && r.Seq == 0 && r.OSeqHi == 0 && r.SeqHi == 0 && len(r.Bitmap) == 0)
}

// GetXfrmReplayState queries the kernel for the replay state of the SA identified by
// (dst, src, spi, ifid, ESP). It returns the parsed XFRMA_REPLAY_VAL or XFRMA_REPLAY_ESN_VAL.
func GetXfrmReplayState(dst, src net.IP, spi uint32, ifid uint32) (*ReplayState, error) {
	if dst == nil || src == nil {
		return nil, errors.New("nil src/dst")
	}
	req := nl.NewNetlinkRequest(nl.XFRM_MSG_GETSA, unix.NLM_F_ACK)

	msg := &nl.XfrmUsersaId{}
	msg.Family = uint16(nl.GetIPFamily(dst))
	msg.Daddr.FromIP(dst)
	msg.Proto = uint8(netlink.XFRM_PROTO_ESP)
	msg.Spi = nl.Swap32(spi)
	req.AddData(msg)

	req.AddData(nl.NewRtAttr(nl.XFRMA_SRCADDR, src.To16()))
	req.AddData(nl.NewRtAttr(nl.XFRMA_IF_ID, nl.Uint32Attr(ifid)))

	msgs, err := req.Execute(unix.NETLINK_XFRM, uint16(nl.XFRM_MSG_NEWSA))
	if err != nil {
		return nil, err
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("xfrm getsa returned no messages (spi=0x%08x)", spi)
	}

	usersa := nl.DeserializeXfrmUsersaInfo(msgs[0])
	attrs, err := nl.ParseRouteAttr(msgs[0][nl.SizeofXfrmUsersaInfo:])
	if err != nil {
		return nil, err
	}

	replay := &ReplayState{
		ReplayWindow: uint32(usersa.ReplayWindow),
	}

	native := nl.NativeEndian()
	found := false
	for _, attr := range attrs {
		switch attr.Attr.Type {
		case nl.XFRMA_REPLAY_VAL:
			if len(attr.Value) < 12 {
				return nil, fmt.Errorf("xfrm replay attr too short (%d bytes)", len(attr.Value))
			}
			found = true
			replay.OSeq = native.Uint32(attr.Value[0:4])
			replay.Seq = native.Uint32(attr.Value[4:8])
			bitmap := native.Uint32(attr.Value[8:12])
			if bitmap != 0 {
				replay.Bitmap = []uint32{bitmap}
			}
		case nl.XFRMA_REPLAY_ESN_VAL:
			if len(attr.Value) < nl.SizeofXfrmReplayStateEsn {
				return nil, fmt.Errorf("xfrm replay-esn attr too short (%d bytes)", len(attr.Value))
			}
			found = true
			bmpLen := native.Uint32(attr.Value[0:4])
			replay.OSeq = native.Uint32(attr.Value[4:8])
			replay.Seq = native.Uint32(attr.Value[8:12])
			replay.OSeqHi = native.Uint32(attr.Value[12:16])
			replay.SeqHi = native.Uint32(attr.Value[16:20])
			replay.ReplayWindow = native.Uint32(attr.Value[20:24])

			// Parse bitmap words if present (may be omitted by some kernels for GETSA).
			bmpBytes := int(bmpLen) * 4
			if len(attr.Value) >= nl.SizeofXfrmReplayStateEsn+bmpBytes {
				replay.Bitmap = make([]uint32, bmpLen)
				offset := nl.SizeofXfrmReplayStateEsn
				for i := uint32(0); i < bmpLen; i++ {
					replay.Bitmap[i] = native.Uint32(attr.Value[offset : offset+4])
					offset += 4
				}
			}
		}
	}

	if !found {
		return nil, fmt.Errorf("xfrm replay state not found for spi=0x%08x (ifid=%d)", spi, ifid)
	}

	return replay, nil
}

// --- Minimal XFRM state add/update with replay state support ---

func xfrmUsersaInfoFromXfrmState(state *netlink.XfrmState) *nl.XfrmUsersaInfo {
	msg := &nl.XfrmUsersaInfo{}
	msg.Family = uint16(nl.GetIPFamily(state.Dst))
	msg.Id.Daddr.FromIP(state.Dst)
	msg.Saddr.FromIP(state.Src)
	msg.Id.Proto = uint8(state.Proto)
	msg.Mode = uint8(state.Mode)
	msg.Id.Spi = nl.Swap32(uint32(state.Spi))
	msg.Reqid = uint32(state.Reqid)
	msg.ReplayWindow = uint8(state.ReplayWindow)
	return msg
}

func writeStateAlgo(a *netlink.XfrmStateAlgo) []byte {
	algo := nl.XfrmAlgo{
		AlgKeyLen: uint32(len(a.Key) * 8),
		AlgKey:    a.Key,
	}
	end := len(a.Name)
	if end > 64 {
		end = 64
	}
	copy(algo.AlgName[:end], a.Name)
	return algo.Serialize()
}

func writeStateAlgoAuth(a *netlink.XfrmStateAlgo) []byte {
	algo := nl.XfrmAlgoAuth{
		AlgKeyLen:   uint32(len(a.Key) * 8),
		AlgTruncLen: uint32(a.TruncateLen),
		AlgKey:      a.Key,
	}
	end := len(a.Name)
	if end > 64 {
		end = 64
	}
	copy(algo.AlgName[:end], a.Name)
	return algo.Serialize()
}

func writeStateAlgoAead(a *netlink.XfrmStateAlgo) []byte {
	algo := nl.XfrmAlgoAEAD{
		AlgKeyLen: uint32(len(a.Key) * 8),
		AlgICVLen: uint32(a.ICVLen),
		AlgKey:    a.Key,
	}
	end := len(a.Name)
	if end > 64 {
		end = 64
	}
	copy(algo.AlgName[:end], a.Name)
	return algo.Serialize()
}

func writeReplayVal(r *ReplayState) []byte {
	if r == nil {
		return nil
	}
	native := nl.NativeEndian()
	b := make([]byte, 12)
	native.PutUint32(b[0:4], r.OSeq)
	native.PutUint32(b[4:8], r.Seq)
	var bitmap uint32
	if len(r.Bitmap) > 0 {
		bitmap = r.Bitmap[0]
	}
	native.PutUint32(b[8:12], bitmap)
	return b
}

func ceilDiv32bits(window uint32) uint32 {
	if window == 0 {
		return 0
	}
	return (window + 31) / 32
}

func writeReplayEsnVal(r *ReplayState) ([]byte, error) {
	if r == nil {
		return nil, errors.New("nil replay state")
	}
	if r.ReplayWindow == 0 {
		return nil, errors.New("missing replayWindow for ESN replay state")
	}

	bmpLen := ceilDiv32bits(r.ReplayWindow)
	if len(r.Bitmap) > 0 {
		bmpLen = uint32(len(r.Bitmap))
	}

	header := (&nl.XfrmReplayStateEsn{
		BmpLen:       bmpLen,
		OSeq:         r.OSeq,
		Seq:          r.Seq,
		OSeqHi:       r.OSeqHi,
		SeqHi:        r.SeqHi,
		ReplayWindow: r.ReplayWindow,
	}).Serialize()

	if len(r.Bitmap) == 0 {
		return header, nil
	}

	b := make([]byte, nl.SizeofXfrmReplayStateEsn+len(r.Bitmap)*4)
	copy(b, header)
	native := nl.NativeEndian()
	offset := nl.SizeofXfrmReplayStateEsn
	for _, word := range r.Bitmap {
		native.PutUint32(b[offset:offset+4], word)
		offset += 4
	}
	return b, nil
}

func xfrmStateAddOrUpdateWithReplay(state *netlink.XfrmState, replay *ReplayState) error {
	if state == nil {
		return nil
	}
	if state.Spi == 0 {
		return errors.New("xfrm state spi must be set")
	}
	if err := xfrmStateAddWithReplay(state, replay); err != nil {
		// netlink does not export syscall.EEXIST; match the iproute2-style string.
		if strings.Contains(err.Error(), "file exists") {
			return xfrmStateUpdateWithReplay(state, replay)
		}
		return err
	}
	return nil
}

func limitsToLft(lmts netlink.XfrmStateLimits, lft *nl.XfrmLifetimeCfg) {
	if lft == nil {
		return
	}
	if lmts.ByteSoft != 0 {
		lft.SoftByteLimit = lmts.ByteSoft
	} else {
		lft.SoftByteLimit = nl.XFRM_INF
	}
	if lmts.ByteHard != 0 {
		lft.HardByteLimit = lmts.ByteHard
	} else {
		lft.HardByteLimit = nl.XFRM_INF
	}
	if lmts.PacketSoft != 0 {
		lft.SoftPacketLimit = lmts.PacketSoft
	} else {
		lft.SoftPacketLimit = nl.XFRM_INF
	}
	if lmts.PacketHard != 0 {
		lft.HardPacketLimit = lmts.PacketHard
	} else {
		lft.HardPacketLimit = nl.XFRM_INF
	}
	lft.SoftAddExpiresSeconds = lmts.TimeSoft
	lft.HardAddExpiresSeconds = lmts.TimeHard
	lft.SoftUseExpiresSeconds = lmts.TimeUseSoft
	lft.HardUseExpiresSeconds = lmts.TimeUseHard
}

func xfrmStateAddWithReplay(state *netlink.XfrmState, replay *ReplayState) error {
	return xfrmStateAddOrUpdateWithReplayInternal(state, replay, nl.XFRM_MSG_NEWSA)
}

func xfrmStateUpdateWithReplay(state *netlink.XfrmState, replay *ReplayState) error {
	return xfrmStateAddOrUpdateWithReplayInternal(state, replay, nl.XFRM_MSG_UPDSA)
}

func xfrmStateAddOrUpdateWithReplayInternal(state *netlink.XfrmState, replay *ReplayState, nlProto int) error {
	req := nl.NewNetlinkRequest(nlProto, unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK)

	msg := xfrmUsersaInfoFromXfrmState(state)
	limitsToLft(state.Limits, &msg.Lft)

	// ESN requires XFRMA_REPLAY_ESN_VAL with a non-zero ReplayWindow; the base struct's ReplayWindow is then zeroed.
	if state.ESN {
		window := state.ReplayWindow
		if replay != nil && replay.ReplayWindow != 0 {
			window = int(replay.ReplayWindow)
		}
		if window == 0 {
			return fmt.Errorf("ESN flag set without ReplayWindow (spi=0x%08x)", uint32(state.Spi))
		}
		msg.Flags |= nl.XFRM_STATE_ESN
		msg.ReplayWindow = 0
	}

	req.AddData(msg)

	if state.Auth != nil {
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_AUTH_TRUNC, writeStateAlgoAuth(state.Auth)))
	}
	if state.Crypt != nil {
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_CRYPT, writeStateAlgo(state.Crypt)))
	}
	if state.Aead != nil {
		req.AddData(nl.NewRtAttr(nl.XFRMA_ALG_AEAD, writeStateAlgoAead(state.Aead)))
	}
	if state.Encap != nil {
		encapData := make([]byte, nl.SizeofXfrmEncapTmpl)
		encap := nl.DeserializeXfrmEncapTmpl(encapData)
		encap.EncapType = uint16(state.Encap.Type) // #nosec G115
		encap.EncapSport = nl.Swap16(uint16(state.Encap.SrcPort))
		encap.EncapDport = nl.Swap16(uint16(state.Encap.DstPort))
		encap.EncapOa.FromIP(state.Encap.OriginalAddress)
		req.AddData(nl.NewRtAttr(nl.XFRMA_ENCAP, encapData))
	}
	if state.Mark != nil {
		req.AddData(nl.NewRtAttr(nl.XFRMA_MARK, writeMark(state.Mark)))
	}

	// Replay/sequence state (critical for no-rekey continuity).
	if replay != nil && !replay.isZero() {
		if state.ESN {
			data, err := writeReplayEsnVal(replay)
			if err != nil {
				return err
			}
			req.AddData(nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, data))
		} else {
			req.AddData(nl.NewRtAttr(nl.XFRMA_REPLAY_VAL, writeReplayVal(replay)))
		}
	} else if state.ESN {
		// For ESN the replay window is mandatory.
		window := state.ReplayWindow
		if window == 0 && replay != nil && replay.ReplayWindow != 0 {
			window = int(replay.ReplayWindow)
		}
		// Build a minimal replay-esn value with zeroed counters/bitmap.
		min := &ReplayState{ReplayWindow: uint32(window)}
		data, err := writeReplayEsnVal(min)
		if err != nil {
			return err
		}
		req.AddData(nl.NewRtAttr(nl.XFRMA_REPLAY_ESN_VAL, data))
	}

	if state.OutputMark != 0 {
		req.AddData(nl.NewRtAttr(nl.XFRMA_OUTPUT_MARK, nl.Uint32Attr(uint32(state.OutputMark))))
	}
	req.AddData(nl.NewRtAttr(nl.XFRMA_IF_ID, nl.Uint32Attr(uint32(state.Ifid))))

	_, err := req.Execute(unix.NETLINK_XFRM, 0)
	return err
}

// writeMark mirrors netlink's mark encoding; keep it local to avoid relying on unexported helpers.
func writeMark(m *netlink.XfrmMark) []byte {
	mark := &nl.XfrmMark{
		Value: m.Value,
		Mask:  m.Mask,
	}
	if mark.Mask == 0 {
		mark.Mask = ^uint32(0)
	}
	return mark.Serialize()
}
