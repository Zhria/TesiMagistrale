package nwuup

import (
	"context"
	"encoding/binary"
	goerrors "errors"
	"fmt"
	"net"
	"runtime/debug"
	"sync"
	"time"

	"github.com/free5gc/ngap/ngapType"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/wmnsk/go-gtp/gtpv1"
	gtpMsg "github.com/wmnsk/go-gtp/gtpv1/message"
	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/gre"
	gtpQoSMsg "github.com/free5gc/n3iwf/internal/gtp/message"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/internal/snapshot"
	"github.com/free5gc/n3iwf/pkg/factory"
)

type n3iwf interface {
	Config() *factory.Config
	Context() *n3iwf_context.N3IWFContext
	CancelContext() context.Context
}

type Server struct {
	n3iwf

	greConn  *ipv4.PacketConn
	gtpuConn *gtpv1.UPlaneConn
	ulCh     chan ulItem // buffered channel for UL forwarding with backpressure
	log      *logrus.Entry
}

const (
	// Default socket buffer used for the raw GRE socket. This helps avoid ENOBUFS
	// ("no buffer space available") when forwarding high-rate downlink traffic to UE.
	// Note: the effective value is capped by kernel sysctls (net.core.{wmem,rmem}_max).
	greSocketBufferBytes = 25 * 1024 * 1024

	greWriteRetryMaxAttempts    = 50
	greWriteRetryInitialBackoff = 200 * time.Microsecond
	greWriteRetryMaxBackoff     = 5 * time.Millisecond
)

func NewServer(n3iwf n3iwf) (*Server, error) {
	s := &Server{
		n3iwf: n3iwf,
		log:   logger.NWuUPLog,
	}
	return s, nil
}

// Run bind and listen IPv4 packet connection on N3IWF NWu interface
// with UP_IP_ADDRESS, catching GRE encapsulated packets and forward
// to N3 interface.
func (s *Server) Run(wg *sync.WaitGroup) error {
	err := s.newGreConn()
	if err != nil {
		return err
	}

	err = s.newGtpuConn()
	if err != nil {
		return err
	}

	// Create UL forwarding queue and start worker pool
	s.ulCh = make(chan ulItem, ulQueueSize)
	wg.Add(ulWorkerCount)
	for i := 0; i < ulWorkerCount; i++ {
		go s.ulWorker(wg, i)
	}

	wg.Add(1)
	go s.greListenAndServe(wg)

	wg.Add(1)
	go s.gtpuListenAndServe(wg)

	return nil
}

func (s *Server) newGreConn() error {
	listenAddr := s.Config().GetIPSecGatewayAddr()

	// Setup IPv4 packet connection socket
	// This socket will only capture GRE encapsulated packet
	connection, err := net.ListenPacket("ip4:gre", listenAddr)
	if err != nil {
		return errors.Wrapf(err, "Error setting GRE listen socket on %s", listenAddr)
	}
	if bufConn, ok := connection.(interface {
		SetReadBuffer(bytes int) error
		SetWriteBuffer(bytes int) error
	}); ok {
		if err := bufConn.SetReadBuffer(greSocketBufferBytes); err != nil {
			s.log.Warnf("Unable to set GRE socket read buffer: %v", err)
		}
		if err := bufConn.SetWriteBuffer(greSocketBufferBytes); err != nil {
			s.log.Warnf("Unable to set GRE socket write buffer: %v", err)
		}
	}
	s.greConn = ipv4.NewPacketConn(connection)
	if s.greConn == nil {
		return errors.Wrapf(err, "Error opening GRE IPv4 packet connection socket on %s", listenAddr)
	}
	return nil
}

func (s *Server) newGtpuConn() error {
	gtpuAddr := s.Config().GetN3iwfGtpBindAddress() + gtpv1.GTPUPort

	laddr, err := net.ResolveUDPAddr("udp", gtpuAddr)
	if err != nil {
		return errors.Wrapf(err, "Resolve GTP-U address %s Failed", gtpuAddr)
	}

	upConn := gtpv1.NewUPlaneConn(laddr)
	// Overwrite T-PDU handler for supporting extension header containing QoS parameters
	upConn.AddHandler(gtpMsg.MsgTypeTPDU, s.handleQoSTPDU)
	// Avoid noisy logs: handle End Marker explicitly.
	upConn.AddHandler(gtpMsg.MsgTypeEndMarker, s.handleEndMarker)
	s.gtpuConn = upConn
	return nil
}

// listenAndServe read from socket and call forward() to
// forward packet.
func (s *Server) greListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		err := s.greConn.Close()
		if err != nil {
			nwuupLog.Errorf("Error closing raw socket: %+v", err)
		}
		wg.Done()
	}()

	buf := make([]byte, factory.MAX_BUF_MSG_LEN)

	err := s.greConn.SetControlMessage(ipv4.FlagInterface|ipv4.FlagTTL, true)
	if err != nil {
		nwuupLog.Errorf("Set control message visibility for IPv4 packet connection fail: %+v", err)
		return
	}

	for {
		n, cm, src, err := s.greConn.ReadFrom(buf)
		nwuupLog.Tracef("Read %d bytes, %s", n, cm)
		if err != nil {
			nwuupLog.Errorf("Error read from IPv4 packet connection: %+v", err)
			return
		}

		forwardData := make([]byte, n)
		copy(forwardData, buf)

		// Blocking send - creates natural backpressure when workers are busy
		s.ulCh <- ulItem{ueInnerIP: src.String(), ifIndex: cm.IfIndex, rawData: forwardData}
	}
}

func (s *Server) gtpuListenAndServe(wg *sync.WaitGroup) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		wg.Done()
	}()

	if err := s.gtpuConn.ListenAndServe(context.Background()); err != nil {
		nwuupLog.Errorf("GTP-U server err: %v", err)
	}
}

// forward forwards user plane packets from NWu to UPF
// with GTP header encapsulated
func (s *Server) forwardUL(ueInnerIP string, ifIndex int, rawData []byte) {
	nwuupLog := s.log
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// Find UE information
	n3iwfCtx := s.Context()
	ikeUe, ok := n3iwfCtx.AllocatedUEIPAddressLoad(ueInnerIP)
	if !ok {
		nwuupLog.Error("Ike UE context not found")
		return
	}

	ranUe, err := n3iwfCtx.RanUeLoadFromIkeSPI(ikeUe.N3IWFIKESecurityAssociation.LocalSPI)
	if err != nil {
		nwuupLog.Error("ranUe not found")
		return
	}

	var pduSession *n3iwf_context.PDUSession

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		// Check which child SA the packet come from with interface index,
		// and find the corresponding PDU session
		if childSA == nil || childSA.XfrmIface == nil || childSA.XfrmIface.Attrs().Index != ifIndex {
			continue
		}
		// UL user plane is always GRE; CP ChildSAs may share the same XFRM interface.
		if childSA.SelectedIPProtocol != unix.IPPROTO_GRE {
			continue
		}
		for _, pduID := range childSA.PDUSessionIds {
			if pduID <= 0 {
				continue
			}
			pduSession = ranUe.GetSharedCtx().PduSessionList[pduID]
			if pduSession != nil {
				break
			}
		}
		if pduSession != nil {
			break
		}
	}

	if pduSession == nil {
		nwuupLog.Errorf("No matching UL PDU session for UE=%s ifindex=%d", ueInnerIP, ifIndex)
		return
	}

	gtpConnection := pduSession.GTPConnInfo

	// Decapsulate GRE header and extract QoS Parameters if exist
	grePacket := gre.GREPacket{}
	if err := grePacket.Unmarshal(rawData); err != nil {
		nwuupLog.Errorf("gre Unmarshal err: %+v", err)
		return
	}

	var (
		n        int
		writeErr error
		qfi      uint8
	)

	payload, _ := grePacket.GetPayload()

	// Encapsulate UL PDU SESSION INFORMATION with extension header if the QoS parameters exist
	if grePacket.GetKeyFlag() {
		qfi, err := grePacket.GetQFI()
		if err != nil {
			nwuupLog.Errorf("forwardUL err: %+v", err)
			return
		}
		gtpPacket, err := gtpQoSMsg.BuildQoSGTPPacket(gtpConnection.OutgoingTEID, qfi, grePacket.GetRQI(), payload)
		if err != nil {
			nwuupLog.Errorf("buildQoSGTPPacket err: %+v", err)
			return
		}

		n, writeErr = s.gtpuConn.WriteTo(gtpPacket, gtpConnection.UPFUDPAddr)
	} else {
		nwuupLog.Warnf("Receive GRE header without key field specifying QFI and RQI.")
		n, writeErr = s.gtpuConn.WriteToGTP(gtpConnection.OutgoingTEID, payload, gtpConnection.UPFUDPAddr)
	}

	if writeErr != nil {
		nwuupLog.Errorf("Write to UPF failed: %+v", writeErr)
		if writeErr == gtpv1.ErrConnNotOpened {
			nwuupLog.Error("The connection has been closed")
			// TODO: Release the GTP resource
		}
		snapshot.TransmittedVolumeUL(uint64(len(payload)), uint64(n), ueInnerIP, qfi, grePacket.GetRQI(), gtpConnection.OutgoingTEID, pduSession.QosFlows[int64(qfi)], pduSession.Snssai)
		return
	}
	nwuupLog.Trace("Forward NWu -> N3")
	nwuupLog.Tracef("Wrote %d bytes", n)
	// Update snapshot with transmitted volume
	snapshot.TransmittedVolumeUL(uint64(len(payload)), uint64(n), ueInnerIP, qfi, grePacket.GetRQI(), gtpConnection.OutgoingTEID, pduSession.QosFlows[int64(qfi)], pduSession.Snssai)
}

func (s *Server) Stop() {
	nwuupLog := s.log
	nwuupLog.Infof("Close Nwuup server...")

	if err := s.greConn.Close(); err != nil {
		nwuupLog.Errorf("Stop nwuup greConn error : %v", err)
	}

	if err := s.gtpuConn.Close(); err != nil {
		nwuupLog.Errorf("Stop nwuup gtpuConn error : %v", err)
	}

	// Close UL channel to signal workers to exit
	if s.ulCh != nil {
		close(s.ulCh)
	}
}

// Parse the fields not supported by go-gtp and forward data to UE.
func (s *Server) handleQoSTPDU(c gtpv1.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	tpdu, ok := msg.(*gtpMsg.TPDU)
	if !ok {
		return errors.Errorf("unexpected message type %T (want *gtpv1/message.TPDU)", msg)
	}

	pdu := gtpQoSMsg.QoSTPDUPacket{}
	err := pdu.Unmarshal(tpdu)
	if err != nil {
		return err
	}

	s.forwardDL(pdu)
	return nil
}

func (s *Server) handleEndMarker(c gtpv1.Conn, senderAddr net.Addr, msg gtpMsg.Message) error {
	s.log.Tracef("GTP-U End Marker received from %s", senderAddr.String())
	return nil
}

func isGreTemporarySendErr(err error) bool {
	if err == nil {
		return false
	}
	return goerrors.Is(err, unix.ENOBUFS) ||
		goerrors.Is(err, unix.EAGAIN) ||
		goerrors.Is(err, unix.EWOULDBLOCK)
}

func (s *Server) greWriteToWithRetry(data []byte, cm *ipv4.ControlMessage, dst net.Addr) (int, error) {
	backoff := greWriteRetryInitialBackoff
	var lastErr error
	for attempt := 0; attempt < greWriteRetryMaxAttempts; attempt++ {
		n, err := s.greConn.WriteTo(data, cm, dst)
		if err == nil {
			return n, nil
		}
		lastErr = err
		if !isGreTemporarySendErr(err) {
			return n, err
		}
		time.Sleep(backoff)
		backoff *= 2
		if backoff > greWriteRetryMaxBackoff {
			backoff = greWriteRetryMaxBackoff
		}
	}
	return 0, lastErr
}

// Forward user plane packets from N3 to UE with GRE header and new IP header encapsulated
func (s *Server) forwardDL(packet gtpQoSMsg.QoSTPDUPacket) {
	nwuupLog := s.log

	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			nwuupLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	n3iwfCtx := s.Context()
	pktTEID := packet.GetTEID()
	nwuupLog.Tracef("pkt teid : %d", pktTEID)

	// Find UE information
	ranUe, ok := n3iwfCtx.AllocatedUETEIDLoad(pktTEID)
	if !ok {
		nwuupLog.Errorf("Cannot find RanUE context from QosPacket TEID : %+v", pktTEID)
		return
	}
	ranUeNgapID := ranUe.GetSharedCtx().RanUeNgapId

	ikeUe, err := n3iwfCtx.IkeUeLoadFromNgapId(ranUeNgapID)
	if err != nil {
		nwuupLog.Errorf("Cannot find IkeUe context from RanUe , NgapID : %+v", ranUeNgapID)

		return
	}

	// UE inner IP in IPSec
	ueInnerIPAddr := ikeUe.IPSecInnerIPAddr

	var cm *ipv4.ControlMessage
	var pdusession *n3iwf_context.PDUSession

	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if childSA == nil || childSA.XfrmIface == nil {
			continue
		}
		for _, pduID := range childSA.PDUSessionIds {
			if pduID <= 0 {
				continue
			}
			pdusession = ranUe.FindPDUSession(pduID)
			if pdusession != nil && pdusession.GTPConnInfo.IncomingTEID == pktTEID {
				nwuupLog.Tracef("forwarding IPSec xfrm interfaceid : %d", childSA.XfrmIface.Attrs().Index)
				cm = &ipv4.ControlMessage{
					IfIndex: childSA.XfrmIface.Attrs().Index,
				}
				break
			}
		}
		if cm != nil {
			break
		}
	}
	// Check if handover is in progress - buffer instead of forwarding to UE
	if pdusession != nil {
		shared := ranUe.GetSharedCtx()

		// Source N3IWF: HoStateExecuting - buffer for indirect forwarding to target
		if shared.HoState == n3iwf_context.HoStateExecuting {
			if pdusession.ForwardingUPTNLInfo != nil {
				qfi, rqi := uint8(0), false
				if packet.HasQoS() {
					qfi, rqi = packet.GetQoSParameters()
				}
				s.bufferForForwarding(pdusession, packet.GetPayload(), qfi, rqi)
				nwuupLog.Debugf("Buffered DL packet for HO forwarding (TEID=%d, QFI=%d, size=%d)",
					pktTEID, qfi, len(packet.GetPayload()))
				return
			} else {
				nwuupLog.Warnf("[HO-SKIP] HoState=Executing but ForwardingUPTNLInfo is nil for PDU Session %d", pdusession.Id)
			}
		}

		// Target N3IWF: HoStateAwaitingUE - buffer until UE completes MOBIKE
		if shared.HoState == n3iwf_context.HoStateAwaitingUE {
			qfi, rqi := uint8(0), false
			if packet.HasQoS() {
				qfi, rqi = packet.GetQoSParameters()
			}
			s.bufferForForwarding(pdusession, packet.GetPayload(), qfi, rqi)
			return
		}
	}

	if cm == nil {
		nwuupLog.Warnf("forwardDL(): Cannot match TEID(%d) to ChildSA", pktTEID)
		snssai := ngapType.SNSSAI{}
		if pdusession != nil {
			snssai = pdusession.Snssai
		}
		snapshot.TransmittedVolumeDL(uint64(len(packet.GetPayload())), uint64(0), ueInnerIPAddr.IP.String(), 0, false, pktTEID, nil, snssai)

		return
	}

	var (
		qfi uint8
		rqi bool
	)

	// QoS Related Parameter
	if packet.HasQoS() {
		qfi, rqi = packet.GetQoSParameters()
		nwuupLog.Tracef("QFI: %v, RQI: %v", qfi, rqi)
	}

	// Encasulate IPv4 packet with GRE header before forward to UE through IPsec
	grePacket := gre.GREPacket{}

	// TODO:[24.502(v15.7) 9.3.3 ] The Protocol Type field should be set to zero
	payload := packet.GetPayload()
	if maxMSS, ok := s.maxSafeTCPMSS(); ok {
		if changed, oldMSS := clampIPv4TCPSYNMSS(payload, maxMSS); changed {
			nwuupLog.Warnf("Clamped DL TCP MSS %d -> %d (TEID=%d)", oldMSS, maxMSS, pktTEID)
		}
	}

	grePacket.SetPayload(payload, gre.IPv4)
	grePacket.SetQoS(qfi, rqi)
	forwardData := grePacket.Marshal()
	qoSFlow := pdusession.QosFlows[int64(qfi)]

	// Send to UE through Nwu
	if n, err := s.greWriteToWithRetry(forwardData, cm, ueInnerIPAddr); err != nil {
		nwuupLog.Errorf("Write to UE failed: %+v", err)
		snapshot.TransmittedVolumeDL(uint64(len(packet.GetPayload())), uint64(0), ueInnerIPAddr.IP.String(), qfi, rqi, pktTEID, qoSFlow, pdusession.Snssai)
		return
	} else {
		nwuupLog.Trace("Forward NWu <- N3")
		nwuupLog.Tracef("Wrote %d bytes", n)
		snapshot.TransmittedVolumeDL(uint64(len(packet.GetPayload())), uint64(len(packet.GetPayload())), ueInnerIPAddr.IP.String(), qfi, rqi, pktTEID, qoSFlow, pdusession.Snssai)

	}
}

// MaxForwardingBufferSize is the maximum number of packets to buffer during handover
const MaxForwardingBufferSize = 50000

// bufferForForwarding adds a packet to the forwarding buffer for indirect forwarding during handover
func (s *Server) bufferForForwarding(session *n3iwf_context.PDUSession, payload []byte, qfi uint8, rqi bool) {
	session.ForwardingBufferLock.Lock()
	defer session.ForwardingBufferLock.Unlock()

	if len(session.ForwardingBuffer) >= MaxForwardingBufferSize {
		s.log.Warnf("Forwarding buffer full (max=%d), dropping packet for PDU Session %d",
			MaxForwardingBufferSize, session.Id)
		return
	}

	// Copy payload to avoid data race
	payloadCopy := make([]byte, len(payload))
	copy(payloadCopy, payload)

	session.ForwardingBuffer = append(session.ForwardingBuffer, n3iwf_context.ForwardingPacket{
		Payload: payloadCopy,
		QFI:     qfi,
		RQI:     rqi,
	})

	s.log.Debugf("[HO-BUFFER] Packet buffered for PDU Session %d (total: %d)", session.Id, len(session.ForwardingBuffer))
}

// FlushForwardingBuffer sends all buffered packets to the UPF forwarding endpoint
func (s *Server) FlushForwardingBuffer(session *n3iwf_context.PDUSession) error {
	if session == nil {
		return errors.New("nil session")
	}
	if session.ForwardingUPTNLInfo == nil {
		return errors.New("no forwarding endpoint configured")
	}
	if session.ForwardingUPTNLInfo.Present != ngapType.UPTransportLayerInformationPresentGTPTunnel {
		return errors.New("forwarding info is not GTP tunnel")
	}

	gtpTunnel := session.ForwardingUPTNLInfo.GTPTunnel
	if gtpTunnel == nil {
		return errors.New("GTP tunnel is nil")
	}

	// Extract TEID and IP from forwarding info
	teid := binary.BigEndian.Uint32(gtpTunnel.GTPTEID.Value)
	ipBytes := gtpTunnel.TransportLayerAddress.Value.Bytes
	if len(ipBytes) < 4 {
		return fmt.Errorf("invalid transport layer address length: %d", len(ipBytes))
	}
	upfIP := net.IP(ipBytes[:4])
	upfAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s%s", upfIP.String(), gtpv1.GTPUPort))
	if err != nil {
		return fmt.Errorf("resolve forwarding address: %w", err)
	}

	// Take packets from buffer
	session.ForwardingBufferLock.Lock()
	packets := session.ForwardingBuffer
	session.ForwardingBuffer = nil
	session.ForwardingBufferLock.Unlock()

	if len(packets) == 0 {
		s.log.Debugf("[HO-FLUSH] No packets to forward for PDU Session %d", session.Id)
		return nil
	}

	s.log.Infof("[HO-FLUSH] Starting flush of %d buffered packets to %s TEID=%d for PDU Session %d",
		len(packets), upfAddr.String(), teid, session.Id)

	// Send each packet to the UPF forwarding endpoint
	for _, pkt := range packets {
		gtpPacket, err := gtpQoSMsg.BuildQoSGTPPacket(teid, pkt.QFI, pkt.RQI, pkt.Payload)
		if err != nil {
			s.log.Warnf("[HO-FLUSH] Failed to build GTP packet: %v", err)
			continue
		}
		if _, err := s.gtpuConn.WriteTo(gtpPacket, upfAddr); err != nil {
			s.log.Warnf("[HO-FLUSH] Failed to send forwarded packet: %v", err)
		}
	}

	s.log.Infof("[HO-FLUSH] Completed forwarding %d packets for PDU Session %d", len(packets), session.Id)
	return nil
}

// FlushBufferToUE sends buffered packets to the UE via IPSec/GRE (for target N3IWF after UE connects)
func (s *Server) FlushBufferToUE(ranUe n3iwf_context.RanUe, session *n3iwf_context.PDUSession) error {
	if session == nil {
		return errors.New("nil session")
	}
	if ranUe == nil {
		return errors.New("nil ranUe")
	}

	n3iwfCtx := s.Context()
	ranUeNgapID := ranUe.GetSharedCtx().RanUeNgapId

	ikeUe, err := n3iwfCtx.IkeUeLoadFromNgapId(ranUeNgapID)
	if err != nil {
		return fmt.Errorf("cannot find IkeUe: %w", err)
	}

	ueInnerIPAddr := ikeUe.IPSecInnerIPAddr
	if ueInnerIPAddr == nil {
		return errors.New("UE inner IP not available")
	}

	// Find the ChildSA for this PDU session
	var cm *ipv4.ControlMessage
	for _, childSA := range ikeUe.N3IWFChildSecurityAssociation {
		if childSA == nil || childSA.XfrmIface == nil {
			continue
		}
		for _, pduID := range childSA.PDUSessionIds {
			if pduID == session.Id {
				cm = &ipv4.ControlMessage{
					IfIndex: childSA.XfrmIface.Attrs().Index,
				}
				break
			}
		}
		if cm != nil {
			break
		}
	}

	if cm == nil {
		return fmt.Errorf("no ChildSA found for PDU Session %d", session.Id)
	}

	// Take packets from buffer
	session.ForwardingBufferLock.Lock()
	packets := session.ForwardingBuffer
	session.ForwardingBuffer = nil
	session.ForwardingBufferLock.Unlock()

	if len(packets) == 0 {
		s.log.Debugf("[HO-TARGET-FLUSH] No packets to deliver for PDU Session %d", session.Id)
		return nil
	}

	s.log.Infof("[HO-TARGET-FLUSH] Starting delivery of %d buffered packets to UE for PDU Session %d",
		len(packets), session.Id)

	delivered := 0
	failed := 0
	var firstErr error
	for _, pkt := range packets {
		grePacket := gre.GREPacket{}
		grePacket.SetPayload(pkt.Payload, gre.IPv4)
		grePacket.SetQoS(pkt.QFI, pkt.RQI)
		forwardData := grePacket.Marshal()

		if _, err := s.greWriteToWithRetry(forwardData, cm, ueInnerIPAddr); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			failed++
		} else {
			delivered++
		}
	}

	if failed > 0 {
		s.log.Warnf("[HO-TARGET-FLUSH] Delivered %d/%d packets to UE for PDU Session %d (failed=%d firstErr=%v)",
			delivered, len(packets), session.Id, failed, firstErr)
	} else {
		s.log.Infof("[HO-TARGET-FLUSH] Delivered %d/%d packets to UE for PDU Session %d",
			delivered, len(packets), session.Id)
	}
	return nil
}

// ClearForwardingBuffer drops all buffered packets (used on HO failure)
func (s *Server) ClearForwardingBuffer(session *n3iwf_context.PDUSession) int {
	if session == nil {
		return 0
	}

	session.ForwardingBufferLock.Lock()
	defer session.ForwardingBufferLock.Unlock()

	count := len(session.ForwardingBuffer)
	session.ForwardingBuffer = nil

	if count > 0 {
		s.log.Infof("[HO-CLEAR] Dropped %d buffered packets for PDU Session %d", count, session.Id)
	}
	return count
}
