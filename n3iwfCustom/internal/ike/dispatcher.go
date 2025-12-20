package ike

import (
	"net"
	"runtime/debug"

	ike_message "github.com/free5gc/ike/message"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
)

func (s *Server) Dispatch(
	udpConn *net.UDPConn,
	localAddr, remoteAddr *net.UDPAddr,
	ikeMessage *ike_message.IKEMessage, msg []byte,
	ikeSA *n3iwf_context.IKESecurityAssociation,
) {
	ikeLog := logger.IKELog
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			ikeLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}
	}()

	// Ensure we always keep a usable UE UDP endpoint in the in-memory SA.
	// This is required for out-of-band INFORMATIONAL sends (e.g., target-to-source notify)
	// after handover state-sync, where the IKESA is imported without a live IKEConnection.
	if ikeSA != nil && ikeSA.IkeUE != nil && udpConn != nil && localAddr != nil && remoteAddr != nil {
		if ikeSA.IKEConnection == nil {
			ikeSA.IKEConnection = &n3iwf_context.UDPSocketInfo{
				Conn:      udpConn,
				N3IWFAddr: localAddr,
				UEAddr:    remoteAddr,
			}
		} else if ikeSA.MobikeSupported &&
			(ikeSA.IKEConnection.UEAddr == nil || ikeSA.IKEConnection.N3IWFAddr == nil ||
				!ikeSA.IKEConnection.UEAddr.IP.Equal(remoteAddr.IP) ||
				ikeSA.IKEConnection.UEAddr.Port != remoteAddr.Port ||
				!ikeSA.IKEConnection.N3IWFAddr.IP.Equal(localAddr.IP) ||
				ikeSA.IKEConnection.N3IWFAddr.Port != localAddr.Port) {
			ikeSA.IKEConnection.Conn = udpConn
			ikeSA.IKEConnection.UEAddr = remoteAddr
			ikeSA.IKEConnection.N3IWFAddr = localAddr
		}
		if ikeSA.IkeUE.IKEConnection == nil {
			ikeSA.IkeUE.IKEConnection = ikeSA.IKEConnection
		}
	}

	switch ikeMessage.ExchangeType {
	case ike_message.IKE_SA_INIT:
		s.HandleIKESAINIT(udpConn, localAddr, remoteAddr, ikeMessage, msg)
	case ike_message.IKE_AUTH:
		s.HandleIKEAUTH(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	case ike_message.CREATE_CHILD_SA:
		s.HandleCREATECHILDSA(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	case ike_message.INFORMATIONAL:
		s.HandleInformational(udpConn, localAddr, remoteAddr, ikeMessage, ikeSA)
	default:
		ikeLog.Warnf("Unimplemented IKE message type, exchange type: %d", ikeMessage.ExchangeType)
	}
}
