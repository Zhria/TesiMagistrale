package statesync

import (
	"encoding/base64"
	"fmt"

	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
)

func BuildTransferFromShared(shared *n3iwf_context.RanUeSharedCtx) (*StateTransfer, error) {
	if shared == nil || shared.N3iwfCtx == nil {
		return nil, errors.New("nil shared context")
	}
	n3iwfCtx := shared.N3iwfCtx

	spi, ok := n3iwfCtx.IkeSpiLoad(shared.RanUeNgapId)
	if !ok {
		return nil, fmt.Errorf("no IKE SPI mapping for ranUeNgapId=%d", shared.RanUeNgapId)
	}
	ikeUe, ok := n3iwfCtx.IkeUePoolLoad(spi)
	if !ok || ikeUe == nil || ikeUe.N3IWFIKESecurityAssociation == nil {
		return nil, fmt.Errorf("no IkeUE/IKESA for spi=%016x", spi)
	}

	ikeSA := ikeUe.N3IWFIKESecurityAssociation

	encrT, err := encr.ToTransform(ikeSA.EncrInfo)
	if err != nil {
		return nil, errors.Wrap(err, "encode IKE encr transform")
	}
	integT := integ.ToTransform(ikeSA.IntegInfo)

	prfT := prf.ToTransform(ikeSA.PrfInfo)
	dhT := dh.ToTransform(ikeSA.DhInfo)

	ikesa := IKESAState{
		LocalSPI:           ikeSA.LocalSPI,
		RemoteSPI:          ikeSA.RemoteSPI,
		InitiatorMessageID: ikeSA.InitiatorMessageID,
		ResponderMessageID: ikeSA.ResponderMessageID,
		State:              ikeSA.State,
		ConcatenatedNonce:  b64(ikeSA.ConcatenatedNonce),
		Encr:               toTransformJSON(encrT),
		Integ:              toTransformJSON(integT),
		Prf:                toTransformJSON(prfT),
		Dh:                 toTransformJSON(dhT),
		SK_d:               b64(ikeSA.SK_d),
		SK_ai:              b64(ikeSA.SK_ai),
		SK_ar:              b64(ikeSA.SK_ar),
		SK_ei:              b64(ikeSA.SK_ei),
		SK_er:              b64(ikeSA.SK_er),
		SK_pi:              b64(ikeSA.SK_pi),
		SK_pr:              b64(ikeSA.SK_pr),
		UeBehindNAT:        ikeSA.UeBehindNAT,
		N3iwfBehindNAT:     ikeSA.N3iwfBehindNAT,
		MobikeEnabled:      ikeSA.MobikeSupported,
	}

	var childSAs []ChildSAState
	for _, child := range ikeUe.N3IWFChildSecurityAssociation {
		if child == nil || child.ChildSAKey == nil {
			continue
		}

		xfrmiId := uint32(0)
		if len(child.XfrmStateList) > 0 {
			ifid := child.XfrmStateList[0].Ifid
			if ifid > 0 {
				xfrmiId = uint32(ifid) // #nosec G115
			}
		}
		if xfrmiId == 0 {
			if cfg := n3iwfCtx.Config(); cfg != nil {
				xfrmiId = cfg.GetXfrmIfaceId()
			}
		}

		encrChildT, err := encr.ToTransformChildSA(child.EncrKInfo)
		if err != nil {
			return nil, errors.Wrap(err, "encode child encr transform")
		}
		var integChildT *ike_message.Transform
		if child.IntegKInfo != nil {
			integChildT = integ.ToTransformChildSA(child.IntegKInfo)
		}
		esnT := esn.ToTransform(child.EsnInfo)

		logger.MainLog.WithFields(logrus.Fields{
			"amfUeNgapId":     shared.AmfUeNgapId,
			"ranUeNgapId":     shared.RanUeNgapId,
			"localSpi":        fmt.Sprintf("%016x", ikeSA.LocalSPI),
			"remoteSpi":       fmt.Sprintf("%016x", ikeSA.RemoteSPI),
			"ueInnerIp":       ikeUe.IPSecInnerIP.String(),
			"inboundSpi":      fmt.Sprintf("0x%08x", child.InboundSPI),
			"outboundSpi":     fmt.Sprintf("0x%08x", child.OutboundSPI),
			"xfrmiId":         xfrmiId,
			"localIsInit":     child.LocalIsInitiator,
			"proto":           int(child.SelectedIPProtocol),
			"tsLocal":         child.TrafficSelectorLocal.String(),
			"tsRemote":        child.TrafficSelectorRemote.String(),
			"peerPublicIp":    child.PeerPublicIPAddr.String(),
			"encapEnabled":    child.EnableEncapsulate,
			"n3iwfPort":       child.N3IWFPort,
			"natPort":         child.NATPort,
			"encrTransformId": child.EncrKInfo.TransformID(),
			"integTransformId": func() uint16 {
				if child.IntegKInfo == nil {
					return 0
				}
				return child.IntegKInfo.TransformID()
			}(),
			"esnEnabled": child.EsnInfo.GetNeedESN(),
			"i2rEncrFp":  keyFingerprint(child.InitiatorToResponderEncryptionKey),
			"r2iEncrFp":  keyFingerprint(child.ResponderToInitiatorEncryptionKey),
			"i2rIntegFp": keyFingerprint(child.InitiatorToResponderIntegrityKey),
			"r2iIntegFp": keyFingerprint(child.ResponderToInitiatorIntegrityKey),
		}).Debug("Handover state-sync: export child SA")

		childSAs = append(childSAs, ChildSAState{
			InboundSPI:                        child.InboundSPI,
			OutboundSPI:                       child.OutboundSPI,
			LocalIsInitiator:                  child.LocalIsInitiator,
			SelectedIPProto:                   child.SelectedIPProtocol,
			PeerPublicIP:                      child.PeerPublicIPAddr.String(),
			TrafficSelectorLocal:              child.TrafficSelectorLocal.String(),
			TrafficSelectorRemote:             child.TrafficSelectorRemote.String(),
			EnableEncapsulate:                 child.EnableEncapsulate,
			N3IWFPort:                         child.N3IWFPort,
			NATPort:                           child.NATPort,
			PDUSessionIds:                     append([]int64(nil), child.PDUSessionIds...),
			XfrmiId:                           xfrmiId,
			Encr:                              toTransformJSON(encrChildT),
			Integ:                             toTransformJSON(integChildT),
			ESN:                               toTransformJSON(esnT),
			InitiatorToResponderEncryptionKey: b64(child.InitiatorToResponderEncryptionKey),
			ResponderToInitiatorEncryptionKey: b64(child.ResponderToInitiatorEncryptionKey),
			InitiatorToResponderIntegrityKey:  b64(child.InitiatorToResponderIntegrityKey),
			ResponderToInitiatorIntegrityKey:  b64(child.ResponderToInitiatorIntegrityKey),
		})
	}

	transfer := &StateTransfer{
		AMFUeNgapID: shared.AmfUeNgapId,
		GUTI:        shared.Guti,
		UeInnerIP:   ikeUe.IPSecInnerIP.String(),
		IKESA:       ikesa,
		ChildSAs:    childSAs,
	}

	logger.MainLog.WithFields(logrus.Fields{
		"amfUeNgapId":    shared.AmfUeNgapId,
		"ranUeNgapId":    shared.RanUeNgapId,
		"localSpi":       fmt.Sprintf("%016x", ikeSA.LocalSPI),
		"remoteSpi":      fmt.Sprintf("%016x", ikeSA.RemoteSPI),
		"ueInnerIp":      ikeUe.IPSecInnerIP.String(),
		"childSAs":       len(childSAs),
		"ueBehindNat":    ikeSA.UeBehindNAT,
		"n3iwfBehindNat": ikeSA.N3iwfBehindNAT,
		"mobike":         ikeSA.MobikeSupported,
	}).Info("Handover state-sync: built transfer")

	return transfer, nil
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
