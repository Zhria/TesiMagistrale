package statesync

import (
	"encoding/base64"
	"fmt"
	"net"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	ike_message "github.com/free5gc/ike/message"
	ike_security "github.com/free5gc/ike/security"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/ike/xfrm"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/factory"
)

const (
	apiPathStatePush = "/handover/v1/state"
	apiVersion       = 1
)

type TransformJSON struct {
	Type uint8  `json:"type"`
	ID   uint16 `json:"id"`

	AttributePresent bool   `json:"attributePresent,omitempty"`
	AttributeType    uint16 `json:"attributeType,omitempty"`
	AttributeValue   uint16 `json:"attributeValue,omitempty"`
	AttributeVL      string `json:"attributeVL,omitempty"` // base64
}

func toTransformJSON(t *ike_message.Transform) TransformJSON {
	if t == nil {
		return TransformJSON{}
	}
	out := TransformJSON{
		Type:             t.TransformType,
		ID:               t.TransformID,
		AttributePresent: t.AttributePresent,
		AttributeType:    t.AttributeType,
		AttributeValue:   t.AttributeValue,
	}
	if len(t.VariableLengthAttributeValue) > 0 {
		out.AttributeVL = base64.StdEncoding.EncodeToString(t.VariableLengthAttributeValue)
	}
	return out
}

func fromTransformJSON(t TransformJSON) (*ike_message.Transform, error) {
	out := &ike_message.Transform{
		TransformType:                t.Type,
		TransformID:                  t.ID,
		AttributePresent:             t.AttributePresent,
		AttributeType:                t.AttributeType,
		AttributeValue:               t.AttributeValue,
		AttributeFormat:              ike_message.AttributeFormatUseTV,
		VariableLengthAttributeValue: nil,
	}
	if t.AttributePresent && t.AttributeVL != "" {
		raw, err := base64.StdEncoding.DecodeString(t.AttributeVL)
		if err != nil {
			return nil, fmt.Errorf("decode transform attributeVL: %w", err)
		}
		out.VariableLengthAttributeValue = raw
		out.AttributeFormat = ike_message.AttributeFormatUseTLV
	}
	return out, nil
}

type IKESAState struct {
	LocalSPI  uint64 `json:"localSpi"`
	RemoteSPI uint64 `json:"remoteSpi"`

	InitiatorMessageID uint32 `json:"initiatorMsgId"`
	ResponderMessageID uint32 `json:"responderMsgId"`
	State              uint8  `json:"state"`

	ConcatenatedNonce string `json:"concatenatedNonce,omitempty"` // base64

	Encr  TransformJSON `json:"encr"`
	Integ TransformJSON `json:"integ"`
	Prf   TransformJSON `json:"prf"`
	Dh    TransformJSON `json:"dh"`

	SK_d  string `json:"sk_d,omitempty"`
	SK_ai string `json:"sk_ai,omitempty"`
	SK_ar string `json:"sk_ar,omitempty"`
	SK_ei string `json:"sk_ei,omitempty"`
	SK_er string `json:"sk_er,omitempty"`
	SK_pi string `json:"sk_pi,omitempty"`
	SK_pr string `json:"sk_pr,omitempty"`

	UeBehindNAT    bool `json:"ueBehindNat,omitempty"`
	N3iwfBehindNAT bool `json:"n3iwfBehindNat,omitempty"`
	MobikeEnabled  bool `json:"mobikeEnabled,omitempty"`
}

type ChildSAState struct {
	InboundSPI  uint32 `json:"inboundSpi"`
	OutboundSPI uint32 `json:"outboundSpi"`

	LocalIsInitiator bool  `json:"localIsInitiator"`
	SelectedIPProto  uint8 `json:"selectedIpProto"`

	PeerPublicIP string `json:"peerPublicIp"`

	TrafficSelectorLocal  string `json:"tsLocal"`
	TrafficSelectorRemote string `json:"tsRemote"`

	EnableEncapsulate bool `json:"enableEncapsulate"`
	N3IWFPort         int  `json:"n3iwfPort,omitempty"`
	NATPort           int  `json:"natPort,omitempty"`

	PDUSessionIds []int64 `json:"pduSessionIds,omitempty"`

	XfrmiId uint32 `json:"xfrmiId"`

	Encr  TransformJSON `json:"encr"`
	Integ TransformJSON `json:"integ"`
	ESN   TransformJSON `json:"esn"`

	InitiatorToResponderEncryptionKey string `json:"i2rEncrKey,omitempty"`
	ResponderToInitiatorEncryptionKey string `json:"r2iEncrKey,omitempty"`
	InitiatorToResponderIntegrityKey  string `json:"i2rIntegKey,omitempty"`
	ResponderToInitiatorIntegrityKey  string `json:"r2iIntegKey,omitempty"`
}

type StateTransfer struct {
	Version int `json:"version"`

	AMFUeNgapID int64  `json:"amfUeNgapId"`
	GUTI        string `json:"guti,omitempty"`

	UeInnerIP string `json:"ueInnerIp"`

	IKESA    IKESAState     `json:"ikesa"`
	ChildSAs []ChildSAState `json:"childSas"`
}

func ImportStateForRanUe(
	n3iwfCtx *n3iwf_context.N3IWFContext,
	cfg *factory.Config,
	ranUe n3iwf_context.RanUe,
	req *StateTransfer,
) error {
	if n3iwfCtx == nil || cfg == nil || req == nil {
		return errors.New("nil context/config/request")
	}
	if ranUe == nil {
		return errors.New("nil target ranUe")
	}
	if req.Version != apiVersion {
		return fmt.Errorf("unsupported version %d", req.Version)
	}

	shared := ranUe.GetSharedCtx()
	if shared == nil {
		return errors.New("target ranUe shared ctx is nil")
	}

	if req.AMFUeNgapID != 0 && req.AMFUeNgapID != shared.AmfUeNgapId {
		logger.MainLog.Warnf("Handover state-sync: AMF UE NGAP ID mismatch: transfer=%d target=%d (continuing import)",
			req.AMFUeNgapID, shared.AmfUeNgapId)
	}

	if _, ok := n3iwfCtx.IKESALoad(req.IKESA.LocalSPI); ok {
		logger.MainLog.Infof("Handover state-sync: IKESA for localSpi=%016x already exists; skipping import", req.IKESA.LocalSPI)
		return nil
	}

	ueInnerIP := net.ParseIP(req.UeInnerIP).To4()
	if ueInnerIP == nil {
		return fmt.Errorf("invalid ueInnerIp %q", req.UeInnerIP)
	}
	if ueInnerIP.String() == cfg.GetIPSecGatewayAddr() {
		return fmt.Errorf("ueInnerIp %s equals IPSec gateway address", ueInnerIP)
	}

	// Reserve the UE inner IP in the local pool to avoid duplication.
	if _, err := n3iwfCtx.IPSecInnerIPPool.Allocate(ueInnerIP); err != nil {
		return errors.Wrap(err, "reserve ue inner ip in pool")
	}

	ikeUe := n3iwfCtx.NewN3iwfIkeUe(req.IKESA.LocalSPI)
	ikeUe.IPSecInnerIP = ueInnerIP
	if ipAddr, err := net.ResolveIPAddr("ip", ueInnerIP.String()); err == nil {
		ikeUe.IPSecInnerIPAddr = ipAddr
	}

	// Track allocation for lookups by inner IP.
	_, loaded := n3iwfCtx.AllocatedUEIPAddress.LoadOrStore(ueInnerIP.String(), ikeUe)
	if loaded {
		return fmt.Errorf("ue inner ip %s already allocated in context", ueInnerIP.String())
	}

	ikeSA, err := buildIKESA(cfg, &req.IKESA)
	if err != nil {
		return err
	}
	ikeSA.IkeUE = ikeUe
	ikeUe.N3IWFIKESecurityAssociation = ikeSA

	n3iwfCtx.IKESA.Store(req.IKESA.LocalSPI, ikeSA)
	n3iwfCtx.IkeSpiNgapIdMapping(req.IKESA.LocalSPI, shared.RanUeNgapId)

	// Import Child SAs and install XFRM rules.
	for _, c := range req.ChildSAs {
		child, err := buildChildSA(cfg, n3iwfCtx, ikeUe, &c)
		if err != nil {
			return fmt.Errorf("childSA inboundSpi=0x%08x: %w", c.InboundSPI, err)
		}

		// Backward compatibility: old transfers didn't carry PDUSessionIds. For UP GRE Child SAs, try to infer it.
		if len(child.PDUSessionIds) == 0 && c.SelectedIPProto == unix.IPPROTO_GRE {
			if len(shared.PduSessionList) == 1 {
				for pduID := range shared.PduSessionList {
					child.PDUSessionIds = []int64{pduID}
					break
				}
			} else if len(shared.PduSessionList) > 1 {
				logger.MainLog.Warnf("Handover state-sync: missing pduSessionIds for childSA inboundSpi=0x%08x (pduSessions=%d)",
					c.InboundSPI, len(shared.PduSessionList))
			}
		}
		// Keep the invariant "len(PDUSessionIds)>0" used in several N3IWF code paths (CP uses -1).
		if len(child.PDUSessionIds) == 0 {
			child.PDUSessionIds = []int64{-1}
		}

		ikeUe.N3IWFChildSecurityAssociation[child.InboundSPI] = child
		n3iwfCtx.ChildSA.Store(child.InboundSPI, child)

		if err := ensureXfrmi(cfg, n3iwfCtx, child, c.XfrmiId); err != nil {
			return fmt.Errorf("ensure xfrmi ifid=%d: %w", c.XfrmiId, err)
		}
		if err := xfrm.ApplyXFRMRule(child.LocalIsInitiator, c.XfrmiId, child); err != nil {
			return fmt.Errorf("apply xfrm ifid=%d: %w", c.XfrmiId, err)
		}
	}

	logger.MainLog.Infof("Imported handover IPSec state: amfUeNgapId=%d ranUeNgapId=%d localSpi=%016x childSAs=%d",
		req.AMFUeNgapID, shared.RanUeNgapId, req.IKESA.LocalSPI, len(req.ChildSAs))

	return nil
}

func buildIKESA(cfg *factory.Config, in *IKESAState) (*n3iwf_context.IKESecurityAssociation, error) {
	if cfg == nil || in == nil {
		return nil, errors.New("nil cfg/ikesa")
	}

	encrT, err := fromTransformJSON(in.Encr)
	if err != nil {
		return nil, err
	}
	integT, err := fromTransformJSON(in.Integ)
	if err != nil {
		return nil, err
	}
	prfT, err := fromTransformJSON(in.Prf)
	if err != nil {
		return nil, err
	}
	dhT, err := fromTransformJSON(in.Dh)
	if err != nil {
		return nil, err
	}

	encrInfo := encr.DecodeTransform(encrT)
	if encrInfo == nil {
		return nil, errors.New("decode IKE encr transform failed")
	}
	integInfo := integ.DecodeTransform(integT)
	if integInfo == nil {
		return nil, errors.New("decode IKE integ transform failed")
	}
	prfInfo := prf.DecodeTransform(prfT)
	if prfInfo == nil {
		return nil, errors.New("decode IKE prf transform failed")
	}
	dhInfo := dh.DecodeTransform(dhT)
	if dhInfo == nil {
		return nil, errors.New("decode IKE dh transform failed")
	}

	nonce, err := base64.StdEncoding.DecodeString(in.ConcatenatedNonce)
	if err != nil {
		return nil, fmt.Errorf("decode concatenatedNonce: %w", err)
	}

	ikesaKey := &ike_security.IKESAKey{
		DhInfo:    dhInfo,
		EncrInfo:  encrInfo,
		IntegInfo: integInfo,
		PrfInfo:   prfInfo,
	}

	var decErr error
	if ikesaKey.SK_d, decErr = decodeB64(in.SK_d, "sk_d"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_ai, decErr = decodeB64(in.SK_ai, "sk_ai"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_ar, decErr = decodeB64(in.SK_ar, "sk_ar"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_ei, decErr = decodeB64(in.SK_ei, "sk_ei"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_er, decErr = decodeB64(in.SK_er, "sk_er"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_pi, decErr = decodeB64(in.SK_pi, "sk_pi"); decErr != nil {
		return nil, decErr
	}
	if ikesaKey.SK_pr, decErr = decodeB64(in.SK_pr, "sk_pr"); decErr != nil {
		return nil, decErr
	}

	if err := initIKESAKeyObjects(ikesaKey); err != nil {
		return nil, err
	}

	ikeSA := &n3iwf_context.IKESecurityAssociation{
		IKESAKey:                 ikesaKey,
		RemoteSPI:                in.RemoteSPI,
		LocalSPI:                 in.LocalSPI,
		InitiatorMessageID:       in.InitiatorMessageID,
		ResponderMessageID:       in.ResponderMessageID,
		ConcatenatedNonce:        nonce,
		State:                    in.State,
		UeBehindNAT:              in.UeBehindNAT,
		N3iwfBehindNAT:           in.N3iwfBehindNAT,
		IKESAClosedCh:            make(chan struct{}, 1),
		IsUseDPD:                 false,
		DPDReqRetransTimer:       nil,
		CurrentRetryTimes:        0,
		TemporaryIkeMsg:          nil,
		InitiatorID:              nil,
		InitiatorCertificate:     nil,
		IKEAuthResponseSA:        nil,
		TrafficSelectorInitiator: nil,
		TrafficSelectorResponder: nil,
		LastEAPIdentifier:        0,
	}
	ikeSA.MobikeSupported = in.MobikeEnabled
	return ikeSA, nil
}

func initIKESAKeyObjects(k *ike_security.IKESAKey) error {
	if k == nil {
		return errors.New("nil ikesa key")
	}
	k.Prf_d = k.PrfInfo.Init(k.SK_d)
	k.Integ_i = k.IntegInfo.Init(k.SK_ai)
	k.Integ_r = k.IntegInfo.Init(k.SK_ar)

	var err error
	k.Encr_i, err = k.EncrInfo.NewCrypto(k.SK_ei)
	if err != nil {
		return err
	}
	k.Encr_r, err = k.EncrInfo.NewCrypto(k.SK_er)
	if err != nil {
		return err
	}
	k.Prf_i = k.PrfInfo.Init(k.SK_pi)
	k.Prf_r = k.PrfInfo.Init(k.SK_pr)
	return nil
}

func decodeB64(s, field string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("decode %s: %w", field, err)
	}
	return b, nil
}

func buildChildSA(
	cfg *factory.Config,
	n3iwfCtx *n3iwf_context.N3IWFContext,
	ikeUe *n3iwf_context.N3IWFIkeUe,
	in *ChildSAState,
) (*n3iwf_context.ChildSecurityAssociation, error) {
	if cfg == nil || n3iwfCtx == nil || ikeUe == nil || in == nil {
		return nil, errors.New("nil inputs")
	}
	peerIP := net.ParseIP(in.PeerPublicIP).To4()
	if peerIP == nil {
		return nil, fmt.Errorf("invalid peerPublicIp %q", in.PeerPublicIP)
	}
	localIP := net.ParseIP(cfg.GetIKEBindAddr()).To4()
	if localIP == nil {
		localIP = net.ParseIP(cfg.GetIKEBindAddr())
	}
	if localIP == nil {
		return nil, fmt.Errorf("invalid local IKE bind address %q", cfg.GetIKEBindAddr())
	}

	_, tsLocal, err := net.ParseCIDR(in.TrafficSelectorLocal)
	if err != nil {
		return nil, fmt.Errorf("parse tsLocal: %w", err)
	}
	_, tsRemote, err := net.ParseCIDR(in.TrafficSelectorRemote)
	if err != nil {
		return nil, fmt.Errorf("parse tsRemote: %w", err)
	}

	encrT, err := fromTransformJSON(in.Encr)
	if err != nil {
		return nil, err
	}
	integT, err := fromTransformJSON(in.Integ)
	if err != nil {
		return nil, err
	}
	esnT, err := fromTransformJSON(in.ESN)
	if err != nil {
		return nil, err
	}

	encrK := encr.DecodeTransformChildSA(encrT)
	if encrK == nil {
		return nil, errors.New("decode child encr transform failed")
	}
	integK := integ.DecodeTransformChildSA(integT)
	// integrity may be nil for some profiles
	esnInfo, err := esn.DecodeTransform(esnT)
	if err != nil {
		return nil, errors.Wrap(err, "decode esn transform")
	}

	childKey := &ike_security.ChildSAKey{
		EncrKInfo:  encrK,
		IntegKInfo: integK,
		EsnInfo:    esnInfo,
	}
	var keyErr error
	if childKey.InitiatorToResponderEncryptionKey, keyErr = decodeB64(in.InitiatorToResponderEncryptionKey, "i2rEncrKey"); keyErr != nil {
		return nil, keyErr
	}
	if childKey.ResponderToInitiatorEncryptionKey, keyErr = decodeB64(in.ResponderToInitiatorEncryptionKey, "r2iEncrKey"); keyErr != nil {
		return nil, keyErr
	}
	if childKey.InitiatorToResponderIntegrityKey, keyErr = decodeB64(in.InitiatorToResponderIntegrityKey, "i2rIntegKey"); keyErr != nil {
		return nil, keyErr
	}
	if childKey.ResponderToInitiatorIntegrityKey, keyErr = decodeB64(in.ResponderToInitiatorIntegrityKey, "r2iIntegKey"); keyErr != nil {
		return nil, keyErr
	}

		child := &n3iwf_context.ChildSecurityAssociation{
			InboundSPI:  in.InboundSPI,
			OutboundSPI: in.OutboundSPI,

			PeerPublicIPAddr:  peerIP,
			LocalPublicIPAddr: localIP,

			SelectedIPProtocol:    in.SelectedIPProto,
			TrafficSelectorLocal:  *tsLocal,
			TrafficSelectorRemote: *tsRemote,

			ChildSAKey:        childKey,
			EnableEncapsulate: in.EnableEncapsulate,
			N3IWFPort:         in.N3IWFPort,
			NATPort:           in.NATPort,

			PDUSessionIds: append([]int64(nil), in.PDUSessionIds...),

			IkeUE:            ikeUe,
			LocalIsInitiator: in.LocalIsInitiator,
		}
		return child, nil
	}

func ensureXfrmi(
	cfg *factory.Config,
	n3iwfCtx *n3iwf_context.N3IWFContext,
	child *n3iwf_context.ChildSecurityAssociation,
	ifid uint32,
) error {
	if cfg == nil || n3iwfCtx == nil || child == nil {
		return errors.New("nil input")
	}
	if ifid == 0 {
		return errors.New("ifid is 0")
	}
	if link, ok := n3iwfCtx.XfrmIfaces.Load(ifid); ok {
		child.XfrmIface = link.(netlink.Link)
		return nil
	}

	// Create missing interface (non-default).
	ipsecGw := net.ParseIP(cfg.GetIPSecGatewayAddr()).To4()
	if ipsecGw == nil {
		return fmt.Errorf("invalid ipSecTunnelAddress %q", cfg.GetIPSecGatewayAddr())
	}
	ipsecAddrAndSubnet := net.IPNet{IP: ipsecGw, Mask: n3iwfCtx.IPSecInnerIPPool.IPSubnet.Mask}
	name := fmt.Sprintf("%s-%d", cfg.GetXfrmIfaceName(), ifid)

	link, err := xfrm.SetupIPsecXfrmi(name, n3iwfCtx.XfrmParentIfaceName, ifid, ipsecAddrAndSubnet)
	if err != nil {
		return err
	}
	n3iwfCtx.XfrmIfaces.LoadOrStore(ifid, link)
	child.XfrmIface = link
	return nil
}
