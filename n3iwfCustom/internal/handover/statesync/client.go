package statesync

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	ike_message "github.com/free5gc/ike/message"
	"github.com/free5gc/ike/security/dh"
	"github.com/free5gc/ike/security/encr"
	"github.com/free5gc/ike/security/esn"
	"github.com/free5gc/ike/security/integ"
	"github.com/free5gc/ike/security/prf"
	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/n3iwf/pkg/factory"
	"github.com/pkg/errors"
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
		LocalSPI:            ikeSA.LocalSPI,
		RemoteSPI:           ikeSA.RemoteSPI,
		InitiatorMessageID:  ikeSA.InitiatorMessageID,
		ResponderMessageID:  ikeSA.ResponderMessageID,
		State:               ikeSA.State,
		ConcatenatedNonce:   b64(ikeSA.ConcatenatedNonce),
		Encr:                toTransformJSON(encrT),
		Integ:               toTransformJSON(integT),
		Prf:                 toTransformJSON(prfT),
		Dh:                  toTransformJSON(dhT),
		SK_d:                b64(ikeSA.SK_d),
		SK_ai:               b64(ikeSA.SK_ai),
		SK_ar:               b64(ikeSA.SK_ar),
		SK_ei:               b64(ikeSA.SK_ei),
		SK_er:               b64(ikeSA.SK_er),
		SK_pi:               b64(ikeSA.SK_pi),
		SK_pr:               b64(ikeSA.SK_pr),
		UeBehindNAT:         ikeSA.UeBehindNAT,
		N3iwfBehindNAT:      ikeSA.N3iwfBehindNAT,
		MobikeEnabled:       ikeSA.MobikeSupported,
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

		childSAs = append(childSAs, ChildSAState{
			InboundSPI:       child.InboundSPI,
			OutboundSPI:      child.OutboundSPI,
			LocalIsInitiator: child.LocalIsInitiator,
			SelectedIPProto:  child.SelectedIPProtocol,
			PeerPublicIP:     child.PeerPublicIPAddr.String(),
			TrafficSelectorLocal:  child.TrafficSelectorLocal.String(),
			TrafficSelectorRemote: child.TrafficSelectorRemote.String(),
			EnableEncapsulate:      child.EnableEncapsulate,
			N3IWFPort:              child.N3IWFPort,
			NATPort:                child.NATPort,
			XfrmiId:                xfrmiId,
			Encr:                   toTransformJSON(encrChildT),
			Integ:                  toTransformJSON(integChildT),
			ESN:                    toTransformJSON(esnT),
			InitiatorToResponderEncryptionKey: b64(child.InitiatorToResponderEncryptionKey),
			ResponderToInitiatorEncryptionKey: b64(child.ResponderToInitiatorEncryptionKey),
			InitiatorToResponderIntegrityKey:  b64(child.InitiatorToResponderIntegrityKey),
			ResponderToInitiatorIntegrityKey:  b64(child.ResponderToInitiatorIntegrityKey),
		})
	}

	transfer := &StateTransfer{
		Version:     apiVersion,
		AMFUeNgapID: shared.AmfUeNgapId,
		GUTI:        shared.Guti,
		UeInnerIP:   ikeUe.IPSecInnerIP.String(),
		IKESA:       ikesa,
		ChildSAs:    childSAs,
	}

	return transfer, nil
}

func PushToTarget(cfg *factory.Config, targetIP string, transfer *StateTransfer) error {
	if cfg == nil || transfer == nil {
		return errors.New("nil cfg/transfer")
	}
	if targetIP == "" {
		return errors.New("target ip is empty")
	}
	if !cfg.GetHandoverStateSyncEnabled() {
		return nil
	}

	url := fmt.Sprintf("http://%s:%d%s", targetIP, cfg.GetHandoverStateSyncPort(), apiPathStatePush)
	b, err := json.Marshal(transfer)
	if err != nil {
		return errors.Wrap(err, "marshal transfer")
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token := cfg.GetHandoverStateSyncToken(); token != "" {
		req.Header.Set("X-Handover-Token", token)
	}

	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "post transfer")
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("state-sync push failed: http %d: %s", resp.StatusCode, string(respBody))
	}
	logger.MainLog.Infof("Pushed handover IPSec state to target %s", url)
	return nil
}

func b64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
