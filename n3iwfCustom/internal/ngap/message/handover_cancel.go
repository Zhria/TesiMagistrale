package message

import (
	"fmt"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func BuildHandoverCancel(shared *n3iwf_context.RanUeSharedCtx) ([]byte, error) {
	if shared == nil {
		return nil, fmt.Errorf("nil shared UE context")
	}
	if shared.AmfUeNgapId == n3iwf_context.AmfUeNgapIdUnspecified {
		return nil, fmt.Errorf("AMF UE NGAP ID unspecified for RanUE %d", shared.RanUeNgapId)
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiating := pdu.InitiatingMessage
	initiating.ProcedureCode.Value = ngapType.ProcedureCodeHandoverCancel
	initiating.Criticality.Value = ngapType.CriticalityPresentReject
	initiating.Value.Present = ngapType.InitiatingMessagePresentHandoverCancel
	initiating.Value.HandoverCancel = new(ngapType.HandoverCancel)

	cancel := initiating.Value.HandoverCancel
	ies := &cancel.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverCancelIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverCancelIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: shared.AmfUeNgapId}
	ies.List = append(ies.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverCancelIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverCancelIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: shared.RanUeNgapId}
	ies.List = append(ies.List, ie)

	// Cause: RadioNetwork / handoverCancelled
	ie = ngapType.HandoverCancelIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverCancelIEsPresentCause
	ie.Value.Cause = &ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork,
		RadioNetwork: &ngapType.CauseRadioNetwork{
			Value: ngapType.CauseRadioNetworkPresentHandoverCancelled,
		},
	}
	ies.List = append(ies.List, ie)

	return ngap.Encoder(pdu)
}
