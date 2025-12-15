package message

import (
	"fmt"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"
)

func BuildHandoverNotify(ranUe n3iwf_context.RanUe) ([]byte, error) {
	if ranUe == nil {
		return nil, errNilRanUeForHandoverNotify
	}

	shared := ranUe.GetSharedCtx()
	if shared == nil {
		return nil, errNilSharedCtxForHandoverNotify
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiating := pdu.InitiatingMessage
	initiating.ProcedureCode.Value = ngapType.ProcedureCodeHandoverNotification
	initiating.Criticality.Value = ngapType.CriticalityPresentIgnore
	initiating.Value.Present = ngapType.InitiatingMessagePresentHandoverNotify
	initiating.Value.HandoverNotify = new(ngapType.HandoverNotify)

	notify := initiating.Value.HandoverNotify
	ies := &notify.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverNotifyIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverNotifyIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: shared.AmfUeNgapId}
	ies.List = append(ies.List, ie)

	// RAN UE NGAP ID
	ie = ngapType.HandoverNotifyIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverNotifyIEsPresentRANUENGAPID
	ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: shared.RanUeNgapId}
	ies.List = append(ies.List, ie)

	// User Location Information (optional)
	if uli := ranUe.GetUserLocationInformation(); uli != nil {
		ie = ngapType.HandoverNotifyIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDUserLocationInformation
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverNotifyIEsPresentUserLocationInformation
		ie.Value.UserLocationInformation = uli
		ies.List = append(ies.List, ie)
	}

	return ngap.Encoder(pdu)
}

var (
	errNilRanUeForHandoverNotify     = fmt.Errorf("nil RanUE")
	errNilSharedCtxForHandoverNotify = fmt.Errorf("nil shared UE context")
)
