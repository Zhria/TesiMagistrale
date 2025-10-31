package message

import (
	"errors"
	"fmt"

	"github.com/free5gc/aper"
	"github.com/free5gc/ngap"
	"github.com/free5gc/ngap/ngapType"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
)

func BuildHandoverRequired(
	ranUe n3iwf_context.RanUe,
	evt *n3iwf_context.TriggerHandoverEvt,
) ([]byte, error) {
	if ranUe == nil {
		return nil, errors.New("nil RanUE")
	}
	if evt == nil {
		return nil, errors.New("nil handover trigger event")
	}
	if evt.TargetID == nil {
		return nil, errors.New("nil TargetID in handover trigger")
	}

	sharedCtx := ranUe.GetSharedCtx()
	if sharedCtx == nil {
		return nil, errors.New("missing shared UE context")
	}
	if sharedCtx.AMF == nil {
		return nil, errors.New("RanUE is not attached to an AMF")
	}
	if sharedCtx.AmfUeNgapId == n3iwf_context.AmfUeNgapIdUnspecified {
		return nil, fmt.Errorf("AMF UE NGAP ID unspecified for RanUE %d", sharedCtx.RanUeNgapId)
	}

	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentInitiatingMessage
	pdu.InitiatingMessage = new(ngapType.InitiatingMessage)

	initiatingMessage := pdu.InitiatingMessage
	initiatingMessage.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	initiatingMessage.Criticality.Value = ngapType.CriticalityPresentReject
	initiatingMessage.Value.Present = ngapType.InitiatingMessagePresentHandoverRequired
	initiatingMessage.Value.HandoverRequired = new(ngapType.HandoverRequired)

	handoverRequired := initiatingMessage.Value.HandoverRequired
	handoverRequiredIEs := &handoverRequired.ProtocolIEs

	// AMF UE NGAP ID
	amfUeNgapIDIE := ngapType.HandoverRequiredIEs{}
	amfUeNgapIDIE.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	amfUeNgapIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	amfUeNgapIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentAMFUENGAPID
	amfUeNgapIDIE.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{
		Value: sharedCtx.AmfUeNgapId,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, amfUeNgapIDIE)

	// RAN UE NGAP ID
	ranUeNgapIDIE := ngapType.HandoverRequiredIEs{}
	ranUeNgapIDIE.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
	ranUeNgapIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	ranUeNgapIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentRANUENGAPID
	ranUeNgapIDIE.Value.RANUENGAPID = &ngapType.RANUENGAPID{
		Value: sharedCtx.RanUeNgapId,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, ranUeNgapIDIE)

	// Handover Type (default to intra-5GS)
	handoverTypeIE := ngapType.HandoverRequiredIEs{}
	handoverTypeIE.Id.Value = ngapType.ProtocolIEIDHandoverType
	handoverTypeIE.Criticality.Value = ngapType.CriticalityPresentReject
	handoverTypeIE.Value.Present = ngapType.HandoverRequiredIEsPresentHandoverType
	handoverTypeIE.Value.HandoverType = &ngapType.HandoverType{
		Value: ngapType.HandoverTypePresentIntra5gs,
	}
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, handoverTypeIE)

	// Cause
	causeIE := ngapType.HandoverRequiredIEs{}
	causeIE.Id.Value = ngapType.ProtocolIEIDCause
	causeIE.Criticality.Value = ngapType.CriticalityPresentIgnore
	causeIE.Value.Present = ngapType.HandoverRequiredIEsPresentCause
	causeCopy := evt.Cause
	causeIE.Value.Cause = &causeCopy
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, causeIE)

	// Target ID
	targetIDIE := ngapType.HandoverRequiredIEs{}
	targetIDIE.Id.Value = ngapType.ProtocolIEIDTargetID
	targetIDIE.Criticality.Value = ngapType.CriticalityPresentReject
	targetIDIE.Value.Present = ngapType.HandoverRequiredIEsPresentTargetID
	targetIDCopy := *evt.TargetID
	targetIDIE.Value.TargetID = &targetIDCopy
	handoverRequiredIEs.List = append(handoverRequiredIEs.List, targetIDIE)

	// Direct Forwarding Path Availability (present if true)
	if evt.DirectForwardingAvailable {
		directForwardingIE := ngapType.HandoverRequiredIEs{}
		directForwardingIE.Id.Value = ngapType.ProtocolIEIDDirectForwardingPathAvailability
		directForwardingIE.Criticality.Value = ngapType.CriticalityPresentIgnore
		directForwardingIE.Value.Present = ngapType.HandoverRequiredIEsPresentDirectForwardingPathAvailability
		directForwardingIE.Value.DirectForwardingPathAvailability = &ngapType.DirectForwardingPathAvailability{
			Value: ngapType.DirectForwardingPathAvailabilityPresentDirectPathAvailable,
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, directForwardingIE)
	}

	// PDU Session Resource List
	if len(evt.PDUSessionResourceHORqd) > 0 {
		pduListIE := ngapType.HandoverRequiredIEs{}
		pduListIE.Id.Value = ngapType.ProtocolIEIDPDUSessionResourceListHORqd
		pduListIE.Criticality.Value = ngapType.CriticalityPresentReject
		pduListIE.Value.Present = ngapType.HandoverRequiredIEsPresentPDUSessionResourceListHORqd
		pduListIE.Value.PDUSessionResourceListHORqd = new(ngapType.PDUSessionResourceListHORqd)

		for _, item := range evt.PDUSessionResourceHORqd {
			cloned := ngapType.PDUSessionResourceItemHORqd{
				PDUSessionID:             item.PDUSessionID,
				HandoverRequiredTransfer: append(aper.OctetString(nil), item.HandoverRequiredTransfer...),
				IEExtensions:             item.IEExtensions,
			}
			pduListIE.Value.PDUSessionResourceListHORqd.List = append(
				pduListIE.Value.PDUSessionResourceListHORqd.List,
				cloned,
			)
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, pduListIE)
	}

	// Source to Target Transparent Container
	if len(evt.SourceToTargetContainer) > 0 {
		containerIE := ngapType.HandoverRequiredIEs{}
		containerIE.Id.Value = ngapType.ProtocolIEIDSourceToTargetTransparentContainer
		containerIE.Criticality.Value = ngapType.CriticalityPresentReject
		containerIE.Value.Present = ngapType.HandoverRequiredIEsPresentSourceToTargetTransparentContainer
		containerIE.Value.SourceToTargetTransparentContainer = &ngapType.SourceToTargetTransparentContainer{
			Value: aper.OctetString(append([]byte(nil), evt.SourceToTargetContainer...)),
		}
		handoverRequiredIEs.List = append(handoverRequiredIEs.List, containerIE)
	}

	return ngap.Encoder(pdu)
}

func BuildHandoverPreparationFailure(
	amfUeNgapId int64,
	ranUeNgapId *int64,
	cause ngapType.Cause,
) ([]byte, error) {
	var pdu ngapType.NGAPPDU
	pdu.Present = ngapType.NGAPPDUPresentUnsuccessfulOutcome
	pdu.UnsuccessfulOutcome = new(ngapType.UnsuccessfulOutcome)

	unsuccessful := pdu.UnsuccessfulOutcome
	unsuccessful.ProcedureCode.Value = ngapType.ProcedureCodeHandoverPreparation
	unsuccessful.Criticality.Value = ngapType.CriticalityPresentReject
	unsuccessful.Value.Present = ngapType.UnsuccessfulOutcomePresentHandoverPreparationFailure
	unsuccessful.Value.HandoverPreparationFailure = new(ngapType.HandoverPreparationFailure)

	handoverFailure := unsuccessful.Value.HandoverPreparationFailure
	handoverFailureIEs := &handoverFailure.ProtocolIEs

	// AMF UE NGAP ID
	ie := ngapType.HandoverPreparationFailureIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDAMFUENGAPID
	ie.Criticality.Value = ngapType.CriticalityPresentReject
	ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentAMFUENGAPID
	ie.Value.AMFUENGAPID = &ngapType.AMFUENGAPID{Value: amfUeNgapId}
	handoverFailureIEs.List = append(handoverFailureIEs.List, ie)

	// RAN UE NGAP ID (optional)
	if ranUeNgapId != nil {
		ie = ngapType.HandoverPreparationFailureIEs{}
		ie.Id.Value = ngapType.ProtocolIEIDRANUENGAPID
		ie.Criticality.Value = ngapType.CriticalityPresentIgnore
		ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentRANUENGAPID
		ie.Value.RANUENGAPID = &ngapType.RANUENGAPID{Value: *ranUeNgapId}
		handoverFailureIEs.List = append(handoverFailureIEs.List, ie)
	}

	// Cause
	ie = ngapType.HandoverPreparationFailureIEs{}
	ie.Id.Value = ngapType.ProtocolIEIDCause
	ie.Criticality.Value = ngapType.CriticalityPresentIgnore
	ie.Value.Present = ngapType.HandoverPreparationFailureIEsPresentCause
	causeCopy := cause
	ie.Value.Cause = &causeCopy
	handoverFailureIEs.List = append(handoverFailureIEs.List, ie)

	return ngap.Encoder(pdu)
}
