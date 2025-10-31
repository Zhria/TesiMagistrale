package rc

import (
	"fmt"
	"sync"

	n3iwf_context "github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/logger"
	"github.com/free5gc/ngap/ngapType"
)

type NgapEventSender interface {
	SendNgapEvt(evt n3iwf_context.NgapEvt)
}

type HandoverAlert struct {
	RanUeNgapId             int64
	Cause                   *ngapType.Cause
	TargetID                *ngapType.TargetID
	PDUSessionResourceHORqd []ngapType.PDUSessionResourceItemHORqd
	DirectForwarding        bool
	SourceToTargetContainer []byte
	Metadata                map[string]string
}

type HandoverAlertHandler struct {
	ctx    *n3iwf_context.N3IWFContext
	sender NgapEventSender
}

var (
	handoverHandlerMu sync.RWMutex
	handoverHandler   *HandoverAlertHandler
)

func NewHandoverAlertHandler(
	ctx *n3iwf_context.N3IWFContext,
	sender NgapEventSender,
) *HandoverAlertHandler {
	return &HandoverAlertHandler{
		ctx:    ctx,
		sender: sender,
	}
}

func (h *HandoverAlertHandler) Handle(alert HandoverAlert) error {
	if h == nil {
		return fmt.Errorf("handover alert handler is nil")
	}
	if h.ctx == nil {
		return fmt.Errorf("n3iwf context not available")
	}
	if h.sender == nil {
		return fmt.Errorf("ngap event sender not available")
	}
	if alert.RanUeNgapId == 0 {
		return fmt.Errorf("handover alert missing ranUeNgapId")
	}
	if alert.TargetID == nil {
		return fmt.Errorf("handover alert missing TargetID")
	}

	if _, ok := h.ctx.RanUePoolLoad(alert.RanUeNgapId); !ok {
		return fmt.Errorf("ranUe with id %d not found", alert.RanUeNgapId)
	}

	cause := defaultHandoverCause()
	if alert.Cause != nil {
		cause = *alert.Cause
	}

	evt := n3iwf_context.NewTriggerHandoverEvt(
		alert.RanUeNgapId,
		cause,
		alert.TargetID,
		alert.PDUSessionResourceHORqd,
		alert.DirectForwarding,
		alert.SourceToTargetContainer,
	)

	logger.MainLog.Infof("HO alert received for RanUeNgapId=%d; forwarding to NGAP layer", alert.RanUeNgapId)
	h.sender.SendNgapEvt(evt)
	return nil
}

func defaultHandoverCause() ngapType.Cause {
	cause := ngapType.Cause{
		Present: ngapType.CausePresentRadioNetwork,
	}
	cause.RadioNetwork = new(ngapType.CauseRadioNetwork)
	cause.RadioNetwork.Value = ngapType.CauseRadioNetworkPresentHandoverDesirableForRadioReason
	return cause
}

func DispatchHandoverAlert(
	ctx *n3iwf_context.N3IWFContext,
	sender NgapEventSender,
	alert HandoverAlert,
) error {
	handler := NewHandoverAlertHandler(ctx, sender)
	return handler.Handle(alert)
}

func SetHandoverAlertHandler(handler *HandoverAlertHandler) {
	handoverHandlerMu.Lock()
	defer handoverHandlerMu.Unlock()
	handoverHandler = handler
}

func HandleHandoverAlert(alert HandoverAlert) error {
	handoverHandlerMu.RLock()
	handler := handoverHandler
	handoverHandlerMu.RUnlock()
	if handler == nil {
		return fmt.Errorf("handover alert handler not configured")
	}
	return handler.Handle(alert)
}
