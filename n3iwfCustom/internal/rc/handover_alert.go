package rc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/free5gc/aper"
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

type handoverTriggerPayload struct {
	RanUeNgapId             int64             `json:"ranUeNgapId"`
	TargetID                string            `json:"targetId"`
	DirectForwarding        bool              `json:"directForwarding"`
	SourceToTargetContainer string            `json:"sourceToTargetContainer,omitempty"`
	Metadata                map[string]string `json:"metadata,omitempty"`
}

// StartHandoverHTTPServer launches a background HTTP server that accepts
// POST /rc/handover requests to trigger an N3IWF handover.
func StartHandoverHTTPServer(addr string) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		addr = ":9085"
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/rc/handover", handleHandoverHTTPPost)
	go func() {
		logger.MainLog.Infof("RC handover HTTP server listening on %s", addr)
		if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.MainLog.Errorf("RC handover HTTP server stopped: %v", err)
		}
	}()
}

func handleHandoverHTTPPost(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeHTTPError(w, http.StatusMethodNotAllowed, fmt.Errorf("only POST supported"))
		return
	}
	defer r.Body.Close()
	var payload handoverTriggerPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeHTTPError(w, http.StatusBadRequest, fmt.Errorf("invalid JSON payload: %w", err))
		return
	}
	if payload.RanUeNgapId == 0 {
		writeHTTPError(w, http.StatusBadRequest, errors.New("ranUeNgapId is required"))
		return
	}
	targetID, err := decodeTargetID(payload.TargetID)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err)
		return
	}
	container, err := decodeOptionalBytes(payload.SourceToTargetContainer)
	if err != nil {
		writeHTTPError(w, http.StatusBadRequest, err)
		return
	}
	alert := HandoverAlert{
		RanUeNgapId:             payload.RanUeNgapId,
		TargetID:                targetID,
		DirectForwarding:        payload.DirectForwarding,
		SourceToTargetContainer: container,
		Metadata:                payload.Metadata,
	}
	if err := HandleHandoverAlert(alert); err != nil {
		writeHTTPError(w, http.StatusBadGateway, err)
		return
	}
	writeHTTPSuccess(w, map[string]interface{}{
		"status":  "handover_triggered",
		"ranUeId": payload.RanUeNgapId,
	})
}

func decodeTargetID(encoded string) (*ngapType.TargetID, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, errors.New("targetId is required")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid targetId encoding: %w", err)
	}
	targetID := new(ngapType.TargetID)
	if err := aper.UnmarshalWithParams(der, targetID, "valueExt"); err != nil {
		return nil, fmt.Errorf("unable to decode targetId: %w", err)
	}
	return targetID, nil
}

func decodeOptionalBytes(encoded string) ([]byte, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, nil
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 payload: %w", err)
	}
	return data, nil
}

func writeHTTPSuccess(w http.ResponseWriter, payload interface{}) {
	writeHTTPJSON(w, http.StatusAccepted, payload)
}

func writeHTTPError(w http.ResponseWriter, status int, err error) {
	logger.MainLog.Errorf("RC handover HTTP error: %v", err)
	writeHTTPJSON(w, status, map[string]interface{}{"error": err.Error()})
}

func writeHTTPJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if payload == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		logger.MainLog.Errorf("RC handover HTTP unable to encode response: %v", err)
	}
}
