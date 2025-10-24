package rc

import (
	"fmt"
	"strings"

	"github.com/free5gc/n3iwf/internal/context"
	"github.com/free5gc/n3iwf/internal/snapshot"
	"github.com/free5gc/ngap/ngapType"
)

// EnrichSnapshot associa le informazioni provenienti da hostapd con i contatori
// raccolti dal N3IWF e con il contesto UE esposto da AMF/N3IWF.
func EnrichSnapshot(rcSnap *snapshot.RCSnapshot, metrics snapshot.Snapshot, ctx *snapshot.N3iwfAppSnapshot) {
	if rcSnap == nil {
		return
	}

	ipMetrics := metrics.ByUEIP
	ueByIP := buildUEMap(ctx)

	var associations []snapshot.RCUEAssociation
	for _, iface := range rcSnap.Interfaces {
		for _, station := range iface.Stations {
			assoc := snapshot.RCUEAssociation{
				Interface: iface.Interface,
				MAC:       station.MAC,
				Station:   station.DeepCopy(),
			}

			ip := extractIPFromStation(station)
			assoc.UEIP = ip

			if counters, ok := ipMetrics[ip]; ok {
				assoc.Counters = counters
			}

			if ue, ok := ueByIP[ip]; ok {
				assoc.UE = buildUEInfo(ue)
			} else if ip != "" && len(ipMetrics) > 0 {
				assoc.Mismatches = append(assoc.Mismatches, "ue_not_found")
			}

			associations = append(associations, assoc)
		}
	}

	rcSnap.Associations = associations
}

func buildUEMap(ctx *snapshot.N3iwfAppSnapshot) map[string]context.N3IWFRanUe {
	result := make(map[string]context.N3IWFRanUe)
	if ctx == nil {
		return result
	}
	for _, ue := range ctx.UEs {
		if ip := strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv4); ip != "" {
			result[ip] = ue
		}
		if ip := strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv6); ip != "" {
			result[ip] = ue
		}
	}
	return result
}

func extractIPFromStation(station snapshot.RCStation) string {
	searchMaps := []map[string]string{
		station.Fields,
		station.Hostapd,
		station.StationDump,
	}
	for _, m := range searchMaps {
		if ip := extractIPFromMap(m); ip != "" {
			return ip
		}
	}
	return ""
}

func extractIPFromMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	candidates := []string{
		m["ip_addr"],
		m["ip"],
		m["ipv4"],
		m["addr"],
	}
	for _, val := range candidates {
		if val == "" {
			continue
		}
		parts := strings.FieldsFunc(val, func(r rune) bool {
			return r == ',' || r == ' ' || r == '\t'
		})
		if len(parts) > 0 {
			return strings.TrimSpace(parts[0])
		}
	}
	return ""
}

func buildUEInfo(ue context.N3IWFRanUe) *snapshot.RCAssociatedUE {
	info := &snapshot.RCAssociatedUE{
		RanUeNgapId: ue.RanUeSharedCtx.RanUeNgapId,
		AmfUeNgapId: ue.RanUeSharedCtx.AmfUeNgapId,
		Guti:        ue.RanUeSharedCtx.Guti,
		IPAddrv4:    strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv4),
		IPAddrv6:    strings.TrimSpace(ue.RanUeSharedCtx.IPAddrv6),
	}

	if len(ue.RanUeSharedCtx.PduSessionList) > 0 {
		info.PduSessions = make([]snapshot.RCPDUSessionInfo, 0, len(ue.RanUeSharedCtx.PduSessionList))
		for _, session := range ue.RanUeSharedCtx.PduSessionList {
			pdu := snapshot.RCPDUSessionInfo{
				ID:     session.Id,
				SNSSAI: snssaiToString(session.Snssai),
				QFIs:   append([]uint8(nil), session.QFIList...),
			}
			if session.GTPConnInfo != nil {
				pdu.IncomingTEID = session.GTPConnInfo.IncomingTEID
				pdu.OutgoingTEID = session.GTPConnInfo.OutgoingTEID
				pdu.UPFIP = session.GTPConnInfo.UPFIPAddr
			}
			info.PduSessions = append(info.PduSessions, pdu)
		}
	}

	return info
}

func snssaiToString(snssai ngapType.SNSSAI) string {
	var sst uint8
	if len(snssai.SST.Value) > 0 {
		sst = snssai.SST.Value[0]
	}
	sd := 0
	if len(snssai.SD.Value) == 3 {
		sd = int(snssai.SD.Value[0])<<16 | int(snssai.SD.Value[1])<<8 | int(snssai.SD.Value[2])
	}
	return fmt.Sprintf("%d-%06x", sst, sd)
}
