package snapshot

import (
	"sync"
	"time"
)

// RCField rappresenta una coppia chiave/valore estratta dall'output di hostapd_cli.
type RCField struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// RCStation contiene le informazioni per un singolo client collegato all'access point.
type RCStation struct {
	MAC           string            `json:"mac"`
	Fields        map[string]string `json:"fields,omitempty"`
	OrderedFields []RCField         `json:"orderedFields,omitempty"`
	Hostapd       map[string]string `json:"hostapd,omitempty"`
	StationDump   map[string]string `json:"stationDump,omitempty"`
}

// DeepCopy crea una copia indipendente di RCStation.
func (s RCStation) DeepCopy() RCStation {
	out := RCStation{
		MAC: s.MAC,
	}
	if len(s.Fields) > 0 {
		out.Fields = make(map[string]string, len(s.Fields))
		for k, v := range s.Fields {
			out.Fields[k] = v
		}
	}
	if len(s.Hostapd) > 0 {
		out.Hostapd = make(map[string]string, len(s.Hostapd))
		for k, v := range s.Hostapd {
			out.Hostapd[k] = v
		}
	}
	if len(s.StationDump) > 0 {
		out.StationDump = make(map[string]string, len(s.StationDump))
		for k, v := range s.StationDump {
			out.StationDump[k] = v
		}
	}
	if len(s.OrderedFields) > 0 {
		out.OrderedFields = make([]RCField, len(s.OrderedFields))
		copy(out.OrderedFields, s.OrderedFields)
	}
	return out
}

// RCInterfaceSnapshot rappresenta i dati raccolti da hostapd_cli per una specifica interfaccia.
type RCInterfaceSnapshot struct {
	Interface     string              `json:"interface"`
	Stations      []RCStation         `json:"stations,omitempty"`
	HostapdStatus map[string]string   `json:"hostapdStatus,omitempty"`
	Survey        []map[string]string `json:"survey,omitempty"`
	Ethtool       map[string]string   `json:"ethtool,omitempty"`
	MetricsTS     time.Time           `json:"metricsTimestamp,omitempty"`
	Raw           string              `json:"raw,omitempty"`
	Error         string              `json:"error,omitempty"`
	Command       []string            `json:"command,omitempty"`
}

// DeepCopy crea una copia indipendente dell'RCInterfaceSnapshot.
func (s RCInterfaceSnapshot) DeepCopy() RCInterfaceSnapshot {
	out := RCInterfaceSnapshot{
		Interface: s.Interface,
		MetricsTS: s.MetricsTS,
		Raw:       s.Raw,
		Error:     s.Error,
	}
	if len(s.Command) > 0 {
		out.Command = make([]string, len(s.Command))
		copy(out.Command, s.Command)
	}
	if len(s.Stations) > 0 {
		out.Stations = make([]RCStation, len(s.Stations))
		for i, st := range s.Stations {
			out.Stations[i] = st.DeepCopy()
		}
	}
	if len(s.HostapdStatus) > 0 {
		out.HostapdStatus = make(map[string]string, len(s.HostapdStatus))
		for k, v := range s.HostapdStatus {
			out.HostapdStatus[k] = v
		}
	}
	if len(s.Survey) > 0 {
		out.Survey = make([]map[string]string, len(s.Survey))
		for i, entry := range s.Survey {
			if len(entry) == 0 {
				continue
			}
			copyEntry := make(map[string]string, len(entry))
			for k, v := range entry {
				copyEntry[k] = v
			}
			out.Survey[i] = copyEntry
		}
	}
	if len(s.Ethtool) > 0 {
		out.Ethtool = make(map[string]string, len(s.Ethtool))
		for k, v := range s.Ethtool {
			out.Ethtool[k] = v
		}
	}
	return out
}

// RCSnapshot contiene lo stato complessivo del collector RC.
type RCSnapshot struct {
	Timestamp    time.Time             `json:"timestamp"`
	Interfaces   []RCInterfaceSnapshot `json:"interfaces,omitempty"`
	Errors       []string              `json:"errors,omitempty"`
	Associations []RCUEAssociation     `json:"associations,omitempty"`
}

// DeepCopy crea una copia indipendente del RCSnapshot.
func (s RCSnapshot) DeepCopy() RCSnapshot {
	out := RCSnapshot{
		Timestamp: s.Timestamp,
	}
	if len(s.Errors) > 0 {
		out.Errors = make([]string, len(s.Errors))
		copy(out.Errors, s.Errors)
	}
	if len(s.Interfaces) > 0 {
		out.Interfaces = make([]RCInterfaceSnapshot, len(s.Interfaces))
		for i, iface := range s.Interfaces {
			out.Interfaces[i] = iface.DeepCopy()
		}
	}
	if len(s.Associations) > 0 {
		out.Associations = make([]RCUEAssociation, len(s.Associations))
		for i, assoc := range s.Associations {
			out.Associations[i] = assoc.DeepCopy()
		}
	}
	return out
}

// RCStore mantiene l'ultimo snapshot disponibile in modo thread-safe.
type RCStore struct {
	mu       sync.RWMutex
	snapshot RCSnapshot
}

// NewRCStore crea un nuovo store vuoto.
func NewRCStore() *RCStore {
	return &RCStore{}
}

// Update salva uno snapshot nel datastore, sovrascrivendo il precedente.
func (s *RCStore) Update(snapshot RCSnapshot) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.snapshot = snapshot.DeepCopy()
}

// Snapshot restituisce una copia dell'ultimo snapshot disponibile.
func (s *RCStore) Snapshot() RCSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snapshot.DeepCopy()
}

// RCAgg è lo store globale per le metriche RC.
var RCAgg = NewRCStore()

// RCUEAssociation raccoglie i dati unificati per un UE tra hostapd, N3IWF e AMF.
type RCUEAssociation struct {
	Interface  string          `json:"interface,omitempty"`
	MAC        string          `json:"mac,omitempty"`
	UEIP       string          `json:"ueIp,omitempty"`
	Station    RCStation       `json:"station"`
	Counters   Counters        `json:"counters"`
	UE         *RCAssociatedUE `json:"ue,omitempty"`
	Mismatches []string        `json:"mismatches,omitempty"`
}

// DeepCopy restituisce una copia indipendente dell'associazione.
func (a RCUEAssociation) DeepCopy() RCUEAssociation {
	out := RCUEAssociation{
		Interface:  a.Interface,
		MAC:        a.MAC,
		UEIP:       a.UEIP,
		Station:    a.Station.DeepCopy(),
		Counters:   a.Counters,
		Mismatches: nil,
	}
	if len(a.Mismatches) > 0 {
		out.Mismatches = make([]string, len(a.Mismatches))
		copy(out.Mismatches, a.Mismatches)
	}
	if a.UE != nil {
		ueCopy := *a.UE
		if len(a.UE.PduSessions) > 0 {
			ueCopy.PduSessions = make([]RCPDUSessionInfo, len(a.UE.PduSessions))
			copy(ueCopy.PduSessions, a.UE.PduSessions)
		}
		out.UE = &ueCopy
	}
	return out
}

// RCAssociatedUE contiene le informazioni del contesto N3IWF/AMF rilevanti per l'UE.
type RCAssociatedUE struct {
	RanUeNgapId int64              `json:"ranUeNgapId"`
	AmfUeNgapId int64              `json:"amfUeNgapId"`
	Guti        string             `json:"guti,omitempty"`
	IPAddrv4    string             `json:"ipAddrV4,omitempty"`
	IPAddrv6    string             `json:"ipAddrV6,omitempty"`
	PduSessions []RCPDUSessionInfo `json:"pduSessions,omitempty"`
}

// RCPDUSessionInfo riassume una PDU session del contesto N3IWF.
type RCPDUSessionInfo struct {
	ID           int64   `json:"id"`
	SNSSAI       string  `json:"snssai,omitempty"`
	QFIs         []uint8 `json:"qfis,omitempty"`
	IncomingTEID uint32  `json:"incomingTeid,omitempty"`
	OutgoingTEID uint32  `json:"outgoingTeid,omitempty"`
	UPFIP        string  `json:"upfIp,omitempty"`
}
