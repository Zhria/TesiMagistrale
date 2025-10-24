package rc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/free5gc/n3iwf/internal/snapshot"
)

// CollectWiFiMetricsSnapshot legge il file JSON generato dal wifi-metrics-exporter
// e produce uno snapshot RC compatibile con l'arricchimento UE.
func CollectWiFiMetricsSnapshot(path string) (snapshot.RCSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		err := fmt.Errorf("wifi metrics file %s is empty", path)
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	var payload map[string]wifiInterfaceMetrics
	if err := json.Unmarshal(data, &payload); err != nil {
		err = fmt.Errorf("cannot parse wifi metrics JSON: %w", err)
		return snapshot.RCSnapshot{
			Timestamp: time.Now(),
			Errors:    []string{err.Error()},
		}, err
	}

	interfaces := make([]snapshot.RCInterfaceSnapshot, 0, len(payload))
	for name, metrics := range payload {
		ifaceSnap := snapshot.RCInterfaceSnapshot{
			Interface: strings.TrimSpace(name),
		}
		if metrics.TS > 0 {
			ifaceSnap.MetricsTS = time.Unix(metrics.TS, 0).UTC()
		}
		if len(metrics.Hostapd.Status) > 0 {
			ifaceSnap.HostapdStatus = copyStringMap(metrics.Hostapd.Status)
		}
		ifaceSnap.Survey = convertSliceMap(metrics.Survey)
		ifaceSnap.Ethtool = convertMapAnyToString(metrics.Ethtool)

		// Costruisci la lista di station combinando hostapd e iw station dump
		hostapdStations := normalizeStationMap(metrics.Hostapd.Stations)
		iwStations := normalizeStationMap(metrics.StationDump)
		ifaceSnap.Stations = buildStationsFromMetrics(hostapdStations, iwStations)

		interfaces = append(interfaces, ifaceSnap)
	}

	// Ordina per nome interfaccia per avere output deterministico
	sort.SliceStable(interfaces, func(i, j int) bool {
		return interfaces[i].Interface < interfaces[j].Interface
	})

	return snapshot.RCSnapshot{
		Timestamp:  time.Now(),
		Interfaces: interfaces,
	}, nil
}

type wifiInterfaceMetrics struct {
	TS          int64                        `json:"ts"`
	Hostapd     wifiHostapdMetrics           `json:"hostapd"`
	StationDump map[string]map[string]string `json:"station_dump"`
	Survey      []map[string]any             `json:"survey"`
	Ethtool     map[string]any               `json:"ethtool"`
}

type wifiHostapdMetrics struct {
	Status   map[string]string            `json:"status"`
	Stations map[string]map[string]string `json:"stations"`
}

func buildStationsFromMetrics(hostapd, stationDump map[string]map[string]string) []snapshot.RCStation {
	allMACs := make(map[string]struct{})
	for mac := range hostapd {
		allMACs[mac] = struct{}{}
	}
	for mac := range stationDump {
		allMACs[mac] = struct{}{}
	}

	if len(allMACs) == 0 {
		return nil
	}

	keys := make([]string, 0, len(allMACs))
	for mac := range allMACs {
		keys = append(keys, mac)
	}
	sort.Strings(keys)

	stations := make([]snapshot.RCStation, 0, len(keys))
	for _, mac := range keys {
		hostData := copyStringMap(hostapd[mac])
		iwData := copyStringMap(stationDump[mac])

		fields := make(map[string]string, len(hostData)+len(iwData))
		ordered := make([]snapshot.RCField, 0, len(hostData)+len(iwData))

		if len(hostData) > 0 {
			keys := sortedKeys(hostData)
			for _, k := range keys {
				v := hostData[k]
				fields[k] = v
				ordered = append(ordered, snapshot.RCField{Key: k, Value: v})
			}
		}

		if len(iwData) > 0 {
			keys := sortedKeys(iwData)
			for _, k := range keys {
				v := iwData[k]
				prefKey := "iw." + k
				fields[prefKey] = v
				ordered = append(ordered, snapshot.RCField{Key: prefKey, Value: v})
			}
		}

		stations = append(stations, snapshot.RCStation{
			MAC:           mac,
			Fields:        fields,
			OrderedFields: ordered,
			Hostapd:       hostData,
			StationDump:   iwData,
		})
	}

	return stations
}

func normalizeStationMap(in map[string]map[string]string) map[string]map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]map[string]string, len(in))
	for mac, fields := range in {
		lower := strings.ToLower(strings.TrimSpace(mac))
		if lower == "" {
			continue
		}
		out[lower] = copyStringMap(fields)
	}
	return out
}

func copyStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func convertSliceMap(in []map[string]any) []map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make([]map[string]string, 0, len(in))
	for _, entry := range in {
		if len(entry) == 0 {
			continue
		}
		outMap := make(map[string]string, len(entry))
		for k, v := range entry {
			outMap[k] = fmt.Sprint(v)
		}
		out = append(out, outMap)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertMapAnyToString(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = fmt.Sprint(v)
	}
	return out
}

func sortedKeys(m map[string]string) []string {
	if len(m) == 0 {
		return nil
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
