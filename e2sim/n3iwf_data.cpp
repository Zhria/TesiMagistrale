#include <cctype>
#include <iostream>
#include <map>
#include <fstream>
#include <optional>
#include <filesystem>
#include <sstream>
#include <string>
#include <nlohmann/json.hpp>

#include "encode_e2apv2.hpp"
#include "n3iwf_data.hpp"
#include "n3iwf_utils.hpp"

extern "C" {
#include "E2SM-KPM-RANfunction-Description.h"
#include "e2ap_asn1c_codec.h"
#include "GlobalE2node-ID.h"
#include "GlobalE2node-gNB-ID.h"
#include "GlobalgNB-ID.h"
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "GNB-ID-Choice.h"
#include "ProtocolIE-Field.h"
#include "E2setupRequest.h"
#include "RICaction-ToBeSetup-Item.h"
#include "RICactions-ToBeSetup-List.h"
#include "RICeventTriggerDefinition.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "ProtocolIE-SingleContainer.h"
#include "RANfunctions-List.h"
#include "RICindication.h"
#include "RICsubsequentActionType.h"
#include "RICsubsequentAction.h"
#include "RICtimeToWait.h"
}

enum Direction{
  DL=0,
  UL=1
};


struct KPMMetric{
    std::string name;
    int64_t value=0;
    int direction=0; // 0=DL, 1=UL
};

struct KPMMetrics{
    std::array<KPMMetric, 20> metrics; // max 20 metriche KPM per cella
    int count=0;
};

KPMMetrics g_metrics; // max 20 metriche KPM per cella

static int64_t getKPMMetricValue(const std::string& name, Direction direction) {
  for (const auto& metric : g_metrics.metrics) {
        if (metric.name == name && metric.direction == direction) {
            return metric.value;
        }
    }
  // If we reach here, the metric was not found
  //So we create a metric with value 0 and return 0
  logln("Metric %s not found, return  0\n", name.c_str());
  return 0; // Default value if not found
}

static void setKPMMetricValue(const std::string& name, int64_t value, Direction direction) {
    for (int i=0; i < g_metrics.count; i++) {
        if (g_metrics.metrics[i].name == name && g_metrics.metrics[i].direction == direction) {
            g_metrics.metrics[i].value = value;
            return;
        }
    }
    // If we reach here, the metric was not found
    //So we create a metric with the given value
    if(g_metrics.count < 20){
      g_metrics.metrics[g_metrics.count++] = {name, value, direction};
  }
}

using json = nlohmann::json;
namespace fs = std::filesystem;

//Last metric values:
std::vector<std::string> kpi=getAllowedKPI();

// -------------------- configurazione (safe) --------------------
static std::string g_fileName = "n3iwf_e2.json";
static std::string g_fileNameKPM="n3iwf_e2.json.kpm.log";
static std::string g_rcFileName = "n3iwf_e2_rc.json";
static std::string g_basePath = []{
  if (const char* p = std::getenv("E2_LOG_BASE")) return std::string(p);
  return std::string("/home/e2sim/log/");  // default nel tuo container
}();

void setBasePath(const std::string& path) {
  g_basePath = path;
  if (!g_basePath.empty() && g_basePath.back() != '/') g_basePath.push_back('/');
}
void setFileName(const std::string& name) {
  g_fileName = name;
}

void setFileNameKPM(const std::string& name) {
  g_fileNameKPM = name;
}

void setRcLogFileName(const std::string& name) {
  if (!name.empty()) {
    g_rcFileName = name;
  }
}

// -------------------- util --------------------
static inline std::string joinPathFile(const std::string& dir, const std::string& file) {
  if (dir.empty()) return file;
  if (dir.back() == '/') return dir + file;
  return dir + "/" + file;
}

static std::optional<std::string> readWholeFile(const std::string& fullpath) {
  std::ifstream f(fullpath, std::ios::in | std::ios::binary);
  if (!f) return std::nullopt;
  std::string data;
  f.seekg(0, std::ios::end);
  data.resize(static_cast<size_t>(f.tellg()));
  f.seekg(0, std::ios::beg);
  f.read(&data[0], static_cast<std::streamsize>(data.size()));
  return data;
}

static std::string json_to_string(const json& value) {
  if (value.is_string()) return value.get<std::string>();
  if (value.is_boolean()) return value.get<bool>() ? "true" : "false";
  if (value.is_number_integer()) return std::to_string(value.get<int64_t>());
  if (value.is_number_unsigned()) return std::to_string(value.get<uint64_t>());
  if (value.is_number_float()) {
    std::ostringstream oss;
    oss << value.get<double>();
    return oss.str();
  }
  if (value.is_null()) return "";
  return value.dump();
}

static uint64_t json_to_u64(const json& value) {
  if (value.is_number_unsigned()) return value.get<uint64_t>();
  if (value.is_number_integer()) {
    auto v = value.get<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
  }
  if (value.is_number_float()) {
    double v = value.get<double>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
  }
  if (value.is_string()) {
    try {
      return std::stoull(value.get<std::string>(), nullptr, 0);
    } catch (...) {
      return 0;
    }
  }
  if (value.is_boolean()) {
    return value.get<bool>() ? 1 : 0;
  }
  return 0;
}

static int64_t json_to_i64(const json& value) {
  if (value.is_number_integer()) return value.get<int64_t>();
  if (value.is_number_unsigned()) return static_cast<int64_t>(value.get<uint64_t>());
  if (value.is_number_float()) return static_cast<int64_t>(value.get<double>());
  if (value.is_string()) {
    try {
      return std::stoll(value.get<std::string>(), nullptr, 0);
    } catch (...) {
      return 0;
    }
  }
  if (value.is_boolean()) return value.get<bool>() ? 1 : 0;
  return 0;
}

static bool json_to_bool(const json& value) {
  if (value.is_boolean()) return value.get<bool>();
  if (value.is_number_integer()) return value.get<int64_t>() != 0;
  if (value.is_number_unsigned()) return value.get<uint64_t>() != 0;
  if (value.is_string()) {
    auto str = value.get<std::string>();
    std::string lower;
    lower.reserve(str.size());
    for (char c : str) {
      lower.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
    }
    return lower == "true" || lower == "1" || lower == "yes";
  }
  return false;
}

static std::vector<int64_t> json_to_int64_vector(const json& value) {
  std::vector<int64_t> out;
  if (!value.is_array()) return out;
  out.reserve(value.size());
  for (const auto& entry : value) {
    out.push_back(json_to_i64(entry));
  }
  return out;
}

static std::map<std::string, std::string> json_to_string_map(const json& value) {
  std::map<std::string, std::string> out;
  if (!value.is_object()) return out;
  for (const auto& [key, val] : value.items()) {
    out.emplace(key, json_to_string(val));
  }
  return out;
}

static RcCountersSnapshot parse_rc_counters(const json& counters) {
  RcCountersSnapshot out;
  if (!counters.is_object()) return out;
  if (auto it = counters.find("incomingOctets"); it != counters.end()) out.incoming_octets = json_to_u64(*it);
  if (auto it = counters.find("transmitOctets"); it != counters.end()) out.transmit_octets = json_to_u64(*it);
  if (auto it = counters.find("incomingPkts"); it != counters.end()) out.incoming_pkts = json_to_u64(*it);
  if (auto it = counters.find("transmitPkts"); it != counters.end()) out.transmit_pkts = json_to_u64(*it);
  if (auto it = counters.find("droppedOctets"); it != counters.end()) out.dropped_octets = json_to_u64(*it);
  return out;
}

static RcChildSaInfoSnapshot parse_child_sa(const json& child) {
  RcChildSaInfoSnapshot out;
  if (!child.is_object()) return out;
  if (auto it = child.find("inboundSpi"); it != child.end()) out.inbound_spi = static_cast<uint32_t>(json_to_u64(*it));
  if (auto it = child.find("outboundSpi"); it != child.end()) out.outbound_spi = static_cast<uint32_t>(json_to_u64(*it));
  if (auto it = child.find("tunnelIface"); it != child.end()) out.tunnel_iface = json_to_string(*it);
  if (auto it = child.find("peerPublicIp"); it != child.end()) out.peer_public_ip = json_to_string(*it);
  if (auto it = child.find("localPublicIp"); it != child.end()) out.local_public_ip = json_to_string(*it);
  if (auto it = child.find("n3iwfPort"); it != child.end()) out.n3iwf_port = static_cast<int>(json_to_i64(*it));
  if (auto it = child.find("natPort"); it != child.end()) out.nat_port = static_cast<int>(json_to_i64(*it));
  if (auto it = child.find("enableEncapsulate"); it != child.end()) out.enable_encapsulate = json_to_bool(*it);
  if (auto it = child.find("selectedIpProto"); it != child.end()) out.selected_ip_proto = static_cast<uint8_t>(json_to_u64(*it));
  if (auto it = child.find("pduSessionIds"); it != child.end()) out.pdu_session_ids = json_to_int64_vector(*it);
  return out;
}

static RcStationSnapshot parse_station_snapshot(const json& station,
                                                const std::string& fallback_iface,
                                                const std::string& fallback_mac,
                                                const std::string& fallback_ip) {
  RcStationSnapshot out;
  out.interface_name = fallback_iface;
  out.mac = fallback_mac;
  out.ip = fallback_ip;
  if (!station.is_object()) return out;
  out.interface_name = station.value("interface", out.interface_name);
  out.mac = station.value("mac", out.mac);
  out.ip = station.value("ip", out.ip);
  if (auto it = station.find("fields"); it != station.end()) out.fields = json_to_string_map(*it);
  if (auto it = station.find("hostapd"); it != station.end()) out.hostapd = json_to_string_map(*it);
  if (auto it = station.find("stationDump"); it != station.end()) out.station_dump = json_to_string_map(*it);
  return out;
}

static RcUeInfoSnapshot parse_ue_snapshot(const json& ue) {
  RcUeInfoSnapshot out;
  if (!ue.is_object()) return out;
  if (auto it = ue.find("ranUeNgapId"); it != ue.end()) out.ran_ue_ngap_id = json_to_i64(*it);
  if (auto it = ue.find("amfUeNgapId"); it != ue.end()) out.amf_ue_ngap_id = json_to_i64(*it);
  if (auto it = ue.find("ipAddrV4"); it != ue.end()) out.ip_addr_v4 = json_to_string(*it);
  if (auto it = ue.find("ipAddrV6"); it != ue.end()) out.ip_addr_v6 = json_to_string(*it);
  if (auto it = ue.find("portNumber"); it != ue.end()) out.port_number = static_cast<int32_t>(json_to_i64(*it));
  if (auto it = ue.find("guti"); it != ue.end()) out.guti = json_to_string(*it);
  if (auto it = ue.find("n3iwfId"); it != ue.end()) out.n3iwf_id = json_to_string(*it);
  if (auto it = ue.find("amfName"); it != ue.end()) out.amf_name = json_to_string(*it);
  if (auto it = ue.find("amfSctp"); it != ue.end()) out.amf_sctp = json_to_string(*it);
  if (auto it = ue.find("rrcEstablishmentCause"); it != ue.end()) out.rrc_establishment_cause = static_cast<int16_t>(json_to_i64(*it));
  if (auto it = ue.find("ikeLocalSpi"); it != ue.end()) out.ike_local_spi = json_to_u64(*it);
  if (auto it = ue.find("ikeRemoteSpi"); it != ue.end()) out.ike_remote_spi = json_to_u64(*it);
  if (auto it = ue.find("ikeState"); it != ue.end()) out.ike_state = static_cast<uint8_t>(json_to_u64(*it));
  if (auto it = ue.find("ueBehindNat"); it != ue.end()) out.ue_behind_nat = json_to_bool(*it);
  if (auto it = ue.find("n3iwfBehindNat"); it != ue.end()) out.n3iwf_behind_nat = json_to_bool(*it);
  if (auto it = ue.find("childSa"); it != ue.end() && it->is_array()) {
    for (const auto& sa : *it) {
      out.child_sa.push_back(parse_child_sa(sa));
    }
  }
  for (const auto& [key, val] : ue.items()) {
    out.extra_fields[key] = json_to_string(val);
  }
  return out;
}

static RcAssociationSnapshot parse_rc_association(const json& assoc) {
  RcAssociationSnapshot out;
  if (!assoc.is_object()) return out;
  out.interface_name = assoc.value("interface", std::string{});
  out.mac = assoc.value("mac", std::string{});
  out.ue_ip = assoc.value("ueIp", std::string{});
  if (auto it = assoc.find("station"); it != assoc.end()) {
    out.station = parse_station_snapshot(*it, out.interface_name, out.mac, out.ue_ip);
  } else {
    out.station = parse_station_snapshot(json{}, out.interface_name, out.mac, out.ue_ip);
  }
  if (auto it = assoc.find("counters"); it != assoc.end()) out.counters = parse_rc_counters(*it);
  if (auto it = assoc.find("ue"); it != assoc.end()) out.ue = parse_ue_snapshot(*it);
  if (auto it = assoc.find("mismatches"); it != assoc.end() && it->is_array()) {
    for (const auto& mismatch : *it) {
      if (mismatch.is_string()) {
        out.mismatches.push_back(mismatch.get<std::string>());
      }
    }
  }
  return out;
}

static std::string normalize_mac(const std::string& mac) {
  std::string out;
  out.reserve(mac.size());
  for (char c : mac) {
    if (c == ':' || c == '-' || c == '.') continue;
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  return out;
}

// -------------------- JSON I/O --------------------
static std::optional<json> getFree5gcData() {
  const std::string full = joinPathFile(g_basePath, g_fileName);
  if (!fs::exists(full)) {
    std::cerr << "[n3iwf] JSON file non trovato: " << full << "\n";
    return std::nullopt;
  }
  auto buf = readWholeFile(full);
  if (!buf) {
    std::cerr << "[n3iwf] Impossibile leggere: " << full << "\n";
    return std::nullopt;
  }
  if (!json::accept(*buf)) {
    std::cerr << "[n3iwf] JSON non valido:\n" << *buf << "\n";
    return std::nullopt;
  }
  try {
    return json::parse(*buf);
  } catch (const std::exception& e) {
    std::cerr << "[n3iwf] Eccezione nel parse JSON: " << e.what() << "\n";
    return std::nullopt;
  }
}

// -------------------- ASN.1 helpers --------------------
// Converte MCC/MNC (stringhe "001","01") in 3 byte PLMN
static bool buildPLMN(const std::string& mcc, const std::string& mnc, OCTET_STRING_t& out) {
  if (mcc.size() != 3 || (mnc.size() != 2 && mnc.size() != 3)) return false;
  uint8_t b0 = static_cast<uint8_t>(((mcc[1]-'0') << 4) | (mcc[0]-'0'));
  uint8_t b1 = static_cast<uint8_t>(((mnc.size()==2? 0xF : (mnc[2]-'0')) << 4) | (mcc[2]-'0'));
  uint8_t b2 = static_cast<uint8_t>(((mnc[1]-'0') << 4) | (mnc[0]-'0'));

  out.buf = (uint8_t*)calloc(1, 3);
  if (!out.buf) return false;
  out.size = 3;
  out.buf[0]=b0; out.buf[1]=b1; out.buf[2]=b2;
  return true;
}

// asn1c: BIT_STRING_t { uint8_t* buf; size_t size; int bits_unused; }
static bool buildBitStringFromUIntN(uint32_t value, BIT_STRING_t* out) {
  int width=22;  
  if (!out || width < 1 || width > 32) return false;

    // controllo che 'value' stia in 'width' bit
    if (width < 32 && (value >> width) != 0) return false;

    const int num_bytes   = (width + 7) / 8;
    const int bits_unused = num_bytes * 8 - width;

    uint8_t* buf = (uint8_t*)calloc(1, num_bytes);
    if (!buf) return false;

    // Allinea a sinistra in modo che i bit inutilizzati (a destra) restino a zero
    uint64_t shifted = ((uint64_t)value) << bits_unused;

    // MSB-first nel buffer ASN.1 (big-endian a livello di ottetti)
    for (int i = 0; i < num_bytes; ++i) {
        int shift = 8 * (num_bytes - 1 - i);
        buf[i] = (uint8_t)((shifted >> shift) & 0xFFu);
    }

    // Azzeriamo esplicitamente i bit di padding (destra dell’ultimo ottetto)
    if (bits_unused) {
        buf[num_bytes - 1] &= (uint8_t)(0xFFu << bits_unused);
    }

    // (opzionale) libera out->buf se stai riusando la struct
    // if (out->buf) free(out->buf);

    out->buf = buf;
    out->size = num_bytes;
    out->bits_unused = bits_unused;
    return true;
}


// -------------------- costruzione strutture --------------------
static bool getPLMNID_from_json(const json& j, OCTET_STRING_t& out) {
  try {
    const auto& plmn = j.at("data").at("config").at("Configuration")
                        .at("N3IWFInfo").at("GlobalN3IWFID").at("PLMNID");
    std::string mcc = plmn.at("Mcc").get<std::string>();
    std::string mnc = plmn.at("Mnc").get<std::string>();
    return buildPLMN(mcc, mnc, out);
  } catch (...) {
    std::cerr << "[n3iwf] campi PLMN mancanti nel JSON\n";
    return false;
  }
}

static bool getGNBIDChoice_from_json(const json& j, GNB_ID_Choice_t& out) {
  try {
    int n3iwfId = 0;
    j.at("data").at("config").at("Configuration")
     .at("N3IWFInfo").at("GlobalN3IWFID").at("N3IWFID").get_to(n3iwfId);
    if (n3iwfId < 0) n3iwfId = 0;

    out.present = GNB_ID_Choice_PR_gnb_ID;
    // alloca buffer interno del bitstring
    BIT_STRING_t bs;
    if (!buildBitStringFromUIntN(static_cast<uint32_t>(n3iwfId), &bs)) return false;
    out.choice.gnb_ID = bs; // copia shallow dei campi (puntatore incluso)
    return true;
  } catch (...) {
    std::cerr << "[n3iwf] campo N3IWFID mancante nel JSON\n";
    return false;
  }
}

// Alloc/Build GlobalgNB_ID (il chiamante lo rilascia con freeGlobalgNB_ID)
static GlobalgNB_ID_t* buildGlobalgNB_ID() {
  auto j = getFree5gcData();
  if (!j) return nullptr;

  auto* gnb = (GlobalgNB_ID_t*)calloc(1, sizeof(GlobalgNB_ID_t));
  if (!gnb) return nullptr;

  if (!getPLMNID_from_json(*j, gnb->plmn_id)) {
    free(gnb); return nullptr;
  }
  if (!getGNBIDChoice_from_json(*j, gnb->gnb_id)) {
    free(gnb->plmn_id.buf);
    free(gnb); return nullptr;
  }
  return gnb;
}

static void freeGlobalgNB_ID(GlobalgNB_ID_t* gnb) {
  if (!gnb) return;
  if (gnb->plmn_id.buf) free(gnb->plmn_id.buf);
  if (gnb->gnb_id.present == GNB_ID_Choice_PR_gnb_ID && gnb->gnb_id.choice.gnb_ID.buf)
    free(gnb->gnb_id.choice.gnb_ID.buf);
  free(gnb);
}

// -------------------- API “pubblica” compatibile --------------------
// Manteniamo un singleton per semplicità
static GlobalgNB_ID_t* g_gnbStore = nullptr;

int init_n3iwf_data() {
  if (g_gnbStore) return 0;
  g_gnbStore = buildGlobalgNB_ID();
  if (!g_gnbStore) {
    std::cerr << "[n3iwf] init_n3iwf_data: buildGlobalgNB_ID fallita\n";
    return -1;
  }
  return 0;
}

GlobalgNB_ID_t* getGNBStore() {
  if (!g_gnbStore) {
    if (init_n3iwf_data() != 0) return nullptr;
  }
  BIT_STRING_t& gnb_id_bs = g_gnbStore->gnb_id.choice.gnb_ID;

  int ret = validate_or_fix_gnb_id_length(&gnb_id_bs, /*min=*/22, /*max=*/32, /*target_if_pad=*/22);
  if (ret != 0) {
    std::cerr << "gNB ID invalid length (must be 22..32 bits) and cannot be auto-fixed.\n";
    return nullptr;
  }

  int total_bits = gnb_id_bs.size * 8 - gnb_id_bs.bits_unused;
  std::cout << "gNB ID length: " << total_bits << " bits\n";

  return g_gnbStore;
}

// Se/Quando vuoi rilasciare risorse (es. a fine programma):
void deinit_n3iwf_data() {
  if (g_gnbStore) {
    freeGlobalgNB_ID(g_gnbStore);
    g_gnbStore = nullptr;
  }
}

static inline double safe_div(double num, double den) {
  if (den <= 0) return 0.0;
  // round half up: (num + den/2) / den
  return num/den;
};

static inline double percent_or_zero(int64_t num, int64_t den) {
  return (den > 0) ? (100.0 * (double)num / (double)den) : 0.0;
}


std::map<std::string, double> getMetricsKPM(GranularityPeriod_t granularityPeriod) {
  logln("Getting KPM metrics with granularityPeriod %ld milliseconds\n", granularityPeriod);
  float granularityPeriodSec=granularityPeriod/1000.0; // converti in secondi
  std::string fullPath= joinPathFile(g_basePath, g_fileNameKPM);
  if (!fs::exists(fullPath)) {
    std::cerr << "[n3iwf] JSON file non trovato: " << fullPath << "\n";
    return {};
  }
  logln("fullPath is %s\n",fullPath.c_str());
  auto buf = readWholeFile(fullPath);
  if (!buf) {
    logln("Impossibile leggere: %s\n",fullPath.c_str());
    return {};
  }
  if (!json::accept(*buf)) {
    logln("JSON non valido:\n%s\n",buf->c_str());
    return {};
  }

  auto j = json::parse(*buf);
  if (j.is_discarded()) {
    logln("JSON non valido (discarded):\n%s\n",buf->c_str());
    return {};
  }
  
  const auto& metrics = j.at("data").at("byDir");
  if (metrics.is_discarded()) {
    logln("JSON non valido (discarded):\n%s\n",buf->c_str());
    return {};
  }
  //Can i use a try catch method to avoid the exception?
  try {
    if (!metrics.contains("0") || !metrics.contains("1")) {
      logln("JSON non valido (missing '0' or '1' in byDir):\n%s\n",buf->c_str());
      return {};
    }
  } catch (...) {
    logln("Eccezione nel controllare '0' e '1' in byDir:\n%s\n",buf->c_str());
    return {};
  }
  const auto& ul = metrics.at("1");
  if( ul.is_discarded()) {
    logln("JSON non valido (discarded) UL:\n%s\n",buf->c_str());
    return {};
  }

  const auto& dl = metrics.at("0");

  auto get64 = [](const json& o, const char* k) -> int64_t {
    if (!o.contains(k)) return 0;
    if (o.at(k).is_number_integer() || o.at(k).is_number_unsigned()) return o.at(k).get<int64_t>();
    if (o.at(k).is_string()) return std::stoll(o.at(k).get<std::string>());
    return 0;
  };

  //Print g_metrics
  logln("Current saved KPM metrics:\n");
  for(int i=0; i<g_metrics.count; i++){
    logln("  %s: %ld (direction %d)\n", g_metrics.metrics[i].name.c_str(), g_metrics.metrics[i].value, g_metrics.metrics[i].direction);
  } 
  
  const int64_t cur_dl_in    = get64(dl, "incomingOctets");   // UPF -> N3IWF
  const int64_t cur_dl_tx    = get64(dl, "transmitOctets");   // N3IWF -> UE
  const int64_t cur_dl_pkt_lost=get64(dl, "incomingPkts") - get64(dl, "transmitPkts"); 
  logln("cur_dl_in: %ld, cur_dl_tx: %ld\n", cur_dl_in, cur_dl_tx);

  const int64_t cur_ul_in    = get64(ul, "incomingOctets");   // UE -> N3IWF
  const int64_t cur_ul_tx    = get64(ul, "transmitOctets");   // N3IWF -> UPF
  const int64_t cur_ul_pkt_lost=get64(ul, "incomingPkts") - get64(ul, "transmitPkts");
  logln("cur_ul_in: %ld, cur_ul_tx: %ld\n", cur_ul_in, cur_ul_tx);


  std::vector<std::string> kpi = getAllowedKPI();
  //Calcolo delta metriche
  int64_t d_dl_in   = cur_dl_in - getKPMMetricValue("incomingOctets",DL);
  int64_t d_dl_tx   = cur_dl_tx - getKPMMetricValue("transmitOctets",DL);
  int64_t d_dl_drop = cur_dl_pkt_lost - getKPMMetricValue("droppedPackets",DL);
  logln("d_dl_in: %ld, d_dl_tx: %ld, d_dl_drop: %ld\n", d_dl_in, d_dl_tx, d_dl_drop);  
  int64_t d_ul_in   = cur_ul_in - getKPMMetricValue("incomingOctets",UL);
  int64_t d_ul_tx   = cur_ul_tx - getKPMMetricValue("transmitOctets",UL);
  int64_t d_ul_drop = cur_ul_pkt_lost - getKPMMetricValue("droppedPackets",UL);
  logln("d_ul_in: %ld, d_ul_tx: %ld, d_ul_drop: %ld\n", d_ul_in, d_ul_tx, d_ul_drop);


  //Save new values for next delta calculation
  setKPMMetricValue("incomingOctets",cur_dl_in, DL);
  setKPMMetricValue("transmitOctets",cur_dl_tx, DL);
  setKPMMetricValue("droppedPackets",cur_dl_pkt_lost, DL);

  setKPMMetricValue("incomingOctets",cur_ul_in, UL);
  setKPMMetricValue("transmitOctets",cur_ul_tx, UL);
  setKPMMetricValue("droppedPackets",cur_ul_pkt_lost, UL);
  logln("Saved new KPM metric values for next delta calculation\n");

  std::map<std::string, double> result;


  for (const auto& metric : kpi) {
    if (metric == "DRB.UEThpDl") {
      //Il throughput è calcolato come delta octets / granularityPeriod (in secondi) perchè noi recuperiamo i valori cumulativi ogni granularityPeriod
      result[metric] = safe_div(d_dl_tx * 8, granularityPeriodSec); // in bps
      
    } else if (metric == "DRB.UEThpUl") {
      result[metric] = safe_div(d_ul_tx * 8, granularityPeriodSec); // in bps

    } else if (metric == "DRB.RlcSduTransmittedVolumeDL") {

      result[metric] = (double)d_dl_tx*8/1000; // in kbits

    } else if (metric == "DRB.RlcSduTransmittedVolumeUL") {
      result[metric] = (double)d_ul_tx*8/1000; // in kbits

    } else if (metric == "DRB.RlcPacketDropRateDLDist") {
      result[metric]= percent_or_zero(d_dl_drop, d_dl_in); //%
    
    } else if (metric == "DRB.RlcPacketLossRateULDist") {
      result[metric]= percent_or_zero(d_ul_drop, d_ul_in); //%

    } else {
      std::cerr << "[n3iwf] Metrica KPM non gestita: " << metric << "\n";
    }
  }

  logln("KPM metrics computed:\n");
  for (const auto& [k, v] : result) {
    logln("  %s: %.2f\n", k.c_str(), v);
  }

  return result;
}

bool loadRcSnapshot(RcSnapshot &out) {
  const std::string full = joinPathFile(g_basePath, g_rcFileName);
  if (!fs::exists(full)) {
    std::cerr << "[n3iwf] RC JSON file non trovato: " << full << "\n";
    return false;
  }
  auto buf = readWholeFile(full);
  if (!buf) {
    std::cerr << "[n3iwf] Impossibile leggere RC JSON: " << full << "\n";
    return false;
  }
  if (!json::accept(*buf)) {
    std::cerr << "[n3iwf] RC JSON non valido:\n" << *buf << "\n";
    return false;
  }
  json j;
  try {
    j = json::parse(*buf);
  } catch (const std::exception &e) {
    std::cerr << "[n3iwf] Eccezione nel parse RC JSON: " << e.what() << "\n";
    return false;
  }

  out.timestamp = j.value("timestamp", std::string{});
  out.associations.clear();
  if (auto it = j.find("associations"); it != j.end() && it->is_array()) {
    out.associations.reserve(it->size());
    for (const auto &entry : *it) {
      out.associations.emplace_back(parse_rc_association(entry));
    }
  }
  return true;
}

std::vector<RcAssociationSnapshot> getRcAssociations() {
  RcSnapshot snap;
  if (!loadRcSnapshot(snap)) {
    return {};
  }
  return snap.associations;
}

std::optional<RcAssociationSnapshot> findRcAssociationByRanUeId(int64_t ran_ue_ngap_id) {
  if (ran_ue_ngap_id < 0) {
    return std::nullopt;
  }
  auto associations = getRcAssociations();
  for (const auto &assoc : associations) {
    if (assoc.ue.ran_ue_ngap_id == ran_ue_ngap_id) {
      return assoc;
    }
  }
  return std::nullopt;
}

std::optional<RcAssociationSnapshot> findRcAssociationByMac(const std::string &mac) {
  if (mac.empty()) {
    return std::nullopt;
  }
  const std::string target = normalize_mac(mac);
  auto associations = getRcAssociations();
  for (const auto &assoc : associations) {
    if (normalize_mac(assoc.mac) == target) {
      return assoc;
    }
  }
  return std::nullopt;
}
