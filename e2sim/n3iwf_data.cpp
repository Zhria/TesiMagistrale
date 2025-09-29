#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <optional>
#include <filesystem>
#include <nlohmann/json.hpp>

#include "encode_e2apv2.hpp"
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
  if(g_metrics.count < 20){
    g_metrics.metrics[g_metrics.count++] = {name, 0, direction};
  }
    return 0; // Default value if not found
}

static void setKPMMetricValue(const std::string& name, int64_t value, Direction direction) {
    for (auto& metric : g_metrics.metrics) {
        if (metric.name == name) {
            metric.value = value;
            return;
        }
    }
    // If we reach here, the metric was not found
    //So we create a metric with the given value
    if(g_metrics.count < 20){
      g_metrics.metrics[g_metrics.count++] = {name, value, 0};
  }
}

using json = nlohmann::json;
namespace fs = std::filesystem;

//Last metric values:
std::vector<std::string> kpi=getAllowedKPI();

// -------------------- configurazione (safe) --------------------
static std::string g_fileName = "n3iwf_e2.json";
static std::string g_fileNameKPM="n3iwf_e2.json.kpm.log";
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

static inline double safe_div(long num, long den) {
  if (den <= 0) return 0;
  // round half up: (num + den/2) / den
  return (num >= 0) ? (num + den/2) / den : (num - den/2) / den;
};


std::map<std::string, double> getMetricsKPM(GranularityPeriod_t granularityPeriod) {
  std::string fullPath= joinPathFile(g_basePath, g_fileNameKPM);
  if (!fs::exists(fullPath)) {
    std::cerr << "[n3iwf] JSON file non trovato: " << fullPath << "\n";
    return {};
  }
  auto buf = readWholeFile(fullPath);
  if (!buf) {
    std::cerr << "[n3iwf] Impossibile leggere: " << fullPath << "\n";
    return {};
  }
  if (!json::accept(*buf)) {
    std::cerr << "[n3iwf] JSON non valido:\n" << *buf << "\n";
    return {};
  }

  auto j = json::parse(*buf);
  
  const auto& metrics = j.at("data").at("byDir");
  const auto& ul = metrics.at("1");
  const auto& dl = metrics.at("0");

  auto get64 = [](const json& o, const char* k) -> int64_t {
    if (!o.contains(k)) return 0;
    if (o.at(k).is_number_integer() || o.at(k).is_number_unsigned()) return o.at(k).get<int64_t>();
    if (o.at(k).is_string()) return std::stoll(o.at(k).get<std::string>());
    return 0;
  };

  const int64_t cur_dl_in    = get64(dl, "incomingOctets");   // UPF -> N3IWF
  const int64_t cur_dl_tx    = get64(dl, "transmitOctets");   // N3IWF -> UE

  const int64_t cur_ul_in    = get64(ul, "incomingOctets");   // UE -> N3IWF
  const int64_t cur_ul_tx    = get64(ul, "transmitOctets");   // N3IWF -> UPF

  const int64_t cur_dl_pkt_lost=get64(dl, "incomingPkts") - get64(dl, "transmitPkts"); 
  const int64_t cur_ul_pkt_lost=get64(ul, "incomingPkts") - get64(ul, "transmitPkts");

  std::vector<std::string> kpi = getAllowedKPI();
  //Calcolo delta metriche
  int64_t d_dl_in   = cur_dl_in - getKPMMetricValue("incomingOctets",DL);
  int64_t d_dl_tx   = cur_dl_tx - getKPMMetricValue("transmitOctets",DL);
  int64_t d_dl_drop = cur_dl_pkt_lost - getKPMMetricValue("droppedPackets",DL);

  int64_t d_ul_in   = cur_ul_in - getKPMMetricValue("incomingOctets",UL);
  int64_t d_ul_tx   = cur_ul_tx - getKPMMetricValue("transmitOctets",UL);
  int64_t d_ul_drop = cur_ul_pkt_lost - getKPMMetricValue("droppedPackets",UL);


  //Save new values for next delta calculation
  setKPMMetricValue("incomingOctets",cur_dl_in, DL);
  setKPMMetricValue("transmitOctets",cur_dl_tx, DL);
  setKPMMetricValue("droppedPackets",cur_dl_pkt_lost, DL);

  setKPMMetricValue("incomingOctets",cur_ul_in, UL);
  setKPMMetricValue("transmitOctets",cur_ul_tx, UL);
  setKPMMetricValue("droppedPackets",cur_ul_pkt_lost, UL);

  std::map<std::string, double> result;


  for (const auto& metric : kpi) {
    if (metric == "DRB.UEThpDl") {
      //Il throughput è calcolato come delta octets / granularityPeriod (in secondi) perchè noi recuperiamo i valori cumulativi ogni granularityPeriod
      result[metric] = safe_div(d_dl_tx * 8, granularityPeriod); // in bps
      
    } else if (metric == "DRB.UEThpUl") {
      result[metric] = safe_div(d_ul_tx * 8, granularityPeriod); // in bps

    } else if (metric == "DRB.RlcSduTransmittedVolumeDL") {

      result[metric] = d_dl_tx*8/1000; // in kbits

    } else if (metric == "DRB.RlcSduTransmittedVolumeUL") {
      result[metric] = d_ul_tx*8/1000; // in kbits

    } else if (metric == "DRB.RlcPacketDropRateDLDist") {
      result[metric]= safe_div(d_dl_drop * 100, d_dl_in);
    
    } else if (metric == "DRB.RlcPacketLossRateULDist") {
      result[metric]= safe_div(d_ul_drop * 100, d_ul_in);

    } else {
      std::cerr << "[n3iwf] Metrica KPM non gestita: " << metric << "\n";
    }
  }

  return result;
}


