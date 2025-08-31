#include <iostream>
#include <string>
#include <map>
#include <fstream>
#include <optional>
#include <filesystem>
#include <nlohmann/json.hpp>

#include "encode_e2apv1.hpp"
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

using json = nlohmann::json;
namespace fs = std::filesystem;

// -------------------- configurazione (safe) --------------------
static std::string g_fileName = "n3iwf_e2.json";
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
static bool buildBitStringFromUIntN(uint32_t value, BIT_STRING_t& out) {
  const int nbits = 32 - __builtin_clz(value); // numero di bit significativi
  const int num_bytes   = (nbits + 7) / 8;
  const int bits_unused = num_bytes * 8 - nbits;

  // maschera di nbits (evita overflow se nbits==32)
  uint32_t mask = (nbits == 32) ? 0xFFFFFFFFu : ((1u << nbits) - 1u);
  if (value > mask) {
    // il valore non entra in nbits
    return false;
  }

  // sposta a sinistra per “occupare” i bit inutilizzati in coda
  uint32_t shifted = value << bits_unused;

  uint8_t* buf = (uint8_t*)calloc(1, num_bytes);
  if (!buf) return false;

  // MSB-first (big-endian nel buffer ASN.1)
  for (int i = 0; i < num_bytes; ++i) {
    int shift = 8 * (num_bytes - 1 - i);
    buf[i] = static_cast<uint8_t>((shifted >> shift) & 0xFF);
  }

  out.buf = buf;
  out.size = num_bytes;
  out.bits_unused = bits_unused;
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
    BIT_STRING_t bs{};
    if (!buildBitStringFromUIntN(static_cast<uint32_t>(n3iwfId), bs)) return false;
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
