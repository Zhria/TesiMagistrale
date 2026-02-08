#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <cstdarg>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>



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

extern struct timespec ts;
#include "n3iwf_utils.hpp"
#include <map>
#include <yaml-cpp/yaml.h>

namespace {

enum class LogLevel : int {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
  Fatal = 5,
};

static LogLevel clamp_level(int level) {
  if (level <= static_cast<int>(LogLevel::Trace)) return LogLevel::Trace;
  if (level >= static_cast<int>(LogLevel::Fatal)) return LogLevel::Fatal;
  return static_cast<LogLevel>(level);
}

struct LoglnState {
  std::mutex mu;
  FILE* file = nullptr;
  LogLevel console_level = LogLevel::Fatal; // default: no console output
  bool tee_high_to_file = true;             // if false: >=console_level goes to console only
};

LoglnState& state() {
  static LoglnState s;
  return s;
}

static std::string to_lower(std::string s) {
  for (char& c : s) {
    if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
  }
  return s;
}

static LogLevel parse_level(std::string s, LogLevel fallback) {
  s = to_lower(s);
  if (s == "trace") return LogLevel::Trace;
  if (s == "debug") return LogLevel::Debug;
  if (s == "info") return LogLevel::Info;
  if (s == "warn" || s == "warning") return LogLevel::Warn;
  if (s == "error" || s == "err") return LogLevel::Error;
  if (s == "fatal") return LogLevel::Fatal;
  return fallback;
}

static const char* skip_bracket_prefixes(const char* p) {
  while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
  while (*p == '[') {
    const char* close = std::strchr(p, ']');
    if (!close) break;
    p = close + 1;
    while (*p == ' ' || *p == '\t') p++;
  }
  return p;
}

static bool starts_with_ci(const char* s, const char* prefix) {
  for (; *prefix; ++prefix, ++s) {
    char a = *s;
    char b = *prefix;
    if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
    if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
    if (a != b) return false;
  }
  return true;
}

static LogLevel infer_level_from_format(const char* fmt) {
  if (!fmt) return LogLevel::Info;

  const char* p = skip_bracket_prefixes(fmt);
  if (starts_with_ci(p, "trace")) return LogLevel::Trace;
  if (starts_with_ci(p, "debug")) return LogLevel::Debug;
  if (starts_with_ci(p, "info")) return LogLevel::Info;
  if (starts_with_ci(p, "warn") || starts_with_ci(p, "warning")) return LogLevel::Warn;
  if (starts_with_ci(p, "error")) return LogLevel::Error;
  if (starts_with_ci(p, "fatal")) return LogLevel::Fatal;

  // Heuristics for existing strings that don't carry an explicit level.
  std::string f(fmt);
  std::string fl = to_lower(f);
  if (fl.find("panic") != std::string::npos) return LogLevel::Fatal;
  if (fl.find("unable") != std::string::npos) return LogLevel::Error;
  if (fl.find("failed") != std::string::npos) return LogLevel::Error;
  if (fl.find("error") != std::string::npos) return LogLevel::Error;
  if (fl.find("invalid") != std::string::npos) return LogLevel::Warn;
  if (fl.find("warning") != std::string::npos) return LogLevel::Warn;
  return LogLevel::Info;
}

static void open_log_file_locked(const std::string& path) {
  auto& s = state();
  if (s.file) {
    std::fclose(s.file);
    s.file = nullptr;
  }

  if (path.empty()) return;
  try {
    std::filesystem::path p(path);
    if (p.has_parent_path()) {
      std::filesystem::create_directories(p.parent_path());
    }
  } catch (...) {
    // Best-effort: directory creation failure will be caught by fopen().
  }

  s.file = std::fopen(path.c_str(), "a");
}

static void write_line(FILE* out, long seconds, long nseconds, const std::string& formatted) {
  if (!out) return;
  std::fprintf(out, "[%ld.%09ld] ", seconds, nseconds);
  std::fwrite(formatted.data(), 1, formatted.size(), out);
  std::fwrite("\n", 1, 1, out);
  std::fflush(out);
}

static void logln_write(LogLevel level, const char* msg, va_list args) {
  struct timespec now;
  clock_gettime(CLOCK_REALTIME, &now);
  long seconds = now.tv_sec - ts.tv_sec;
  long nseconds = now.tv_nsec - ts.tv_nsec;
  if (nseconds < 0) {
    seconds -= 1;
    nseconds += 1000000000L;
  }

  va_list args_copy;
  va_copy(args_copy, args);
  int needed = std::vsnprintf(nullptr, 0, msg ? msg : "", args_copy);
  va_end(args_copy);

  std::string formatted;
  if (needed < 0) {
    formatted = "(log format error)";
  } else {
    formatted.resize(static_cast<size_t>(needed) + 1);
    std::vsnprintf(formatted.data(), static_cast<size_t>(needed) + 1, msg ? msg : "", args);
    formatted.resize(static_cast<size_t>(needed));
  }

  auto& s = state();
  std::lock_guard<std::mutex> lock(s.mu);

  const bool to_console = static_cast<int>(level) >= static_cast<int>(s.console_level);
  const bool to_file_low = !to_console;
  const bool to_file_high = to_console && s.tee_high_to_file;

  if (to_console) {
    write_line(stdout, seconds, nseconds, formatted);
  }
  if (to_file_low || to_file_high) {
    if (s.file) {
      write_line(s.file, seconds, nseconds, formatted);
    } else if (!to_console) {
      // Avoid silently dropping logs if the file can't be opened.
      write_line(stderr, seconds, nseconds, formatted);
    }
  }
}

} // namespace

extern "C" void logln_init_from_yaml(const char* config_path) {
  auto& s = state();
  std::lock_guard<std::mutex> lock(s.mu);

  // Defaults: write to a file in the docker volume, keep console silent.
  std::string file_path = "/home/e2sim/log/e2node.log";
  s.console_level = LogLevel::Fatal;
  s.tee_high_to_file = true;

  if (config_path && *config_path) {
    try {
      YAML::Node root = YAML::LoadFile(config_path);
      YAML::Node cfg = root["configuration"];
      YAML::Node logcfg = cfg ? cfg["logging"] : YAML::Node();

      if (logcfg) {
        if (logcfg["file"] && logcfg["file"].IsScalar()) {
          file_path = logcfg["file"].as<std::string>(file_path);
        }
        if (logcfg["consoleLevel"] && logcfg["consoleLevel"].IsScalar()) {
          s.console_level = parse_level(logcfg["consoleLevel"].as<std::string>("fatal"), LogLevel::Fatal);
        }
        if (logcfg["teeHighToFile"] && logcfg["teeHighToFile"].IsScalar()) {
          s.tee_high_to_file = logcfg["teeHighToFile"].as<bool>(true);
        }
      }
    } catch (...) {
      // Keep defaults on parse/load errors.
    }
  }

  open_log_file_locked(file_path);
}

//String ammettendo n variabili variabili
void logln(const char* msg, ...) {
  LogLevel level = infer_level_from_format(msg);

  va_list args;
  va_start(args, msg);
  logln_write(level, msg, args);
  va_end(args);
}

extern "C" void logln_level(int level, const char* msg, ...) {
  va_list args;
  va_start(args, msg);
  logln_write(clamp_level(level), msg, args);
  va_end(args);
}
// Ritorna il numero di bit effettivi (size*8 - bits_unused)
static inline int bit_length(const BIT_STRING_t& bs) {
  if (!bs.buf || bs.size <= 0 || bs.bits_unused < 0 || bs.bits_unused > 7) return -1;
  return bs.size * 8 - bs.bits_unused;
}

// Copia di sicurezza per (ri)allocare il buffer
static bool realloc_and_zero(uint8_t** buf, int new_size) {
  uint8_t* nb = (uint8_t*)calloc(1, new_size);
  if (!nb) return false;
  free(*buf);
  *buf = nb;
  return true;
}

/**
 * Valida o corregge la lunghezza del gNB ID:
 * - Se 22 <= len <= 32: OK (nessuna modifica)
 * - Se len < 22: left-pad a 22 mantenendo il valore
 * - Se len > 32: errore
 *
 * Ritorna 0 se OK (o dopo fix), -1 se errore.
 */
int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits = 22,
                                  int max_bits = 32,
                                  int target_if_pad = 22) {
  if (!gnb_id_bs) return -1;
  if (min_bits < 1 || max_bits < min_bits) return -1;

  int total_bits = bit_length(*gnb_id_bs);
  if (total_bits < 0) return -1;

  if (total_bits > max_bits) {
    // Non tronchiamo: meglio segnalare errore
    LOG_D("gNB ID too long: %d bits (max %d)\n", total_bits, max_bits);
    return -1;
  }

  if (total_bits >= min_bits && total_bits <= max_bits) {
    // Già valido: nessuna azione
    return 0;
  }

  // total_bits < min_bits -> left-pad a target_if_pad (tipicamente 22)
  const int target_bits = target_if_pad;
  if (target_bits < min_bits || target_bits > max_bits) return -1;

  // 1) Ricostruisci il valore intero corrente (big-endian), rimuovendo i bits_unused
  uint64_t value = 0;
  for (int i = 0; i < gnb_id_bs->size; ++i) {
    value = (value << 8) | gnb_id_bs->buf[i];
  }
  // Rimuove gli unused bit (in coda all'ultimo byte)
  if (gnb_id_bs->bits_unused > 0) {
    value >>= gnb_id_bs->bits_unused;
  }

  // A questo punto 'value' rappresenta i 'total_bits' effettivi del gNB ID.
  // 2) Prepara il nuovo contenitore con target_bits
  const int num_bytes = (target_bits + 7) / 8;
  const int bits_unused_new = num_bytes * 8 - target_bits;

  if (!realloc_and_zero(&gnb_id_bs->buf, num_bytes)) {
    return -1;
  }
  gnb_id_bs->size = num_bytes;
  gnb_id_bs->bits_unused = bits_unused_new;

  // 3) Inserisci il valore nei target_bits *senza* cambiarlo (vero left-pad)
  // Per codifica ASN.1 BIT STRING: i bit inutilizzati sono in coda ⇒ shiftiamo a sinistra di bits_unused_new
  uint64_t out = value;
  out <<= bits_unused_new;

  // 4) Scrivi in big-endian
  for (int i = num_bytes - 1; i >= 0; --i) {
    gnb_id_bs->buf[i] = static_cast<uint8_t>(out & 0xFF);
    out >>= 8;
  }

  return 0;
}


// List of KPIs that the simulator can populate in KPM indications.
std::vector<std::string> getAllowedKPI() {
    return {
        "DRB.UEThpDl",         // Throughput downlink per UE/DRB (classico CU-UP)
        "DRB.UEThpUl",         // Throughput uplink per UE/DRB
        "DRB.RlcSduTransmittedVolumeDL" , // RLC SDU Transmitted Volume DL per UE/DRB O-RAN metric
        "DRB.RlcSduTransmittedVolumeUL" , // RLC SDU Transmitted Volume UL per UE/DRB O-RAN metric
        "DRB.RlcPacketDropRateDLDist", // RLC Packet Drop Rate DL per UE/DRB
        "DRB.RlcPacketLossRateULDist", // RLC Packet Loss Rate UL per UE/DRB
        /*// Extended UE level KPIs derived from RC logger
        "UE.ActiveUeCount",
        "UE.SignalStrengthAvgDbm",
        "UE.TxBytesWiFi",
        "UE.RxBytesWiFi",
        "UE.TxPacketsWiFi",
        "UE.RxPacketsWiFi",
        "UE.TxRetryRatePercent",
        "UE.ConnectionTimeAvgSec",
        "UE.InactiveTimeAvgSec",
        "UE.TxBitrateAvgMbps",
        "UE.RxBitrateAvgMbps"*/
    };
}
/*
std::vector<std::string> getJSONKeysKPM(){
  return {
    "incomingOctets",
    "transmitOctets",
    "droppedOctets"
  };
}*/

// RAN Parameters that are declared as part of the RC report style.
std::map<long,std::string> getAllowedReportMetricsRC(){
    return {
        // L3 / UE context
        {41001, "UE ID"},             // (IE referenziato in 9.3.10; qui come RAN param per AD/IM)
        {41002, "Old UE ID"},         // UE ID precedente (Style 4)
        {41003, "RRC State"},         // vedi 7.3.5 (RRC state change)

        // Messaggio che ha causato il cambio UE ID (context)
        {41010, "Triggering NI/RRC Message"},

        {42001, "UE RSRP"},

        // Variabili L2 UE (raggruppo esempi comuni: PDCP/RLC/MAC)
        {43001, "PDCP UL Throughput"},
        {43002, "PDCP DL Throughput"},


        // Traffico aggregato per-UE
        {44001, "UL Data Volume"},
        {44002, "DL Data Volume"}
    };
}

// RAN Parameters consumed/produced by RC control actions.
std::map<long,std::string> getAllowedControlMetricsRC(){
    return {
        {1, "Target Primary Cell ID"},
        {2, "CHOICE Target Cell"},
        {3, "NR Cell"},
        {4, "NR CGI"},
        {5, "E-UTRA Cell"},
        {6, "E-UTRA CGI"},
        {7, "List of PDU sessions for handover"},
        {8, "PDU session Item for handover"},
        {9, "PDU session ID"},
        {10, "List of QoS flows in the PDU session"},
        {11, "QoS flow Item"},
        {12, "QoS Flow Identifier"},
        {13, "List of DRBs for handover"},
        {14, "DRB item for handover"},
        {15, "DRB ID"},
        {16, "List of QoS flows to be modified in DRB"},
        {17, "QoS flow Item"},
        {18, "QoS flow Identifier"},
        {19, "List of Secondary cells to be setup"},
        {20, "Secondary cell Item to be setup"},
        {21, "Secondary Cell ID"},
    };
}


// UE identification parameters referenced in the RC event trigger definition.
std::map<long,std::string> getUEIdentifierRC(){
    return {
        {35010, "S-NSSAI"},     // STRUCTURE
        {35011, "SST"},        // ELEMENT (SST)
        {35012, "SD"},         // ELEMENT (SD)
        {35091, "UE ID"}       // ELEMENT (OCTET STRING) – vedi 9.3.10
    };
}
