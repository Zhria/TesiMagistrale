#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

extern "C" {
#include "asn_application.h"
#include "E2AP-PDU.h"
#include "RICcontrolRequest.h"
}

#include "../rc_callbacks.hpp"

// Stub per soddisfare il link da e2ap_message_handler.cpp (non usato in questo test)
void stop_kpm_subscription(long, long, long) {}

namespace {

bool load_hex_file(const std::string &path, std::vector<uint8_t> &out_buf) {
  std::ifstream in(path);
  if (!in) {
    std::cerr << "Unable to open file: " << path << "\n";
    return false;
  }

  std::string hex;
  std::stringstream ss;
  ss << in.rdbuf();
  hex = ss.str();

  std::string clean;
  clean.reserve(hex.size());
  for (char c : hex) {
    if (c == ' ' || c == '\n' || c == '\r' || c == '\t' || c == ':')
      continue;
    clean.push_back(c);
  }

  if (clean.size() % 2 != 0) {
    std::cerr << "Hex string has odd length after cleaning (" << clean.size()
              << ")\n";
    return false;
  }

  out_buf.clear();
  out_buf.reserve(clean.size() / 2);
  for (size_t i = 0; i < clean.size(); i += 2) {
    unsigned int byte = 0;
    if (sscanf(clean.c_str() + i, "%02x", &byte) != 1) {
      std::cerr << "Invalid hex at position " << i << "\n";
      return false;
    }
    out_buf.push_back(static_cast<uint8_t>(byte));
  }
  return true;
}

} // namespace

int main(int argc, char **argv) {
  const char *path = (argc > 1) ? argv[1] : "/tmp/rc_ctrl_pdu.hex";
  std::vector<uint8_t> buf;
  if (!load_hex_file(path, buf)) {
    return 1;
  }
  std::cout << "[ROUNDTRIP] Loaded " << buf.size() << " bytes from " << path
            << "\n";

  E2AP_PDU_t *pdu = nullptr;
  asn_dec_rval_t ret = asn_decode(nullptr,
                                  ATS_ALIGNED_BASIC_PER,
                                  &asn_DEF_E2AP_PDU,
                                  reinterpret_cast<void **>(&pdu),
                                  buf.data(),
                                  buf.size());
  if (ret.code != RC_OK || !pdu) {
    std::cerr << "[ROUNDTRIP] E2AP decode failed code=" << ret.code
              << " consumed=" << ret.consumed << "\n";
    return 1;
  }

  // Debug opzionale: stampa il PDU decodificato.
  xer_fprint(stdout, &asn_DEF_E2AP_PDU, pdu);

  // Riusa la catena RC di e2sim: se il callback gestisce il messaggio,
  // l'header e il message RC sono stati decodificati correttamente.
  callback_rc_control_request(pdu);

  ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
  return 0;
}
