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
#include "E2SM-RC-ControlHeader.h"
#include "E2SM-RC-ControlHeader-Format1.h"
}

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

  // Remove whitespace and common separators.
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

void decode_as_choice(const std::vector<uint8_t> &buf) {
  E2SM_RC_ControlHeader_t *decoded = nullptr;
  asn_dec_rval_t ret = asn_decode(nullptr,
                                  ATS_ALIGNED_BASIC_PER,
                                  &asn_DEF_E2SM_RC_ControlHeader,
                                  reinterpret_cast<void **>(&decoded),
                                  buf.data(),
                                  buf.size());
  std::cout << "\n== Choice decode (ALIGNED) ==\n";
  if (ret.code != RC_OK || !decoded) {
    std::cout << "Decode failed code=" << ret.code
              << " consumed=" << ret.consumed << "\n";
    return;
  }
  xer_fprint(stdout, &asn_DEF_E2SM_RC_ControlHeader, decoded);
  if (decoded->ric_controlHeader_formats.present ==
      E2SM_RC_ControlHeader__ric_controlHeader_formats_PR_controlHeader_Format1) {
    auto *fmt1 = decoded->ric_controlHeader_formats.choice.controlHeader_Format1;
    if (fmt1) {
      std::cout << "Style=" << fmt1->ric_Style_Type
                << " Action=" << fmt1->ric_ControlAction_ID << "\n";
    }
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader, decoded);
}

void decode_as_choice_unaligned(const std::vector<uint8_t> &buf) {
  E2SM_RC_ControlHeader_t *decoded = nullptr;
  asn_dec_rval_t ret = asn_decode(nullptr,
                                  ATS_UNALIGNED_BASIC_PER,
                                  &asn_DEF_E2SM_RC_ControlHeader,
                                  reinterpret_cast<void **>(&decoded),
                                  buf.data(),
                                  buf.size());
  std::cout << "\n== Choice decode (UNALIGNED) ==\n";
  if (ret.code != RC_OK || !decoded) {
    std::cout << "Decode failed code=" << ret.code
              << " consumed=" << ret.consumed << "\n";
    return;
  }
  xer_fprint(stdout, &asn_DEF_E2SM_RC_ControlHeader, decoded);
  if (decoded->ric_controlHeader_formats.present ==
      E2SM_RC_ControlHeader__ric_controlHeader_formats_PR_controlHeader_Format1) {
    auto *fmt1 = decoded->ric_controlHeader_formats.choice.controlHeader_Format1;
    if (fmt1) {
      std::cout << "Style=" << fmt1->ric_Style_Type
                << " Action=" << fmt1->ric_ControlAction_ID << "\n";
    }
  }
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader, decoded);
}

void decode_as_format1(const std::vector<uint8_t> &buf, bool aligned) {
  E2SM_RC_ControlHeader_Format1_t *fmt1 = nullptr;
  asn_dec_rval_t ret = asn_decode(nullptr,
                                  aligned ? ATS_ALIGNED_BASIC_PER
                                          : ATS_UNALIGNED_BASIC_PER,
                                  &asn_DEF_E2SM_RC_ControlHeader_Format1,
                                  reinterpret_cast<void **>(&fmt1),
                                  buf.data(),
                                  buf.size());
  std::cout << "\n== Format1 decode (" << (aligned ? "ALIGNED" : "UNALIGNED")
            << ") ==\n";
  if (ret.code != RC_OK || !fmt1) {
    std::cout << "Decode failed code=" << ret.code
              << " consumed=" << ret.consumed << "\n";
    return;
  }
  xer_fprint(stdout, &asn_DEF_E2SM_RC_ControlHeader_Format1, fmt1);
  std::cout << "Style=" << fmt1->ric_Style_Type
            << " Action=" << fmt1->ric_ControlAction_ID << "\n";
  ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ControlHeader_Format1, fmt1);
}

} // namespace

int main(int argc, char **argv) {
  const char *path = (argc > 1) ? argv[1] : "/tmp/rc_hdr.hex";
  std::vector<uint8_t> buf;
  if (!load_hex_file(path, buf)) {
    return 1;
  }
  std::cout << "Loaded " << buf.size() << " bytes from " << path << "\n";

  decode_as_choice(buf);
  decode_as_format1(buf, true);
  decode_as_format1(buf, false);
  return 0;
}
