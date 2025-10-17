#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <vector>

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

static inline int bit_length(const BIT_STRING_t& bs);
static bool realloc_and_zero(uint8_t** buf, int new_size);


int validate_or_fix_gnb_id_length(BIT_STRING_t* gnb_id_bs,
                                  int min_bits,
                                  int max_bits,
                                  int target_if_pad);
                                  
void stampaln(const char* msg, ...);

std::vector<std::string> getAllowedKPI();

std::vector<std::string> getAllowedMetricsRC();

std::map<long,std::string> getUEIdentifierRC();