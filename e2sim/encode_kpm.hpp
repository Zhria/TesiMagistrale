#ifndef ENCODE_KPM_V3_HPP
#define ENCODE_KPM_V3_HPP

// encode_kpm_v3.cpp
#include <cstring>
#include <cstdlib>
#include <cassert>
#include "n3iwf_utils.hpp"
#include <vector>
#include <map>
extern "C" {
  #include "asn_application.h"
  #include "OCTET_STRING.h"
  #include "TimeStamp.h"

  // RAN function description (stili ET/Report esistono ancora)
  #include "E2SM-KPM-RANfunction-Description.h"
  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"
  #include "asn_SEQUENCE_OF.h"

  // Header/Message v3 (formati)
  #include "E2SM-KPM-IndicationHeader.h"
  #include "E2SM-KPM-IndicationHeader-Format1.h"
  #include "E2SM-KPM-IndicationMessage.h"
  #include "E2SM-KPM-IndicationMessage-Format1.h"
  #include "E2SM-KPM-IndicationMessage-Format2.h"

  // Nuovo data model delle misure
  #include "MeasurementInfoList.h"
  #include "MeasurementInfoItem.h"
  #include "LabelInfoList.h"
  #include "LabelInfoItem.h"
  #include "MeasurementLabel.h"
  #include "MeasurementData.h"
  #include "MeasurementDataItem.h"
  #include "MeasurementRecord.h"
  #include "MeasurementRecordItem.h"

  #include "MeasurementInfo-Action-Item.h"

  #include "INTEGER.h"

  #include "E2SM-KPM-RANfunction-Description.h"
  #include "E2SM-KPM-ActionDefinition.h" // or the correct header where MeasurementInfoAction_Item_t is defined

  #include "RIC-EventTriggerStyle-Item.h"
  #include "RIC-ReportStyle-Item.h"

}
  
// --- RAN Function Description (rimane)
void encode_kpm_function_description(E2SM_KPM_RANfunction_Description_t* ranfunc_desc);

// --- Indication Header/Message (nuovi formati v3)
void encode_kpm_ind_hdr_fmt1(E2SM_KPM_IndicationHeader_t* hdr);

void kpm_fill_ue_rf_basic(E2SM_KPM_IndicationMessage_t* indMsg,std::map<std::string, double> kpi);


#endif // ENCODE_KPM_V3_HPP
