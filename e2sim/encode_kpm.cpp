// encode_kpm.cpp
#include "encode_kpm.hpp"
#include <ctime>

// -----------------------------
// Utility locali
// -----------------------------
static inline void set_octet_string(OCTET_STRING_t *dst, const void *src)
{
  size_t len = strlen((const char *)src);
  if (!dst)
    return;
  dst->buf = (uint8_t *)calloc(1, len);
  dst->size = len;
  if (len && src)
    memcpy(dst->buf, src, len);
}

static inline void add_meas_name(MeasurementInfoList_t *list,const char *name) {

  stampaln("  Adding measurement name function: %s\n", name);
  if (!list) return;  // oppure assert/alloca, ma non dereferenziare
  MeasurementInfoItem_t *it = (MeasurementInfoItem_t *)calloc(1, sizeof(*it));
  it->measType.present = MeasurementType_PR_measName;
  OCTET_STRING_fromBuf(&it->measType.choice.measName, name, (int)strlen(name));

  LabelInfoItem *li = (LabelInfoItem *)calloc(1, sizeof(LabelInfoItem));
  li->measLabel.noLabel = (long*)calloc(1, sizeof(long));
  *li->measLabel.noLabel = 0; 
  ASN_SEQUENCE_ADD(&it->labelInfoList.list, li);

  ASN_SEQUENCE_ADD(&list->list, it);
}

static inline void rec_add_double(MeasurementRecord_t *rec, double v)
{
  stampaln("  Adding measurement record: %.2f\n", v);
  MeasurementRecordItem_t *item = (MeasurementRecordItem_t *)calloc(1, sizeof(*item));
  item->present = MeasurementRecordItem_PR_real;
  item->choice.real = v;
  ASN_SEQUENCE_ADD(&rec->list, item);
}

// -----------------------------
// RAN Function Description (v3)
// -----------------------------

void encode_kpm_function_description(E2SM_KPM_RANfunction_Description_t *desc)
{
  // --- RANfunction-Name / OID / Instance
  set_octet_string(&desc->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-KPM");
  set_octet_string(&desc->ranFunction_Name.ranFunction_Description, "KPM monitor");
  set_octet_string(&desc->ranFunction_Name.ranFunction_E2SM_OID, "1.3.6.1.4.1.53148.1.1.2.2");
  desc->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *desc->ranFunction_Name.ranFunction_Instance = 2;

  desc->ric_EventTriggerStyle_List =
      (decltype(desc->ric_EventTriggerStyle_List))calloc(1, sizeof(*desc->ric_EventTriggerStyle_List));
  desc->ric_ReportStyle_List =
      (decltype(desc->ric_ReportStyle_List))calloc(1, sizeof(*desc->ric_ReportStyle_List));

  // --- EventTrigger style: Periodic (Format 1)
  RIC_EventTriggerStyle_Item_t *et = (RIC_EventTriggerStyle_Item_t *)calloc(1, sizeof(*et));
  et->ric_EventTriggerStyle_Type = 1;
  set_octet_string(&et->ric_EventTriggerStyle_Name, "Periodic report");
  et->ric_EventTriggerFormat_Type = 1; // KPM EventTrigger Format 1
  ASN_SEQUENCE_ADD(&desc->ric_EventTriggerStyle_List->list, et);

  // --- Report style type 1 con Header/Message Format 1/1.
  RIC_ReportStyle_Item_t *rs = (RIC_ReportStyle_Item_t *)calloc(1, sizeof(*rs));
  rs->ric_ReportStyle_Type = 1; // usa 4 se il tuo xApp lo richiede
  set_octet_string(&rs->ric_ReportStyle_Name, "KPM v3 N3IWF");
  rs->ric_IndicationHeaderFormat_Type = 1;
  rs->ric_IndicationMessageFormat_Type = 1;

  // --- measInfoActionList (ALMENO 1 misura!)
  // helper per aggiungere 1 misura con noLabel
  auto add_meas = [&](const char *name)
  {
    MeasurementInfo_Action_Item_t *mi = (MeasurementInfo_Action_Item_t *)calloc(1, sizeof(*mi));
    set_octet_string(&mi->measName, name);
    ASN_SEQUENCE_ADD(&rs->measInfo_Action_List.list, mi);
  };

  std::vector<std::string> allowedKPI = getAllowedKPI();
  for (const auto &kpi : allowedKPI)
  {
    add_meas(kpi.c_str());
  }

  // --- chiudi lo style
  ASN_SEQUENCE_ADD(&desc->ric_ReportStyle_List->list, rs);
}

void get_current_timestamp(OCTET_STRING_t *os)
{
  uint8_t buf[8];
  uint64_t ts = (uint64_t)time(NULL); // secondi epoch

  // scrivi ts in big-endian
  for (int i = 0; i < 8; ++i)
    buf[7 - i] = (uint8_t)((ts >> (8 * i)) & 0xFF);

  // Copia profonda nel campo ASN. Usa la funzione standard generata da asn1c.
  OCTET_STRING_fromBuf(os, (const char *)buf, 8);
}

// ---------------------------------------
// Indication Header - Format 1
// ---------------------------------------
void encode_kpm_ind_hdr_fmt1(E2SM_KPM_IndicationHeader_t *hdr)
{
  memset(hdr, 0, sizeof(*hdr));
  hdr->indicationHeader_formats.present = E2SM_KPM_IndicationHeader__indicationHeader_formats_PR_indicationHeader_Format1;

  E2SM_KPM_IndicationHeader_Format1_t *h1 = (E2SM_KPM_IndicationHeader_Format1_t *)calloc(1, sizeof(*h1));

  // In KPM v3 il campo è (tipicamente) scritto "colletStartTime" (refuso nel naming)
  // È un OCTET STRING(4..8). Qui metto una stringa timestamp semplice.
  get_current_timestamp(&h1->colletStartTime);
  h1->senderName = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(h1->senderName, "O-RAN N3IWF", strlen("O-RAN N3IWF"));
  h1->fileFormatversion = (PrintableString_t *)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(h1->fileFormatversion, "3.0", strlen("3.0"));

  hdr->indicationHeader_formats.choice.indicationHeader_Format1 = h1; // by value
  
}

// ---------------------------------------------------------------------------------
void kpm_fill_ue_rf_basic(E2SM_KPM_IndicationMessage_t *indMsg, std::map<std::string, double> kpi)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present =
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 = (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));
  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(*mdi));
  fmt1->measInfoList = (MeasurementInfoList_t*)calloc(1, sizeof(*fmt1->measInfoList));

  for (const auto &kv : kpi)
  {
    const char *name = kv.first.c_str();
    double value = kv.second;
    stampaln("  Adding measurement %s = %.2f\n", name, value);
    // Un record con i 3 valori
    if (value != -1)
    {
      // Aggiungi il nome della misura (se non c'è già) e l'etichetta (vuota)
      add_meas_name(fmt1->measInfoList, name);
      rec_add_double(&mdi->measRecord, value);
    }
  }

  if (fmt1->measInfoList->list.count == 0 || mdi->measRecord.list.count != fmt1->measInfoList->list.count)
  {
    stampaln("No measurements to send in KPM Indication Message or inconsistent measurement counts\n");
    // niente da inviare: pulisci e rientra
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_MeasurementRecord, &mdi->measRecord);
    free(mdi);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_MeasurementInfoList, fmt1->measInfoList);
    free(fmt1->measInfoList);
    free(fmt1);
    return;
  }
  stampaln("  Total measurements added: %d\n", fmt1->measInfoList->list.count);
  ASN_SEQUENCE_ADD(&fmt1->measData.list, mdi);

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;
}
