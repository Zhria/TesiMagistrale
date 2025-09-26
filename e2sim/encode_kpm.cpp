// encode_kpm.cpp
#include "encode_kpm.hpp"

// -----------------------------
// Utility locali
// -----------------------------
static inline void set_octet_string(OCTET_STRING_t *dst, const void *src, size_t len)
{
  if (!dst)
    return;
  dst->buf = (uint8_t *)calloc(1, len);
  dst->size = len;
  if (len && src)
    memcpy(dst->buf, src, len);
}

static inline void add_meas_name(MeasurementInfoList_t *list,
                                 const char *name,
                                 const MeasurementLabel_t *opt_label /* può essere nullptr */)
{
  MeasurementInfoItem_t *it = (MeasurementInfoItem_t *)calloc(1, sizeof(*it));
  it->measType.present = MeasurementType_PR_measName;
  set_octet_string(&it->measType.choice.measName, name, strlen(name));

  if (opt_label)
  {
    // Copia "by value" dell'etichetta dentro un LabelInfoItem
    LabelInfoItem *li = (LabelInfoItem *)calloc(1, sizeof(LabelInfoItem));
    li->measLabel = *opt_label;
    ASN_SEQUENCE_ADD(&it->labelInfoList.list, li);
  }

  ASN_SEQUENCE_ADD(&list->list, it);
}

static inline void rec_add_int(MeasurementRecord_t *rec, long v)
{
  MeasurementRecordItem_t *item = (MeasurementRecordItem_t *)calloc(1, sizeof(*item));
  item->present = MeasurementRecordItem_PR_integer;
  item->choice.integer = v; //(INTEGER_t*)calloc(1, sizeof(INTEGER_t));
  // asn_long2INTEGER(item->choice.integer, v);
  ASN_SEQUENCE_ADD(&rec->list, item);
}

// -----------------------------
// RAN Function Description (v3)
// -----------------------------

void encode_kpm_function_description(E2SM_KPM_RANfunction_Description_t *desc)
{
  // --- RANfunction-Name / OID / Instance
  set_octet_string(&desc->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-KPM", strlen("ORAN-E2SM-KPM"));
  set_octet_string(&desc->ranFunction_Name.ranFunction_Description, "KPM monitor", strlen("KPM monitor"));
  set_octet_string(&desc->ranFunction_Name.ranFunction_E2SM_OID, "1.3.6.1.4.1.53148.1.1.2.2", strlen("1.3.6.1.4.1.53148.1.1.2.2"));
  desc->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *desc->ranFunction_Name.ranFunction_Instance = 2;

  desc->ric_EventTriggerStyle_List =
      (decltype(desc->ric_EventTriggerStyle_List))calloc(1, sizeof(*desc->ric_EventTriggerStyle_List));
  desc->ric_ReportStyle_List =
      (decltype(desc->ric_ReportStyle_List))calloc(1, sizeof(*desc->ric_ReportStyle_List));

  // --- EventTrigger style: Periodic (Format 1)
  RIC_EventTriggerStyle_Item_t *et = (RIC_EventTriggerStyle_Item_t *)calloc(1, sizeof(*et));
  et->ric_EventTriggerStyle_Type = 1;
  set_octet_string(&et->ric_EventTriggerStyle_Name, "Periodic report", strlen("Periodic report"));
  et->ric_EventTriggerFormat_Type = 1; // KPM EventTrigger Format 1
  ASN_SEQUENCE_ADD(&desc->ric_EventTriggerStyle_List->list, et);

  // --- Report style: CU-UP (Type 4) con Header/Message Format 1/1
  RIC_ReportStyle_Item_t *rs = (RIC_ReportStyle_Item_t *)calloc(1, sizeof(*rs));
  rs->ric_ReportStyle_Type = 4; // usa 4 se il tuo xApp lo richiede
  set_octet_string(&rs->ric_ReportStyle_Name, "KPM v3 CU-UP", strlen("KPM v3 CU-UP"));
  rs->ric_IndicationHeaderFormat_Type = 1;
  rs->ric_IndicationMessageFormat_Type = 1;

  // --- measInfoActionList (ALMENO 1 misura!)
  // helper per aggiungere 1 misura con noLabel
  auto add_meas = [&](const char *name)
  {
    MeasurementInfo_Action_Item_t *mi = (MeasurementInfo_Action_Item_t *)calloc(1, sizeof(*mi));
    set_octet_string(&mi->measName, name, strlen(name));

    // labelInfoList con un item "noLabel" (minimo indispensabile)
    /*mi->labelInfoList = (struct LabelInfoList_t*)calloc(1,sizeof(*mi->labelInfoList));
    LabelInfoItem_t* li = (LabelInfoItem_t*)calloc(1,sizeof(*li));
    li->measLabel = (MeasurementLabel_t*)calloc(1,sizeof(*li->measLabel));
    //li->measLabel.noLabel = (NULL_t*)calloc(1,sizeof(NULL_t));
    ASN_SEQUENCE_ADD(&mi->labelInfoList->list, li);*/

    ASN_SEQUENCE_ADD(&rs->measInfo_Action_List.list, mi);
  };

  add_meas("DRB.UEThpDl");         // Throughput downlink per UE/DRB (classico CU-UP)
  add_meas("DRB.UEThpUl");         // Throughput uplink per UE/DRB
  add_meas("DRB.PdcpPduVolumeDl"); // Volume PDCP downlink per UE/DRB
  add_meas("DRB.PdcpPduVolumeUl"); // Volume PDCP
  add_meas("PRB.UsageDl");         // PRB usage downlink (classico gNB)
  add_meas("PRB.UsageUl");         // PRB usage uplink

  // --- chiudi lo style
  ASN_SEQUENCE_ADD(&desc->ric_ReportStyle_List->list, rs);
}

// ---------------------------------------
// Indication Header - Format 1 (minimale)
// ---------------------------------------
void encode_kpm_ind_hdr_fmt1(E2SM_KPM_IndicationHeader_t *hdr)
{
  memset(hdr, 0, sizeof(*hdr));
  hdr->indicationHeader_formats.present = E2SM_KPM_IndicationHeader__indicationHeader_formats_PR_indicationHeader_Format1;

  E2SM_KPM_IndicationHeader_Format1_t *h1 = (E2SM_KPM_IndicationHeader_Format1_t *)calloc(1, sizeof(*h1));

  // In KPM v3 il campo è (tipicamente) scritto "colletStartTime" (refuso nel naming)
  // È un OCTET STRING(4..8). Qui metto una stringa timestamp semplice.
  const char ts[] = "20240620123000Z";
  set_octet_string(&h1->colletStartTime, ts, sizeof(ts) - 1);

  // (opzionali) id_GlobalKPMnode_ID, ecc. -> lascio non settati

  hdr->indicationHeader_formats.choice.indicationHeader_Format1 = h1; // by value
  free(h1);
}

// --------------------------------------------------
// Indication Message - Format 1 (minimo dimostrativo)
// --------------------------------------------------
void encode_kpm_ind_msg_fmt1(E2SM_KPM_IndicationMessage_t *indMsg)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 = (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));

  // Colonne: PDCP_BytesDL, PDCP_BytesUL (senza label)
  add_meas_name(fmt1->measInfoList, "PDCP_BytesDL", nullptr);
  add_meas_name(fmt1->measInfoList, "PDCP_BytesUL", nullptr);

  // Una riga con 2 valori
  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(*mdi));
  rec_add_int(&mdi->measRecord, 0);
  rec_add_int(&mdi->measRecord, 0);
  ASN_SEQUENCE_ADD(&fmt1->measData.list, mdi);

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1; // by value
  free(fmt1);
}

// -----------------------------------------------------------------------
// Indication Message - Format 2 (stub minimo: presente ma senza contenuti)
// -----------------------------------------------------------------------
void encode_kpm_ind_msg_fmt2(E2SM_KPM_IndicationMessage_t *indMsg)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format2;

  // Se davvero ti serve il Format2 (misure condizionate/UE), riempio volentieri
  // i campi specifici (measCondUEidList, ecc.). Qui lo lascio vuoto per compilare.
  E2SM_KPM_IndicationMessage_Format2_t *fmt2 = (E2SM_KPM_IndicationMessage_Format2_t *)calloc(1, sizeof(*fmt2));
  indMsg->indicationMessage_formats.choice.indicationMessage_Format2 = fmt2;
  free(fmt2);
}

// ---------------------------------------------------------------------------------
// ex-STYLE5 → Throughput CU-UP: PDCP_BytesDL/UL con (eventuale) etichettatura slice
// ---------------------------------------------------------------------------------
void kpm_fill_cuup_throughput(E2SM_KPM_IndicationMessage_t *indMsg,
                              const uint8_t * /*gnbcuupname_buf*/,
                              int bytes_dl, int bytes_ul,
                              const uint8_t * /*sst_buf*/, const uint8_t * /*sd_buf*/,
                              const uint8_t * /*plmnid_buf*/)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 = (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));

  // Colonne
  add_meas_name(fmt1->measInfoList, "PDCP_BytesDL", nullptr);
  add_meas_name(fmt1->measInfoList, "PDCP_BytesUL", nullptr);

  // Record
  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(*mdi));
  rec_add_int(&mdi->measRecord, (long)bytes_dl);
  rec_add_int(&mdi->measRecord, (long)bytes_ul);
  ASN_SEQUENCE_ADD(&fmt1->measData.list, mdi);

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;
  free(fmt1);
}

// ----------------------------------------------------------------------------------------------------
// ex-STYLE1 → PRB usage per cella/slice/5QI:  DL_PRB_Usage, UL_PRB_Usage, DL_Total_PRBs, UL_Total_PRBs
// ----------------------------------------------------------------------------------------------------
void kpm_fill_cell_slice_qos_meas(E2SM_KPM_IndicationMessage_t *indMsg,
                                  long fiveqi,
                                  const uint8_t * /*sst_buf*/, const uint8_t * /*sd_buf*/,
                                  const uint8_t * /*plmnid_buf*/,
                                  const uint8_t * /*nrcellid_buf*/,
                                  const long *dl_prbs, const long *ul_prbs,
                                  long dl_prb_usage, long ul_prb_usage)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present = E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 = (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));

  // Etichetta minimale: solo 5QI (per evitare dipendenze da mapping IDL variabile di slice/cella)
  MeasurementLabel_t label{};
  label.fiveQI = (long *)calloc(1, sizeof(long));
  *label.fiveQI = fiveqi;

  // Definizione colonne con etichetta
  add_meas_name(fmt1->measInfoList, "DL_PRB_Usage", &label);
  add_meas_name(fmt1->measInfoList, "UL_PRB_Usage", &label);
  add_meas_name(fmt1->measInfoList, "DL_Total_PRBs", &label);
  add_meas_name(fmt1->measInfoList, "UL_Total_PRBs", &label);

  // Un record con quattro valori
  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(*mdi));
  rec_add_int(&mdi->measRecord, dl_prb_usage);
  rec_add_int(&mdi->measRecord, ul_prb_usage);
  rec_add_int(&mdi->measRecord, dl_prbs ? *dl_prbs : 0);
  rec_add_int(&mdi->measRecord, ul_prbs ? *ul_prbs : 0);
  ASN_SEQUENCE_ADD(&fmt1->measData.list, mdi);

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;
  free(fmt1);
}

void kpm_fill_ue_rf_basic(E2SM_KPM_IndicationMessage_t *indMsg,
                          long rsrp, long rsrq, long rssinr)
{
  memset(indMsg, 0, sizeof(*indMsg));
  indMsg->indicationMessage_formats.present =
      E2SM_KPM_IndicationMessage__indicationMessage_formats_PR_indicationMessage_Format1;

  E2SM_KPM_IndicationMessage_Format1_t *fmt1 =
      (E2SM_KPM_IndicationMessage_Format1_t *)calloc(1, sizeof(*fmt1));

  // Colonne misure base UE RF
  add_meas_name(fmt1->measInfoList, "UE_RSRP", nullptr);
  add_meas_name(fmt1->measInfoList, "UE_RSRQ", nullptr);
  add_meas_name(fmt1->measInfoList, "UE_RSSINR", nullptr);

  // Un record con i 3 valori
  MeasurementDataItem_t *mdi = (MeasurementDataItem_t *)calloc(1, sizeof(*mdi));
  rec_add_int(&mdi->measRecord, rsrp);
  rec_add_int(&mdi->measRecord, rsrq);
  rec_add_int(&mdi->measRecord, rssinr);
  ASN_SEQUENCE_ADD(&fmt1->measData.list, mdi);

  indMsg->indicationMessage_formats.choice.indicationMessage_Format1 = fmt1;
  free(fmt1);
}
