#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>


extern "C" {
  #include "OCTET_STRING.h"
  #include "asn_application.h"
  #include "E2SM-KPM-IndicationMessage.h"
  #include "E2SM-KPM-RANfunction-Description.h"
  #include "E2AP-PDU.h"
  #include "RICsubscriptionRequest.h"
  #include "RICsubscriptionResponse.h"
  #include "RICactionType.h"
  #include "ProtocolIE-Field.h"
  #include "ProtocolIE-SingleContainer.h"
  #include "InitiatingMessage.h"
}


#include "kpm_callbacks.hpp"
#include "encode_kpm.hpp"
#include "n3iwf_utils.hpp"

#include "encode_e2apv2.hpp"

#include <nlohmann/json.hpp>

struct timespec ts;    // DEFINIZIONE (una sola volta in tutto l’eseguibile)


using namespace std;
using json = nlohmann::json;
static E2Sim e2;

/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[])
{
  // pausa per permettere al n3iwf di avviarsi e iniziare a loggare
  std::this_thread::sleep_for(std::chrono::seconds(5));
  stampaln("Starting E2 Simulator with KPM Callbacks (KPM v3)\n");
  clock_gettime(CLOCK_REALTIME, &ts); // Inizializza ts all'avvio

  // --- RANfunction-Description KPM v3 ---
  E2SM_KPM_RANfunction_Description_t *ranfunc_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  if (ranfunc_desc == NULL) {
    stampaln( "calloc failed for ranfunc_desc\n");
    return -1;
  }

  // Deve riempire i campi secondo KPM v3
  encode_kpm_function_description(ranfunc_desc);

  // Codifica della RANfunction-Description
  const size_t e2smbuffer_size = 16384;
  uint8_t *e2smbuffer = (uint8_t *)calloc(1, e2smbuffer_size);
  if (e2smbuffer == NULL) {
    stampaln( "calloc failed for e2smbuffer\n");
    return -1;
  }

  asn_enc_rval_t er = asn_encode_to_buffer(
      NULL, ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_KPM_RANfunction_Description,
      ranfunc_desc, e2smbuffer, e2smbuffer_size);

  if (er.encoded < 0) {
    stampaln("Encoding failed: %s\n", er.failed_type ? er.failed_type->name : "unknown");
    free(e2smbuffer);
    return -1;
  }

  // Crea OCTET_STRING per registrazione nel simulatore
  OCTET_STRING_t *ranfunc_ostr = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  if (ranfunc_ostr == NULL) {
    stampaln( "calloc failed for ranfunc_ostr\n");
    free(e2smbuffer);
    return -1;
  }
  ranfunc_ostr->buf  = (uint8_t *)calloc(1, (size_t)er.encoded);
  ranfunc_ostr->size = (er.encoded > 0) ? (size_t)er.encoded : 0;
  if (ranfunc_ostr->buf == NULL) {
    stampaln( "calloc failed for ranfunc_ostr->buf\n");
    free(ranfunc_ostr);
    free(e2smbuffer);
    return -1;
  }
  memcpy(ranfunc_ostr->buf, e2smbuffer, ranfunc_ostr->size);

  // Registra la SM (FunctionID=2) e callback subscription
  e2.register_e2sm(2, ranfunc_ostr);
  e2.register_subscription_callback(2, &callback_kpm_subscription_request);

  // Self-test: decodifica della RANfunction-Description appena encodata
  E2SM_KPM_RANfunction_Description_t *check = NULL;
  asn_dec_rval_t dr = asn_decode(NULL, ATS_ALIGNED_BASIC_PER,
                                 &asn_DEF_E2SM_KPM_RANfunction_Description,
                                 (void **)&check,
                                 ranfunc_ostr->buf, ranfunc_ostr->size);
  if (dr.code != RC_OK) {
    stampaln( "Self-test decode KPM FAILED (%d) at byte %zu\n", dr.code, dr.consumed);
  } else {
    stampaln( "Self-test decode KPM OK (consumed=%zu)\n", dr.consumed);
  }

  // Non servono più questi buffer locali
  free(e2smbuffer);
  // (ranfunc_ostr viene mantenuto registrato dentro e2)

  // Avvia loop del simulatore
  e2.run_loop(argc, argv);
  return 0;
}

/* ============================================================
 * REPORT LOOP (genera e invia Indication in base ai file JSON)
 * ============================================================ */
void run_report_loop(long requestorId, long instanceId, long ranFunctionId, long actionId)
{
  std::ifstream simfile("simulation.txt", std::ios::in); // eventuale uso futuro
  (void)simfile;

  long seqNum = 1;

  std::ifstream ue_stream("ueMeasReport.txt");
  std::ifstream cell_stream("cellMeasReport.txt");

  if (!ue_stream.is_open()) {
    stampaln( "Failed to open ueMeasReport.txt\n");
    return;
  }
  if (!cell_stream.is_open()) {
    stampaln( "Failed to open cellMeasReport.txt\n");
    return;
  }

  json all_ues_json;
  json all_cells_json;

  ue_stream >> all_ues_json;
  cell_stream >> all_cells_json;

  asn_codec_ctx_t *opt_cod = NULL; // usare NULL per il contesto (standard)

  std::cout << "UE RF Measurements" << std::endl;
  std::cout << "******************" << std::endl;

  int numMeasReports =
      (int)(all_ues_json["/ueMeasReport/ueMeasReportList"_json_pointer]).size();

  for (int i = 0; i < numMeasReports; i++) {
    int nextCellId;
    int nextRsrp;
    int nextRsrq;
    int nextRssinr;

    std::cout << "UE number " << i << std::endl;
    std::cout << "**********" << std::endl;

    json::json_pointer p1(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) + "/nrCellIdentity");
    nextCellId = all_ues_json[p1].get<int>();
    std::cout << "Serving Cell " << nextCellId << std::endl;

    json::json_pointer p2(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) + "/servingCellRfReport/rsrp");
    nextRsrp = all_ues_json[p2].get<int>();
    std::cout << "  RSRP " << nextRsrp << std::endl;

    json::json_pointer p3(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) + "/servingCellRfReport/rsrq");
    nextRsrq = all_ues_json[p3].get<int>();
    std::cout << "  RSRQ " << nextRsrq << std::endl;

    json::json_pointer p4(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) + "/servingCellRfReport/rssinr");
    nextRssinr = all_ues_json[p4].get<int>();
    std::cout << "  RSSINR " << nextRssinr << std::endl;

    json::json_pointer p5(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) + "/neighbourCellList");
    int numNeighborCells = (int)(all_ues_json[p5]).size();

    // === REPORT Message 3: OCU-CP user-level report (RAN Container) ===
    E2SM_KPM_IndicationMessage_t *ind_msg3 =
        (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
    E2AP_PDU *pdu3 = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
    if (ind_msg3 == NULL || pdu3 == NULL) {
      stampaln( "calloc failed for ind_msg3/pdu3\n");
      return;
    }

    uint8_t *crnti_buf = (uint8_t *)calloc(1, 2);
    if (crnti_buf == NULL) {
      stampaln( "calloc failed for crnti_buf\n");
      return;
    }

    if (nextCellId == 0) {
      const uint8_t tmp[2] = {'1','2'};
      memcpy(crnti_buf, tmp, 2);
    } else if (nextCellId == 1) {
      const uint8_t tmp[2] = {'2','2'};
      memcpy(crnti_buf, tmp, 2);
    } else {
      const uint8_t tmp[2] = {'0','0'};
      memcpy(crnti_buf, tmp, 2);
    }

    // JSON per serving & neighbors
    std::string serving_str =
        std::string("{\"rsrp\": ") + std::to_string(nextRsrp) +
        ", \"rsrq\": " + std::to_string(nextRsrq) +
        ", \"rssinr\": " + std::to_string(nextRssinr) + "}";

    const uint8_t *serving_buf =
        reinterpret_cast<const uint8_t *>(serving_str.c_str());

    std::string neighbor_str = "[";
    for (int j = 0; j < numNeighborCells; j++) {
      int nextNbCell;
      int nextNbRsrp;
      int nextNbRsrq;
      int nextNbRssinr;

      json::json_pointer p8(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) +
                            "/neighbourCellList/" + std::to_string(j) + "/nbCellIdentity");
      nextNbCell = all_ues_json[p8].get<int>();
      std::cout << "Neighbor Cell " << nextNbCell << std::endl;

      json::json_pointer p9(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) +
                            "/neighbourCellList/" + std::to_string(j) + "/nbCellRfReport/rsrp");
      nextNbRsrp = all_ues_json[p9].get<int>();
      std::cout << "  RSRP " << nextNbRsrp << std::endl;

      json::json_pointer p10(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) +
                             "/neighbourCellList/" + std::to_string(j) + "/nbCellRfReport/rsrq");
      nextNbRsrq = all_ues_json[p10].get<int>();
      std::cout << "  RSRQ " << nextNbRsrq << std::endl;

      json::json_pointer p11(std::string("/ueMeasReport/ueMeasReportList/") + std::to_string(i) +
                             "/neighbourCellList/" + std::to_string(j) + "/nbCellRfReport/rssinr");
      nextNbRssinr = all_ues_json[p11].get<int>();
      std::cout << "  RSSINR " << nextNbRssinr << std::endl;

      if (j != 0) neighbor_str += ",";

      // JSON corretto (niente virgolette attorno all'oggetto interno)
      neighbor_str += std::string("{\"CID\":\"") + std::to_string(nextNbCell) +
                      "\", \"Cell-RF\": {\"rsrp\": " + std::to_string(nextNbRsrp) +
                      ", \"rsrq\": " + std::to_string(nextNbRsrq) +
                      ", \"rssinr\": " + std::to_string(nextNbRssinr) + "}}";
    }
    neighbor_str += "]";

    const uint8_t *neighbor_buf =
        reinterpret_cast<const uint8_t *>(neighbor_str.c_str());

    std::printf("Neighbor string\n%s\n", (const char *)neighbor_buf);

    uint8_t *plmnid_buf = (uint8_t *)"747";
    uint8_t *nrcellid_buf = (uint8_t *)"12340";

    // Encoder KPM v3 (RAN Container CU-CP)
    //encode_kpm_report_rancontainer_cucp_parameterized(ind_msg3, plmnid_buf, nrcellid_buf, crnti_buf, serving_buf, neighbor_buf);
// ----- HEADER v3 (Format1) -----
E2SM_KPM_IndicationHeader_t hdr3;
encode_kpm_ind_hdr_fmt1(&hdr3);

uint8_t hdr_buf3[512];
asn_enc_rval_t ehr3 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,
    &hdr3, hdr_buf3, sizeof(hdr_buf3));
if (ehr3.encoded < 0) { stampaln( "hdr enc failed\n"); /* handle */ }

// ----- MESSAGE v3: UE RF basic (ex RANcontainer CU-CP) -----
kpm_fill_ue_rf_basic(ind_msg3, nextRsrp, nextRsrq, nextRssinr);

uint8_t msg_buf3[8192];
asn_enc_rval_t emr3 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
    &ind_msg3, msg_buf3, sizeof(msg_buf3));
if (emr3.encoded < 0) { stampaln( "msg enc failed\n"); /* handle */ }

// ----- E2AP wrapper -----
generate_e2apv2_indication_request_parameterized(
    pdu3, requestorId, instanceId, ranFunctionId, actionId, seqNum,
    hdr_buf3, (int)ehr3.encoded, msg_buf3, (int)emr3.encoded);

e2.encode_and_send_sctp_data(pdu3);
seqNum++;
    uint8_t e2smbuffer3[8192];
    size_t e2smbuffer_size3 = sizeof(e2smbuffer3);

    asn_enc_rval_t er3 = asn_encode_to_buffer(
        opt_cod, ATS_ALIGNED_BASIC_PER,
        &asn_DEF_E2SM_KPM_IndicationMessage,
        ind_msg3, e2smbuffer3, e2smbuffer_size3);

    stampaln( "er encoded is %ld\n", er3.encoded);
    stampaln( "after encoding message\n");

    uint8_t *e2smheader_buf3 = (uint8_t *)"header"; // header KPM (v3)

    generate_e2apv2_indication_request_parameterized(
        pdu3, requestorId, instanceId, ranFunctionId, actionId, seqNum,
        e2smheader_buf3, 6, e2smbuffer3, er3.encoded);

    e2.encode_and_send_sctp_data(pdu3);
    seqNum++;

    // free semplici (ind_msg3/pdu3 in genere rimangono referenziati fino a invio)
    free(crnti_buf);
  }

  std::cout << "Cell Measurements" << std::endl;
  std::cout << "******************" << std::endl;

  int numCellMeasReports =
      (int)(all_cells_json["/cellMeasReport/cellMeasReportList"_json_pointer]).size();

  uint8_t *sst_buf   = (uint8_t *)"1";
  uint8_t *sd_buf    = (uint8_t *)"100";
  uint8_t *plmnid_buf = (uint8_t *)"747";

  for (int i = 0; i < numCellMeasReports; i++) {
    int nextCellId;
    int nextPdcpBytesDL;
    int nextPdcpBytesUL;
    int nextPRBBytesDL;
    int nextPRBBytesUL;

    json::json_pointer p1(std::string("/cellMeasReport/cellMeasReportList/") + std::to_string(i) + "/nrCellIdentity");
    nextCellId = all_cells_json[p1].get<int>();
    std::cout << "Cell number " << nextCellId << std::endl;
    std::cout << "**********" << std::endl;

    json::json_pointer p2(std::string("/cellMeasReport/cellMeasReportList/") + std::to_string(i) + "/pdcpByteMeasReport/pdcpBytesDl");
    nextPdcpBytesDL = all_cells_json[p2].get<int>();
    std::cout << "  PDCP Bytes DL " << nextPdcpBytesDL << std::endl;

    json::json_pointer p3(std::string("/cellMeasReport/cellMeasReportList/") + std::to_string(i) + "/pdcpByteMeasReport/pdcpBytesUl");
    nextPdcpBytesUL = all_cells_json[p3].get<int>();
    std::cout << "  PDCP Bytes UL " << nextPdcpBytesUL << std::endl;

    uint8_t *node_name_buf = (uint8_t *)"GNBCUUP5";
    int bytes_dl = nextPdcpBytesDL;
    int bytes_ul = nextPdcpBytesUL;

    // === REPORT Message 2: Style5 (PDCP bytes per slice) ===
    E2SM_KPM_IndicationMessage_t *ind_msg2 =
        (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
    E2AP_PDU *pdu2 = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
    if (ind_msg2 == NULL || pdu2 == NULL) {
      stampaln( "calloc failed for ind_msg2/pdu2\n");
      return;
    }

    //encode_kpm_report_style5_parameterized(ind_msg2, node_name_buf, bytes_dl, bytes_ul, sst_buf, sd_buf, plmnid_buf);
// HEADER
E2SM_KPM_IndicationHeader_t hdr2;
encode_kpm_ind_hdr_fmt1(&hdr2);
uint8_t hdr_buf2[512];
asn_enc_rval_t ehr2 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,
    &hdr2, hdr_buf2, sizeof(hdr_buf2));
if (ehr2.encoded < 0) { stampaln( "hdr enc failed\n"); }

// MESSAGE
kpm_fill_cuup_throughput(ind_msg2, (const uint8_t*)"GNBCUUP5",
                         bytes_dl, bytes_ul,
                         sst_buf, sd_buf, plmnid_buf);

uint8_t msg_buf2[8192];
asn_enc_rval_t emr2 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
    &ind_msg2, msg_buf2, sizeof(msg_buf2));
if (emr2.encoded < 0) { stampaln( "msg enc failed\n"); }

// E2AP
generate_e2apv2_indication_request_parameterized(
    pdu2, requestorId, instanceId, ranFunctionId, actionId, seqNum,
    hdr_buf2, (int)ehr2.encoded, msg_buf2, (int)emr2.encoded);

e2.encode_and_send_sctp_data(pdu2);
seqNum++;
    uint8_t e2smbuffer2[8192];
    size_t e2smbuffer_size2 = sizeof(e2smbuffer2);

    asn_enc_rval_t er2 = asn_encode_to_buffer(
        opt_cod, ATS_ALIGNED_BASIC_PER,
        &asn_DEF_E2SM_KPM_IndicationMessage,
        ind_msg2, e2smbuffer2, e2smbuffer_size2);

    stampaln( "er encoded is %ld\n", er2.encoded);
    stampaln( "after encoding message\n");

    uint8_t *e2smheader_buf2 = (uint8_t *)"header";

    generate_e2apv2_indication_request_parameterized(
        pdu2, requestorId, instanceId, ranFunctionId, actionId,
        seqNum, e2smheader_buf2, 6, e2smbuffer2, er2.encoded);

    e2.encode_and_send_sctp_data(pdu2);
    seqNum++;

    // === REPORT Message 1: Style1 (PRB per cell) ===
    json::json_pointer p4(std::string("/cellMeasReport/cellMeasReportList/") + std::to_string(i) + "/prbMeasReport/availPrbDl");
    nextPRBBytesDL = all_cells_json[p4].get<int>();
    std::cout << "  PRB Bytes DL " << nextPRBBytesDL << std::endl;

    json::json_pointer p5(std::string("/cellMeasReport/cellMeasReportList/") + std::to_string(i) + "/prbMeasReport/availPrbUl");
    nextPRBBytesUL = all_cells_json[p5].get<int>();
    std::cout << "  PRB Bytes UL " << nextPRBBytesUL << std::endl;

    E2SM_KPM_IndicationMessage_t *ind_msg1 =
        (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
    E2AP_PDU *pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
    if (ind_msg1 == NULL || pdu == NULL) {
      stampaln( "calloc failed for ind_msg1/pdu\n");
      return;
    }

    long fiveqi = 7;
    uint8_t *nrcellid_buf2 = (uint8_t *)"12340";
    long dl_prbs = (long)nextPRBBytesDL;
    long ul_prbs = (long)nextPRBBytesUL;

    //encode_kpm_report_style1_parameterized(ind_msg1, fiveqi, dl_prbs, ul_prbs,sst_buf, sd_buf, plmnid_buf, nrcellid_buf2, &dl_prbs, &ul_prbs);
// HEADER
E2SM_KPM_IndicationHeader_t hdr1;
encode_kpm_ind_hdr_fmt1(&hdr1);
uint8_t hdr_buf1[512];
asn_enc_rval_t ehr1 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,
    &hdr1, hdr_buf1, sizeof(hdr_buf1));
if (ehr1.encoded < 0) { stampaln( "hdr enc failed\n"); }

// MESSAGE
long dl_prbs_long = (long)nextPRBBytesDL;
long ul_prbs_long = (long)nextPRBBytesUL;
long dl_usage = 0; // o calcolalo tu (es. percentuale)
long ul_usage = 0;

kpm_fill_cell_slice_qos_meas(ind_msg1,
                             7 /*fiveqi*/,
                             sst_buf, sd_buf, plmnid_buf,
                             (const uint8_t*)"12340" /*nrcellid*/,
                             &dl_prbs_long, &ul_prbs_long,
                             dl_usage, ul_usage);

uint8_t msg_buf1[8192];
asn_enc_rval_t emr1 = asn_encode_to_buffer(
    NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
    &ind_msg1, msg_buf1, sizeof(msg_buf1));
if (emr1.encoded < 0) { stampaln( "msg enc failed\n"); }

// E2AP
generate_e2apv2_indication_request_parameterized(
    pdu, requestorId, instanceId, ranFunctionId, actionId, seqNum,
    hdr_buf1, (int)ehr1.encoded, msg_buf1, (int)emr1.encoded);

e2.encode_and_send_sctp_data(pdu);
seqNum++;
    uint8_t e2smbuffer[8192];
    size_t e2smbuffer_size = sizeof(e2smbuffer);

    asn_enc_rval_t er = asn_encode_to_buffer(
        opt_cod, ATS_ALIGNED_BASIC_PER,
        &asn_DEF_E2SM_KPM_IndicationMessage,
        ind_msg1, e2smbuffer, e2smbuffer_size);

    stampaln( "er encoded is %ld\n", er.encoded);
    stampaln( "after encoding message\n");

    uint8_t *e2smheader_buf = (uint8_t *)"header";

    stampaln( "About to encode Indication\n");
    generate_e2apv2_indication_request_parameterized(
        pdu, requestorId, instanceId, ranFunctionId, actionId,
        seqNum, e2smheader_buf, 6, e2smbuffer, er.encoded);

    e2.encode_and_send_sctp_data(pdu);
    seqNum++;
  }
}

/* ============================================================
 * SUBSCRIPTION CALLBACK
 * Accetta il primo actionType==REPORT, rifiuta le altre
 * (niente auto; KPM v3 a livello E2SM è gestito dagli encoder)
 * ============================================================ */
void callback_kpm_subscription_request(E2AP_PDU_t *sub_req_pdu)
{
  stampaln("[CALLBACK KPM SUBSCRIPTION REQUEST] Received Subscription Request\n");
  stampaln("Decoding Subscription Request...\n");
  xer_fprint(stdout, &asn_DEF_E2AP_PDU, sub_req_pdu);
  stampln("POST XER Subscription Request\n");
  RICsubscriptionRequest_t orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  int count = orig_req.protocolIEs.list.count;

  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;

  stampaln("Processing Subscription Request...count %d\n", count);

  RICsubscriptionRequest_IEs__value_PR pres;

  long reqRequestorId = -1;
  long reqInstanceId  = -1;
  long reqActionId    = -1;

  std::vector<long> actionIdsAccept;
  std::vector<long> actionIdsReject;

  for (int i = 0; i < count; i++) {
    RICsubscriptionRequest_IEs_t *next_ie = ies[i];
    pres = next_ie->value.present;

    stampaln("next present value %d\n", pres);

    switch (pres) {
      case RICsubscriptionRequest_IEs__value_PR_RICrequestID: {
        RICrequestID_t reqId = next_ie->value.choice.RICrequestID;
        long requestorId = reqId.ricRequestorID;
        long instanceId  = reqId.ricInstanceID;
        stampaln("requestorId %ld\n", requestorId);
        stampaln("instanceId %ld\n", instanceId);
        reqRequestorId = requestorId;
        reqInstanceId  = instanceId;
        break;
      }
      case RICsubscriptionRequest_IEs__value_PR_RANfunctionID: {
        // non usato qui
        break;
      }
      case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
        RICsubscriptionDetails_t subDetails = next_ie->value.choice.RICsubscriptionDetails;
        RICactions_ToBeSetup_List_t actionList = subDetails.ricAction_ToBeSetup_List;

        int actionCount = actionList.list.count;
        stampaln("action count %d\n", actionCount);

        RICaction_ToBeSetup_ItemIEs_t **item_array =
            (RICaction_ToBeSetup_ItemIEs_t **)actionList.list.array;

        int foundAction = 0;

        for (int j = 0; j < actionCount; j++) {
          RICaction_ToBeSetup_ItemIEs_t *next_item = item_array[j];

          RICactionID_t actionId =
              next_item->value.choice.RICaction_ToBeSetup_Item.ricActionID;
          RICactionType_t actionType =
              next_item->value.choice.RICaction_ToBeSetup_Item.ricActionType;

          if (!foundAction && actionType == RICactionType_report) {
            reqActionId = actionId;
            actionIdsAccept.push_back(reqActionId);
            printf("adding accept\n");
            foundAction = 1;
          } else {
            reqActionId = actionId;
            printf("adding reject\n");
            actionIdsReject.push_back(reqActionId);
          }
        }
        break;
      }
      default:
        break;
    }
  }

  stampaln( "After Processing Subscription Request\n");
  stampaln( "requestorId %ld\n", reqRequestorId);
  stampaln( "instanceId %ld\n", reqInstanceId);

  for (size_t i = 0; i < actionIdsAccept.size(); i++) {
    stampaln( "Action ID %zu %ld\n", i, actionIdsAccept.at(i));
  }

  // Costruisci e invia la Subscription Response (success)
  E2AP_PDU *e2ap_pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
  if (e2ap_pdu == NULL) {
    stampaln( "calloc failed for e2ap_pdu\n");
    return;
  }

  long *accept_array = NULL;
  long *reject_array = NULL;
  int accept_size = (int)actionIdsAccept.size();
  int reject_size = (int)actionIdsReject.size();

  if (accept_size > 0) accept_array = &actionIdsAccept[0];
  if (reject_size > 0) reject_array = &actionIdsReject[0];

  generate_e2apv2_subscription_response_success(
      e2ap_pdu, accept_array, reject_array,
      accept_size, reject_size,
      reqRequestorId, reqInstanceId);

  e2.encode_and_send_sctp_data(e2ap_pdu);

  // Avvia il loop di invio REPORT (sincrono in questo esempio)
  long funcId = 1;
  run_report_loop(reqRequestorId, reqInstanceId, funcId, reqActionId);
}

/* ============================================================
 * Helper NR Cell ID → stringa decimale (come nel tuo originale)
 * ============================================================ */
void get_cell_id(uint8_t *nrcellid_buf, char *cid_return_buf)
{
  uint8_t nr0 = (uint8_t)(nrcellid_buf[0] >> 4);
  uint8_t nr1 = (uint8_t)((nrcellid_buf[0] << 4) >> 4);

  uint8_t nr2 = (uint8_t)(nrcellid_buf[1] >> 4);
  uint8_t nr3 = (uint8_t)((nrcellid_buf[1] << 4) >> 4);

  uint8_t nr4 = (uint8_t)(nrcellid_buf[2] >> 4);
  uint8_t nr5 = (uint8_t)((nrcellid_buf[2] << 4) >> 4);

  uint8_t nr6 = (uint8_t)(nrcellid_buf[3] >> 4);
  uint8_t nr7 = (uint8_t)((nrcellid_buf[3] << 4) >> 4);

  uint8_t nr8 = (uint8_t)(nrcellid_buf[4] >> 4);

  std::sprintf(cid_return_buf, "373437%d%d%d%d%d%d%d%d%d",
               nr0, nr1, nr2, nr3, nr4, nr5, nr6, nr7, nr8);
}