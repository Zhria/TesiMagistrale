#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>   // shutdown()
#include <netinet/sctp.h> // SCTP


extern "C"
{
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


#include "E2SM-RC-RANFunctionDefinition.h"
#include "E2SM-RC-IndicationMessage.h"
}

#include "kpm_callbacks.hpp"
#include "encode_kpm.hpp"
#include "n3iwf_utils.hpp"
#include "encode_rc.hpp"

#include "encode_e2apv2.hpp"

#include <nlohmann/json.hpp>
#include "n3iwf_data.hpp"
#include <atomic>
#include <signal.h>

struct timespec ts; // DEFINIZIONE (una sola volta in tutto l’eseguibile)

using namespace std;
using json = nlohmann::json;
static E2Sim e2;
static std::atomic_bool g_stop{false};
extern int client_fd;  

static void graceful_sctp_close(int fd) {
    // 1) annuncia fine scritture -> kernel invia SHUTDOWN all peer
    shutdown(fd, SHUT_WR);
    // 2) drena eventuali dati in arrivo finché peer chiude
    char buf[2048];
    while (true) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n == 0) break;         // EOF -> SHUTDOWN-ACK/COMPLETE completato
        if (n < 0) break;          // errore -> chiudi comunque
    }
    // 3) chiusura definitiva della socket
    close(fd);
}

static void on_term(int) {
    g_stop = true;

    // (opzionale) manda un E2AP Reset verso il RIC
    // send_e2ap_reset_request(g_sctp_fd);

    // chiudi TUTTE le associazioni SCTP con teardown pulito
    graceful_sctp_close(client_fd);

    // libera risorse (ASN.1, heap, thread join, ecc.)
    // cleanup_asn1();
    // join_threads();

    _exit(0);  // uscita rapida dopo cleanup
}
/* ============================================================
 * MAIN
 * ============================================================ */
int main(int argc, char *argv[])
{
  // pausa per permettere al n3iwf di avviarsi e iniziare a loggare
  std::this_thread::sleep_for(std::chrono::seconds(5));
  stampaln("Starting E2 Simulator with KPM Callbacks (KPM v3)\n");
  clock_gettime(CLOCK_REALTIME, &ts); // Inizializza ts all'avvio

  struct sigaction sa{};
    sa.sa_handler = on_term;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT,  &sa, nullptr);
    sigaction(SIGSEGV, &sa, nullptr);

  // --- RANfunction-Description KPM v3 ---
  E2SM_KPM_RANfunction_Description_t *ranfunc_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  if (ranfunc_desc == NULL)
  {
    stampaln("calloc failed for ranfunc_desc\n");
    return -1;
  }

  // Deve riempire i campi secondo KPM v3
  encode_kpm_function_description(ranfunc_desc);

  // Codifica della RANfunction-Description
  const size_t e2smbuffer_size = 16384;
  uint8_t *e2smbuffer = (uint8_t *)calloc(1, e2smbuffer_size);
  if (e2smbuffer == NULL)
  {
    stampaln("calloc failed for e2smbuffer\n");
    return -1;
  }

  asn_enc_rval_t er = asn_encode_to_buffer(
      NULL, ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_KPM_RANfunction_Description,
      ranfunc_desc, e2smbuffer, e2smbuffer_size);

  if (er.encoded < 0)
  {
    stampaln("Encoding failed: %s\n", er.failed_type ? er.failed_type->name : "unknown");
    free(e2smbuffer);
    return -1;
  }

  // Crea OCTET_STRING per registrazione nel simulatore
  OCTET_STRING_t *ranfunc_ostr = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  if (ranfunc_ostr == NULL)
  {
    stampaln("calloc failed for ranfunc_ostr\n");
    free(e2smbuffer);
    return -1;
  }
  ranfunc_ostr->buf = (uint8_t *)calloc(1, (size_t)er.encoded);
  ranfunc_ostr->size = (er.encoded > 0) ? (size_t)er.encoded : 0;
  if (ranfunc_ostr->buf == NULL)
  {
    stampaln("calloc failed for ranfunc_ostr->buf\n");
    free(ranfunc_ostr);
    free(e2smbuffer);
    return -1;
  }
  memcpy(ranfunc_ostr->buf, e2smbuffer, ranfunc_ostr->size);

  // Registra la SM (FunctionID=2) e callback subscription
  e2.register_e2sm(2, ranfunc_ostr);
  e2.register_subscription_callback(2, &callback_kpm_subscription_request);

  //Mi occupo di integrare il setup RC qui
  E2SM_RC_RANFunctionDefinition_t *rc_ranfunc_desc =
      (E2SM_RC_RANFunctionDefinition_t *)calloc(1, sizeof(E2SM_RC_RANFunctionDefinition_t));
  if (rc_ranfunc_desc == NULL)
  {
    stampaln("calloc failed for rc_ranfunc_desc\n");
    return -1;
  }

  // Deve riempire i campi secondo RC v1
  encode_rc_function_definition(rc_ranfunc_desc);



  // Self-test: decodifica della RANfunction-Description appena encodata
  E2SM_KPM_RANfunction_Description_t *check = NULL;
  asn_dec_rval_t dr = asn_decode(NULL, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_RANfunction_Description, (void **)&check, ranfunc_ostr->buf, ranfunc_ostr->size);
  if (dr.code != RC_OK){
    stampaln("Self-test decode KPM FAILED (%d) at byte %zu\n", dr.code, dr.consumed);
  }
  else {
    stampaln("Self-test decode KPM OK (consumed=%zu)\n", dr.consumed);
  }

  // Non servono più questi buffer locali
  free(e2smbuffer);
  // Avvia loop del simulatore
  e2.run_loop(argc, argv);
  return 0;
}

/* ============================================================
 * REPORT LOOP (genera e invia Indication in base ai file JSON)
 * ============================================================ */
void run_report_loop(long requestorId, long instanceId, long ranFunctionId, long actionId, GranularityPeriod_t granularityPeriod)
{
  stampaln("Starting report loop with period %ld milliseconds\n", granularityPeriod);
  long seqNum = 1;
  asn_codec_ctx_t *opt_cod = NULL; // usare NULL per il contesto (standard)

  // Encoder KPM v3 (RAN Container CU-CP)
  // encode_kpm_report_rancontainer_cucp_parameterized(ind_msg3, plmnid_buf, nrcellid_buf, crnti_buf, serving_buf, neighbor_buf);
  // ----- HEADER v3 (Format1) -----
  for (;;)
  {
    stampaln("Report loop iteration with seqNum %ld\n", seqNum);
    std::this_thread::sleep_for(std::chrono::milliseconds(granularityPeriod));
    std::map<std::string, double> kpi = getMetricsKPM(granularityPeriod);
    E2SM_KPM_IndicationHeader_t hdr;
    encode_kpm_ind_hdr_fmt1(&hdr);

    uint8_t hdr_buf[MAX_SCTP_BUFFER];
    asn_enc_rval_t ehr = asn_encode_to_buffer(
        opt_cod, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationHeader,
        &hdr, hdr_buf, sizeof(hdr_buf));
    if (ehr.encoded < 0)
    {
      stampaln("hdr enc failed\n"); /* handle */
      stampaln("Reason: %s\n", ehr.failed_type ? ehr.failed_type->name : "unknown");
      continue;
    }

    E2SM_KPM_IndicationMessage_t *ind_msg =
        (E2SM_KPM_IndicationMessage_t *)calloc(1, sizeof(E2SM_KPM_IndicationMessage_t));
    // ----- MESSAGE v3: UE RF basic (ex RANcontainer CU-CP) -----

    kpm_fill_ue_rf_basic(ind_msg, kpi);
    stampaln("Encoded KPM indication message (Format1)\n");
    xer_fprint(stderr, &asn_DEF_E2SM_KPM_IndicationMessage, ind_msg);

    char errbuf[512] = {0};
    size_t errlen = sizeof(errbuf);
    int rc = asn_check_constraints(&asn_DEF_E2SM_KPM_IndicationMessage, ind_msg, errbuf, &errlen);
    if (rc != 0) {
      stampaln("Constraint check FAILED for IndicationMessage: %s\n", errbuf[0] ? errbuf : "no details");
      // opzionale: vai in continue
      continue;
    }

    uint8_t msg_buf[8192];
    asn_enc_rval_t emr = asn_encode_to_buffer(opt_cod, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2SM_KPM_IndicationMessage,
        ind_msg, msg_buf, sizeof(msg_buf));
    if (emr.encoded < 0)
    {
      stampaln("msg enc failed\n"); /* handle */
      stampaln("Reason: %s\n", emr.failed_type ? emr.failed_type->name : "unknown");
      continue;
    }
    E2AP_PDU *pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
    if (pdu == NULL)
    {
      stampaln("calloc failed for pdu\n");
      continue;
    }
    // ----- E2AP wrapper -----
    generate_e2apv2_indication_request_parameterized(
        pdu, requestorId, instanceId, ranFunctionId, actionId, seqNum,
        hdr_buf, (int)ehr.encoded, msg_buf, (int)emr.encoded);

    e2.encode_and_send_sctp_data(pdu);
    ASN_STRUCT_FREE(asn_DEF_E2AP_PDU, pdu);
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_IndicationMessage, ind_msg);
    ASN_STRUCT_FREE_CONTENTS_ONLY(asn_DEF_E2SM_KPM_IndicationHeader, &hdr);

    seqNum++;
  }
}

static bool extract_meas_names_from_kpm_actiondef(const OCTET_STRING_t *act_def, std::vector<std::string> &out_meas, GranularityPeriod_t *granularityPeriod)
{
  if (!act_def || !act_def->buf || act_def->size == 0)
    return false;

  E2SM_KPM_ActionDefinition_t *ad = nullptr;
  asn_dec_rval_t dr = aper_decode(
      /*opt_ctx*/ nullptr,
      &asn_DEF_E2SM_KPM_ActionDefinition,
      (void **)&ad,
      act_def->buf, act_def->size,
      /*skip_bits*/ 0, /*unused_bits*/ 0);

  if (dr.code != RC_OK || !ad)
    return false;

  // Accetta solo Format1
  if (ad->actionDefinition_formats.present !=
      E2SM_KPM_ActionDefinition__actionDefinition_formats_PR_actionDefinition_Format1)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, ad);
    return false;
  }

  E2SM_KPM_ActionDefinition_Format1_t *f1 =
      ad->actionDefinition_formats.choice.actionDefinition_Format1;
  if (!f1)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, ad);
    return false;
  }

  int n = f1->measInfoList.list.count;
  if (n <= 0)
  {
    ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, ad);
    return false;
  }

  // array: void** → cast a MeasurementInfoItem_t**
  MeasurementInfoItem_t **arr =
      (MeasurementInfoItem_t **)f1->measInfoList.list.array;

  for (int i = 0; i < n; ++i)
  {
    MeasurementInfoItem_t *mi = arr[i];
    if (!mi)
      continue;

    // measType può essere measName o measID
    // In genere MeasurementType_t è un campo non-pointer
    MeasurementType_t *mt = &mi->measType;

    if (mt->present == MeasurementType_PR_measName && mt->choice.measName.buf && mt->choice.measName.size > 0)
    {
      out_meas.emplace_back((char *)mt->choice.measName.buf, mt->choice.measName.size);
    }
  }

  *granularityPeriod = f1->granulPeriod;

  ASN_STRUCT_FREE(asn_DEF_E2SM_KPM_ActionDefinition, ad);
  return !out_meas.empty();
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
  stampaln("POST XER Subscription Request\n");
  RICsubscriptionRequest_t orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  int count = orig_req.protocolIEs.list.count;

  
  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;

  stampaln("Processing Subscription Request...count %d\n", count);

  RICsubscriptionRequest_IEs__value_PR pres;

  long reqRequestorId = -1;
  long reqInstanceId = -1;
  long reqActionId = -1;

  // std::vector<long> actionIdsAccept;
  // std::vector<long> actionIdsReject;
  std::vector<long> acceptedActions; // actionId
  std::vector<long> rejectedActions; // actionId
  bool any_metric_not_allowed = false;
  GranularityPeriod_t granularityPeriod = 0;

  for (int i = 0; i < count; i++)
  {
    RICsubscriptionRequest_IEs_t *next_ie = ies[i];
    pres = next_ie->value.present;

    stampaln("next present value %d\n", pres);

    switch (pres)
    {
    case RICsubscriptionRequest_IEs__value_PR_RICrequestID:
    {
      RICrequestID_t reqId = next_ie->value.choice.RICrequestID;
      long requestorId = reqId.ricRequestorID;
      long instanceId = reqId.ricInstanceID;
      stampaln("requestorId %ld\n", requestorId);
      stampaln("instanceId %ld\n", instanceId);
      reqRequestorId = requestorId;
      reqInstanceId = instanceId;
      break;
    }
    case RICsubscriptionRequest_IEs__value_PR_RANfunctionID:
    {
      // non usato qui
      break;
    }
    case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails:
    {
      RICsubscriptionDetails_t subDetails = next_ie->value.choice.RICsubscriptionDetails;
      RICactions_ToBeSetup_List_t actionList = subDetails.ricAction_ToBeSetup_List;

      int actionCount = actionList.list.count;
      stampaln("action count %d\n", actionCount);

      RICaction_ToBeSetup_ItemIEs_t **item_array =
          (RICaction_ToBeSetup_ItemIEs_t **)actionList.list.array;

      for (int j = 0; j < actionCount; j++)
      {
        RICaction_ToBeSetup_ItemIEs_t *next_item = item_array[j];

        RICactionID_t actionId =
            next_item->value.choice.RICaction_ToBeSetup_Item.ricActionID;
        RICactionType_t actionType =
            next_item->value.choice.RICaction_ToBeSetup_Item.ricActionType;

        // Consideriamo solo REPORT (coerente con KPM)
        if (actionType != RICactionType_report)
        {
          any_metric_not_allowed = true;
          rejectedActions.push_back(actionId);
          continue;
        }
        OCTET_STRING_t *act_def = next_item->value.choice.RICaction_ToBeSetup_Item.ricActionDefinition;
        std::vector<std::string> meas_names;
        if (!extract_meas_names_from_kpm_actiondef(act_def, meas_names, &granularityPeriod))
        {
          any_metric_not_allowed = true;
          rejectedActions.push_back(actionId);
          continue;
        }

        for (auto &m : meas_names)
        {
          if (std::find(getAllowedKPI().begin(), getAllowedKPI().end(), m) == getAllowedKPI().end())
          {
            any_metric_not_allowed = true;
            rejectedActions.push_back(actionId);
          }
        }
        if (!any_metric_not_allowed)
        {
          acceptedActions.push_back(actionId);
          reqActionId = actionId; // salva l'ultimo actionId accettato
        }
      }
      break;
    }
    default:
      break;
    }
  }

  stampaln("After Processing Subscription Request\n");
  stampaln("requestorId %ld\n", reqRequestorId);
  stampaln("instanceId %ld\n", reqInstanceId);

  // Costruisci e invia la Subscription Response (success)
  E2AP_PDU *e2ap_pdu = (E2AP_PDU *)calloc(1, sizeof(E2AP_PDU));
  if (e2ap_pdu == NULL)
  {
    stampaln("calloc failed for e2ap_pdu\n");
    return;
  }

  long *accept_array = acceptedActions.empty()?NULL: acceptedActions.data();
  long *reject_array = rejectedActions.empty()?NULL: rejectedActions.data();
  int accept_size = (int)acceptedActions.size();
  int reject_size = (int)rejectedActions.size();

  // Se c'è almeno un azione rifiutata, rifiuto tutto
  if (any_metric_not_allowed)
  {
    stampaln("At least one action not allowed, rejecting subscription\n");
    generate_e2apv2_subscription_failure(e2ap_pdu, reqRequestorId, reqInstanceId, 2, reject_array, reject_size);
    e2.encode_and_send_sctp_data(e2ap_pdu);
    return;
  }

  stampaln("All actions allowed, accepting subscription\n");
  generate_e2apv2_subscription_response_success(e2ap_pdu, accept_array, reject_array, accept_size, reject_size, reqRequestorId, reqInstanceId, 2);
  e2.encode_and_send_sctp_data(e2ap_pdu);

  // Avvia il loop di invio REPORT (sincrono in questo esempio)
  long funcId = 2; // KPM
  run_report_loop(reqRequestorId, reqInstanceId, funcId, reqActionId, granularityPeriod);
}
