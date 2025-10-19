

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
#include <nlohmann/json.hpp>
#include <atomic>
#include <signal.h>
#include <unordered_set>
#include <algorithm>


#include "rc_callbacks.hpp"

extern "C"
{
#include "OCTET_STRING.h"
#include "asn_application.h"
#include "E2AP-PDU.h"
#include "RICsubscriptionRequest.h"
#include "RICsubscriptionResponse.h"
#include "RICactionType.h"
#include "ProtocolIE-Field.h"
#include "ProtocolIE-SingleContainer.h"
#include "InitiatingMessage.h"


#include "E2SM-RC-RANFunctionDefinition.h"
#include "E2SM-RC-IndicationMessage.h"
#include "E2SM-RC-EventTrigger.h"
#include "E2SM-RC-EventTrigger-Format1.h"
#include "E2SM-RC-EventTrigger-Format2.h"
#include "E2SM-RC-EventTrigger-Format3.h"
#include "E2SM-RC-EventTrigger-Format4.h"
#include "E2SM-RC-ActionDefinition-Format1-Item.h"
#include "E2SM-RC-ActionDefinition-Format1.h"
#include "E2SM-RC-ActionDefinition.h"

}

#include "n3iwf_utils.hpp"
#include "n3iwf_data.hpp"

#include "encode_rc.hpp"
#include "encode_e2apv2.hpp"



using namespace std;
using json = nlohmann::json;
static E2Sim e2;
E2SM_RC_RANFunctionDefinition_t *g_rc_ranfunc_def = nullptr;


// ---------------------------------------------------------------------
// Raccoglie gli ID dichiarati in RANFunctionDefinition-Report, opzionalmente
// filtrando per ric_ReportStyle_Type == report_style_type (se >0).
// ---------------------------------------------------------------------
static void collect_declared_report_param_ids(const E2SM_RC_RANFunctionDefinition_t *def,
                                              int report_style_type,                  // 0 = qualunque style
                                              std::unordered_set<long> &out_ids)
{
    out_ids.clear();
    if (!def || !def->ranFunctionDefinition_Report) return;

    const RANFunctionDefinition_Report_t *rep = def->ranFunctionDefinition_Report;
    const auto &lst = rep->ric_ReportStyle_List.list;
    for (int i = 0; i < lst.count; ++i) {
        const RANFunctionDefinition_Report_Item_t *it =
            (const RANFunctionDefinition_Report_Item_t *)lst.array[i];
        if (!it) continue;

        // se richiesto, filtra per style specifico
        if (report_style_type > 0 && (int)it->ric_ReportStyle_Type != report_style_type) {
            continue;
        }

        // lista dei RAN params supportati per quello style
        const auto *rp_list = it->ran_ReportParameters_List;
        if (!rp_list) continue;

        const auto &rp = rp_list->list;
        for (int j = 0; j < rp.count; ++j) {
            const Report_RANParameter_Item_t *p =
                (const Report_RANParameter_Item_t *)rp.array[j];
            if (!p) continue;
            out_ids.insert((long)p->ranParameter_ID);
        }
    }
}

// ---------------------------------------------------------------------
// Verifica: tutti gli 'ids' richiesti compaiono tra quelli dichiarati.
// Se 'out_missing' non è nullptr, riempie i mancanti.
// report_style_type: 0 = qualunque style; >0 = filtra su quello specifico.
// Ritorna true se TUTTI presenti, false se almeno uno manca.
// ---------------------------------------------------------------------
bool all_ids_declared_in_ranFunctionDefinition(const std::vector<long> &ids,int report_style_type,std::vector<long> *out_missing)
{
    if (out_missing) out_missing->clear();
    if (!g_rc_ranfunc_def) return false;

    std::unordered_set<long> declared;
    collect_declared_report_param_ids(g_rc_ranfunc_def, report_style_type, declared);

    bool ok = true;
    for (long id : ids) {
        if (declared.find(id) == declared.end()) {
            ok = false;
            if (out_missing) out_missing->push_back(id);
        }
    }
    return ok;
}


bool decode_rc_event_trigger(RICeventTriggerDefinition_t *et, int *out_format)
{
    if (!et || !et->buf || et->size == 0 || !out_format)
        return false;

    // Decodifica PER non allineata (Packed Encoding Rules) come da E2AP
    asn_dec_rval_t rval;
    E2SM_RC_EventTrigger *decoded = NULL;

    rval = aper_decode_complete(
        NULL,                                 // codec context
        &asn_DEF_E2SM_RC_EventTrigger, // descrittore ASN.1
        (void **)&decoded,
        et->buf,
        et->size
    );

    if (rval.code != RC_OK || decoded == NULL) {
        fprintf(stderr, "[decode_rc_event_trigger] Decode failed: %s (consumed %zu bytes)\n",
                rval.code == RC_FAIL ? "RC_FAIL" : "RC_WMORE",
                rval.consumed);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
        return false;
    }

    // Identifica quale formato è presente
    if (decoded->ric_eventTrigger_formats.present ==
        E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format1) {
        *out_format = 1;
    } else if (decoded->ric_eventTrigger_formats.present ==
               E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format2) {
        *out_format = 2;
    } else if (decoded->ric_eventTrigger_formats.present ==
               E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format3) {
        *out_format = 3;
    } else if (decoded->ric_eventTrigger_formats.present ==
               E2SM_RC_EventTrigger__ric_eventTrigger_formats_PR_eventTrigger_Format4) {
        *out_format = 4;
    } else {
        fprintf(stderr, "[decode_rc_event_trigger] Unknown format in EventTrigger\n");
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
        return false;
    }

    xer_fprint(stdout, &asn_DEF_E2SM_RC_EventTrigger, decoded);

    // Cleanup
    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_EventTrigger, decoded);
    return true;
}


/**
 * Decodifica E2SM-RC Action Definition e accetta solo il Format 1 (REPORT).
 * Estrae la lista di RAN Parameter ID richiesti dalla xApp.
 *
 * @param ad                 OCTET STRING (E2AP) con la Action Definition RC
 * @param out_ids            output: lista di RAN Parameter ID richiesti
 * @return true se decodifica ok e format==1, altrimenti false
 */
bool decode_rc_actiondef_format1(const OCTET_STRING_t *ad,std::vector<long> &out_ids)
{
    out_ids.clear();

    if (!ad || !ad->buf || ad->size == 0) {
        fprintf(stderr, "[decode_rc_actiondef_format1] invalid input\n");
        return false;
    }

    E2SM_RC_ActionDefinition_t *decoded = nullptr;
    asn_dec_rval_t rval = aper_decode_complete(
        /*opt_codec_ctx*/ nullptr,
        &asn_DEF_E2SM_RC_ActionDefinition,
        (void **)&decoded,
        ad->buf,
        ad->size
    );

    if (rval.code != RC_OK || !decoded) {
        fprintf(stderr, "[decode_rc_actiondef_format1] PER decode failed (%s), consumed=%zu\n",
                (rval.code == RC_WMORE ? "RC_WMORE" : "RC_FAIL"), rval.consumed);
        if (decoded) ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    // Verifica che il CHOICE sia il Format 1 (REPORT) come da 9.2.1.2.1. :contentReference[oaicite:3]{index=3}
    auto &fmt = decoded->ric_actionDefinition_formats;
    if (fmt.present != E2SM_RC_ActionDefinition__ric_actionDefinition_formats_PR_actionDefinition_Format1) {
        fprintf(stderr, "[decode_rc_actiondef_format1] not Format1 (present=%d)\n", fmt.present);
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    // Estrai i RAN Parameter ID dalla lista "Parameters to be Reported"
    E2SM_RC_ActionDefinition_Format1 *f1 = fmt.choice.actionDefinition_Format1;
    if (!f1) {
        fprintf(stderr, "[decode_rc_actiondef_format1] NULL Format1 pointer\n");
        ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
        return false;
    }

    auto lst = f1->ranP_ToBeReported_List.list;
    for (int i = 0; i < lst.count; ++i) {
        E2SM_RC_ActionDefinition_Format1_Item *item = (E2SM_RC_ActionDefinition_Format1_Item *)lst.array[i];
        if (!item) continue;

        // Ogni item ha: RAN Parameter ID (obbligatorio) + RAN Parameter Definition (opzionale).
        // "Solo ID dichiarati in RAN Function Definition" sono validi. :contentReference[oaicite:4]{index=4}
        long id = (long)item->ranParameter_ID;
        out_ids.push_back(id);

        // Se ti serve: l'item->ranParameter_Definition (opzionale) ti dice se il parametro è STRUCTURE/LIST
        // e, se non incluso per STRUCTURE/LIST, la spec assume "tutti i sub-parameters supportati". :contentReference[oaicite:5]{index=5}
    }

    ASN_STRUCT_FREE(asn_DEF_E2SM_RC_ActionDefinition, decoded);
    return true;
}


void start_rc_report_pipeline(int et_format, const std::vector<long> &ad_param_ids)
{
    // Implementa qui la logica per avviare il producer di report RC
    stampaln("Starting RC report pipeline with ET format %d and %zu RAN Param IDs\n",
             et_format, ad_param_ids.size());

    // Esempio: stampa gli ID richiesti
    for (long id : ad_param_ids) {
        stampaln("  Requested RAN Parameter ID: %ld\n", id);
    }
}


/* ============================================================
 * SUBSCRIPTION CALLBACK RC 
 * ============================================================ */
void callback_rc_subscription_request(E2AP_PDU_t *sub_req_pdu)
{
  stampaln("[CALLBACK RC SUBSCRIPTION REQUEST] Received Subscription Request\n");
  RICsubscriptionRequest_t &orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;
  int count = orig_req.protocolIEs.list.count;

  long reqRequestorId = -1, reqInstanceId = -1;
  std::vector<long> acceptedActions, rejectedActions;
  bool reject_all = false;

  // --- helper outputs
  int et_format_detected = 0;     // 1..4 per RC (noi vogliamo 4 per UE change)
  int report_style_hint = 0;      // opzionale: dedotto da AD (p.es. 4 per UE Info)
  std::vector<long> ad_param_ids; // RAN Parameter IDs richiesti dal RIC

  // ---- 1) parse IEs
  for (int i = 0; i < count; ++i) {
    RICsubscriptionRequest_IEs_t *ie = ies[i];
    switch (ie->value.present) {
      case RICsubscriptionRequest_IEs__value_PR_RICrequestID: {
        reqRequestorId = ie->value.choice.RICrequestID.ricRequestorID;
        reqInstanceId  = ie->value.choice.RICrequestID.ricInstanceID;
        break;
      }
      case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
        RICsubscriptionDetails_t &sd = ie->value.choice.RICsubscriptionDetails;

        // ---- 1a) decode RC Event Trigger Definition (expect Format 4 per UE change)
        if (!decode_rc_event_trigger(&sd.ricEventTriggerDefinition, &et_format_detected)) {
          stampaln("Invalid RC Event Trigger Definition\n");
          reject_all = true;
          break;
        }

        // ---- 1b) actions loop
        RICactions_ToBeSetup_List_t &alist = sd.ricAction_ToBeSetup_List;
        auto **aitems = (RICaction_ToBeSetup_ItemIEs_t **)alist.list.array;

        for (int j = 0; j < alist.list.count; ++j) {
          auto *it = aitems[j];
          long actionId   = it->value.choice.RICaction_ToBeSetup_Item.ricActionID;
          auto actionType = it->value.choice.RICaction_ToBeSetup_Item.ricActionType;

          // In RC qui gestiamo REPORT; altri tipi (INSERT/POLICY/CONTROL) se vuoi
          if (actionType != RICactionType_report) {
            rejectedActions.push_back(actionId);
            continue;
          }

          OCTET_STRING_t *ad_oct = it->value.choice.RICaction_ToBeSetup_Item.ricActionDefinition;
          std::vector<long> ids_req;

          if (!decode_rc_actiondef_format1(ad_oct, ids_req)) {
            stampaln("ActionDef not RC-Format1 or decode failed\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          // ---- 1c) valida che tutti i RAN Parameter ID richiesti siano stati dichiarati
          if (!all_ids_declared_in_ranFunctionDefinition(ids_req,report_style_hint,nullptr)) {
            stampaln("Requested RAN Parameter not declared in RANFunctionDefinition\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          // (opz) vincoli incrociati ET/ReportStyle: per Style 4 ci aspettiamo IM=2 ecc.
          if (et_format_detected == 4 && report_style_hint != 4) {
            stampaln("ET=UE-Change but ActionDef does not target UE-Info style\n");
            rejectedActions.push_back(actionId);
            continue;
          }

          acceptedActions.push_back(actionId);
          ad_param_ids = std::move(ids_req); // tieni l'ultima (o accumula per multi-action)
        }
        break;
      }
      default:
        break;
    }
  }

  // ---- 2) rispondi
  E2AP_PDU *rsp = (E2AP_PDU *)calloc(1, sizeof(*rsp));

  if (reject_all || acceptedActions.empty()) {
    // E2AP cause tipiche: Event Trigger not supported / Action not supported / Invalid Info Request
    generate_e2apv2_subscription_failure(
        rsp, reqRequestorId, reqInstanceId,
        /*num causes*/ (int)rejectedActions.size(),
        rejectedActions.empty()? NULL : rejectedActions.data(),
        (int)rejectedActions.size());
    e2.encode_and_send_sctp_data(rsp);
    return;
  }

  generate_e2apv2_subscription_response_success(
      rsp,
      acceptedActions.data(),
      rejectedActions.empty()? NULL : rejectedActions.data(),
      (int)acceptedActions.size(),
      (int)rejectedActions.size(),
      reqRequestorId, reqInstanceId,3);
  e2.encode_and_send_sctp_data(rsp);

  // ---- 3) attiva il producer REPORT
  start_rc_report_pipeline(et_format_detected, ad_param_ids);
}



void registerRCfunctionDefinition(E2Sim &e2){
      //Mi occupo di integrare il setup RC qui
  E2SM_RC_RANFunctionDefinition_t *rc_ranfunc_desc =
      (E2SM_RC_RANFunctionDefinition_t *)calloc(1, sizeof(E2SM_RC_RANFunctionDefinition_t));
  if (rc_ranfunc_desc == NULL)
  {
    stampaln("calloc failed for rc_ranfunc_desc\n");
    return;
  }

  // Deve riempire i campi secondo RC v1
  encode_rc_function_definition(rc_ranfunc_desc);

    // Codifica della RANfunction-Description
  const size_t e2smbuffer_size = 16384;
  uint8_t *e2smbuffer_rc = (uint8_t *)calloc(1, e2smbuffer_size);
  if (e2smbuffer_rc == NULL)
  {
    stampaln("calloc failed for e2smbuffer_rc\n");
    return;
  }

  asn_enc_rval_t er_rc = asn_encode_to_buffer(
      NULL, ATS_ALIGNED_BASIC_PER,
      &asn_DEF_E2SM_RC_RANFunctionDefinition,
      rc_ranfunc_desc, e2smbuffer_rc, e2smbuffer_size);

  if (er_rc.encoded < 0)
  {
    stampaln("Encoding failed: %s\n", er_rc.failed_type ? er_rc.failed_type->name : "unknown");
    free(e2smbuffer_rc);
    return;
  }

  // Crea OCTET_STRING per registrazione nel simulatore
  OCTET_STRING_t *ranfunc_ostr_rc = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  if (ranfunc_ostr_rc == NULL)
  {
    stampaln("calloc failed for ranfunc_ostr_rc\n");
    free(e2smbuffer_rc);
    return;
  }
  ranfunc_ostr_rc->buf = (uint8_t *)calloc(1, (size_t)er_rc.encoded);
  ranfunc_ostr_rc->size = (er_rc.encoded > 0) ? (size_t)er_rc.encoded : 0;
  if (ranfunc_ostr_rc->buf == NULL)
  {
    stampaln("calloc failed for ranfunc_ostr_rc->buf\n");
    free(ranfunc_ostr_rc);
    free(e2smbuffer_rc);
    return;
  }
  memcpy(ranfunc_ostr_rc->buf, e2smbuffer_rc, ranfunc_ostr_rc->size);

  e2.register_e2sm(3, ranfunc_ostr_rc);
  e2.register_subscription_callback(3, &callback_rc_subscription_request);
  const char* oid = "1.3.6.1.4.1.53148.1.1.2.3"; 
  PrintableString_t* ranFunctionOIDe = (PrintableString_t*)calloc(1, sizeof(PrintableString_t));
  OCTET_STRING_fromBuf(ranFunctionOIDe, oid, strlen(oid));
  e2.register_e2sm_oid(3, ranFunctionOIDe);
  g_rc_ranfunc_def = rc_ranfunc_desc;
  return;

}