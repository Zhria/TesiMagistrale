/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
# Copyright (c) 2020 Samsung Electronics Co., Ltd. All Rights Reserved.      *
#                                                                            *
# Licensed under the Apache License, Version 2.0 (the "License");            *
# you may not use this file except in compliance with the License.           *
# You may obtain a copy of the License at                                    *
#                                                                            *
#      http://www.apache.org/licenses/LICENSE-2.0                            *
#                                                                            *
# Unless required by applicable law or agreed to in writing, software        *
# distributed under the License is distributed on an "AS IS" BASIS,          *
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.   *
# See the License for the specific language governing permissions and        *
# limitations under the License.                                             *
#                                                                            *
******************************************************************************/

#include <stdio.h>
#include <string.h>
#include <iostream>
#include <unistd.h>

#include <iterator>
#include <vector>

#include "encode_e2apv2.hpp"
#include "n3iwf_data.hpp"

// Se usi un tuo helper per la KPM v3 RANfunction_Description
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
  #include "E2nodeComponentInterfaceNG.h"
  #include "E2nodeComponentInterfaceE1.h"
  #include "INTEGER.h"
  #include "ProtocolIE-ID.h"
}

/* =========================================================================
 * RIC Service Update (E2AP v2) – usa KPM v3: ranFunctionRevision=3, OID settato
 * ========================================================================= */
void generate_e2apv2_service_update(E2AP_PDU_t *e2ap_pdu)
{
  char *ran_function_op_type = getenv("RAN_FUNCTION_OP_TYPE");
  LOG_D("Ran funciton : %s", ran_function_op_type);
  ProtocolIE_ID_t prID;

  if (ran_function_op_type != NULL) {
    if (strcmp(ran_function_op_type, "ADD") == 0) {
      prID = ProtocolIE_ID_id_RANfunctionsAdded;
    } else if (strcmp(ran_function_op_type, "DELETE") == 0) {
      prID = ProtocolIE_ID_id_RANfunctionsDeleted;
    } else {
      prID = ProtocolIE_ID_id_RANfunctionsModified;
    }
  } else {
    prID = ProtocolIE_ID_id_RANfunctionsModified;
  }

  RANfunction_ItemIEs_t *itemIes = (RANfunction_ItemIEs_t *)calloc(1, sizeof(RANfunction_ItemIEs_t));
  itemIes->id = ProtocolIE_ID_id_RANfunction_Item;
  itemIes->criticality = Criticality_reject;
  itemIes->value.present = RANfunction_ItemIEs__value_PR_RANfunction_Item;
  itemIes->value.choice.RANfunction_Item.ranFunctionID = 1;

  /* KPM v3 RANfunction_Description */
  E2SM_KPM_RANfunction_Description_t *ranfunc_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  encode_kpm_function_description(ranfunc_desc);

  uint8_t e2smbuffer[8192];
  size_t e2smbuffer_size = sizeof(e2smbuffer);

  asn_enc_rval_t er =
      asn_encode_to_buffer(NULL,
                           ATS_ALIGNED_BASIC_PER,
                           &asn_DEF_E2SM_KPM_RANfunction_Description,
                           ranfunc_desc, e2smbuffer, e2smbuffer_size);

  fprintf(stderr, "er encoded is %ld\n", er.encoded);
  fprintf(stderr, "after encoding message\n");

  OCTET_STRING_t *ranfuncdesc_str = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  ranfuncdesc_str->buf = (uint8_t *)calloc(1, er.encoded);
  ranfuncdesc_str->size = er.encoded;
  memcpy(ranfuncdesc_str->buf, e2smbuffer, er.encoded);

  itemIes->value.choice.RANfunction_Item.ranFunctionDefinition = *ranfuncdesc_str;
  itemIes->value.choice.RANfunction_Item.ranFunctionRevision = (long)3; // KPM v3

  /* Consigliato: mettere anche l’OID SM nel RANfunction-Item di E2AP */
  const char* oid = "1.3.6.1.4.1.53148.1.1.2.2";
  OCTET_STRING_fromBuf(&itemIes->value.choice.RANfunction_Item.ranFunctionOID,
                       oid, (int)strlen(oid));

  RICserviceUpdate_IEs_t *e2serviceUpdateList = (RICserviceUpdate_IEs_t *)calloc(1, sizeof(RICserviceUpdate_IEs_t));
  e2serviceUpdateList->id = prID;
  e2serviceUpdateList->criticality = Criticality_reject;
  e2serviceUpdateList->value.present = RICserviceUpdate_IEs__value_PR_RANfunctions_List;
  ASN_SEQUENCE_ADD(&e2serviceUpdateList->value.choice.RANfunctions_List.list, itemIes);

  RICserviceUpdate_t *ricServiceUpdate = (RICserviceUpdate_t *)calloc(1, sizeof(RICserviceUpdate_t));
  ASN_SEQUENCE_ADD(&ricServiceUpdate->protocolIEs.list, e2serviceUpdateList);

  InitiatingMessage_t *initiatingMessage = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  initiatingMessage->criticality = Criticality_reject;
  initiatingMessage->procedureCode = ProcedureCode_id_RICserviceUpdate;
  initiatingMessage->value.present = InitiatingMessage__value_PR_RICserviceUpdate;
  initiatingMessage->value.choice.RICserviceUpdate = *ricServiceUpdate;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = initiatingMessage;
}

/* =========================================================================
 * Estrae il RANfunctionID da una RICsubscriptionRequest (E2AP v2)
 * ========================================================================= */
long get_function_id_from_subscription(E2AP_PDU_t *e2ap_pdu)
{
  RICsubscriptionRequest_t orig_req =
      e2ap_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  int count = orig_req.protocolIEs.list.count;
  RICsubscriptionRequest_IEs_t **ies =
      (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;

  fprintf(stderr, "[GetFunctionIDFromSubscription] count %d\n", count);

  RICsubscriptionRequest_IEs__value_PR pres;
  long func_id = -1;

  for (int i = 0; i < count; i++) {
    RICsubscriptionRequest_IEs_t *next_ie = ies[i];
    pres = next_ie->value.present;

    if (pres == RICsubscriptionRequest_IEs__value_PR_RANfunctionID) {
      func_id = next_ie->value.choice.RANfunctionID;
    }
  }
  return func_id;
}

/* =========================================================================
 * E2setupRequest (parametrica) – include RANfunctionsAdded con KPM v3
 * ========================================================================= */
void generate_e2apv2_setup_request_parameterized(E2AP_PDU_t *e2ap_pdu,
                                                 std::vector<ran_func_info> all_funcs)
{
  // ========= GlobalE2node-ID.gNB =========
  GlobalgNB_ID_t *gnb = getGNBStore();

  GlobalE2node_gNB_ID_t *e2gnb = (GlobalE2node_gNB_ID_t*)calloc(1, sizeof(*e2gnb));
  e2gnb->global_gNB_ID = *gnb;

  // CU-UP-ID (>0)
  e2gnb->gNB_CU_UP_ID = (E2AP_IEs_GNB_CU_UP_ID_t*)calloc(1, sizeof(*e2gnb->gNB_CU_UP_ID));
  if (asn_long2INTEGER(e2gnb->gNB_CU_UP_ID, 1) != 0) {
    fprintf(stderr, "asn_long2INTEGER(gNB_CU_UP_ID) failed\n");
  }

  // DU-ID (>0) – opzionale secondo il tuo scenario
  e2gnb->gNB_DU_ID = (E2AP_IEs_GNB_DU_ID_t*)calloc(1, sizeof(*e2gnb->gNB_DU_ID));
  if (asn_long2INTEGER(e2gnb->gNB_DU_ID, 1) != 0) {
    fprintf(stderr, "asn_long2INTEGER(gNB_DU_ID) failed\n");
  }

  GlobalE2node_ID_t *globale2nodeid = (GlobalE2node_ID_t*)calloc(1, sizeof(*globale2nodeid));
  globale2nodeid->present    = GlobalE2node_ID_PR_gNB;
  globale2nodeid->choice.gNB = e2gnb;

  // ========= IE: TransactionID =========
  E2setupRequestIEs_t *ie_txid = (E2setupRequestIEs_t*)calloc(1, sizeof(*ie_txid));
  ie_txid->id                   = ProtocolIE_ID_id_TransactionID;
  ie_txid->criticality          = Criticality_reject;
  ie_txid->value.present        = E2setupRequestIEs__value_PR_TransactionID;
  ie_txid->value.choice.TransactionID = 1;

  // ========= IE: GlobalE2node-ID =========
  E2setupRequestIEs_t *ie_global = (E2setupRequestIEs_t*)calloc(1, sizeof(*ie_global));
  ie_global->id                   = ProtocolIE_ID_id_GlobalE2node_ID;
  ie_global->criticality          = Criticality_reject;
  ie_global->value.present        = E2setupRequestIEs__value_PR_GlobalE2node_ID;
  ie_global->value.choice.GlobalE2node_ID = *globale2nodeid;

  // ========= IE: RANfunctions-Added =========
  E2setupRequestIEs_t *ie_ranf = (E2setupRequestIEs_t*)calloc(1, sizeof(*ie_ranf));
  ASN_STRUCT_RESET(asn_DEF_E2setupRequestIEs, ie_ranf);
  ie_ranf->id            = ProtocolIE_ID_id_RANfunctionsAdded;
  ie_ranf->criticality   = Criticality_reject;
  ie_ranf->value.present = E2setupRequestIEs__value_PR_RANfunctions_List;

  for (size_t i = 0; i < all_funcs.size(); i++) {
    const ran_func_info &rf = all_funcs[i];

    RANfunction_ItemIEs_t *item = (RANfunction_ItemIEs_t*)calloc(1, sizeof(*item));
    item->id            = ProtocolIE_ID_id_RANfunction_Item;
    item->criticality   = Criticality_reject;
    item->value.present = RANfunction_ItemIEs__value_PR_RANfunction_Item;

    // ID & Revision (KPM v3)
    item->value.choice.RANfunction_Item.ranFunctionID       = rf.ranFunctionId;
    item->value.choice.RANfunction_Item.ranFunctionRevision = 3;

    // Definition (deep copy)
    OCTET_STRING_fromBuf(
      &item->value.choice.RANfunction_Item.ranFunctionDefinition,
      (const char*)rf.ranFunctionDesc->buf,
      (int)rf.ranFunctionDesc->size
    );

    // OID (consigliato)
    const char* oid = "1.3.6.1.4.1.53148.1.1.2.2";
    OCTET_STRING_fromBuf(&item->value.choice.RANfunction_Item.ranFunctionOID,
                         oid, (int)strlen(oid));

    ASN_SEQUENCE_ADD(&ie_ranf->value.choice.RANfunctions_List.list, item);
  }

  // ========= IE: E2nodeComponentConfigAddition-List =========
  E2setupRequestIEs_t *ie_add = (E2setupRequestIEs_t*)calloc(1, sizeof(*ie_add));
  ie_add->id            = ProtocolIE_ID_id_E2nodeComponentConfigAddition;
  ie_add->criticality   = Criticality_reject;
  ie_add->value.present = E2setupRequestIEs__value_PR_E2nodeComponentConfigAddition_List;

  E2nodeComponentConfigAddition_ItemIEs_t *add_ie =
      (E2nodeComponentConfigAddition_ItemIEs_t*)calloc(1, sizeof(*add_ie));
  add_ie->id            = ProtocolIE_ID_id_E2nodeComponentConfigAddition_Item;
  add_ie->criticality   = Criticality_reject;
  add_ie->value.present = E2nodeComponentConfigAddition_ItemIEs__value_PR_E2nodeComponentConfigAddition_Item;

  add_ie->value.choice.E2nodeComponentConfigAddition_Item.e2nodeComponentInterfaceType =
      E2nodeComponentInterfaceType_e1;

  E2nodeComponentID_t *compId =
      &add_ie->value.choice.E2nodeComponentConfigAddition_Item.e2nodeComponentID;
  compId->present = E2nodeComponentID_PR_e2nodeComponentInterfaceTypeE1;

  E2nodeComponentInterfaceE1_t *e1 =
      (E2nodeComponentInterfaceE1_t*)calloc(1, sizeof(*e1));
  if (asn_long2INTEGER(&e1->gNB_CU_UP_ID, 1) != 0) {
    fprintf(stderr, "asn_long2INTEGER(gNB_CU_UP_ID) failed\n");
  }
  compId->choice.e2nodeComponentInterfaceTypeE1 = e1;

  OCTET_STRING_fromBuf(
    &add_ie->value.choice.E2nodeComponentConfigAddition_Item
        .e2nodeComponentConfiguration.e2nodeComponentRequestPart,
    "req", 3);

  OCTET_STRING_fromBuf(
    &add_ie->value.choice.E2nodeComponentConfigAddition_Item
        .e2nodeComponentConfiguration.e2nodeComponentResponsePart,
    "rsp", 3);

  ASN_SEQUENCE_ADD(&ie_add->value.choice.E2nodeComponentConfigAddition_List.list, add_ie);

  // ========= Build E2setupRequest =========
  E2setupRequest_t *req = (E2setupRequest_t*)calloc(1, sizeof(*req));
  ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie_txid);
  ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie_global);
  ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie_ranf);
  ASN_SEQUENCE_ADD(&req->protocolIEs.list, ie_add);

  // ========= Wrap nell'InitiatingMessage =========
  InitiatingMessage_t *init = (InitiatingMessage_t*)calloc(1, sizeof(*init));
  init->procedureCode               = ProcedureCode_id_E2setup;
  init->criticality                 = Criticality_reject;
  init->value.present               = InitiatingMessage__value_PR_E2setupRequest;
  init->value.choice.E2setupRequest = *req;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = init;
}

/* =========================================================================
 * E2setupRequest (semplice) – KPM v3 su ranFunctionRevision=3 + OID
 * ========================================================================= */
void generate_e2apv2_setup_request(E2AP_PDU_t *e2ap_pdu)
{
  BIT_STRING_t *gnb_bstring = (BIT_STRING_t *)calloc(1, sizeof(BIT_STRING_t));
  gnb_bstring->buf = (uint8_t *)calloc(1, 4);
  gnb_bstring->size = 4;
  gnb_bstring->buf[0] = 0xB5;
  gnb_bstring->buf[1] = 0xC6;
  gnb_bstring->buf[2] = 0x77;
  gnb_bstring->buf[3] = 0x88;
  gnb_bstring->bits_unused = 3;

  uint8_t *buf2 = (uint8_t *)"747";
  OCTET_STRING_t *plmn = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  plmn->buf = (uint8_t *)calloc(1, 3);
  memcpy(plmn->buf, buf2, 3);
  plmn->size = 3;

  GNB_ID_Choice_t *gnbchoice = (GNB_ID_Choice_t *)calloc(1, sizeof(GNB_ID_Choice_t));
  gnbchoice->present = GNB_ID_Choice_PR_gnb_ID;
  gnbchoice->choice.gnb_ID = *gnb_bstring;

  GlobalgNB_ID_t *gnb = (GlobalgNB_ID_t *)calloc(1, sizeof(GlobalgNB_ID_t));
  gnb->plmn_id = *plmn;
  gnb->gnb_id = *gnbchoice;

  GlobalE2node_gNB_ID_t *e2gnb = (GlobalE2node_gNB_ID_t *)calloc(1, sizeof(GlobalE2node_gNB_ID_t));
  e2gnb->global_gNB_ID = *gnb;

  GlobalE2node_ID_t *globale2nodeid = (GlobalE2node_ID_t *)calloc(1, sizeof(GlobalE2node_ID_t));
  globale2nodeid->present = GlobalE2node_ID_PR_gNB;
  globale2nodeid->choice.gNB = e2gnb;

  E2setupRequestIEs_t *e2setuprid = (E2setupRequestIEs_t *)calloc(1, sizeof(E2setupRequestIEs_t));
  e2setuprid->id = ProtocolIE_ID_id_GlobalE2node_ID;
  e2setuprid->criticality = Criticality_reject;
  e2setuprid->value.present = E2setupRequestIEs__value_PR_GlobalE2node_ID;
  e2setuprid->value.choice.GlobalE2node_ID = *globale2nodeid;

  E2setupRequestIEs_t *ranFlistIEs = (E2setupRequestIEs_t *)calloc(1, sizeof(E2setupRequestIEs_t));
  ASN_STRUCT_RESET(asn_DEF_E2setupRequestIEs, ranFlistIEs);
  ranFlistIEs->criticality = Criticality_reject;
  ranFlistIEs->id = ProtocolIE_ID_id_RANfunctionsAdded;
  ranFlistIEs->value.present = E2setupRequestIEs__value_PR_RANfunctions_List;

  RANfunction_ItemIEs_t *itemIes = (RANfunction_ItemIEs_t *)calloc(1, sizeof(RANfunction_ItemIEs_t));
  itemIes->id = ProtocolIE_ID_id_RANfunction_Item;
  itemIes->criticality = Criticality_reject;
  itemIes->value.present = RANfunction_ItemIEs__value_PR_RANfunction_Item;
  itemIes->value.choice.RANfunction_Item.ranFunctionID = 1;

  // KPM v3 function description
  E2SM_KPM_RANfunction_Description_t *ranfunc_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  encode_kpm_function_description(ranfunc_desc);

  uint8_t e2smbuffer[8192];
  size_t e2smbuffer_size = sizeof(e2smbuffer);

  asn_enc_rval_t er =
      asn_encode_to_buffer(NULL,
                           ATS_ALIGNED_BASIC_PER,
                           &asn_DEF_E2SM_KPM_RANfunction_Description,
                           ranfunc_desc, e2smbuffer, e2smbuffer_size);

  fprintf(stderr, "er encoded is %ld\n", er.encoded);
  fprintf(stderr, "after encoding message\n");

  OCTET_STRING_t *ranfuncdesc_str = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  ranfuncdesc_str->buf = (uint8_t *)calloc(1, er.encoded);
  ranfuncdesc_str->size = er.encoded;
  memcpy(ranfuncdesc_str->buf, e2smbuffer, er.encoded);

  itemIes->value.choice.RANfunction_Item.ranFunctionDefinition = *ranfuncdesc_str;
  itemIes->value.choice.RANfunction_Item.ranFunctionRevision = (long)3; // KPM v3
  // OID (consigliato)
  const char* oid = "1.3.6.1.4.1.53148.1.1.2.2";
  OCTET_STRING_fromBuf(&itemIes->value.choice.RANfunction_Item.ranFunctionOID,
                       oid, (int)strlen(oid));

  ASN_SEQUENCE_ADD(&ranFlistIEs->value.choice.RANfunctions_List.list, itemIes);

  E2setupRequest_t *e2setupreq = (E2setupRequest_t *)calloc(1, sizeof(E2setupRequest_t));
  ASN_SEQUENCE_ADD(&e2setupreq->protocolIEs.list, e2setuprid);
  ASN_SEQUENCE_ADD(&e2setupreq->protocolIEs.list, ranFlistIEs);

  InitiatingMessage_t *initmsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  initmsg->procedureCode = ProcedureCode_id_E2setup;
  initmsg->criticality = Criticality_reject;
  initmsg->value.present = InitiatingMessage__value_PR_E2setupRequest;
  initmsg->value.choice.E2setupRequest = *e2setupreq;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = initmsg;
}

/* =========================================================================
 * RIC Subscription Request – fix memcpy e niente auto
 * ========================================================================= */
void generate_e2apv2_subscription_request(E2AP_PDU *e2ap_pdu)
{
  fprintf(stderr, "[generate_e2apv2_subscription_request] init function\n");

  RICsubscriptionRequest_IEs_t *ricreqid = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
  ASN_STRUCT_RESET(asn_DEF_RICsubscriptionRequest_IEs, ricreqid);

  RICsubscriptionRequest_IEs_t *ricsubrid = (RICsubscriptionRequest_IEs_t *)calloc(1, sizeof(RICsubscriptionRequest_IEs_t));
  ASN_STRUCT_RESET(asn_DEF_RICsubscriptionRequest_IEs, ricsubrid);

  // Event Trigger Definition
  uint8_t *buf2 = (uint8_t *)"SubscriptionTriggers";
  OCTET_STRING_t *triggerdef = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  triggerdef->buf = (uint8_t *)calloc(1, 20);
  triggerdef->size = 20;
  memcpy(triggerdef->buf, buf2, triggerdef->size);

  ProtocolIE_ID_t proto_id = ProtocolIE_ID_id_RICaction_ToBeSetup_Item;

  RICaction_ToBeSetup_ItemIEs__value_PR pres6;
  pres6 = RICaction_ToBeSetup_ItemIEs__value_PR_RICaction_ToBeSetup_Item;

  // Action Definition
  uint8_t *buf5 = (uint8_t *)"ActionDef";
  OCTET_STRING_t *actdef = (OCTET_STRING_t *)calloc(1, sizeof(OCTET_STRING_t));
  actdef->buf = (uint8_t *)calloc(1, 9);
  actdef->size = 9;
  memcpy(actdef->buf, buf5, 9);  // FIX: prima copiava su triggerdef->buf

  RICsubsequentAction_t *sa = (RICsubsequentAction_t *)calloc(1, sizeof(RICsubsequentAction_t));
  ASN_STRUCT_RESET(asn_DEF_RICsubsequentAction, sa);
  sa->ricTimeToWait = RICtimeToWait_w500ms;
  sa->ricSubsequentActionType = RICsubsequentActionType_continue;

  RICaction_ToBeSetup_ItemIEs_t *action_item_ies =
      (RICaction_ToBeSetup_ItemIEs_t *)calloc(1, sizeof(RICaction_ToBeSetup_ItemIEs_t));
  action_item_ies->id = proto_id;
  action_item_ies->criticality = Criticality_reject;
  action_item_ies->value.present = pres6;
  action_item_ies->value.choice.RICaction_ToBeSetup_Item.ricActionID = 5;
  action_item_ies->value.choice.RICaction_ToBeSetup_Item.ricActionType = RICactionType_report;
  action_item_ies->value.choice.RICaction_ToBeSetup_Item.ricActionDefinition = actdef;
  action_item_ies->value.choice.RICaction_ToBeSetup_Item.ricSubsequentAction = sa;

  ricsubrid->id = ProtocolIE_ID_id_RICsubscriptionDetails;
  ricsubrid->criticality = Criticality_reject;
  ricsubrid->value.present = RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails;
  ricsubrid->value.choice.RICsubscriptionDetails.ricEventTriggerDefinition = *triggerdef;
  ASN_SEQUENCE_ADD(&ricsubrid->value.choice.RICsubscriptionDetails.ricAction_ToBeSetup_List.list, action_item_ies);

  ricreqid->id = ProtocolIE_ID_id_RICrequestID;
  ricreqid->criticality = Criticality_reject;
  ricreqid->value.present = RICsubscriptionRequest_IEs__value_PR_RICrequestID;
  ricreqid->value.choice.RICrequestID.ricRequestorID = 22;
  ricreqid->value.choice.RICrequestID.ricInstanceID = 6;

  RICsubscriptionRequest_t *ricsubreq = (RICsubscriptionRequest_t *)calloc(1, sizeof(RICsubscriptionRequest_t));
  ASN_SEQUENCE_ADD(&ricsubreq->protocolIEs.list, ricreqid);
  ASN_SEQUENCE_ADD(&ricsubreq->protocolIEs.list, ricsubrid);

  InitiatingMessage_t *initmsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  initmsg->procedureCode = ProcedureCode_id_RICsubscription;
  initmsg->criticality = Criticality_reject;
  initmsg->value.present = InitiatingMessage__value_PR_RICsubscriptionRequest;
  initmsg->value.choice.RICsubscriptionRequest = *ricsubreq;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = initmsg;

  char *error_buf = (char *)calloc(300, sizeof(char));
  size_t errlen;
  asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu, error_buf, &errlen);
  printf("error length %ld\n", errlen);
  printf("error buf %s\n", error_buf);
}

/* =========================================================================
 * RIC Subscription Response (success) – niente auto
 * ========================================================================= */
void generate_e2apv2_subscription_response_success(E2AP_PDU *e2ap_pdu, long reqActionIdsAccepted[],
                                                   long reqActionIdsRejected[], int accept_size, int reject_size,
                                                   long reqRequestorId, long reqInstanceId)
{
  RICsubscriptionResponse_IEs_t *respricreqid =
      (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
  respricreqid->id = ProtocolIE_ID_id_RICrequestID;
  respricreqid->criticality = Criticality_reject;
  respricreqid->value.present = RICsubscriptionResponse_IEs__value_PR_RICrequestID;
  respricreqid->value.choice.RICrequestID.ricRequestorID = reqRequestorId;
  respricreqid->value.choice.RICrequestID.ricInstanceID = reqInstanceId;

  RICsubscriptionResponse_IEs_t *ricactionadmitted =
      (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
  ricactionadmitted->id = ProtocolIE_ID_id_RICactions_Admitted;
  ricactionadmitted->criticality = Criticality_reject;
  ricactionadmitted->value.present = RICsubscriptionResponse_IEs__value_PR_RICaction_Admitted_List;

  RICaction_Admitted_List_t *admlist =
      (RICaction_Admitted_List_t *)calloc(1, sizeof(RICaction_Admitted_List_t));
  ricactionadmitted->value.choice.RICaction_Admitted_List = *admlist;

  for (int i = 0; i < accept_size; i++) {
    long aid = reqActionIdsAccepted[i];
    RICaction_Admitted_ItemIEs_t *admitie =
        (RICaction_Admitted_ItemIEs_t *)calloc(1, sizeof(RICaction_Admitted_ItemIEs_t));
    admitie->id = ProtocolIE_ID_id_RICaction_Admitted_Item;
    admitie->criticality = Criticality_reject;
    admitie->value.present = RICaction_Admitted_ItemIEs__value_PR_RICaction_Admitted_Item;
    admitie->value.choice.RICaction_Admitted_Item.ricActionID = aid;
    ASN_SEQUENCE_ADD(&ricactionadmitted->value.choice.RICaction_Admitted_List.list, admitie);
  }

  RICsubscriptionResponse_t *ricsubresp = (RICsubscriptionResponse_t *)calloc(1, sizeof(RICsubscriptionResponse_t));
  ASN_SEQUENCE_ADD(&ricsubresp->protocolIEs.list, respricreqid);
  ASN_SEQUENCE_ADD(&ricsubresp->protocolIEs.list, ricactionadmitted);

  if (reject_size > 0) {
    RICsubscriptionResponse_IEs_t *ricactionrejected =
        (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
    ricactionrejected->id = ProtocolIE_ID_id_RICactions_NotAdmitted;
    ricactionrejected->criticality = Criticality_reject;
    ricactionrejected->value.present = RICsubscriptionResponse_IEs__value_PR_RICaction_NotAdmitted_List;

    for (int i = 0; i < reject_size; i++) {
      long aid = reqActionIdsRejected[i];
      RICaction_NotAdmitted_ItemIEs_t *noadmitie =
          (RICaction_NotAdmitted_ItemIEs_t *)calloc(1, sizeof(RICaction_NotAdmitted_ItemIEs_t));
      noadmitie->id = ProtocolIE_ID_id_RICaction_NotAdmitted_Item;
      noadmitie->criticality = Criticality_reject;
      noadmitie->value.present = RICaction_NotAdmitted_ItemIEs__value_PR_RICaction_NotAdmitted_Item;
      noadmitie->value.choice.RICaction_NotAdmitted_Item.ricActionID = aid;
      ASN_SEQUENCE_ADD(&ricactionrejected->value.choice.RICaction_NotAdmitted_List.list, noadmitie);
    }
    ASN_SEQUENCE_ADD(&ricsubresp->protocolIEs.list, ricactionrejected);
  }

  SuccessfulOutcome_t *successoutcome = (SuccessfulOutcome_t *)calloc(1, sizeof(SuccessfulOutcome_t));
  successoutcome->procedureCode = ProcedureCode_id_RICsubscription;
  successoutcome->criticality = Criticality_reject;
  successoutcome->value.present = SuccessfulOutcome__value_PR_RICsubscriptionResponse;
  successoutcome->value.choice.RICsubscriptionResponse = *ricsubresp;

  e2ap_pdu->present = E2AP_PDU_PR_successfulOutcome;
  e2ap_pdu->choice.successfulOutcome = successoutcome;

  char *error_buf = (char *)calloc(300, sizeof(char));
  size_t errlen;
  asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu, error_buf, &errlen);
  printf("error length %ld\n", errlen);
  printf("error buf %s\n", error_buf);
}

/* =========================================================================
 * Subscription Response (costruita a partire dalla Request) – niente auto
 * ========================================================================= */
void generate_e2apv2_subscription_response(E2AP_PDU *e2ap_pdu, E2AP_PDU *sub_req_pdu)
{
  RICsubscriptionRequest_t orig_req =
      sub_req_pdu->choice.initiatingMessage->value.choice.RICsubscriptionRequest;

  int count = orig_req.protocolIEs.list.count;
  RICsubscriptionRequest_IEs_t **ies = (RICsubscriptionRequest_IEs_t **)orig_req.protocolIEs.list.array;

  RICsubscriptionRequest_IEs__value_PR pres;

  long responseRequestorId = -1;
  long responseInstanceId  = -1;
  std::vector<long> actionIds;

  for (int i = 0; i < count; i++) {
    RICsubscriptionRequest_IEs_t *next_ie = ies[i];
    pres = next_ie->value.present;

    switch (pres) {
      case RICsubscriptionRequest_IEs__value_PR_RICrequestID: {
        RICrequestID_t reqId = next_ie->value.choice.RICrequestID;
        responseRequestorId = reqId.ricRequestorID;
        responseInstanceId  = reqId.ricInstanceID;
        break;
      }
      case RICsubscriptionRequest_IEs__value_PR_RICsubscriptionDetails: {
        RICsubscriptionDetails_t subDetails = next_ie->value.choice.RICsubscriptionDetails;
        RICactions_ToBeSetup_List_t actionList = subDetails.ricAction_ToBeSetup_List;

        int actionCount = actionList.list.count;
        RICaction_ToBeSetup_ItemIEs_t **item_array =
            (RICaction_ToBeSetup_ItemIEs_t **)actionList.list.array;

        for (int j = 0; j < actionCount; j++) {
          RICaction_ToBeSetup_ItemIEs_t *next_item = item_array[j];
          RICactionID_t actionId =
              next_item->value.choice.RICaction_ToBeSetup_Item.ricActionID;
          actionIds.push_back(actionId);
        }
        break;
      }
      default:
        break;
    }
  }

  RICsubscriptionResponse_IEs_t *respricreqid =
      (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
  respricreqid->id = ProtocolIE_ID_id_RICrequestID;
  respricreqid->criticality = Criticality_reject;
  respricreqid->value.present = RICsubscriptionResponse_IEs__value_PR_RICrequestID;
  respricreqid->value.choice.RICrequestID.ricRequestorID = responseRequestorId;
  respricreqid->value.choice.RICrequestID.ricInstanceID  = responseInstanceId;

  RICsubscriptionResponse_IEs_t *ricactionadmitted =
      (RICsubscriptionResponse_IEs_t *)calloc(1, sizeof(RICsubscriptionResponse_IEs_t));
  ricactionadmitted->id = ProtocolIE_ID_id_RICactions_Admitted;
  ricactionadmitted->criticality = Criticality_reject;
  ricactionadmitted->value.present = RICsubscriptionResponse_IEs__value_PR_RICaction_Admitted_List;

  RICaction_Admitted_List_t *admlist =
      (RICaction_Admitted_List_t *)calloc(1, sizeof(RICaction_Admitted_List_t));
  ricactionadmitted->value.choice.RICaction_Admitted_List = *admlist;

  for (size_t i = 0; i < actionIds.size(); i++) {
    long aid = actionIds[i];
    RICaction_Admitted_ItemIEs_t *admitie =
        (RICaction_Admitted_ItemIEs_t *)calloc(1, sizeof(RICaction_Admitted_ItemIEs_t));
    admitie->id = ProtocolIE_ID_id_RICaction_Admitted_Item;
    admitie->criticality = Criticality_reject;
    admitie->value.present = RICaction_Admitted_ItemIEs__value_PR_RICaction_Admitted_Item;
    admitie->value.choice.RICaction_Admitted_Item.ricActionID = aid;
    ASN_SEQUENCE_ADD(&ricactionadmitted->value.choice.RICaction_Admitted_List.list, admitie);
  }

  RICsubscriptionResponse_t *ricsubresp = (RICsubscriptionResponse_t *)calloc(1, sizeof(RICsubscriptionResponse_t));
  ASN_SEQUENCE_ADD(&ricsubresp->protocolIEs.list, respricreqid);
  ASN_SEQUENCE_ADD(&ricsubresp->protocolIEs.list, ricactionadmitted);

  SuccessfulOutcome_t *successoutcome = (SuccessfulOutcome_t *)calloc(1, sizeof(SuccessfulOutcome_t));
  successoutcome->procedureCode = ProcedureCode_id_RICsubscription;
  successoutcome->criticality = Criticality_reject;
  successoutcome->value.present = SuccessfulOutcome__value_PR_RICsubscriptionResponse;
  successoutcome->value.choice.RICsubscriptionResponse = *ricsubresp;

  e2ap_pdu->present = E2AP_PDU_PR_successfulOutcome;
  e2ap_pdu->choice.successfulOutcome = successoutcome;

  char *error_buf = (char *)calloc(300, sizeof(char));
  size_t errlen;
  asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu, error_buf, &errlen);
  printf("error length %ld\n", errlen);
  printf("error buf %s\n", error_buf);
}

/* =========================================================================
 * RIC Indication (parametrica) – E2AP livello puro (header/message buffer)
 * ========================================================================= */
void generate_e2apv2_indication_request_parameterized(E2AP_PDU *e2ap_pdu,
                                                      long requestorId,
                                                      long instanceId,
                                                      long ranFunctionId,
                                                      long actionId,
                                                      long seqNum,
                                                      uint8_t *ind_header_buf,
                                                      int header_length,
                                                      uint8_t *ind_message_buf,
                                                      int message_length)
{
  RICindication_IEs_t *ricind_ies  = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies2 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies3 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies4 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies5 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies6 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies7 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));

  ricind_ies->id = ProtocolIE_ID_id_RICrequestID;
  ricind_ies->criticality = Criticality_reject;
  ricind_ies->value.present = RICindication_IEs__value_PR_RICrequestID;
  ricind_ies->value.choice.RICrequestID.ricRequestorID = requestorId;
  ricind_ies->value.choice.RICrequestID.ricInstanceID  = instanceId;

  ricind_ies2->id = ProtocolIE_ID_id_RANfunctionID;
  ricind_ies2->criticality = Criticality_reject;
  ricind_ies2->value.present = RICindication_IEs__value_PR_RANfunctionID;
  ricind_ies2->value.choice.RANfunctionID = ranFunctionId;

  ricind_ies3->id = ProtocolIE_ID_id_RICactionID;
  ricind_ies3->criticality = Criticality_reject;
  ricind_ies3->value.present = RICindication_IEs__value_PR_RICactionID;
  ricind_ies3->value.choice.RICactionID = actionId;

  ricind_ies4->id = ProtocolIE_ID_id_RICindicationSN;
  ricind_ies4->criticality = Criticality_reject;
  ricind_ies4->value.present = RICindication_IEs__value_PR_RICindicationSN;
  ricind_ies4->value.choice.RICindicationSN = seqNum;

  ricind_ies5->id = ProtocolIE_ID_id_RICindicationType;
  ricind_ies5->criticality = Criticality_reject;
  ricind_ies5->value.present = RICindication_IEs__value_PR_RICindicationType;
  ricind_ies5->value.choice.RICindicationType = 0; // REPORT

  ricind_ies6->id = ProtocolIE_ID_id_RICindicationHeader;
  ricind_ies6->criticality = Criticality_reject;
  ricind_ies6->value.present = RICindication_IEs__value_PR_RICindicationHeader;
  ricind_ies6->value.choice.RICindicationHeader.buf  = (uint8_t*)calloc(1, header_length);
  ricind_ies6->value.choice.RICindicationHeader.size = header_length;
  memcpy(ricind_ies6->value.choice.RICindicationHeader.buf, ind_header_buf, header_length);

  ricind_ies7->id = ProtocolIE_ID_id_RICindicationMessage;
  ricind_ies7->criticality = Criticality_reject;
  ricind_ies7->value.present = RICindication_IEs__value_PR_RICindicationMessage;
  ricind_ies7->value.choice.RICindicationMessage.buf  = (uint8_t*)calloc(1, message_length);
  ricind_ies7->value.choice.RICindicationMessage.size = message_length;
  memcpy(ricind_ies7->value.choice.RICindicationMessage.buf, ind_message_buf, message_length);

  RICindication_t *ricindication = (RICindication_t *)calloc(1, sizeof(RICindication_t));
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies2);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies3);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies4);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies5);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies6);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies7);

  InitiatingMessage_t *initmsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  initmsg->procedureCode = ProcedureCode_id_RICindication;
  initmsg->criticality   = Criticality_reject;
  initmsg->value.present = InitiatingMessage__value_PR_RICindication;
  initmsg->value.choice.RICindication = *ricindication;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = initmsg;

  char *error_buf = (char *)calloc(300, sizeof(char));
  size_t errlen;
  asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu, error_buf, &errlen);
  printf("error length %ld\n", errlen);
  printf("error buf %s\n", error_buf);

  xer_fprint(stderr, &asn_DEF_E2AP_PDU, e2ap_pdu);
}

/* =========================================================================
 * RIC Indication (semplice) – dimostrativa
 * ========================================================================= */
void generate_e2apv2_indication_request(E2AP_PDU *e2ap_pdu)
{
  RICindication_IEs_t *ricind_ies7 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));
  RICindication_IEs_t *ricind_ies8 = (RICindication_IEs_t *)calloc(1, sizeof(RICindication_IEs_t));

  ricind_ies7->value.choice.RICindicationMessage.buf = (uint8_t *)calloc(1, 8192);

  // Per demo: usiamo la KPM v3 RANfunction_Description come payload
  E2SM_KPM_RANfunction_Description_t *e2sm_desc =
      (E2SM_KPM_RANfunction_Description_t *)calloc(1, sizeof(E2SM_KPM_RANfunction_Description_t));
  encode_kpm_function_description(e2sm_desc);

  uint8_t e2smbuffer[8192];
  size_t e2smbuffer_size = sizeof(e2smbuffer);

  asn_enc_rval_t er =
      asn_encode_to_buffer(NULL,
                           ATS_ALIGNED_BASIC_PER,
                           &asn_DEF_E2SM_KPM_RANfunction_Description,
                           e2sm_desc, e2smbuffer, e2smbuffer_size);

  fprintf(stderr, "er encoded is %ld\n", er.encoded);
  fprintf(stderr, "after encoding message\n");

  ricind_ies7->id = ProtocolIE_ID_id_RICindicationMessage;
  ricind_ies7->criticality = Criticality_reject;
  ricind_ies7->value.present = RICindication_IEs__value_PR_RICindicationMessage;
  ricind_ies7->value.choice.RICindicationMessage.size = er.encoded;
  memcpy(ricind_ies7->value.choice.RICindicationMessage.buf, e2smbuffer, er.encoded);

  uint8_t *buf4 = (uint8_t *)"cpid";
  ricind_ies8->id = ProtocolIE_ID_id_RICcallProcessID;
  ricind_ies8->criticality = Criticality_reject;
  ricind_ies8->value.present = RICindication_IEs__value_PR_RICcallProcessID;
  ricind_ies8->value.choice.RICcallProcessID.buf = buf4;
  ricind_ies8->value.choice.RICcallProcessID.size = 4;

  RICindication_t *ricindication = (RICindication_t *)calloc(1, sizeof(RICindication_t));
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies7);
  ASN_SEQUENCE_ADD(&ricindication->protocolIEs.list, ricind_ies8);

  InitiatingMessage_t *initmsg = (InitiatingMessage_t *)calloc(1, sizeof(InitiatingMessage_t));
  initmsg->procedureCode = ProcedureCode_id_RICindication;
  initmsg->criticality   = Criticality_reject;
  initmsg->value.present = InitiatingMessage__value_PR_RICindication;
  initmsg->value.choice.RICindication = *ricindication;

  e2ap_pdu->present = E2AP_PDU_PR_initiatingMessage;
  e2ap_pdu->choice.initiatingMessage = initmsg;

  char *error_buf = (char *)calloc(300, sizeof(char));
  size_t errlen;
  asn_check_constraints(&asn_DEF_E2AP_PDU, e2ap_pdu, error_buf, &errlen);
  printf("error length %ld\n", errlen);
  printf("error buf %s\n", error_buf);

  xer_fprint(stderr, &asn_DEF_E2AP_PDU, e2ap_pdu);
}

void generate_e2apv2_indication_response(E2AP_PDU *e2ap_pdu)
{
  (void)e2ap_pdu;
}

/* =========================================================================
 * Helper per costruire un RICserviceUpdate (senza auto, con OID e rev=3)
 * ========================================================================= */
void build_ric_service_update(E2AP_PDU_t* pdu_out,
                              const std::vector<ran_func_info>& funcs,
                              long txid /* es. 2 */)
{
  RICserviceUpdate_t *ru = (RICserviceUpdate_t*)calloc(1, sizeof(*ru));

  // IE: TransactionID
  RICserviceUpdate_IEs_t *ie_tx = (RICserviceUpdate_IEs_t*)calloc(1, sizeof(*ie_tx));
  ie_tx->id = ProtocolIE_ID_id_TransactionID;
  ie_tx->criticality = Criticality_reject;
  ie_tx->value.present = RICserviceUpdate_IEs__value_PR_TransactionID;
  ie_tx->value.choice.TransactionID = txid;
  ASN_SEQUENCE_ADD(&ru->protocolIEs.list, ie_tx);

  // IE: RANfunctions-Added
  RICserviceUpdate_IEs_t *ie_added = (RICserviceUpdate_IEs_t*)calloc(1, sizeof(*ie_added));
  ie_added->id = ProtocolIE_ID_id_RANfunctionsAdded;
  ie_added->criticality = Criticality_reject;
  ie_added->value.present = RICserviceUpdate_IEs__value_PR_RANfunctions_List;

  for (size_t i = 0; i < funcs.size(); i++) {
    const ran_func_info &rf = funcs[i];

    RANfunction_ItemIEs_t *item = (RANfunction_ItemIEs_t*)calloc(1, sizeof(*item));
    item->id = ProtocolIE_ID_id_RANfunction_Item;
    item->criticality = Criticality_reject;
    item->value.present = RANfunction_ItemIEs__value_PR_RANfunction_Item;

    item->value.choice.RANfunction_Item.ranFunctionID       = rf.ranFunctionId;
    item->value.choice.RANfunction_Item.ranFunctionRevision = 3;

    OCTET_STRING_fromBuf(&item->value.choice.RANfunction_Item.ranFunctionDefinition,
                         (const char*)rf.ranFunctionDesc->buf,
                         (int)rf.ranFunctionDesc->size);

    const char* oid = "1.3.6.1.4.1.53148.1.1.2.2";
    OCTET_STRING_fromBuf(&item->value.choice.RANfunction_Item.ranFunctionOID,
                         oid, (int)strlen(oid));

    ASN_SEQUENCE_ADD(&ie_added->value.choice.RANfunctions_List.list, item);
  }
  ASN_SEQUENCE_ADD(&ru->protocolIEs.list, ie_added);

  // Wrapping
  InitiatingMessage_t *init = (InitiatingMessage_t*)calloc(1, sizeof(*init));
  init->procedureCode = ProcedureCode_id_RICserviceUpdate;
  init->criticality = Criticality_reject;
  init->value.present = InitiatingMessage__value_PR_RICserviceUpdate;
  init->value.choice.RICserviceUpdate = *ru;

  pdu_out->present = E2AP_PDU_PR_initiatingMessage;
  pdu_out->choice.initiatingMessage = init;
}
