/*****************************************************************************
#                                                                            *
# Copyright 2019 AT&T Intellectual Property                                  *
# Copyright 2019 Nokia                                                       *
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
#include <unistd.h>
#include <string>
#include <iostream>
#include <fstream>
#include <vector>

#include "e2sim.hpp"
#include "e2sim_defs.h"
#include "e2sim_sctp.hpp"
#include "e2ap_message_handler.hpp"
#include "encode_e2apv1.hpp"
#include "n3iwf_data.hpp"
#include "n3iwf_utils.hpp"


using namespace std;

int client_fd = 0;

void E2Sim::register_subscription_callback(long func_id, SubscriptionCallback cb) {
  printf("%%%%about to register callback for subscription for func_id %ld\n", func_id);
  subscription_callbacks[func_id] = cb;
  
}

SubscriptionCallback E2Sim::get_subscription_callback(long func_id) {
  printf("%%%%we are getting the subscription callback for func id %ld\n", func_id);
  SubscriptionCallback cb = subscription_callbacks[func_id];
  return cb;

}

void E2Sim::register_e2sm(long func_id, OCTET_STRING_t *ostr) {

  //Error conditions:
  //If we already have an entry for func_id
  
  printf("%%%%about to register e2sm func desc for %ld\n", func_id);

  ran_functions_registered[func_id] = ostr;

}


void E2Sim::encode_and_send_sctp_data(E2AP_PDU_t* pdu)
{
  uint8_t       *buf;
  sctp_buffer_t data;

  data.len = e2ap_asn1c_encode_pdu(pdu, &buf);
  memcpy(data.buffer, buf, min(data.len, MAX_SCTP_BUFFER));

  sctp_send_data(client_fd, data);
}


void E2Sim::wait_for_sctp_data()
{
  sctp_buffer_t recv_buf;
  if(sctp_receive_data(client_fd, recv_buf) > 0)
  {
    LOG_I("[SCTP] Received new data of size %d", recv_buf.len);
    e2ap_handle_sctp_data(client_fd, recv_buf, false, this);
  }
}



int E2Sim::run_loop(int argc, char* argv[]){

  stampaln("Start E2 Agent (E2 Simulator)");
  stampaln("Per vedere se funziona la lettura da file");
  stampaln("Apro il file n3iwf");
  GlobalgNB_ID_t *gnb = getGNBStore();
  if (gnb == NULL) {
    fprintf(stderr, "GNB Store is NULL\n");
    return -1;
  }
  

  bool xmlenc = false;

  options_t ops = read_input_options(argc, argv);

  //E2 Agent will automatically restart upon sctp disconnection
  //  int server_fd = sctp_start_server(ops.server_ip, ops.server_port);

  client_fd = sctp_start_client(ops.server_ip, ops.server_port, ops.client_ip);

  if(client_fd == -1) {
    LOG_E("[SCTP] Unable to start SCTP client");
    stampaln("[SCTP] Unable to start SCTP client\n");
    return -1;
  }
  E2AP_PDU_t* pdu_setup = (E2AP_PDU_t*)calloc(1,sizeof(E2AP_PDU));

  stampaln("client_fd SCTP START CLIENT value is %d\n", client_fd);

  std::vector<ran_func_info> all_funcs;

  //Loop through RAN function definitions that are registered

  for (std::pair<long, OCTET_STRING_t*> elem : ran_functions_registered) {
    stampaln("looping through ran func");
    ran_func_info next_func;

    next_func.ranFunctionId = elem.first;
    next_func.ranFunctionDesc = elem.second;
    next_func.ranFunctionRev = (long)2;
    all_funcs.push_back(next_func);
  }
      
  //PRINT All_funcs
  for (const auto& func : all_funcs) {
    printf("RAN Function ID: %ld, Description Size: %ld, Revision: %ld\n",
           func.ranFunctionId, func.ranFunctionDesc->size, func.ranFunctionRev);
  }
  stampaln("After printing all functions\n");

  //Generate E2AP PDU for E2 Setup Request
  stampaln("About to generate E2AP PDU for E2 Setup Request\n");
  stampaln("Number of RAN Functions: %zu\n", all_funcs.size());
  generate_e2apv1_setup_request_parameterized(pdu_setup, all_funcs);

  stampaln("After generating e2setup req ----------------------------------------------------------\n");

  xer_fprint(stderr, &asn_DEF_E2AP_PDU, pdu_setup);

  stampaln("After XER (XML Encoding Rules) Encoding ------------------------------------------------\n");

  auto buffer_size = MAX_SCTP_BUFFER;
  unsigned char buffer[MAX_SCTP_BUFFER];
  
  sctp_buffer_t data;

  char *error_buf = (char*)calloc(300, sizeof(char));
  size_t errlen;

  int checkConstraintE2AP_PDU=asn_check_constraints(&asn_DEF_E2AP_PDU, pdu_setup, error_buf, &errlen);
  
  if (checkConstraintE2AP_PDU != 0) {
    stampaln("E2AP PDU constraints check failed: %s\n", error_buf);
    stampaln("error length %ld\n", errlen);
    stampaln("error buf %s\n", error_buf);
    free(error_buf);
    return -1;
  }


  stampaln("ASN ENCODE TO BUFFER IN ATS_ALIGNED_BASIC_PER\n");
  auto er = asn_encode_to_buffer(nullptr, ATS_ALIGNED_BASIC_PER, &asn_DEF_E2AP_PDU, pdu_setup, buffer, buffer_size);
  if(er.encoded < 0) {
    stampaln("E2AP PDU encoding failed: %s\n", er.failed_type->name);
    free(error_buf);
    return -1;
  }

  data.len = er.encoded;

  stampaln("ASN_ENCODE_TO_BUFFER encoded is %ld length\n",er.encoded);

  memcpy(data.buffer, buffer, er.encoded);

  stampaln("after encoding message\n");

  if(sctp_send_data(client_fd, data) > 0) {
    LOG_I("[SCTP] Sent E2-SETUP-REQUEST");
    stampaln("[SCTP] Sent E2-SETUP-REQUEST\n");

  } else {
    LOG_E("[SCTP] Unable to send E2-SETUP-REQUEST to peer");
    stampaln("[SCTP] Unable to send E2-SETUP-REQUEST to peer\n");
  }

  sctp_buffer_t recv_buf;

  LOG_I("[SCTP] Waiting for SCTP data");

  while(1) //constantly looking for data on SCTP interface
  {
    if(sctp_receive_data(client_fd, recv_buf) <= 0)
      break;

    LOG_I("[SCTP] Received new data of size %d", recv_buf.len);

    e2ap_handle_sctp_data(client_fd, recv_buf, xmlenc, this);
    if (xmlenc) xmlenc = false;
  }

  return 0;
}
