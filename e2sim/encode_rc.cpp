#include "encode_rc.hpp"



// -----------------------------
// Utility locali
// -----------------------------
static int add_event_trigger_style(RANFunctionDefinition_EventTrigger *ev){
    RIC_EventTriggerStyle_Item_t *et = (RIC_EventTriggerStyle_Item_t*)calloc(1, sizeof(RIC_EventTriggerStyle_Item_t));
    if(!et) return -1;
    et->ric_EventTriggerStyle_Type = 1;                               // scegli tu
    OCTET_STRING_fromBuf(&et->ric_EventTriggerStyle_Name,"Periodic report", strlen("Periodic report"));
    et->ric_EventTriggerFormat_Type = 1;                               // Format-1
    return ASN_SEQUENCE_ADD(&ev->ric_EventTriggerStyle_List.list, et);
}


static int add_report_style(RANFunctionDefinition_Report *rep){
    // Item di report
    RIC_ReportStyle_Item_t *rs =(RIC_ReportStyle_Item_t*)calloc(1, sizeof(RIC_ReportStyle_Item_t));
    if(!rs) return -1;
    rs->ric_ReportStyle_Type = 1;                                      // scegli tu
    OCTET_STRING_fromBuf(&rs->ric_ReportStyle_Name,"RCv1.0.3 N3IWF", strlen("RCv1.0.3 N3IWF"));
    rs->ric_IndicationHeaderFormat_Type  = 1;                          // Header fmt
    rs->ric_IndicationMessageFormat_Type = 1;                          // Message fmt

    // --- measInfoActionList (ALMENO 1 misura!)
    // helper per aggiungere 1 misura con noLabel
    auto add_meas = [&](const char *name)
    {
        MeasurementInfo_Action_Item_t *mi = (MeasurementInfo_Action_Item_t *)calloc(1, sizeof(*mi));
        OCTET_STRING_fromBuf(&mi->measName, name, strlen(name));
        ASN_SEQUENCE_ADD(&rs->measInfo_Action_List.list, mi);
    };

    std::vector<std::string> allowedKPI = getAllowedKPI();
    for (const auto &kpi : allowedKPI)
    {
        add_meas(kpi.c_str());
    }


    return ASN_SEQUENCE_ADD(&rep->ric_ReportStyle_List.list, rs);
}

static int add_control_style(RANFunctionDefinition_Control *ctl){
    RANFunctionDefinition_Control_Item *ci = (RANFunctionDefinition_Control_Item*)calloc(1, sizeof(RANFunctionDefinition_Control_Item));
    ci->ric_ControlStyle_Type = 1;
    OCTET_STRING_fromBuf(&ci->ric_ControlStyle_Name,"RC Control Style 1",strlen("RC Control Style 1"));
    ci->ric_ControlHeaderFormat_Type  = 1;                              // Header fmt
    ci->ric_ControlMessageFormat_Type = 1;                              // Message fmt
    // ci->ric_CallProcessIDFormat_Type = 1;                            // (se richiesto)
    return ASN_SEQUENCE_ADD(&ctl->ric_ControlStyle_List.list, ci);
}


void encode_rc_function_definition(E2SM_RC_RANFunctionDefinition* desc){

  // --- RANfunction-Name / OID / Instance
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_ShortName, "ORAN-E2SM-RC", strlen("ORAN-E2SM-RC"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_Description, "Service Model Radio Control v1.0.3", strlen("Service Model Radio Control v1.0.3"));
  OCTET_STRING_fromBuf(&desc->ranFunction_Name.ranFunction_E2SM_OID, "1.3.6.1.4.1.53148.1.1.2.3", strlen("1.3.6.1.4.1.53148.1.1.2.3"));
  desc->ranFunction_Name.ranFunction_Instance = (long *)calloc(1, sizeof(long));
  *desc->ranFunction_Name.ranFunction_Instance = 3;

  desc->ranFunctionDefinition_EventTrigger=(RANFunctionDefinition_EventTrigger*)calloc(1,sizeof(RANFunctionDefinition_EventTrigger));
  add_event_trigger_style(desc->ranFunctionDefinition_EventTrigger);

  desc->ranFunctionDefinition_Report=(RANFunctionDefinition_Report*)calloc(1,sizeof(RANFunctionDefinition_Report));
  add_report_style(desc->ranFunctionDefinition_Report);

  desc->ranFunctionDefinition_Control = (RANFunctionDefinition_Control*)calloc(1, sizeof(RANFunctionDefinition_Control));
  add_control_style(desc->ranFunctionDefinition_Control);



  return;

}