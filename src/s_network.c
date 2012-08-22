/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Hayoon Ko <hayoon.ko@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_network.h>
#include <co_ps.h>
#include <server.h>
#include <storage.h>
#include <util.h>
#include <at.h>

#include "s_common.h"
#include "s_network.h"

#define AT_CREG_STAT_NOT_REG	0 /* not registered, MT is not currently searching a new operator to register to */
#define AT_CREG_STAT_REG_HOME	1 /* registered, home network */
#define AT_CREG_STAT_SEARCHING	2 /* not registered, but MT is currently searching a new operator to register to */
#define AT_CREG_STAT_REG_DENIED	3 /* registration denied */
#define AT_CREG_STAT_UNKNOWN	4 /* unknown */
#define AT_CREG_STAT_REG_ROAM	5 /* registered, roaming */

#define AT_COPS_MODE_AUTOMATIC	0 /* automatic (<oper> field is ignored) */
#define AT_COPS_MODE_MANUAL	1 /* manual (<oper> field shall be present, and <AcT> optionally) */
#define AT_COPS_MODE_DEREGISTER	2 /* deregister from network */
#define AT_COPS_MODE_SET_ONLY	3 /* set only <format> */
#define AT_COPS_MODE_MANUAL_AUTOMATIC 4 /*automatic - manual*/

#define AT_COPS_FORMAT_LONG_ALPHANUMERIC	0 /* long format alphanumeric <oper> */
#define AT_COPS_FORMAT_SHORT_ALPHANUMERIC	1 /* short format alphanumeric <oper> */
#define AT_COPS_FORMAT_NUMERIC			2 /* numeric <oper> */

#define AT_COPS_ACT_GSM			0	/* GSM */
#define AT_COPS_ACT_GSM_COMPACT		1	/* GSM Compact */
#define AT_COPS_ACT_UTRAN		2	/* UTRAN */
#define AT_COPS_ACT_GSM_EGPRS		3	/* GSM w/EGPRS */
#define AT_COPS_ACT_UTRAN_HSDPA		4	/* UTRAN w/HSDPA */
#define AT_COPS_ACT_UTRAN_HSUPA		5	/* UTRAN w/HSUPA */
#define AT_COPS_ACT_UTRAN_HSDPA_HSUPA	6	/* UTRAN w/HSDPA and HSUPA */
#define AT_COPS_ACT_E_UTRAN		7	/* E-UTRAN */

#define AT_XBANDSEL_0 0 
#define AT_XBANDSEL_1800 1800
#define AT_XBANDSEL_1900 1900
#define AT_XBANDSEL_850 850
#define AT_XBANDSEL_450 450
#define AT_XBANDSEL_480 480
#define AT_XBANDSEL_750 750
#define AT_XBANDSEL_380 380
#define AT_XBANDSEL_410 410

#define MAX_NETWORKS_PREF_PLMN_SUPPORT 150
#define MAX_NETWORKS_MANUAL_SEARCH_SUPPORT 20

static unsigned int lookup_tbl_net_status[] = {
		[AT_CREG_STAT_NOT_REG] = NETWORK_SERVICE_DOMAIN_STATUS_NO,
		[AT_CREG_STAT_REG_HOME] = NETWORK_SERVICE_DOMAIN_STATUS_FULL,
		[AT_CREG_STAT_SEARCHING] = NETWORK_SERVICE_DOMAIN_STATUS_SEARCH,
		[AT_CREG_STAT_REG_DENIED] = NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY,
		[AT_CREG_STAT_UNKNOWN] = NETWORK_SERVICE_DOMAIN_STATUS_NO,
		[AT_CREG_STAT_REG_ROAM] = NETWORK_SERVICE_DOMAIN_STATUS_FULL,
};

static unsigned int lookup_tbl_access_technology[] = {
	[AT_COPS_ACT_GSM]		= NETWORK_ACT_GSM,
	[AT_COPS_ACT_GSM_COMPACT]	= NETWORK_ACT_GSM,
	[AT_COPS_ACT_UTRAN]		= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_GSM_EGPRS]		= NETWORK_ACT_EGPRS,
	[AT_COPS_ACT_UTRAN_HSDPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSUPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_UTRAN_HSDPA_HSUPA]	= NETWORK_ACT_UTRAN,
	[AT_COPS_ACT_E_UTRAN]		= NETWORK_ACT_GSM_UTRAN,
};

static gboolean get_serving_network(CoreObject *o, UserRequest *ur);


static void on_confirmation_network_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("on_confirmation_modem_message_send - msg out from queue.\n");

	if (result == FALSE) {
		/* Fail */
		dbg("SEND FAIL");
	}
	else {
		dbg("SEND OK");
	}
}

static void nwk_prepare_and_send_pending_request(TcorePlugin *plugin, char *co_name, const char *at_cmd, const char* prefix,enum tcore_at_command_type at_cmd_type, TcorePendingResponseCallback callback)
{
	TcoreATRequest *req = NULL;
	TcoreHal *hal;
	CoreObject *o= NULL;
	TcorePending *pending = NULL;
	TReturn ret;
	
	o = tcore_plugin_ref_core_object(plugin, co_name);
	hal = tcore_object_get_hal(o);
	
	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(at_cmd, prefix, at_cmd_type);

	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));

	tcore_pending_set_request_data(pending, 0, req);
	tcore_pending_set_response_callback(pending, callback, req->cmd);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);

	ret = tcore_hal_send_request(hal, pending);
	return;
}


static void _insert_mcc_mnc_oper_list(TcorePlugin *p, CoreObject *o)
{
	Server *s;
	Storage *strg;
	void *handle;
	char query[255] = {	0, };
	GHashTableIter iter;
	gpointer key, value;
	GHashTable *result = NULL, *row = NULL;
	struct tcore_network_operator_info *noi = NULL;
	int count = 0;

	s = tcore_plugin_ref_server(p);
	strg = tcore_server_find_storage(s, "database");

	handle = tcore_storage_create_handle(strg, "/opt/dbspace/.mcc_mnc_oper_list.db");
	if (!handle) {
		dbg("fail to create database handle");
		return;
	}

	snprintf(query, 255, "select country, mcc, mnc, oper from mcc_mnc_oper_list");

	result = g_hash_table_new_full(g_str_hash, g_str_equal, NULL,
			(GDestroyNotify) g_hash_table_destroy);

	tcore_storage_read_query_database(strg, handle, query, NULL, result, 4);

	g_hash_table_iter_init(&iter, result);
	while (g_hash_table_iter_next(&iter, &key, &value) == TRUE) {
		row = value;

		noi = calloc(sizeof(struct tcore_network_operator_info), 1);

		snprintf(noi->mcc, 4, "%s", (char *)g_hash_table_lookup(row, "1"));
		snprintf(noi->mnc, 4, "%s",  (char *)g_hash_table_lookup(row, "2"));
		snprintf(noi->name, 41, "%s",  (char *)g_hash_table_lookup(row, "3"));
		snprintf(noi->country, 4, "%s",  (char *)g_hash_table_lookup(row, "0"));

		tcore_network_operator_info_add(o, noi);

		count++;
	}

	dbg("count = %d", count);

	g_hash_table_destroy(result);

	tcore_storage_remove_handle(strg, handle);
}

static enum telephony_network_service_type _get_service_type(enum telephony_network_service_type prev_type,
		int domain, int act, int cs_status, int ps_status)
{
	enum telephony_network_service_type ret;

	ret = prev_type;

	switch (act) {
		case NETWORK_ACT_UNKNOWN:
			ret = NETWORK_SERVICE_TYPE_UNKNOWN;
			break;

		case NETWORK_ACT_GSM:
			if (prev_type == NETWORK_SERVICE_TYPE_2_5G_EDGE && domain == NETWORK_SERVICE_DOMAIN_CS)
				ret = NETWORK_SERVICE_TYPE_2_5G_EDGE;
			else
				ret = NETWORK_SERVICE_TYPE_2G;
			break;

		case NETWORK_ACT_EGPRS:
			return NETWORK_SERVICE_TYPE_2_5G_EDGE;
			break;

		case NETWORK_ACT_UMTS:
			ret = NETWORK_SERVICE_TYPE_3G;
			break;

	}

	if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_NO && ps_status == NETWORK_SERVICE_DOMAIN_STATUS_NO) {
		ret = NETWORK_SERVICE_TYPE_NO_SERVICE;
	}
	else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_SEARCH) 
	{
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) 
		{
			/* no change */
		}
		else 
		{
			ret = NETWORK_SERVICE_TYPE_SEARCH;
		}
	}
	else if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_EMERGENCY) 
	{
		if (cs_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL || ps_status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) 
		{
			/* no change */
		}
		else 
		{
			ret = NETWORK_SERVICE_TYPE_EMERGENCY;
		}
	}

	return ret;
}

static void _ps_set(TcorePlugin *p, int status)
{
	GSList *co_list = NULL;

	co_list = tcore_plugin_get_core_objects_bytype(p, CORE_OBJECT_TYPE_PS);
	do {
		CoreObject *o = NULL;
		o = (CoreObject *) co_list->data;
		if (!o)
			break;

		if (status == NETWORK_SERVICE_DOMAIN_STATUS_FULL) {
			tcore_ps_set_online(o, TRUE);
		}
		else {
			tcore_ps_set_online(o, FALSE);
		}
	} while ((co_list = g_slist_next(co_list)));

	g_slist_free(co_list);
}

static void on_timeout_search_network(TcorePending *p, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_search resp;

	dbg("TIMEOUT !!!!! pending=%p", p);

	memset(&resp, 0, sizeof(struct tresp_network_search));

	resp.list_count = 0;

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_SEARCH, sizeof(struct tresp_network_search), &resp);
	}
}

static void on_response_set_plmn_selection_mode(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	const TcoreATResponse *atResp = data;
       //GSList *tokens = NULL;
	//char * line = NULL;
	struct tresp_network_set_plmn_selection_mode resp = {0};
	
	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");
		resp.result = TCORE_RETURN_SUCCESS;
	}
	else
	{
		dbg("RESPONSE NOK");
		resp.result = TCORE_RETURN_FAILURE;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_SET_PLMN_SELECTION_MODE, sizeof(struct tresp_network_set_plmn_selection_mode), &resp);
	}
}

static void on_response_get_plmn_selection_mode(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_get_plmn_selection_mode resp = {0};
	const TcoreATResponse *atResp = data;
       GSList *tokens = NULL;
	char * line = NULL;
	int mode = 0;

	resp.result = TCORE_RETURN_FAILURE;

	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");
		/* Format of output 
		+COPS: <mode>[,<format>,<oper>[,< AcT>]]
		*/
		
		if(atResp->lines)
			{
				line = (char*)atResp->lines->data;
				tokens = tcore_at_tok_new(line);
				if (g_slist_length(tokens) < 1){
				msg("invalid message");
				goto OUT;
				}
				mode = atoi(tcore_at_tok_nth(tokens, 0));
				dbg("mode = %d", mode);
			
				switch(mode) {
					case AT_COPS_MODE_AUTOMATIC:
						resp.mode = NETWORK_SELECT_MODE_GLOBAL_AUTOMATIC;
						break;
					case AT_COPS_MODE_MANUAL:
					case AT_COPS_MODE_MANUAL_AUTOMATIC:
						resp.mode = NETWORK_SELECT_MODE_GSM_MANUAL;
						break;
					case AT_COPS_MODE_DEREGISTER:
					case AT_COPS_MODE_SET_ONLY:
						resp.result = TCORE_RETURN_FAILURE;
					goto OUT;
				}
			resp.result = TCORE_RETURN_SUCCESS;
			}
	}
	else
	{
		dbg("RESPONSE NOK");
		resp.result = TCORE_RETURN_FAILURE;
	}

OUT:
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_GET_PLMN_SELECTION_MODE, sizeof(struct tresp_network_get_plmn_selection_mode), &resp);
	}

	if(tokens != NULL)
		tcore_at_tok_free(tokens);

	return;

}

static void on_response_search_network(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_search resp;
	int i = 0, ctr =0;
	char* line=NULL;
	const TcoreATResponse *atResp = data;
       GSList *tokens = NULL;
       GSList *network_token = NULL;
	int AcT=0 , stat = 0;
	char* cp_plmn =NULL;
	char* temp_plmn_info =NULL;
	char *pResp = NULL;
	int num_network_avail = 0;

	memset(&resp, 0, sizeof(struct tresp_network_search));
	resp.result = TCORE_RETURN_FAILURE;
	resp.list_count = 0;

	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");
		if(atResp->lines) {
			line = (char*)atResp->lines->data;
			tokens = tcore_at_tok_new(line);
			num_network_avail = g_slist_length(tokens);
			dbg(" length of tokens is %d\n", num_network_avail);
			if (num_network_avail < 1) {
				msg("invalid message");
				goto OUT;
			}
		}
					
		resp.result = TCORE_RETURN_SUCCESS;
		/*
		 *	+COPS: [list of supported (<stat>,long alphanumeric <oper>,short alphanumeric <oper>,numeric <oper>[,<AcT>])s]
		 *	       [,,(list of supported <mode>s),(list of supported <format>s)]
		*/
			
		/* (2,"IND airtel","airtel","40445",2,),(1,"IND airtel","airtel","40445",0,),(3,"TATA DOCOMO","TATA DO","405034",2,) */
			
		for(i=0; ((i<num_network_avail) && (i<MAX_NETWORKS_MANUAL_SEARCH_SUPPORT)); i++)
			{
			/* (2,"IND airtel","airtel","40445",2,) */
			network_token = tcore_at_tok_new(g_slist_nth_data(tokens, i));

			pResp = (tcore_at_tok_nth(network_token, 0));
			if(pResp != NULL){
				dbg("status : %s",pResp);
				resp.list[i].status = (enum telephony_network_plmn_status)atoi(pResp);
			}

			if (pResp = (tcore_at_tok_nth(network_token, 1)))
			{ /* Long Aplha name */
				dbg("Long Aplha name : %s",pResp);
				
				if(strlen(pResp) > 0)
					/* Strip off starting quote & ending quote */
					strncpy(resp.list[i].name, pResp+1, strlen(pResp)-2);
			}
			else if (pResp = (tcore_at_tok_nth(network_token, 2)))
			{ 
				dbg("Short Aplha name : %s",pResp);
				/* Short Aplha name */
				/* Strip off starting quote & ending quote */
				if(strlen(pResp) > 0)
					strncpy(resp.list[i].name, pResp+1, strlen(pResp)-2);
			}

			/* PLMN ID */
			pResp = tcore_at_tok_nth(network_token, 3);
			if(pResp != NULL)
			{
				dbg("PLMN ID : %s",pResp);
				if(strlen(pResp) > 0){
					temp_plmn_info = malloc((strlen(pResp) - 2)+1); /* 1 extra character for NULL storage */
					memset(temp_plmn_info, 0x00, strlen(pResp) -2+1);
					
					/* Strip off starting quotes & ending quotes */
					strncpy(temp_plmn_info, pResp+1, strlen(pResp)-2);
				}
			}

			/* Decode PLMN ID from Hexa String to Hexa bytes */
			//cp_plmn = util_hexStringToBytes(temp_plmn_info);
		
			memcpy(resp.list[i].plmn, temp_plmn_info, 6);
					if (resp.list[i].plmn[5] == '#')
						resp.list[i].plmn[5] = '\0';

			/* Parse Access Technology */
			if(pResp = tcore_at_tok_nth(tokens, 4))
			{
				if(strlen(pResp) > 0){
					AcT = atoi(pResp);
				
					if (0 == AcT)
						resp.list[i].act = NETWORK_ACT_GSM;
					else if(2 == AcT)
						resp.list[i].act = NETWORK_ACT_UMTS;
				}
			}

			dbg("Operator [%d] :: stat = %d, Name =%s, plmnId = %s, AcT=%d\n", resp.list_count, resp.list[i].status, resp.list[i].name, resp.list[i].plmn, AcT);
			resp.list_count++;

			tcore_at_tok_free(network_token);
			free(temp_plmn_info);
			//free(cp_plmn);
		}
	}
	else
	{
			dbg("RESPONSE NOK");
			resp.result = TCORE_RETURN_FAILURE;
	}

OUT:
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_SEARCH, sizeof(struct tresp_network_search), &resp);
	}
	tcore_at_tok_free(tokens);
	return;
}

static void on_response_set_service_domain(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_get_service_domain(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_set_band(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	struct tresp_network_set_band resp;

	char* line=NULL;
	const TcoreATResponse *atResp = data;

	dbg("On Response Set Band");
	if(atResp->success > 0)
	{
		dbg("Response OK");
		resp.result = TCORE_RETURN_SUCCESS;
	}else
	{
		dbg("Response NOK");
		resp.result = TCORE_RETURN_FAILURE;
	}

	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_SET_BAND, sizeof(struct tresp_network_set_band), &resp);
	}
}

static void on_response_get_band(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_set_preferred_plmn(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_get_preferred_plmn(TcorePending *p, int data_len, const void *data, void *user_data)
{
	UserRequest *ur;
	int i = 0, ctr =0;
	char* line=NULL;
	const TcoreATResponse *atResp = data;
       GSList *tokens = NULL;
	char* cp_plmn =NULL;
	char temp_plmn_info[17] = {0};
	char *pResp = NULL;
	int num_network_avail = 0;
	int plmn_format = 0;
	
	struct tresp_network_get_preferred_plmn resp = {0};
	int total_lines = 0;
	int GSM_AcT2 = 0, GSM_Compact_AcT2= 0, UTRAN_AcT2 = 0;

	dbg("Entry");

	if(atResp->success > 0)
	{
		dbg("RESPONSE OK");
		if(atResp->lines) {
			total_lines = g_slist_length(atResp->lines);
			dbg("Total number of network present in Preferred PLMN list is %d\n", total_lines);

			if (total_lines < 1) {
				msg("invalid message");
				goto OUT;
			}

			if (total_lines >= MAX_NETWORKS_PREF_PLMN_SUPPORT)
				total_lines = MAX_NETWORKS_PREF_PLMN_SUPPORT;
			
/*
+COPL: <index1>,<format>,<oper1>[,<GSM_AcT1>,<GSM_Compact_AcT1>,<UTRAN_AcT1>,<E-UTRAN_AcT1>] [<CR><LF>
+CPOL: <index2>,<format>,<oper2>[,<GSM_AcT2>,<GSM_Compact_AcT2>,<UTRAN_AcT2>,<E-UTRAN_AcT2>]
*/

			resp.result = TCORE_RETURN_SUCCESS;

			for (i=0; i<total_lines; i++) {
				/* Take each line response at a time & parse it */
				line = tcore_at_tok_nth(atResp->lines, i);
				tokens = tcore_at_tok_new(line);

				/* <index2>,<format>,<oper2>[,<GSM_AcT2>,<GSM_Compact_AcT2>,<UTRAN_AcT2>,<E-UTRAN_AcT2>] */

				/* EF Index */
				if (pResp = tcore_at_tok_nth(tokens, 0))
				{
					dbg("Index : %s",pResp);					
					resp.list[i].ef_index = atoi(pResp);
				}
				/* Format */
				if(pResp = tcore_at_tok_nth(tokens, 1))
				{
					dbg("format : %s",pResp);
					plmn_format = atoi(pResp);
				}

				/* Operator PLMN ID */
				if(pResp = tcore_at_tok_nth(tokens, 2));
				{
					dbg("plmn ID : %s",pResp);

					if(strlen(pResp) > 0){
						strncmp(temp_plmn_info, pResp+1, strlen(pResp)-2);
					
						//Get only PLMN ID
						if (plmn_format == 2)
						{
							//cp_plmn = util_hexStringToBytes(temp_plmn_info);
						
							if (strncmp((char *)temp_plmn_info, "000000", 6) == 0)
								continue;
				
							memcpy(resp.list[i].plmn, temp_plmn_info, 6);
							if (resp.list[i].plmn[5] == '#')
								resp.list[i].plmn[5] = '\0';

							//free(cp_plmn);
						}
					}
				}

				if(pResp = tcore_at_tok_nth(tokens, 3)){
					dbg("GSM_AcT2  : %s",pResp);
					GSM_AcT2 = atoi(pResp);
				}
					
				if(pResp = tcore_at_tok_nth(tokens, 4)){
					dbg("GSM_Compact AcT2  : %s",pResp);
					GSM_Compact_AcT2 = atoi(pResp);
				}
	
				if(pResp = tcore_at_tok_nth(tokens, 5)){
					dbg("UTRAN_AcT2  : %s",pResp);
					UTRAN_AcT2 = atoi(pResp);
				}

				if(UTRAN_AcT2 && (GSM_AcT2 ||GSM_Compact_AcT2))
					resp.list[i].act = NETWORK_ACT_GSM_UTRAN;
				else if (UTRAN_AcT2)
					resp.list[i].act = NETWORK_ACT_UMTS;
				else if (GSM_AcT2 || GSM_Compact_AcT2)
					resp.list[i].act = NETWORK_ACT_GPRS;

				(resp.list_count)++;

				tcore_at_tok_free(tokens);
			}
		}
	}
OUT:
	ur = tcore_pending_ref_user_request(p);
	if (ur) {
		tcore_user_request_send_response(ur, TRESP_NETWORK_GET_PREFERRED_PLMN, sizeof(struct tresp_network_get_preferred_plmn), &resp);
	}
	dbg("Exit");
	return;
}

static void on_response_set_order(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_get_order(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_set_power_on_attach(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_get_power_on_attach(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}

static void on_response_set_cancel_manual_search(TcorePending *p, int data_len, const void *data, void *user_data)
{
	dbg("Entry");

	dbg("Exit");
	return;
}


static void on_response_get_serving_network(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse* resp = data;
	UserRequest *ur;
	struct tresp_network_get_serving_network Tresp = {0};
	char plmn[7] = {0};
	char *long_plmn_name, *short_plmn_name = NULL;
	CoreObject *o;
	GSList *tokens=NULL;
	const char *line;
	int network_mode = -1;
	int plmn_format = -1;
	enum telephony_network_access_technology AcT = NETWORK_ACT_UNKNOWN;
	struct tnoti_network_identity noti ={0};
	char *pResp = NULL;
	int nol, count =0;

	o = tcore_pending_ref_core_object(p);

	if(resp->success <= 0){
		dbg("RESPONSE NOK");

		ur = tcore_pending_ref_user_request(p);
		if (ur) {
			Tresp.result = TCORE_RETURN_FAILURE;		
			tcore_user_request_send_response(ur, TRESP_NETWORK_GET_SERVING_NETWORK, sizeof(struct tresp_network_get_serving_network), &Tresp);
		}

		return;
	}else{
	dbg("RESPONSE OK");
		nol = g_slist_length(resp->lines);
		dbg("nol : %d", nol);

		for(count =0; count < nol; count++){
			//parse each line 
				line = g_slist_nth_data(resp->lines, count);
		tokens = tcore_at_tok_new(line);
			dbg("line %d start---------------",count);
			//mode
		if (pResp = tcore_at_tok_nth(tokens, 0)){
			dbg("mode  : %s",pResp);
			network_mode = atoi(pResp);
		}

			//format (optional)			
		if(pResp = tcore_at_tok_nth(tokens, 1))
		{
			dbg("format  : %s",pResp);
					if(strlen(pResp)>0)
			plmn_format = atoi(pResp);
		}

			//plmn 
		switch(plmn_format)
		{
			case AT_COPS_FORMAT_LONG_ALPHANUMERIC: 
				if(pResp = tcore_at_tok_nth(tokens, 2))
				{		
					dbg("long PLMN  : %s",pResp);
					if(strlen(pResp) > 0){
						long_plmn_name = malloc((strlen(pResp) - 2)+1); /* 1 extra character for NULL storage */
						memset(long_plmn_name, 0x00, strlen(pResp) -2+1);
						/* Strip off starting quotes & ending quotes */
						strncpy(long_plmn_name, pResp+1, strlen(pResp)-2);

						//set network name into po
						tcore_network_set_network_name(o,TCORE_NETWORK_NAME_TYPE_FULL,long_plmn_name);
					}
				}
				break;
		
				case AT_COPS_FORMAT_SHORT_ALPHANUMERIC:
					if(pResp = tcore_at_tok_nth(tokens, 2))
					{
						dbg("short PLMN  : %s",pResp);
						if(strlen(pResp)>0){
							short_plmn_name = malloc((strlen(pResp) - 2)+1); /* 1 extra character for NULL storage */
							memset(short_plmn_name, 0x00, strlen(pResp) -2+1);
							/* Strip off starting quotes & ending quotes */
							strncpy(short_plmn_name, pResp+1, strlen(pResp)-2);
							
							//set network name into po							
							tcore_network_set_network_name(o,TCORE_NETWORK_NAME_TYPE_SHORT,short_plmn_name);							
						}
					}					
				break;

				case AT_COPS_FORMAT_NUMERIC:
					if(pResp = tcore_at_tok_nth(tokens, 2))
					{
						dbg("numeric : %s", pResp);
						if(strlen(pResp)>0){
							memset(plmn, 0, 7);
							/* Strip off starting quotes & ending quotes */
							strncpy(plmn, pResp+1, strlen(pResp)-2);							

							tcore_network_set_plmn(o,plmn);
						}
					}
				break;
	
				default:
				break;
			}

			//act 
			if(pResp = tcore_at_tok_nth(tokens, 3))
			{		
				if(strlen(pResp)>0){
					dbg("act  : %s",pResp);						
					 AcT = lookup_tbl_access_technology[atoi(pResp)];
					dbg("AcT  : %d",AcT);	

					tcore_network_set_access_technology(o, AcT);
				}
			}

			tcore_at_tok_free(tokens);
		}

		memcpy(Tresp.plmn, plmn, 7);
		tcore_network_get_access_technology(o, &(Tresp.act)); 
		tcore_network_get_lac(o, &(Tresp.gsm.lac)); 

		ur = tcore_pending_ref_user_request(p);
		if (ur) {
			Tresp.result = TCORE_RETURN_SUCCESS;		
			tcore_user_request_send_response(ur, TRESP_NETWORK_GET_SERVING_NETWORK, sizeof(struct tresp_network_get_serving_network), &Tresp);
		}
		else
		{
			/* Network change noti */
			struct tnoti_network_change network_change;

			memset(&network_change, 0, sizeof(struct tnoti_network_change));
			memcpy(network_change.plmn, plmn, 7);
			tcore_network_get_access_technology(o, &(network_change.act));
			tcore_network_get_lac(o, &(network_change.gsm.lac));

			tcore_server_send_notification(tcore_plugin_ref_server(tcore_pending_ref_plugin(p)), tcore_pending_ref_core_object(p),
				TNOTI_NETWORK_CHANGE, sizeof(struct tnoti_network_change), &network_change);

			dbg("dbg.. network_change.plmn  : %s",network_change.plmn);
			dbg("dbg.. network_change.act  : %d",network_change.act);						
			dbg("dbg.. network_change.gsm.lac  : %d",network_change.gsm.lac);


			if((AT_COPS_MODE_DEREGISTER !=network_mode) &&
				(AT_COPS_MODE_SET_ONLY != network_mode)){
				/*Network identity noti*/
				memset(&noti, 0, sizeof(struct tnoti_network_change));
				if(long_plmn_name)
					memcpy(noti.full_name, long_plmn_name, MIN(33, strlen(long_plmn_name)) );
				if(short_plmn_name)
					memcpy(noti.short_name, short_plmn_name, MIN(17, strlen(long_plmn_name)) );
				memcpy(noti.plmn, plmn,7);
				tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), 
					o, TNOTI_NETWORK_IDENTITY,	sizeof(struct tnoti_network_identity), &noti);		

				dbg("dbg.. noti.short_name  : %s",noti.short_name);
				dbg("dbg.. noti.full_name  : %s",noti.full_name);						
				dbg("dbg.. noti.plmn  : %s",noti.plmn);	
			}
		}

		if(long_plmn_name)
			free(long_plmn_name);
		if(short_plmn_name)
			free(short_plmn_name);
	}

	return;

}

static gboolean on_event_ps_network_regist(CoreObject *o, const void *data, void *user_data)
{
	struct tnoti_network_registration_status regist_status;
	enum telephony_network_service_domain_status cs_status;
	enum telephony_network_service_domain_status ps_status;
	enum telephony_network_service_type service_type;
	enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;
	struct tnoti_network_location_cellinfo net_lac_cell_info = {0};
	struct tnoti_ps_protocol_status noti = {0};
	int ret;
	unsigned char svc_domain = NETWORK_SERVICE_DOMAIN_PS;
	int stat= 0, AcT=0;
	unsigned int lac=0xffff, ci=0xffff;
	unsigned int rac = 0xffff;
	GSList* tokens = NULL;
	char* pResp;
	char *line = NULL;
    	GSList *lines = NULL;

	lines = (GSList*)data;
	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}
   	line  = (char*)(lines->data);
	dbg("+CGREG NOTI RECEIVED");

/*
+CREG: <stat> [[,<lac>,<ci>[AcT]]

Possible values of <stat> can be
0 Not registered, ME is not currently searching a new operator to register to
1 Registered, home network
2 Not registered, but ME is currently searching a new operator to register
3 Registration denied
4 Unknown
5 Registered, in roaming

<lac>
string type; two byte location area code in hexadecimal format (e.g. �00C3�)

<ci>
string type; four byte cell ID in hexadecimal format (e.g. �0000A13F�)

<ACT>
0 GSM
2 UTRAN
3 GSM w/EGPRS
4 UTRAN w/HSDPA
5 UTRAN w/HSUPA
6 UTRAN w/HSDPA and HSUPA
Note: <Act> is supporting from R7 and above Protocol Stack.

<rac>: is R7 and above feature, string type; one byte routing area code in hexadecimal format.
*/
	if (line!=NULL)
	{
		tokens = tcore_at_tok_new(line);
		if(g_slist_length(tokens) < 1) {
			msg("invalid message");
			goto OUT;
		}

		if(!(pResp = g_slist_nth_data(tokens, 0)))
		{
			dbg("No  STAT in +CGREG");
			goto OUT;
		}
		else
		{
			stat = atoi(pResp);	
			if(pResp = g_slist_nth_data(tokens, 1))
				lac = atoi(pResp);

			if((pResp = g_slist_nth_data(tokens, 2)))
				ci = atoi(pResp);
			else
				dbg("No ci in +CGREG");
				
			if(pResp = g_slist_nth_data(tokens, 3))
				AcT = atoi(pResp);
			else
				dbg("No AcT in +CGREG");
			
			if(pResp = g_slist_nth_data(tokens, 4))
				rac = atoi(pResp);
			else
				dbg("No rac in +CGREG");
		}


		dbg("stat=%d, lac=0x%lx, ci=0x%lx, Act=%d, rac = 0x%x", stat, lac, ci, AcT, rac);

		ps_status = lookup_tbl_net_status[stat];
		
		tcore_network_set_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, ps_status);
		_ps_set(tcore_object_ref_plugin(o), ps_status);
			
		tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &cs_status);

		act = lookup_tbl_access_technology[AcT];
		tcore_network_set_access_technology(o, act);

		if (stat == AT_CREG_STAT_REG_ROAM)
			tcore_network_set_roaming_state(o, TRUE);
		else
			tcore_network_set_roaming_state(o, FALSE);

		tcore_network_get_service_type(o, &service_type);
		dbg("prev_service_type = 0x%x", service_type);
		service_type = _get_service_type(service_type, svc_domain, act, cs_status, ps_status);
		dbg("new_service_type = 0x%x", service_type);
		tcore_network_set_service_type(o, service_type);

		tcore_network_set_lac(o, lac);
		tcore_network_set_cell_id(o, ci);
		tcore_network_set_rac(o, rac);

		net_lac_cell_info.lac = lac;
		net_lac_cell_info.cell_id = ci;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_LOCATION_CELLINFO,
				sizeof(struct tnoti_network_location_cellinfo), &net_lac_cell_info);

		regist_status.cs_domain_status = cs_status;
		regist_status.ps_domain_status = ps_status;
		regist_status.service_type = service_type;
		regist_status.roaming_status = tcore_network_get_roaming_state(o);

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
				TNOTI_NETWORK_REGISTRATION_STATUS, sizeof(struct tnoti_network_registration_status), &regist_status);

		if(service_type == NETWORK_SERVICE_TYPE_HSDPA)
			noti.status = TELEPHONY_HSDPA_ON;
		else
			noti.status = TELEPHONY_HSDPA_OFF;
		
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_PS_PROTOCOL_STATUS,
		sizeof(struct tnoti_ps_protocol_status), &noti);

		/* Get PLMN ID needed to application */
		//get_serving_network(o, NULL);


	}
	else
	{
		dbg("Response NOK");
	}

OUT:
	if(NULL!=tokens)
	tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean on_event_cs_network_regist(CoreObject *o, const void *event_info, void *user_data)
{
    	GSList *lines = NULL;
	char *line = NULL;
	struct tnoti_network_registration_status regist_status;
	enum telephony_network_service_domain_status cs_status;
	enum telephony_network_service_domain_status ps_status;
	enum telephony_network_service_type service_type;
	enum telephony_network_access_technology act = NETWORK_ACT_UNKNOWN;
	struct tnoti_network_location_cellinfo net_lac_cell_info = {0};

	int ret;
	unsigned char svc_domain = NETWORK_SERVICE_DOMAIN_CS;
	int stat= 0, AcT=0;
	unsigned int lac=0xffff, ci=0xffff;
	GSList* tokens = NULL;
	char* pResp;

	lines = (GSList*)event_info;
	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}
   	line  = (char*)(lines->data);

	dbg("+CREG NOTI RECEIVED");

/*
+CREG: <stat> [[,<lac>,<ci>[AcT]]

Possible values of <stat> can be
0 Not registered, ME is not currently searching a new operator to register to
1 Registered, home network
2 Not registered, but ME is currently searching a new operator to register
3 Registration denied
4 Unknown
5 Registered, in roaming

<lac>
string type; two byte location area code in hexadecimal format (e.g. �00C3�)

<ci>
string type; four byte cell ID in hexadecimal format (e.g. �0000A13F�)

<ACT>
0 GSM
2 UTRAN
3 GSM w/EGPRS
4 UTRAN w/HSDPA
5 UTRAN w/HSUPA
6 UTRAN w/HSDPA and HSUPA
Note: <Act> is supporting from R7 and above Protocol Stack.
*/
	if (line!=NULL)
	{
		tokens = tcore_at_tok_new(line);
		if(g_slist_length(tokens) < 1) {
			msg("invalid message");
			goto OUT;
		}

		if(!(pResp = g_slist_nth_data(tokens, 0)))
		{
			dbg("No  STAT in +CREG");
			goto OUT;
		}
		else
		{
			stat = atoi(pResp);	
			if(pResp = g_slist_nth_data(tokens, 1))
				lac = atoi(pResp);

			if((pResp = g_slist_nth_data(tokens, 2)))
				ci = atoi(pResp);
			else
				dbg("No ci in +CREG");
				
			if(pResp = g_slist_nth_data(tokens, 3))
				AcT = atoi(pResp);
			else
				dbg("No AcT in +CREG");
		}


		dbg("stat=%d, lac=0x%lx, ci=0x%lx, Act=%d", stat, lac, ci, AcT);

		cs_status = lookup_tbl_net_status[stat];
		tcore_network_set_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, cs_status);

	//	tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_CIRCUIT, &cs_status);
		tcore_network_get_service_status(o, TCORE_NETWORK_SERVICE_DOMAIN_TYPE_PACKET, &ps_status);

		act = lookup_tbl_access_technology[AcT];
		tcore_network_set_access_technology(o, act);

		if (stat == AT_CREG_STAT_REG_ROAM)
			tcore_network_set_roaming_state(o, TRUE);
		else
			tcore_network_set_roaming_state(o, FALSE);

		tcore_network_get_service_type(o, &service_type);
		dbg("prev_service_type = 0x%x", service_type);
		service_type = _get_service_type(service_type, svc_domain, act, cs_status, ps_status);
		dbg("new_service_type = 0x%x", service_type);
		tcore_network_set_service_type(o, service_type);

		tcore_network_set_lac(o, lac);
		tcore_network_set_cell_id(o, ci);

		net_lac_cell_info.lac = lac;
		net_lac_cell_info.cell_id = ci;

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_LOCATION_CELLINFO,
				sizeof(struct tnoti_network_location_cellinfo), &net_lac_cell_info);

		regist_status.cs_domain_status = cs_status;
		regist_status.ps_domain_status = ps_status;
		regist_status.service_type = service_type;
		regist_status.roaming_status = tcore_network_get_roaming_state(o);

		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
				TNOTI_NETWORK_REGISTRATION_STATUS, sizeof(struct tnoti_network_registration_status), &regist_status);

		/* Get PLMN ID needed to application */
		if((NETWORK_SERVICE_DOMAIN_STATUS_FULL == cs_status )||
			NETWORK_SERVICE_DOMAIN_STATUS_FULL ==ps_status )
		get_serving_network(o, NULL);
	}
	else
	{
		dbg("Response NOK");
	}

OUT:
	if(NULL!=tokens)
	tcore_at_tok_free(tokens);
	return TRUE;

}

static gboolean on_event_network_icon_info(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_network_icon_info net_icon_info = {0};
	char *line = NULL;
	
	int rssi = 0, battery = 0;
	char * rssiToken = NULL;
	char *batteryToken = NULL;
	GSList* tokens = NULL;
    	GSList *lines = NULL;

	lines = (GSList*)event_info;
	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}
	line = (char*)(lines->data);
	dbg("+XCIEV Network Icon Info Noti Recieve");
	memset(&net_icon_info, 0, sizeof(struct tnoti_network_icon_info));

	if(line != NULL)
	{
		dbg("Response OK");
	
		tokens = tcore_at_tok_new(line);
		if (g_slist_length(tokens) != 2) {
			msg("invalid message");
			goto OUT;
		}

		rssiToken = (char *)g_slist_nth_data(tokens, 0);

		if (strlen(rssiToken)>0)
		{
			net_icon_info.type = NETWORK_ICON_INFO_RSSI;
			net_icon_info.rssi= atoi(g_slist_nth_data(tokens, 0));
			dbg("rssi level : %d",net_icon_info.rssi);
		}
		else
		{
			dbg("No rssi value");
		}
		
		batteryToken = (char *)g_slist_nth_data(tokens,1);
		if (strlen(batteryToken)>0)
		{
			net_icon_info.type = NETWORK_ICON_INFO_BATTERY;
			net_icon_info.battery= 1 + atoi(g_slist_nth_data(tokens, 1)); // 1 level added for proper battery indication
			dbg("battery level : %d",net_icon_info.battery);
		}
		else
		{
			dbg("No battery level recieved");
		}
		
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_ICON_INFO,
				sizeof(struct tnoti_network_icon_info), &net_icon_info);
	}
	else
	{
		dbg("Response NOK");		
	}


OUT:
	if(NULL!=tokens)
	tcore_at_tok_free(tokens);
	return TRUE;
	
}

static gboolean on_event_network_time_info(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_network_timeinfo net_time_info = {0};
	int gmtoff;
	char *line = NULL;
	GSList* tokens = NULL;
	char *time= NULL, *time_zone_variance = NULL;
   	GSList *lines = NULL;

	dbg("Network Time Info Noti Recieved");
	memset(&net_time_info, 0, sizeof(struct tnoti_network_icon_info));

   	lines = (GSList*)event_info;
	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}
  	line  = (char*)(lines->data);

	/*
	<time> string type value; format is \93yy/MM/dd,hh:mms\94, wherein characters indicates year, month, day, hour, minutes, seconds.
	<timzone_variance> is a string \93GMT+HH:MM\94 or \93GMT-HH:MM\94 e.g. \93GMT+5:30\94
	*/
	dbg("Network time info noti recieved");
	
	if (line != NULL)
	{	
		dbg("Response OK");
			dbg("noti line is %s", line);
			
			tokens = tcore_at_tok_new(line);
			strcpy(time, g_slist_nth_data(tokens, 0));
			strcpy(time_zone_variance , g_slist_nth_data(tokens, 1));

			strncpy(net_time_info.hour,time ,2);
			strncpy(net_time_info.month, time+3, 2);	
			strncpy(net_time_info.day, time+6, 2);
			strncpy(net_time_info.hour, time+9 ,2);
			strncpy(net_time_info.minute, time+12,3);
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_TIMEINFO, sizeof(struct tnoti_network_timeinfo), &net_time_info);
	}
	else
	{	
		dbg("line is  NULL");
	}
OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean on_event_network_identity(CoreObject *o, const void *event_info, void *user_data)
{
	struct tnoti_network_identity noti;
	char plmn[7] = { 0, };
	int type = 0;
	char *tmp;
    	GSList *lines = NULL;
	char *line = NULL;
	GSList* tokens = NULL;

	dbg("NOTI RECEIVED");
	lines = (GSList*)event_info;

	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}

	line  = (char*)(lines->data);

	memset(&noti, 0, sizeof(struct tnoti_network_identity));
	dbg("Network identity noti recieved");

	if(line!=NULL)
	{
		dbg("Response OK");
			dbg("noti line is %s", line);
			tokens = tcore_at_tok_new(line);
			//noti.type = 0;
			strcpy(noti.plmn, g_slist_nth_data(tokens, 0));
			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o, TNOTI_NETWORK_IDENTITY,	sizeof(struct tnoti_network_identity), &noti);			
	}
	else
	{
		dbg("Response NOK");		
	}

OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}


static void on_sim_resp_hook_get_netname(UserRequest *ur, enum tcore_response_command command, unsigned int data_len,
		const void *data, void *user_data)
{
	const struct tresp_sim_read *resp = data;
	CoreObject *o = user_data;

	if (command == TRESP_SIM_GET_SPN) {
		dbg("OK SPN GETTING!!");
		dbg("resp->result = 0x%x", resp->result);
		dbg("resp->data.spn.display_condition = 0x%x", resp->data.spn.display_condition);
		dbg("resp->data.spn.spn = [%s]", resp->data.spn.spn);

		tcore_network_set_network_name(o, TCORE_NETWORK_NAME_TYPE_SPN, (const char *)resp->data.spn.spn);

		/**
		 * display condition
		 *  bit[0]: 0 = display of registered PLMN name not required when registered PLMN is either HPLMN or a PLMN in the service provider PLMN list
		 *          1 = display of registered PLMN name required when registered PLMN is either HPLMN or a PLMN in the service provider PLMN list
		 *  bit[1]: 0 = display of the service provider name is required when registered PLMN is neither HPLMN nor a PLMN in the service provider PLMN list
		 *          1 = display of the service provider name is not required when registered PLMN is neither HPLMN nor a PLMN in the service provider PLMN list
		 */
		if (resp->data.spn.display_condition & 0x01) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_NETWORK);
		}
		if ((resp->data.spn.display_condition & 0x02) == 0) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_SPN);
		}
		if ((resp->data.spn.display_condition & 0x03) == 0x01) {
			tcore_network_set_network_name_priority(o, TCORE_NETWORK_NAME_PRIORITY_ANY);
		}
	}
}

static enum tcore_hook_return on_hook_sim_init(Server *s, CoreObject *source, enum tcore_notification_command command,
		unsigned int data_len, void *data, void *user_data)
{
	const struct tnoti_sim_status *sim = data;
	UserRequest *ur = NULL;

	if (sim->sim_status == SIM_STATUS_INIT_COMPLETED) {
		ur = tcore_user_request_new(NULL, NULL);
		tcore_user_request_set_command(ur, TREQ_SIM_GET_SPN);
		tcore_user_request_set_response_hook(ur, on_sim_resp_hook_get_netname, user_data);
		tcore_object_dispatch_request(source, ur);
	}

	return TCORE_HOOK_RETURN_CONTINUE;
}

static TReturn search_network(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
  	TcoreATRequest *atreq = NULL;

	char*cmd_str = NULL;
	dbg("search_network - ENTER!!");
	
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+COPS=?\r");
	atreq = tcore_at_request_new(cmd_str, "+COPS", TCORE_AT_SINGLELINE);
	
	tcore_pending_set_request_data(pending, 0, atreq);
	//tcore_pending_set_timeout(pending, 60);
	//tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_search_network, NULL);
	//tcore_pending_set_timeout_callback(pending, on_timeout_search_network, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);

	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn set_plmn_selection_mode(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq;
	char*cmd_str = NULL;
	int format = 0; /* default value for long alphanumeric */
	int mode = 0;
	char plmn[7];
	
	const struct treq_network_set_plmn_selection_mode *req_data;


	dbg("set_plmn_selection_mode - ENTER!!");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);
  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	// Command Format - AT+COPS=[<mode>[,<format>[,<oper>[,< AcT>]]]]	
	/* oper parameter format
		- 0 <oper> format presentations are set to long alphanumeric. If Network name not available it displays combination of Mcc and MNC in string format.
		- 1 <oper> format presentation is set to short alphanumeric.
		- 2 <oper> format presentations set to numeric.
	*/
	
	switch(req_data->mode) {
		case NETWORK_SELECT_MODE_GSM_MANUAL:
		{
			mode = AT_COPS_MODE_MANUAL;
			format = AT_COPS_FORMAT_NUMERIC;

			memset(plmn, 0, 7);
			memcpy(plmn, req_data->plmn, 6);

			if (strlen(req_data->plmn) == 5) {
				plmn[5] = '#';
			}		

			cmd_str = g_strdup_printf("AT+COPS=%d,%d,%s\r", mode, format, plmn);
		}
		break;
		
		case NETWORK_SELECT_MODE_GLOBAL_AUTOMATIC:
		default:
			cmd_str = g_strdup("AT+COPS=0\r");
			break;
	}

	
	atreq = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_set_plmn_selection_mode, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn get_plmn_selection_mode(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq;
	char*cmd_str = NULL;

	dbg("get_plmn_selection_mode - ENTER!!");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

 	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+COPS?\r");
	atreq = tcore_at_request_new(cmd_str, "+COPS", TCORE_AT_SINGLELINE);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_plmn_selection_mode, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);

	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}


static TReturn set_band(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *atreq;
	char*cmd_str = NULL;
	const struct treq_network_set_band *req_data;
	int band = 0;
	dbg("set_band - ENTER!!");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	req_data = tcore_user_request_ref_data(ur, NULL);

  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	switch (req_data->band)
	{
 		case NETWORK_BAND_TYPE_GSM850:
			band = AT_XBANDSEL_850;
			break;

		case NETWORK_BAND_TYPE_GSM_900_1800:
			band = AT_XBANDSEL_1800; //summerize 900 + 1800
			break;

		case NETWORK_BAND_TYPE_GSM1900:
			band = AT_XBANDSEL_1900;
			break;
 		case NETWORK_BAND_TYPE_GSM1800:
			band = AT_XBANDSEL_1800;
			break;
		case NETWORK_BAND_TYPE_GSM_850_1900:
			band = AT_XBANDSEL_1900; //summerize 850 + 1900
			break; 
		default:
			break;
	}
 
	pending = tcore_pending_new(o, 0);

 	//TODO - Done only for UMTS case, need to do for GSM seperately?
	cmd_str = g_strdup_printf("AT+XUBANDSEL=%d", req_data->band);
	atreq = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);

	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_timeout(pending, 0);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_response_callback(pending, on_response_set_band, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);


	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}

static TReturn get_band(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;

	TcoreATRequest *atreq;
	char*cmd_str = NULL;
	dbg("get_band - ENTER!!");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+XUBANDSEL?\r");
	atreq = tcore_at_request_new(cmd_str, "+XUBANDSEL", TCORE_AT_SINGLELINE);

 	pending = tcore_pending_new(o, 0);
	tcore_pending_set_request_data(pending, 0, atreq);
 	tcore_pending_set_response_callback(pending, on_response_get_band, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);
	tcore_hal_send_request(h, pending);



	return TCORE_RETURN_SUCCESS;
}

static TReturn set_preferred_plmn(CoreObject *o, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS; 
}

static TReturn get_preferred_plmn(CoreObject *o, UserRequest *ur)
{
	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
  	TcoreATRequest *atreq = NULL;

	char*cmd_str = NULL;

	dbg("get_preferred_plmn - ENTER!!");

	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

  	h = tcore_object_get_hal(o);
	pending = tcore_pending_new(o, 0);

	cmd_str = g_strdup_printf("AT+CPOL?\r");
	atreq = tcore_at_request_new(cmd_str, "+CPOL", TCORE_AT_MULTILINE);
	
	tcore_pending_set_request_data(pending, 0, atreq);
	tcore_pending_set_response_callback(pending, on_response_get_preferred_plmn, NULL);
	tcore_pending_link_user_request(pending, ur);
	tcore_pending_set_send_callback(pending, on_confirmation_network_message_send, NULL);

	tcore_hal_send_request(h, pending);

	return TCORE_RETURN_SUCCESS;
}


static TReturn set_cancel_manual_search(CoreObject *o, UserRequest *ur)
{
	dbg("Entry");

	dbg("Exit");
	return TCORE_RETURN_SUCCESS;
}

static TReturn get_serving_network(CoreObject *o, UserRequest *ur)
{
 	TcorePlugin *p = NULL;
	TcoreHal *h = NULL;
	TcorePending *pending = NULL;
	dbg("get_serving_network - ENTER!!");
	
	if (!o)
		return TCORE_RETURN_EINVAL;

	dbg("new pending(AT+COPS?)");

	nwk_prepare_and_send_pending_request(tcore_object_ref_plugin(o), "umts_network", "AT+COPS=3,2;+COPS?;+COPS=3,0;+COPS?\r", "+COPS", TCORE_AT_MULTILINE,on_response_get_serving_network);
	return TCORE_RETURN_SUCCESS;
}

static struct tcore_network_operations network_ops = {
		.search					= search_network,
		.set_plmn_selection_mode	= set_plmn_selection_mode,
		.get_plmn_selection_mode	= get_plmn_selection_mode,
		.set_service_domain		= NULL,
		.get_service_domain		= NULL,
		.set_band				= set_band,
		.get_band				= get_band,
		.set_preferred_plmn		= set_preferred_plmn,
		.get_preferred_plmn		= get_preferred_plmn,
		.set_order				= NULL,
		.get_order				= NULL,
		.set_power_on_attach		= NULL,
		.get_power_on_attach		= NULL,
		.set_cancel_manual_search	= set_cancel_manual_search,
		.get_serving_network		= get_serving_network,
};

gboolean s_network_init(TcorePlugin *p, TcoreHal *h)
{
	CoreObject *o = NULL;

	o = tcore_network_new(p, "umts_network", &network_ops, h);
	if (!o)
		return FALSE;

	tcore_object_add_callback(o,"+CREG", on_event_cs_network_regist, NULL);
	tcore_object_add_callback(o,"+CGREG", on_event_ps_network_regist, NULL);
	tcore_object_add_callback(o, "+XCIEV", on_event_network_icon_info, NULL);

	//XNITZINFO is for <time><timezone variance>
	//CTZDST is for <dst>
	tcore_object_add_callback(o, "+XNITZINFO", on_event_network_time_info, NULL);
	tcore_object_add_callback(o, "+CTZDST", on_event_network_time_info, NULL);

	//tcore_object_add_callback(o, "+XCOPS", on_event_network_identity, NULL);

	//need to check whether the following is needed

	//tcore_server_add_notification_hook(tcore_plugin_ref_server(p), TNOTI_SIM_STATUS, on_hook_sim_init, o);

	_insert_mcc_mnc_oper_list(p, o);

	return TRUE;
}

void s_network_exit(TcorePlugin *p)
{
	CoreObject *o;

	o = tcore_plugin_ref_core_object(p, "umts_network");

	tcore_network_free(o);
}
