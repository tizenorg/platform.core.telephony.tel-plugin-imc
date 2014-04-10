/*
 * tel-plugin-imc
 *
 * Copyright (c) 2013 Samsung Electronics Co. Ltd. All rights reserved.
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
#include <server.h>
#include <plugin.h>
#include <core_object.h>
#include <hal.h>
#include <queue.h>
#include <storage.h>
#include <at.h>

#include <co_ps.h>
#include <co_context.h>

#include "imc_ps.h"
#include "imc_common.h"

typedef struct {
	TcorePsCallState ps_call_status;
} PrivateInfo;

static void __notify_context_status_changed(CoreObject *co_ps, guint context_id,
						TcorePsCallState status)
{
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
	TcorePsCallStatusInfo data_resp = {0,};
	tcore_check_return_assert(private_info != NULL);

	private_info->ps_call_status = status;
	data_resp.context_id = context_id;
	data_resp.state = status;
	dbg("Sending PS Call Status Notification - Context ID: [%d] Context State: [%d]",
					data_resp.context_id, data_resp.state);

	/* Send PS CALL Status Notification */
	(void)tcore_object_send_notification(co_ps,
			TCORE_NOTIFICATION_PS_CALL_STATUS,
			sizeof(TcorePsCallStatusInfo),
			&data_resp);

}

static TcoreHookReturn on_hook_imc_nw_registration_status(TcorePlugin *plugin,
    TcoreNotification command, guint data_len, void *data, void *user_data)
{
	const TelNetworkRegStatusInfo *nw_reg_status = (TelNetworkRegStatusInfo *)data;
	gboolean state = FALSE;

	tcore_check_return_value(nw_reg_status != NULL,
        TCORE_HOOK_RETURN_CONTINUE);


	dbg("nw_reg_status->ps_status [%d]",nw_reg_status->ps_status);
	dbg("nw_reg_status->cs_status [%d]",nw_reg_status->cs_status);

	/* Setting if PS is online or not */
	if(nw_reg_status->ps_status == TEL_NETWORK_REG_STATUS_REGISTERED ||
		nw_reg_status->ps_status == TEL_NETWORK_REG_STATUS_ROAMING) {
		/* Set PS is online */
		state = TRUE;
	}

	dbg("PS online state [%d]", state);

	/* Set Online state */
	tcore_ps_set_online((CoreObject *)user_data, state);
	return TCORE_HOOK_RETURN_CONTINUE;
}

/*
 * Notification - GPRS event reporting
 *
 * Notification -
 * +CGEV: NW DEACT <PDP_type>, <PDP_addr>, [<cid>]
 * The network has forced a context deactivation. The <cid> that was used to activate the context is provided if
 * known to the MT
 */
static gboolean on_notification_imc_ps_cgev(CoreObject *co_ps,
	const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *lines = (GSList *)data;
	const gchar *line = lines->data;
	gchar *noti_data;
	guint context_id;
	TcoreHal *hal;

	dbg("Entry");

	if (line == NULL) {
		err("Ignore, No data present in notification received for CGEV");
		return TRUE;
	}

	dbg("Lines->data :%s", line);

	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) != 3) {
		err("Ignore, sufficient data not present for deactivation");
		goto out;

	}
	noti_data = g_slist_nth_data(tokens, 0);

	/* Only care about NW context deactivation */
	if (g_str_has_prefix(noti_data, "NW DEACT") == FALSE) {
		err("Ignore, only care about nw deactivation");
		goto out;
	}

	noti_data = g_slist_nth_data(tokens, 1);
	dbg("PDP Address: %s", noti_data);

	noti_data = g_slist_nth_data(tokens, 2);
	/*TODO: Need to handle context id with multiple PDP*/
	if (noti_data != NULL)
		context_id = (guint)atoi(noti_data);
	else{
		err("No Context ID!");
		goto out;
	}

	dbg("Context %d deactivated", context_id);

	__notify_context_status_changed(co_ps, context_id, TCORE_PS_CALL_STATE_NOT_CONNECTED);

	hal = tcore_object_get_hal(co_ps);
	if (tcore_hal_setup_netif(hal, co_ps, NULL, NULL, context_id,
					FALSE) != TEL_RETURN_SUCCESS)
		err("Failed to disable network interface");
out:
	tcore_at_tok_free(tokens);
	return TRUE;
}

static void __imc_ps_setup_pdp(CoreObject *co_ps, gint result, const gchar *netif_name,
	void *user_data)
{
	CoreObject *ps_context = user_data;
	guint context_id;

	tcore_check_return_assert(ps_context != NULL);

	dbg("Enter");

	if (result < 0) {
		err("Result [%d],Hence Deactivating context ", result);
		/* Deactivate PDP context */
		(void)tcore_object_dispatch_request(co_ps, TRUE,
				TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
				NULL, 0,
				NULL, NULL);

		return;
	}

	dbg("devname = [%s]", netif_name);

	tcore_context_set_ipv4_devname(ps_context, netif_name);

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	__notify_context_status_changed(co_ps, context_id, TCORE_PS_CALL_STATE_CONNECTED);

	dbg("Exit");
}

static void __on_response_imc_ps_send_get_dns_cmd(TcorePending *p, guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *ps_context = user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	guint context_id;
	GSList *tokens = NULL;
	GSList *lines;
	const char *line = NULL;
	char *dns_prim = NULL;
	char *dns_sec = NULL;
	char *token_dns = NULL;
	gint no_pdp_active = 0;
	TcoreHal *hal = tcore_object_get_hal(co_ps);

	dbg("Entered");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);


	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	if (at_resp && at_resp->success) {
		dbg("Response OK");
		if (at_resp->lines) {
			dbg("DNS data present in the Response");
			lines = (GSList *) at_resp->lines;
			no_pdp_active = g_slist_length(lines);
			dbg("Total Number of Active PS Context: [%d]", no_pdp_active);
			if (0 == no_pdp_active) {
				goto fail;
			}

			while (lines) {
				line = (const char *) lines->data;
				dbg("Received Data: [%s]", line);
				tokens = tcore_at_tok_new(line);

				/* Check if Context ID is matching */
				if (context_id == (guint)(atoi(g_slist_nth_data(tokens, 0)))) {
					dbg("Found the DNS details for the Current Context - Context ID: [%d]", context_id);
					break;
				}

				tcore_at_tok_free(tokens);
				tokens = NULL;

				/* Move to next line */
				lines = lines->next;
			}

			/* Read primary DNS */
			{
				token_dns = g_slist_nth_data(tokens, 1);
				dns_prim = tcore_at_tok_extract(token_dns);
				dbg("Primary DNS: [%s]", dns_prim);
			}

			/* Read Secondary DNS */
			{
				token_dns = g_slist_nth_data(tokens, 2);
				dns_sec = tcore_at_tok_extract(token_dns);
				dbg("Secondary DNS: [%s]", dns_sec);
			}

			if ((g_strcmp0("0.0.0.0", dns_prim) == 0)
					&& (g_strcmp0("0.0.0.0", dns_sec) == 0)) {
				dbg("Invalid DNS");

				tcore_free(dns_prim);
				tcore_free(dns_sec);

				tcore_at_tok_free(tokens);
				tokens = NULL;

				goto fail;
			}

			/* Set DNS Address */
			tcore_context_set_ipv4_dns(ps_context, dns_prim, dns_sec);
			tcore_free(dns_prim);
			tcore_free(dns_sec);

			tcore_at_tok_free(tokens);
			tokens = NULL;
			goto success;
		} else {
			dbg("No data present in the Response");
		}
	}
	dbg("Response NOK");

fail:
	dbg("Adding default DNS");
	tcore_context_set_ipv4_dns(ps_context, "8.8.8.8", "8.8.4.4");

success:
	/* Mount network interface */
	if (tcore_hal_setup_netif(hal, co_ps, __imc_ps_setup_pdp, ps_context, context_id, TRUE)
			!= TEL_RETURN_SUCCESS) {
		err("Setup network interface failed");
		return;
	}
}

static void __imc_ps_send_get_dns_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	guint context_id;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	dbg("Entered");

	tcore_check_return_assert(private_info != NULL);

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		"AT+XDNS?", "+XDNS",
		TCORE_AT_COMMAND_TYPE_MULTILINE,
		NULL,
		__on_response_imc_ps_send_get_dns_cmd,
		ps_context,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;
		err("Failed to prepare and send AT request");
		curr_call_status = private_info->ps_call_status;
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
}

static void __on_response_imc_ps_get_pdp_address(TcorePending *p, guint data_len,
					const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	GSList *tokens = NULL;
	const char *line;
	char *pdp_address;
	char *real_pdp_address;

	dbg("Entered");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	if (at_resp->success != TRUE) {
		err("Response NOt OK");
		goto error;
	}

	dbg("Response OK");

	if (at_resp->lines == NULL) {
		err("Invalid response line");
		goto error;
	}

	line = (const char *)at_resp->lines->data;
	tokens = tcore_at_tok_new(line);
	if (g_slist_length(tokens) < 2) {
		err("Invalid message");
		goto error;
	}

	dbg("Line: %s", line);

	/* Skip CID & read directly IP address */
	pdp_address = g_slist_nth_data(tokens, 1);
	real_pdp_address = tcore_at_tok_extract(pdp_address);

	tcore_context_set_ipv4_addr(ps_context, real_pdp_address);

	dbg("PDP address: %s", real_pdp_address);

	tcore_free(real_pdp_address);

	/* Get DNS Address */
	dbg("Getting DNS Address");
	__imc_ps_send_get_dns_cmd(co_ps, ps_context);
	goto exit;

error:
	err("Failed to get PDP address deactivating context...");
	/* Deactivate PDP context */
	(void)tcore_object_dispatch_request(co_ps, TRUE,
			TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
			NULL, 0,
			NULL, NULL);
exit:
	tcore_at_tok_free(tokens);
	dbg("Exit");
}

static void __imc_ps_get_pdp_address(CoreObject *co_ps, CoreObject *ps_context)
{
	TelReturn ret;
	gchar *at_cmd = NULL;
	guint context_id;

	dbg("Entered");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CGPADDR=%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_imc_ps_get_pdp_address,
		ps_context,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS){
		err("Failed to prepare and send AT request");
		/* Deactivate PDP context */
		(void)tcore_object_dispatch_request(co_ps, TRUE,
				TCORE_COMMAND_PS_DEACTIVATE_CONTEXT,
				&ps_context, sizeof(CoreObject *),
				NULL, NULL);
	}
	tcore_free(at_cmd);
}

static void __on_response_imc_ps_send_xdns_enable_cmd(TcorePending *p,
				guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = (CoreObject *) user_data;
	guint context_id;
	TcorePsCallState status = TCORE_PS_CALL_STATE_NOT_CONNECTED;

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	dbg("Entered");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	if (at_resp->success) {
		dbg("Response OK, Dynamic DNS is enabled successfully");
		status = TCORE_PS_CALL_STATE_CTX_DEFINED;
	} else {
		PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);
		tcore_check_return_assert(private_info != NULL);

		status = private_info->ps_call_status;
		err("ERROR [%s]", at_resp->final_response);
	}
	/* Send PS CALL Status Notification */
	__notify_context_status_changed(co_ps, context_id, status);
}

static TelReturn __imc_ps_send_xdns_enable_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	guint context_id;
	gchar *at_cmd = NULL;
	TelReturn ret;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entered");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+XDNS=%d,1", context_id);
	dbg("AT Command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_SINGLELINE,
		NULL,
		__on_response_imc_ps_send_xdns_enable_cmd,
		ps_context,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;

		err("Failed to prepare and send AT request");
		curr_call_status = private_info->ps_call_status;
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
	return ret;
}

static void on_response_imc_ps_activate_context(TcorePending *p, guint data_len,
							const void *data,
							void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	dbg("Entered");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);
	tcore_check_return_assert(private_info != NULL);

	if (at_resp->success) {
		dbg("Response OK, Get IP address of data session");
		__imc_ps_get_pdp_address(co_ps, ps_context);
	} else {
		guint context_id;
		TcorePsCallState curr_call_status;
		(void)tcore_context_get_id(ps_context, &context_id);
		err("Response NOT OK,Sending call disconnect notification");
		curr_call_status = private_info->ps_call_status;
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
}

static void on_response_imc_ps_deactivate_context(TcorePending *p, guint data_len,
							const void *data,
							void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	TcoreHal *hal = tcore_object_get_hal(co_ps);
	guint context_id;

	dbg("Entered");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	/*
	 * AT+CGACT = 0 is returning NO CARRIER or an error. Just test if the
	 * response contains NO CARRIER else decode CME error.
	 */
#if 0
	if (at_resp->success) {
		const gchar *line;

		line = (const gchar *)at_resp->lines->data;
		if (g_strcmp0(line, "NO CARRIER") != 0) {
			err("%s", line);
			err("Context %d has not been deactivated", context_id);

			goto out;
		}
	}

#endif
	__notify_context_status_changed(co_ps, context_id, TCORE_PS_CALL_STATE_NOT_CONNECTED);

	if (tcore_hal_setup_netif(hal, co_ps, NULL, NULL, context_id, FALSE) != TEL_RETURN_SUCCESS)
		err("Failed to disable network interface");
}

static void on_response_imc_ps_define_context(TcorePending *p,
				guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	CoreObject *ps_context = (CoreObject *) user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	dbg("Entred");

	tcore_check_return_assert(at_resp != NULL);
	tcore_check_return_assert(ps_context != NULL);
	tcore_check_return_assert(private_info != NULL);

	if (at_resp->success) {
		dbg("Response OK,Sending DNS enable command");
		__imc_ps_send_xdns_enable_cmd(co_ps, ps_context);
	} else {
		guint context_id;
		TcorePsCallState curr_call_status;

		err("ERROR[%s]", at_resp->final_response);
		(void)tcore_context_get_id(ps_context, &context_id);
		curr_call_status = private_info->ps_call_status;
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
}

/*
 * Operation - PDP Context Activate
 *
 * Request -
 * AT-Command: AT+CGACT= [<state> [, <cid> [, <cid> [,...]]]]
 *
 * where,
 * <state>
 * indicates the state of PDP context activation
 *
 * 1 activated
 *
 * <cid>
 * It is a numeric parameter which specifies a particular PDP context definition
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */

static TelReturn imc_ps_activate_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	gchar *at_cmd = NULL;
	guint context_id;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entered");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=1,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_ps_activate_context,
		ps_context,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;
		curr_call_status = private_info->ps_call_status;
		err("AT request failed. Send notification for call status [%d]", curr_call_status);
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
	tcore_free(at_cmd);
	return ret;
}

/*
 * Operation - PDP Context Deactivate
 *
 * Request -
 * AT-Command: AT+CGACT= [<state> [, <cid> [, <cid> [,...]]]]
 *
 * where,
 * <state>
 * indicates the state of PDP context activation
 *
 * 0 deactivated
 *
 * <cid>
 * It is a numeric parameter which specifies a particular PDP context definition
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_ps_deactivate_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	gchar *at_cmd = NULL;
	guint context_id;
	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entered");

	(void)tcore_context_get_id(ps_context, &context_id);
	dbg("Context ID : %d", context_id);

	at_cmd = g_strdup_printf("AT+CGACT=0,%d", context_id);
	dbg(" at command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_ps_deactivate_context,
		ps_context,
		on_send_imc_request, NULL);
	if (ret != TEL_RETURN_SUCCESS){
		TcorePsCallState curr_call_status;
		curr_call_status = private_info->ps_call_status;
		err("AT request failed. Send notification for call status [%d]", curr_call_status);
		__notify_context_status_changed(co_ps, context_id, curr_call_status);
	}
	tcore_free(at_cmd);
	return ret;
}

/*
 * Operation - Define PDP Context
 *
 * Request -
 * AT-Command: AT+CGDCONT= [<cid> [, <PDP_type> [, <APN> [, <PDP_addr> [,
 * <d_comp> [, <h_comp> [, <pd1> [... [, pdN]]]]]]]]]
 * where,
 * <cid>
 * It is a numeric parameter, which specifies a particular PDP context definition
 *
 * <PDP_type>
 * "IP" Internet Protocol (IETF STD 5)
 * "IPV6" Internet Protocol, version 6 (IETF RFC 2460)
 * "IPV4V6" Virtual <PDP_type>introduced to handle dual IP stack UE capability (see 3GPP
 *  TS 24.301[83])
 *
 * <APN>
 * Access Point Name
 *
 * <PDP_address>
 * It is the string parameter that identifies the MT in the address space applicable to the PDP
 * The allocated address may be read using the command +CGPADDR command
 *
 * <d_comp>
 * A numeric parameter that controls PDP data compression
 * 0 off
 * 1 on
 * 2 V.42 bis
 *
 * <h_comp>
 * A numeric parameter that controls PDP header compression
 * 0 off
 * 1 on
 * 2 RFC1144
 * 3 RFC2507
 * 4 RFC3095
 *
 * <pd1>...<pdN>
 * zero to N string parameters whose meanings are specific to the <PDP_type>
 *
 * Response -
 * Success: (No Result)
 *	OK
 * Failure:
 *	+CME ERROR: <error>
 */
static TelReturn imc_ps_define_context(CoreObject *co_ps, CoreObject *ps_context,
				TcoreObjectResponseCallback cb, void *cb_data)
{
	TelReturn ret = TEL_RETURN_FAILURE;
	gchar *at_cmd = NULL;
	guint context_id = 0;
	gchar *apn = NULL;
	gchar *pdp_type_str = NULL;
	TcoreContextType pdp_type;
	TcoreContextDComp d_comp;
	TcoreContextHComp h_comp;
	TcorePsCallState curr_call_status;

	PrivateInfo *private_info = tcore_object_ref_user_data(co_ps);

	tcore_check_return_value_assert(private_info != NULL, TEL_RETURN_INVALID_PARAMETER);

	dbg("Entred");

	(void)tcore_context_get_id(ps_context, &context_id);
	(void)tcore_context_get_type(ps_context, &pdp_type);

	switch (pdp_type) {
	case TCORE_CONTEXT_TYPE_X25:
		dbg("CONTEXT_TYPE_X25");
		pdp_type_str = g_strdup("X.25");
	break;

	case TCORE_CONTEXT_TYPE_IP:
		dbg("CONTEXT_TYPE_IP");
		pdp_type_str = g_strdup("IP");
	break;

	case TCORE_CONTEXT_TYPE_PPP:
		dbg("CONTEXT_TYPE_PPP");
		pdp_type_str = g_strdup("PPP");
	break;

	case TCORE_CONTEXT_TYPE_IPV6:
		dbg("CONTEXT_TYPE_IPV6");
		pdp_type_str = g_strdup("IPV6");
		break;

	default:
		/*PDP Type not supported*/
		dbg("Unsupported PDP type: %d", pdp_type);
		goto error;
	}

	(void)tcore_context_get_data_compression(ps_context, &d_comp);
	(void)tcore_context_get_header_compression(ps_context, &h_comp);
	(void)tcore_context_get_apn(ps_context, &apn);

	dbg("Define context for CID: %d", context_id);

	/* AT-Command */
	at_cmd = g_strdup_printf("AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d", context_id, pdp_type_str, apn, d_comp, h_comp);
	dbg("AT Command : %s", at_cmd);

	/* Send Request to modem */
	ret = tcore_at_prepare_and_send_request(co_ps,
		at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		NULL,
		on_response_imc_ps_define_context,
		ps_context,
		on_send_imc_request, NULL);

	tcore_free(pdp_type_str);
	tcore_free(at_cmd);
	tcore_free(apn);

	if (ret == TEL_RETURN_SUCCESS)
		goto out;

error:
	err("Failed to prepare and send AT request");

	curr_call_status = private_info->ps_call_status;
	__notify_context_status_changed(co_ps, context_id, curr_call_status);

out:
	return ret;
}

/* PS Operations */
static TcorePsOps imc_ps_ops = {
	.define_context = imc_ps_define_context,
	.activate_context = imc_ps_activate_context,
	.deactivate_context = imc_ps_deactivate_context
};


gboolean imc_ps_init(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	dbg("Entry");

	/* Set PrivateInfo */
	private_info = tcore_malloc0(sizeof(PrivateInfo));
	tcore_object_link_user_data(co, private_info);

	/* Set operations */
	tcore_ps_set_ops(co, &imc_ps_ops);

	/* Add Callbacks */
	tcore_object_add_callback(co, "+CGEV", on_notification_imc_ps_cgev, NULL);

	tcore_plugin_add_notification_hook(p,
        TCORE_NOTIFICATION_NETWORK_REGISTRATION_STATUS,
        on_hook_imc_nw_registration_status, co);

	dbg("Exit");
	return TRUE;
}

void imc_ps_exit(TcorePlugin *p, CoreObject *co)
{
	PrivateInfo *private_info;

	private_info = tcore_object_ref_user_data(co);
	tcore_check_return_assert(private_info != NULL);

	tcore_free(private_info);

	dbg("Exit");
}
