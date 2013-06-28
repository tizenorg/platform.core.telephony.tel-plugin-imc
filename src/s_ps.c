/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Arun Shukla <arun.shukla@samsung.com>
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
#include <unistd.h>

#include <glib.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_ps.h>
#include <co_context.h>
#include <storage.h>
#include <server.h>
#include <at.h>
#include <util.h>
#include <type/ps.h>

#include "s_common.h"
#include "s_ps.h"

/*Invalid Session ID*/
#define PS_INVALID_CID  999 /*Need to check */

/*Maximum String length Of the Command*/
#define MAX_AT_CMD_STR_LEN  150

/*Command for PDP activation and Deactivation*/
#define AT_PDP_ACTIVATE 1
#define AT_PDP_DEACTIVATE 0

#define AT_XDNS_ENABLE 1
#define AT_XDNS_DISABLE 0
#define AT_SESSION_DOWN 0

static void _unable_to_get_pending(CoreObject *co_ps, CoreObject *ps_context)
{
	struct tnoti_ps_call_status data_resp = {0};
	dbg("Entry");

	data_resp.context_id = tcore_context_get_id(ps_context);
	data_resp.state = PS_DATA_CALL_NOT_CONNECTED;
	dbg("Sending Call Status Notification - Context ID: [%d] Context State: [NOT CONNECTED]",
					data_resp.context_id);

	/* Send CALL Status Notification */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)),
				co_ps, TNOTI_PS_CALL_STATUS, sizeof(data_resp), &data_resp);

	/* Set PS State to Deactivated */
	(void) tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	dbg("Exit");
}

static gboolean on_event_dun_call_notification(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	const char *line = NULL;
	int value = 0;
	GSList *lines = NULL;
	dbg("Entry");

	lines = (GSList *) data;
	if (g_slist_length(lines) != 1) {
		dbg("Unsolicited message BUT multiple lines");
		goto OUT;
	}

	line = (char *) (lines->data);
	tokens = tcore_at_tok_new(line);
	value = atoi(g_slist_nth_data(tokens, 0));

	/*
	 * <status> may be
	 *	0: DUN Activation in progress
	 *	1: DUN Deactivation in progress
	 *	2: DUN Activated
	 *	3: DUN Deactivated
	 */
	switch (value) {
	case 0:    /* FALL THROUGH */
	case 1:
	{
		break;
	}

	case 2:
	{
		/* TODO:- Fill Data structure: 'data' */
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
									   TNOTI_PS_EXTERNAL_CALL, sizeof(struct tnoti_ps_external_call), &data);
	}

	case 3:
	{
		/* TODO:- Fill Data structure: 'data' */
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
									   TNOTI_PS_EXTERNAL_CALL, sizeof(struct tnoti_ps_external_call), &data);
	}
	break;

	default:
		break;
	}

OUT:
	/* Free tokens */
	tcore_at_tok_free(tokens);

	return TRUE;
}
static void on_response_undefine_context_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = NULL;
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = user_data;
	dbg("Entry");

	co_ps = tcore_pending_ref_core_object(p);
	if (resp->success) {
		dbg("Response Ok");
		goto exit;
	}
	dbg("Response NOk");

exit:
	_unable_to_get_pending(co_ps, ps_context);
	return;
}

static void send_undefine_context_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN];
	int cid = 0;

	dbg("Entry");
	memset(cmd_str, 0x0, MAX_AT_CMD_STR_LEN);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);

	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);

	(void) sprintf(cmd_str, "AT+CGDCONT=%d", cid);
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, NULL, TCORE_AT_NO_RESULT,
								   on_response_undefine_context_cmd, ps_context);
	if (NULL == pending) {
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exit: Successfully");
	return;
error:
	{
		dbg("Exit: With error");
		_unable_to_get_pending(co_ps, ps_context);
		return;
	}
}

static void on_setup_pdp(CoreObject *co_ps, int result,
			const char *netif_name, void *user_data)
{
	CoreObject *ps_context = user_data;
	struct tnoti_ps_call_status data_status = {0};
	Server *server;

	dbg("Entry");

	if (result < 0) {
		/* Deactivate PDP context */
		tcore_ps_deactivate_context(co_ps, ps_context, NULL);
		return;
	}

	dbg("Device name: [%s]", netif_name);

	/* Set Device name */
	tcore_context_set_ipv4_devname(ps_context, netif_name);

	/* Set State - CONNECTED */
	data_status.context_id = tcore_context_get_id(ps_context);
	data_status.state = PS_DATA_CALL_CONNECTED;
	dbg("Sending Call Status Notification - Context ID: [%d] Context State: [CONNECTED]", data_status.context_id);

	/* Send Notification */
	server = tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps));
	tcore_server_send_notification(server, co_ps,
					TNOTI_PS_CALL_STATUS,
					sizeof(struct tnoti_ps_call_status),
					&data_status);

	dbg("Exit");
}

static void on_response_get_dns_cmnd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	GSList *tokens = NULL;
	GSList *pRespData;
	const char *line = NULL;
	char *dns_prim = NULL;
	char *dns_sec = NULL;
	char *token_dns = NULL;
	int no_pdp_active = 0;
	CoreObject *ps_context = user_data;
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	int cid = tcore_context_get_id(ps_context);
	TcoreHal *h = tcore_object_get_hal(co_ps);

	dbg("Entry");

	if (resp->final_response) {
		dbg("Response OK");
		if (resp->lines) {
			dbg("DNS data present in the Response");
			pRespData = (GSList *) resp->lines;
			no_pdp_active = g_slist_length(pRespData);
			dbg("Total Number of Active PS Context: [%d]", no_pdp_active);
			if (0 == no_pdp_active) {
				goto exit_fail;
			}

			while (pRespData) {
				line = (const char *) pRespData->data;
				dbg("Received Data: [%s]", line);
				tokens = tcore_at_tok_new(line);

				/* Check if Context ID is matching */
				if (cid == atoi(g_slist_nth_data(tokens, 0))) {
					dbg("Found the DNS details for the Current Context - Context ID: [%d]", cid);
					break;
				}

				/* Free tokens */
				tcore_at_tok_free(tokens);
				tokens = NULL;

				/* Move to next line */
				pRespData = pRespData->next;
			}

			/* Read primary DNS */
			{
				token_dns = g_slist_nth_data(tokens, 1);

				/* Strip off starting " and ending " from this token to read actual PDP address */
				dns_prim = util_removeQuotes((void *)token_dns);
				dbg("Primary DNS: [%s]", dns_prim);
			}

			/* Read Secondary DNS */
			{
				token_dns = g_slist_nth_data(tokens, 2);

				/* Strip off starting " and ending " from this token to read actual PDP address */
				dns_sec = util_removeQuotes((void *)token_dns);
				dbg("Secondary DNS: [%s]", dns_sec);
			}

			if ((g_strcmp0("0.0.0.0", dns_prim) == 0)
					&& (g_strcmp0("0.0.0.0", dns_sec) == 0)) {
				dbg("Invalid DNS");

				g_free(dns_prim);
				g_free(dns_sec);

				tcore_at_tok_free(tokens);
				tokens = NULL;

				goto exit_fail;
			}

			/* Set DNS Address */
			tcore_context_set_ipv4_dns(ps_context, dns_prim, dns_sec);
			g_free(dns_prim);
			g_free(dns_sec);

			tcore_at_tok_free(tokens);
			tokens = NULL;
			goto exit_success;
		} else {
			dbg("No data present in the Response");
		}
	}
	dbg("Response NOK");

exit_fail:
	dbg("Adding default DNS");
	tcore_context_set_ipv4_dns(ps_context, "8.8.8.8", "8.8.4.4");

exit_success:
	/* Mount network interface */
	if (tcore_hal_setup_netif(h, co_ps, on_setup_pdp, ps_context, cid, TRUE)
			!= TCORE_RETURN_SUCCESS) {
		err("Setup network interface failed");
		return;
	}

	dbg("EXIT : Without error");
}

static TReturn send_get_dns_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN];

	memset(cmd_str, 0x0, MAX_AT_CMD_STR_LEN);

	dbg("Entry");
	hal = tcore_object_get_hal(co_ps);

	(void) sprintf(cmd_str, "AT+XDNS?");
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, "+XDNS", TCORE_AT_MULTILINE,
								   on_response_get_dns_cmnd, ps_context);
	if (TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal, pending)) {
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps, ps_context);
	return TCORE_RETURN_FAILURE;
}

static void on_response_get_pdp_address(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	GSList *tokens = NULL;
	const char *line;
	char *token_pdp_address;
	dbg("Enetered");
	if (resp->final_response) {
		dbg("RESPONSE OK");
		if (resp->lines != NULL) {
			line = (const char *) resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) {
				msg("Invalid message");
				goto error;
			}
			dbg("Received Data: [%s]", line);

			/* CID is already stored in ps_context, skip over & read PDP address */
			token_pdp_address = g_slist_nth_data(tokens, 1);
			token_pdp_address = util_removeQuotes((void *)token_pdp_address);
			dbg("IP Address: [%s]", token_pdp_address);

			/* Strip off starting " and ending " from this token to read actual PDP address */
			/* Set IP Address */
			(void)tcore_context_set_ipv4_addr(ps_context, (const char *)token_pdp_address);

			g_free(token_pdp_address);
		}

		/* Get DNS Address */
		(void) send_get_dns_cmd(co_ps, ps_context);
	} else {
		dbg("Response NOK");

		/*without PDP address we will not be able to start packet service*/
		tcore_ps_deactivate_context(co_ps, ps_context, NULL);
	}
error:
	tcore_at_tok_free(tokens);
	return;
}

static TReturn send_get_pdp_address_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	unsigned int cid = PS_INVALID_CID;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};

	dbg("Entry");
	hal = tcore_object_get_hal(co_ps);

	cid = tcore_context_get_id(ps_context);
	(void) sprintf(cmd_str, "AT+CGPADDR=%d", cid);
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, "+CGPADDR", TCORE_AT_SINGLELINE,
								   on_response_get_pdp_address, ps_context);
	if (TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal, pending)) {
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps, ps_context);
	return TCORE_RETURN_FAILURE;
}

static void on_response_send_pdp_activate_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = NULL;
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = user_data;

	int cid;
	cid = tcore_context_get_id(ps_context);


	dbg("Entry");
	if (!p) {
		goto error;
	}
	co_ps = tcore_pending_ref_core_object(p);

	if (resp->success) {
		dbg("Response OK");

		/* Getting the IP address and DNS from the modem */
		dbg("Getting IP Address");
		(void) send_get_pdp_address_cmd(co_ps, ps_context);
		return;
	} else {
		dbg("Unable to activate PDP context - Context ID: [%d]", cid);
		dbg("Undefining PDP context");
		(void) tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
		send_undefine_context_cmd(co_ps, ps_context);
		return;
	}
error:
	{
		_unable_to_get_pending(co_ps, ps_context);
		return;
	}
}

static TReturn send_pdp_activate_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};
	int cid = 0;
	dbg("Entry");
	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);

	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);
	(void) sprintf(cmd_str, "AT+CGACT=%d,%d", AT_PDP_ACTIVATE, cid);
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, NULL, TCORE_AT_NO_RESULT,
								   on_response_send_pdp_activate_cmd, ps_context);
	if (TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal, pending)) {
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps, ps_context);
	return TCORE_RETURN_FAILURE;
}

static TReturn activate_ps_context(CoreObject *co_ps, CoreObject *ps_context, void *user_data)
{
	dbg("Entry");
	return send_pdp_activate_cmd(co_ps, ps_context);
}

static void on_response_xdns_enable_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcoreATResponse *resp = (TcoreATResponse *) data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	struct tnoti_ps_call_status noti = {0};
	int cid = -1;

	dbg("Entry");

	cid = tcore_context_get_id(ps_context);

	if (resp->success) {
		dbg("Response OK");
		dbg("DNS address getting is Enabled");
		noti.context_id = cid;
		noti.state = PS_DATA_CALL_CTX_DEFINED;
	} else {
		dbg("Response NOK");
		noti.context_id = cid;
		noti.state = PS_DATA_CALL_NOT_CONNECTED;
		/*If response to enable the DNS NOK then we will use google DNS for the PDP context*/
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
								   TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &noti);
	return;
}

static TReturn send_xdns_enable_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	int cid = -1;
	char cmd_str[MAX_AT_CMD_STR_LEN];

	dbg("Entry");
	memset(cmd_str, 0x0, MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);
	cid = tcore_context_get_id(ps_context);

	(void) sprintf(cmd_str, "AT+XDNS=%d,%d", cid, AT_XDNS_ENABLE);
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, NULL, TCORE_AT_NO_RESULT,
								   on_response_xdns_enable_cmd, ps_context);
	if (TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal, pending)) {
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps, ps_context);
	return TCORE_RETURN_FAILURE;
}

static void on_response_define_pdp_context(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = (CoreObject *) user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);

	dbg("Entry");
	if (resp->success) {
		dbg("Response OK");
		send_xdns_enable_cmd(co_ps, ps_context);
	} else {
		dbg("response NOK");
		_unable_to_get_pending(co_ps, ps_context);
		dbg("Exiting");
	}
	return;
}

static TReturn define_ps_context(CoreObject *co_ps, CoreObject *ps_context, void *user_data)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char *apn = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};
	char pdp_type_str[10] = {0};
	unsigned int cid = PS_INVALID_CID;
	enum co_context_type pdp_type;
	enum co_context_d_comp d_comp;
	enum co_context_h_comp h_comp;

	dbg("Entry");

	cid = tcore_context_get_id(ps_context);
	pdp_type = tcore_context_get_type(ps_context);
	d_comp = tcore_context_get_data_compression(ps_context);
	h_comp = tcore_context_get_header_compression(ps_context);
	apn = tcore_context_get_apn(ps_context);

	hal = tcore_object_get_hal(co_ps);
	switch (pdp_type) {
	case CONTEXT_TYPE_X25:
	{
		dbg("CONTEXT_TYPE_X25");
		strcpy(pdp_type_str, "X.25");
		break;
	}

	case CONTEXT_TYPE_IP:
	{
		dbg("CONTEXT_TYPE_IP");
		strcpy(pdp_type_str, "IP");
	}
	break;

	case CONTEXT_TYPE_PPP:
	{
		dbg("CONTEXT_TYPE_PPP");
		strcpy(pdp_type_str, "PPP");
	}
	break;

	case CONTEXT_TYPE_IPV6:
	{
		dbg("CONTEXT_TYPE_IPV6");
		strcpy(pdp_type_str, "IPV6");
		break;
	}

	default:
	{
		/*PDP Type not supported supported*/
		dbg("Unsupported PDP type: %d returning ", pdp_type);
		return TCORE_RETURN_FAILURE;
	}
	}
	dbg("Activating context for CID: %d", cid);
	(void) sprintf(cmd_str, "AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d", cid, pdp_type_str, apn, d_comp, h_comp);
	dbg("Command: [%s] Command Length: [%d]", cmd_str, strlen(cmd_str));

	pending = tcore_at_pending_new(co_ps, cmd_str, NULL, TCORE_AT_NO_RESULT,
								   on_response_define_pdp_context, ps_context);
	if (TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal, pending)) {
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps, ps_context);
	return TCORE_RETURN_FAILURE;
}


static struct tcore_ps_operations ps_ops = {
	.define_context = define_ps_context,
	.activate_context = activate_ps_context,
	/* Use AT_standard entry point */
	.deactivate_context = NULL
};

gboolean s_ps_init(TcorePlugin *cp, CoreObject *co_ps)
{
	TcorePlugin *plugin = tcore_object_ref_plugin(co_ps);

	dbg("Entry");

	tcore_ps_override_ops(co_ps, &ps_ops);

	/*
	 * AT_standard handles standard CGEV notifications:
	 * tcore_object_override_callback(co, "+CGEV", on_cgev_notification, NULL);
	 * no need to handle it here.
	 */

	tcore_object_override_callback(co_ps, "+XNOTIFYDUNSTATUS", on_event_dun_call_notification, plugin);

	dbg("Exit");

	return TRUE;
}

void s_ps_exit(TcorePlugin *cp, CoreObject *co_ps)
{
	dbg("Exit");
}
