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
#include <at.h>

#include "imc_modem.h"
#include "imc_sim.h"
#include "imc_sat.h"
#include "imc_sap.h"
#include "imc_network.h"
#include "imc_ps.h"
#include "imc_call.h"
#include "imc_ss.h"
#include "imc_sms.h"
#include "imc_phonebook.h"
#include "imc_gps.h"

#include "imc_common.h"

/* Initializer Table */
TcoreObjectInitializer imc_init_table = {
	.modem_init = imc_modem_init,
	.sim_init = imc_sim_init,
	.sat_init = imc_sat_init,
	.sap_init = imc_sap_init,
	.network_init = imc_network_init,
	.ps_init = imc_ps_init,
	.call_init = imc_call_init,
	.ss_init = imc_ss_init,
	.sms_init = imc_sms_init,
	.phonebook_init = imc_phonebook_init,
	.gps_init = imc_gps_init,
};

/* Deinitializer Table */
TcoreObjectDeinitializer imc_deinit_table = {
	.modem_deinit = imc_modem_exit,
	.sim_deinit = imc_sim_exit,
	.sat_deinit = imc_sat_exit,
	.sap_deinit = imc_sap_exit,
	.network_deinit = imc_network_exit,
	.ps_deinit = imc_ps_exit,
	.call_deinit = imc_call_exit,
	.ss_deinit = imc_ss_exit,
	.sms_deinit = imc_sms_exit,
	.phonebook_deinit = imc_phonebook_exit,
	.gps_deinit = imc_gps_exit,
};

static void __send_request(CoreObject *co, const gchar *at_cmd,
	TcorePendingResponseCallback resp_cb, void *resp_cb_data)
{
	(void)tcore_at_prepare_and_send_request(co, at_cmd, NULL,
		TCORE_AT_COMMAND_TYPE_NO_RESULT,
		TCORE_PENDING_PRIORITY_DEFAULT,
		NULL,
		resp_cb, resp_cb_data,
		on_send_imc_request, NULL,
		0, NULL, NULL);
}

static void __on_response_subscribe_bootup_notification(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	dbg("Entry");

	if (at_resp && at_resp->success) {
		dbg("Subscription for '%s' - [OK]", (gchar *)user_data);
	} else {
		err("Subscription for '%s' - [NOK]", (gchar *)user_data);
	}

	/* Free resource */
	tcore_free(user_data);
}

static void __on_response_subscribe_bootup_notification_last(TcorePending *p,
	guint data_len, const void *data, void *user_data)
{
	const TcoreAtResponse *at_resp = data;
	TcorePlugin *plugin = tcore_pending_ref_plugin(p);
	gboolean ret;

	if (at_resp && at_resp->success) {
		dbg("[Last] Subscription for '%s' - [OK]", (gchar *)user_data);
	} else {
		err("[Last] Subscription for '%s' - [NOK]", (gchar *)user_data);
	}

	/* Free resource */
	tcore_free(user_data);

	dbg("Boot-up configration completed for IMC modem, "
		"Bring CP to ONLINE state based on Flight mode status");

	/* Modem Power */
	ret = imc_modem_power_on_modem(plugin);
	dbg("Modem Power ON: [%s]", (ret == TRUE ? "SUCCESS" : "FAIL"));

	/* NVM Registration */
	dbg("Registering modem for NVM manager");
	imc_modem_register_nvm(tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM));
}

static void __subscribe_modem_notifications(TcorePlugin *plugin)
{
	CoreObject *call, *sim, *sms, *network, *ps, *gps;
	dbg("Entry");

	/*
	 * URC Subscriptions
	 */
	/****** SIM subscriptions ******/
	sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
	/* XSIMSTATE  */
	__send_request(sim, "AT+XSIMSTATE=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XSIMSTATE=1"));

	/****** CALL subscriptions ******/
	call = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	/* XCALLSTAT */
	__send_request(call, "AT+XCALLSTAT=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XCALLSTAT=1"));

	/* CSSN */
	__send_request(call, "AT+CSSN=1,1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CSSN=1,1"));

	/* CUSD */
	__send_request(call, "AT+CUSD=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CUSD=1"));

	/* CLIP */
	__send_request(call, "AT+CLIP=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CLIP=1"));

	/****** NETWORK subscriptions ******/
	network = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_NETWORK);
	/* CREG */
	__send_request(network, "AT+CREG=2",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CREG=2"));

	/* CGREG */
	__send_request(network, "AT+CGREG=2",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CGREG=2"));

	/* Allow Automatic Time Zone updation via NITZ */
	__send_request(network, "AT+CTZU=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CTZU=1"));

	/* TZ, Time & Daylight changing event reporting Subscription */
	__send_request(network, "AT+CTZR=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CTZR=1"));

	/* XMER */
	__send_request(network, "AT+XMER=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XMER=1"));

	/****** PS subscriptions ******/
	ps = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_PS);
	/* CGEREP */
	__send_request(ps, "AT+CGEREP=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CGEREP=1"));

	/* XDATASTAT */
	__send_request(ps, "AT+XDATASTAT=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XDATASTAT=1"));

	/* XDNS */
	__send_request(ps, "AT+XDNS=1,1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XDNS=1,1"));

	/* CMEE */
	__send_request(ps, "AT+CMEE=2",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CMEE=2"));

	/****** SMS subscriptions ******/
	sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	/* CMEE */
	__send_request(sms, "AT+CMEE=2",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CMEE=2"));

	/* Incoming SMS, Cell Broadcast, Status Report Subscription */
	__send_request(sms, "AT+CNMI=1,2,2,1,0",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CNMI=1,2,2,1,0"));

	/* Text/PDU mode Subscription */
	__send_request(sms, "AT+CMGF=0",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CMGF=0"));

#if 0	/* Temporarily Blocking as modem doesn't support */
	/****** SAP subscriptions ******/
	sap = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SAP);
	/* XBCSTAT */
	__send_request(sap, "AT+XBCSTAT=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+XBCSTAT=1"));
#endif	/* Temporarily Blocking as modem doesn't support */

	/****** GPS subscriptions ******/
	gps = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_GPS);
	/* AGPS- Assist Data and Reset Assist Data Subscription */
	__send_request(gps, "AT+CPOSR=1",
		__on_response_subscribe_bootup_notification,
		tcore_strdup("AT+CPOSR=1"));

	__send_request(gps, "AT+XCPOSR=1",
		__on_response_subscribe_bootup_notification_last,
		tcore_strdup("AT+XCPOSR=1"));

	dbg("Exit");
}

static gboolean on_load()
{
	dbg("Load!!!");

	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	dbg("Init!!!");
	tcore_check_return_value(p != NULL, FALSE);

	/* Initialize Modules (Core Objects) */
	if (tcore_object_init_objects(p, &imc_init_table)
			!= TEL_RETURN_SUCCESS) {
		err("Failed to initialize Core Objects");
		return FALSE;
	}

	/* Subscribe for the Events from CP */
	__subscribe_modem_notifications(p);

	dbg("Init - Successful");
	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	dbg("Unload!!!");
	tcore_check_return(p != NULL);

	/* Deinitialize Modules (Core Objects) */
	tcore_object_deinit_objects(p, &imc_deinit_table);
}

/* IMC - Modem Plug-in Descriptor */
struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "imc",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
