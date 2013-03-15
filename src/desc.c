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
#include <sys/utsname.h>
#include <glib.h>
#include <tcore.h>
#include <plugin.h>
#include <core_object.h>
#include <hal.h>
#include <at.h>
#include <server.h>

#include "s_network.h"
#include "s_modem.h"
#include "s_sim.h"
#include "s_sap.h"
#include "s_ps.h"
#include "s_call.h"
#include "s_ss.h"
#include "s_sms.h"
#include "s_sat.h"
#include "s_phonebook.h"
#include "s_gps.h"


static gboolean on_load()
{
	dbg("i'm load!");

	return TRUE;
}

static void on_confirmation_modem_message_send(TcorePending *p,
						gboolean result,
						void *user_data)
{
	dbg("msg out from queue");

	dbg("%s", result == FALSE ? "SEND FAIL" : "SEND OK");
}

static void on_response_bootup_subscription(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcorePlugin *plugin = user_data;
	const TcoreATResponse *resp = data;

	dbg("Entry");

	if (resp->success > 0) {
		dbg("result OK");
	} else {
		dbg("result ERROR");
	}

	if (plugin != NULL)
		modem_power_on(plugin);
}

static void modem_subscribe_events(TcorePlugin *plugin)
{
	CoreObject *co_call = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_CALL);
	CoreObject *co_sim = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SIM);
	CoreObject *co_sms = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SMS);
	CoreObject *co_modem = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_MODEM);
	CoreObject *co_network = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_NETWORK);
	CoreObject *co_ps = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_PS);
	CoreObject *co_sap = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_SAP);
	CoreObject *co_gps = tcore_plugin_ref_core_object(plugin, CORE_OBJECT_TYPE_GPS);

	dbg("Entry");

	/* XCALLSTAT subscription */
	tcore_prepare_and_send_at_request(co_call, "at+xcallstat=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* XSIMSTATE subscription */
	tcore_prepare_and_send_at_request(co_sim, "at+xsimstate=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	tcore_prepare_and_send_at_request(co_sms, "at+xsimstate=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);
	tcore_prepare_and_send_at_request(co_modem, "at+xsimstate=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CREG subscription */
	tcore_prepare_and_send_at_request(co_network, "at+creg=2", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CGREG subscription */
	tcore_prepare_and_send_at_request(co_network, "at+cgreg=2", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* Allow automatic time Zone updation via NITZ */
	tcore_prepare_and_send_at_request(co_network, "at+ctzu=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* TZ, time & daylight changing event reporting subscription */
	tcore_prepare_and_send_at_request(co_network, "at+ctzr=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* XMER subscription */
	tcore_prepare_and_send_at_request(co_network, "at+xmer=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CGEREP subscription */
	tcore_prepare_and_send_at_request(co_ps, "at+cgerep=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* XDATASTAT subscription */
	tcore_prepare_and_send_at_request(co_ps, "at+xdatastat=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CSSN subscription */
	tcore_prepare_and_send_at_request(co_call, "at+cssn=1,1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CUSD subscription */
	tcore_prepare_and_send_at_request(co_call, "at+cusd=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* XDNS subscription */
	tcore_prepare_and_send_at_request(co_ps, "at+xdns=1,1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* CLIP subscription */
	tcore_prepare_and_send_at_request(co_call, "at+clip=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/*CMEE subscription for ps*/
	tcore_prepare_and_send_at_request(co_ps, "at+cmee=2", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/*CMEE subscription for sms*/
	tcore_prepare_and_send_at_request(co_sms, "at+cmee=2", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/*incoming sms,cb,status report subscription*/
	tcore_prepare_and_send_at_request(co_sms, "at+cnmi=1,2,2,1,0", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* XBCSTAT subscription */
	tcore_prepare_and_send_at_request(co_sap, "at+xbcstat=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL, 
						on_confirmation_modem_message_send, NULL);
	/* AGPS- assist data and reset assist data subscription */
	tcore_prepare_and_send_at_request(co_gps, "at+cposr=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	tcore_prepare_and_send_at_request(co_gps, "at+xcposr=1", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, NULL,
						on_confirmation_modem_message_send, NULL);

	/* text/pdu mode subscription*/
	tcore_prepare_and_send_at_request(co_sms, "at+cmgf=0", NULL, TCORE_AT_NO_RESULT, NULL,
						on_response_bootup_subscription, plugin,
						on_confirmation_modem_message_send, NULL);

	dbg("Exit");
}

struct object_initializer init_table = {
	.modem_init = s_modem_init,
	.sim_init = s_sim_init,
	.sat_init = s_sat_init,
	.sap_init = s_sap_init,
	.network_init = s_network_init,
	.ps_init = s_ps_init,
	.call_init = s_call_init,
	.ss_init = s_ss_init,
	.sms_init = s_sms_init,
	.phonebook_init = s_phonebook_init,
	.gps_init = s_gps_init,
};

struct object_deinitializer deinit_table = {
	.modem_deinit = s_modem_exit,
	.sim_deinit = s_sim_exit,
	.sat_deinit = s_sat_exit,
	.sap_deinit = s_sap_exit,
	.network_deinit = s_network_exit,
	.ps_deinit = s_ps_exit,
	.call_deinit = s_call_exit,
	.ss_deinit = s_ss_exit,
	.sms_deinit = s_sms_exit,
	.phonebook_deinit = s_phonebook_exit,
	.gps_deinit = s_gps_exit,
};

static gboolean on_init(TcorePlugin *p)
{
	CoreObject *co_modem;
	if (!p)
		return FALSE;

	if (tcore_object_init_objects(p, &init_table)
			!= TCORE_RETURN_SUCCESS) {
		err("Failed to initialize Core Objects");
		return FALSE;
	}

	dbg("i'm init!");
	co_modem = tcore_plugin_ref_core_object(p, CORE_OBJECT_TYPE_MODEM);
	tcore_server_send_notification(tcore_plugin_ref_server(p), co_modem, TNOTI_MODEM_ADDED, 0, NULL);
	modem_subscribe_events(p);

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	if (!p)
		return;

	tcore_object_deinit_objects(p, &deinit_table);

	dbg("i'm unload");
}

struct tcore_plugin_define_desc plugin_define_desc = {
	.name = "IMC",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
