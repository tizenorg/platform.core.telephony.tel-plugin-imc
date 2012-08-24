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
#include <hal.h>
#include <server.h>
#include <at.h>

#include "s_common.h"
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

static char *cp_name;

static enum tcore_hook_return on_hal_send(TcoreHal *hal, unsigned int data_len, void *data, void *user_data)
{
	hook_hex_dump(TX, data_len, data);
	return TCORE_HOOK_RETURN_CONTINUE;
}

static void on_hal_recv(TcoreHal *hal, unsigned int data_len, const void *data, void *user_data)
{
	msg("=== RX data DUMP =====");
	util_hex_dump("          ", data_len, data);
	msg("=== RX data DUMP =====");
}

static gboolean on_load()
{
	dbg("i'm load!");

	return TRUE;
}

static int _get_cp_name(char** name)
{
	struct utsname u;

	char *svnet1_models[] = { "F1", "S1", "M2", "H2", "H2_SDK",
		"CRESPO", "STEALTHV", "SLP45", "Kessler", "P1P2",
		"U1SLP", "U1HD", "SLP7_C210", "SLP10_C210", NULL };

	char *svnet2_models[] = { "SMDK4410", "SMDK4212", "SLP_PQ", "SLP_PQ_LTE", "SLP_NAPLES", "REDWOOD", "TRATS", NULL };

	char* tty_models[] = {"QCT MSM8X55 SURF" , "QCT MSM7x27a FFA", NULL };

	int i=0;

	if (*name) {
		dbg("[ error ] name is not empty");
		return FALSE;
	}

	memset(&u, '\0', sizeof(struct utsname));

	uname(&u);

	dbg("u.nodename : [ %s ]", u.nodename);

	for(i=0; svnet1_models[i]; i++) {
		if (!strcmp(u.nodename, svnet1_models[i])) {
			*name = g_new0(char, 5);
			strcpy(*name, "6260");
			return 5;
		}
	}

	for(i=0; svnet2_models[i]; i++) {
		if (!strcmp(u.nodename, svnet2_models[i])) {
			*name = g_new0(char, 5);
			strcpy(*name, "6262");
			return 5;
		}
	}

	for(i=0; tty_models[i]; i++) {
		if (!strcmp(u.nodename, tty_models[i])) {
			*name = g_new0(char, 6);
			strcpy(*name, "dpram");
			return 6;
		}
	}

	dbg("[ error ] unknown model : (%s)", u.nodename);

	return 0;
}

static gboolean on_response_default(TcoreAT *at, const char *line, void *user_data)
{
	/* TODO:  */
	dbg("[ TODO ] on_response_default ");
	return TRUE;
}

static gboolean on_init(TcorePlugin *p)
{
	TcoreHal *h;
	struct global_data *gd;
	//char *cp_name = 0;
	int len = 0;

	if (!p)
		return FALSE;

	gd = calloc(sizeof(struct global_data), 1);
	if (!gd)
		return FALSE;

	dbg("i'm init!");

	gd->msg_auto_id_current = 0;
	gd->msg_auto_id_start = 1;
	gd->msg_auto_id_end = 255;

	len = _get_cp_name(&cp_name);
	if (!len) {
		dbg("[ error ] unsupport cp (name : %s)", cp_name);
		free(gd);
		return FALSE;
	}

	/* FIXME: HAL will reside in Co-object.
	 * This HAL is just used as default before MUX setup.
	 * Each HAL has AT pasre functionality.
	 */
	h = tcore_server_find_hal(tcore_plugin_ref_server(p), cp_name);
	if (!h)  {
		g_free(cp_name);
		free(gd);
		return FALSE;
	}

	//set physical hal into plugin's userdata	
	gd->hal = h;

	tcore_plugin_link_user_data(p, gd);

	tcore_hal_add_send_hook(h, on_hal_send, p);
	tcore_hal_add_recv_callback(h, on_hal_recv, p);

	dbg("skip _register_unsolicited_messages() - this should be done in each co-object");

	/* Register Unsolicited msg handler */
	//_register_unsolicited_messages(p);

	s_modem_init(p, h);
	s_sim_init(p, h);
	s_sat_init(p, h);
	s_network_init(p, h);
//	s_sap_init(p, h);
	s_ps_init(p, h);
	s_call_init(p, h);
	s_ss_init(p, h);
	s_sms_init(p, h);
//	s_phonebook_init(p, h);
//	s_gps_init(p, h);

	g_free(cp_name);

	tcore_hal_set_power(h, TRUE);
	/* SEND CPAS command to invoke modem power on. */
	s_modem_send_poweron(p);

	return TRUE;
}

static void on_unload(TcorePlugin *p)
{
	struct global_data *gd;

	if (!p)
		return;

	dbg("i'm unload");

	gd = tcore_plugin_ref_user_data(p);
	if (gd) {
		free(gd);
	}
}

struct tcore_plugin_define_desc plugin_define_desc =
{
	.name = "IMC",
	.priority = TCORE_PLUGIN_PRIORITY_MID,
	.version = 1,
	.load = on_load,
	.init = on_init,
	.unload = on_unload
};
