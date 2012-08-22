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

#define CR '\r'
#define LF '\n'



#define VNET_CH_PATH_BOOT0	"/dev/umts_boot0"
#define IOCTL_CG_DATA_SEND  _IO('o', 0x37)

/*Invalid Session ID*/
#define PS_INVALID_CID	999 /*Need to check */

/*Maximum Number of Active PDP context */
#define MAX_NUM_PS_PDP_ACTIVE_SESSION 5

/*Maximum String length Of the Command*/
#define MAX_AT_CMD_STR_LEN	150

/*Name of Packet Service */

/*ps call status*/
#define AT_SESSION_UP 1
#define AT_SESSION_DOWN 0

/*Command for PS Attach and Detach*/
#define AT_PS_ATTACH 1
#define AT_PS_DETACH 0

/*Max retry for the message*/
#define AT_MAX_RETRY_COUNT 5

/*Command for PDP activation and Deactivation*/
#define AT_PDP_ACTIVATE 1
#define AT_PDP_DEACTIVATE 0

#define AT_DUN_NOTIFICATION_ENABLE 1
#define AT_DUN_NOTIFICATION_DISABLE	0

#define AT_XDNS_ENABLE 1
#define AT_XDNS_DISABLE 0

static char addr[4];
static void _ps_free(void * ptr)
{
	dbg("Entered");
	if(ptr)
	{
		(void)free(ptr);
		ptr = NULL;
	}
	dbg("Exit");
	return;
}
static void unable_to_get_pending(CoreObject *co_ps,CoreObject *ps_context)
{
	struct tnoti_ps_call_status data_resp = {0};
	dbg("Entered");
	data_resp.context_id = tcore_context_get_id(ps_context);
	data_resp.state = AT_SESSION_DOWN;/*check value of state*/
	data_resp.result =0xFF;/*check error value*/
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
		TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_resp);
	(void)tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
	dbg("Exit");
}
static TReturn _pdp_device_control(gboolean flag, unsigned int context_id)
{
	int fd = -1;
	int ret = -1 ;
	//int errno; 
	fd = open ( VNET_CH_PATH_BOOT0, O_RDWR );
	if ( fd < 0 ) {
		dbg("error : open [ %s ] [ %s ]", VNET_CH_PATH_BOOT0, strerror(errno));
		return -1;
	}

	dbg("Send IOCTL: arg 0x05 (0101) HSIC1, cid=%d \n",context_id);
	ret = ioctl(fd, IOCTL_CG_DATA_SEND, 0x05);
	if (ret < 0) 
	{
		dbg("[ error ] send IOCTL_CG_DATA_SEND (0x%x) fail!! \n",IOCTL_CG_DATA_SEND);
		close(fd);
		return TCORE_RETURN_FAILURE;
	}
	else
	{
		dbg("[ ok ] send IOCTL_CG_DATA_SEND (0x%x) success!! \n",IOCTL_CG_DATA_SEND);
		close(fd);
		return TCORE_RETURN_SUCCESS;
	}
}

static gboolean on_event_cgev_handle(CoreObject *co_ps, const void *data, void *user_data)
{
	
	char *token = NULL;
	GSList *tokens= NULL;
    GSList *lines = NULL;
	const char *line = NULL;
	char *noti_data = NULL;
	int i = 0;
	int value = 20;
	int state = -1;

	dbg("Entered");
	lines = (GSList*)data;
	line = (const char *)lines->data;
	dbg("Lines->data :-%s",line);
	
	tokens = tcore_at_tok_new(line);
	switch(g_slist_length(tokens))
	{
		case 0:
		{
			dbg("No token present: Ignore +CGEV Notifications ");
			return TRUE;
		}
		case 1:
		{
			dbg("one Token present");
			noti_data = g_slist_nth_data(tokens, 0);
			dbg("notification data :-%s",noti_data);
			if(0 ==  strcmp(noti_data,"ME CLASS B"))
			{
				dbg("ME Class B notification received");
				goto ignore;
			}
			dbg("");
			if(0 ==  strcmp(noti_data,"NW CLASS A"))
			{
				dbg("NW Class A notification received");
				goto ignore;
			}	
			
			token = strtok(noti_data, " ");
			while(token != NULL)
			{
				if((i == 0) && (0!=  strcmp(token,"ME")))
					break;
				if((i == 1) && (0!=  strcmp(token,"PDN")))
					break;
				if((i == 2) && (0 ==  strcmp(token,"ACT")))
						state = 1;				
				if((i == 2) && (0 ==  strcmp(token,"DEACT")))
						state = 0;	
				if(i == 3 )
				{
					value = atoi(token);
					break;
				}
				
				i++;
				token = strtok(NULL, " ");
			}
			dbg("value:%d ",value);
			i = 0;
			break;
		}
		case 3:
		{
			i = 0;	
			state = 0;
			value = 0;
			dbg("Three Token present");
			noti_data = g_slist_nth_data(tokens, 0);
			dbg("notification data :-%s",noti_data);
			token = strtok(noti_data, " ");
			while(token != NULL)
			{
				if((i == 0) && (0 ==  strcmp(token,"ME")))
					state = 1;
				if((i == 1) && (0!=  strcmp(token,"DEACT")))
					break;
				if((i == 2) && (0 ==  strcmp(token,"\"IP\"")) && (0 == state))
				{
					dbg("MObile Deactiavted the Context");
					value = 10;
						break;				
				}
				if((i == 2) && (0 ==  strcmp(token,"\"IP\"")) && (1 == state))
				{
					dbg("NW Deactiavted the Context");
					value = 10;
						break;				
				}	
				i++;
				token = strtok(NULL, " ");
			}
			if(value == 10 && state == 0)
			{
				dbg("Recieved Notification for Context deactivations from network");
				noti_data = g_slist_nth_data(tokens, 1);
				dbg("PDP Address :- %s",noti_data);
				noti_data = g_slist_nth_data(tokens, 2);
				dbg("CID got deactivated :- %d",atoi(noti_data));
			}
			if(value == 10 && state == 1)
			{
				dbg("Recieved Notification for Context deactivations from Mobile");
				noti_data = g_slist_nth_data(tokens, 1);
				dbg("PDP Address :- %s",noti_data);
				noti_data = g_slist_nth_data(tokens, 2);
				dbg("CID got deactivated :- %d",atoi(noti_data));				

			}
			state = 100;
			value  = 100;
			break;
		}
		default:
		{
			dbg("Ignore +CGEV Notifications ");
			
		}
	}
	if(state == 1)
	{
		dbg("Notification recieved for Activation of CID:-%d",value);
		
	}
	else if(state == 0)
	{
		dbg("Notification recieved for Deactivation of CID:-%d",value);
		
	}
	else
	{
		dbg("ignore");
	}	
ignore:		
	tcore_at_tok_free(tokens);
	return TRUE;
		
}

#if 0 /*Not Needed Right Now*/
static void on_response_send_ps_attach (TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = NULL;
	CoreObject *ps_context = user_data;
	struct tnoti_ps_call_status resp_data;

	dbg("Entered");
	memset(&resp_data,0x0,sizeof(struct tnoti_ps_call_status));
	
	co_ps = tcore_pending_ref_core_object(p);

	if(resp->success)
	{
		dbg("Response Ok");
		/*Activating the Context */
		send_pdp_activate_cmd(co_ps,ps_context);
		return;
	}
	else
	{
		send_ps_attach_cmd(co_ps,ps_context);
		
		
		dbg("Retry Count: %d",retry_count);
		resp_data.context_id =tcore_context_get_id(ps_context);
		resp_data.state = AT_SESSION_DOWN;/*check value of state*/
		resp_data.result =0xFF;/*check error value*/
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &resp_data);
		dbg("Exit: Response NOK");
		return;
	}
}

static void send_ps_attach_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	
	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	
	(void)sprintf(cmd_str, "AT+CGATT=%d%c",AT_PS_ATTACH,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_send_ps_attach,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exit: Successfully");
	return ;	

error:
	err("Unable to create At request");
	send_undefine_context_cmd(co_ps,ps_context);
	return;	
}
static void on_response_check_ps_attach(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = NULL;
	CoreObject *ps_context = user_data;

	GSList *tokens=NULL;
	const char *line = NULL;

	co_ps = tcore_pending_ref_core_object(p);
	if(resp->final_response)
	{
		if(resp->lines)
		{
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if((g_slist_length (tokens)) < 1 )
				goto error;	
			if(atoi((char *)g_slist_nth_data(tokens,0)) == 1)
			{
				dbg("PS is Already Attached");
				send_pdp_activate_cmd(co_ps,ps_context);
			}
			else
			{
				dbg("PS is not attached:Need To send AT command To attach PS");
				send_ps_attach_cmd(co_ps,ps_context);
			}
			tcore_at_tok_free(tokens);
			return;
		}
	}
	else
	{
		
		send_check_ps_attach_cmd(co_ps,ps_context);
		
	}
error:
	
	err("Exit:Response NOK");
	tcore_at_tok_free(tokens);
	send_undefine_context_cmd(co_ps,ps_context);
	return;
}

static void send_check_ps_attach_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	
	
	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);
	
	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	
	(void)sprintf(cmd_str, "AT+CGATT?%c",CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,"+CGATT",TCORE_AT_SINGLELINE,
					on_response_check_ps_attach,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exit: Successfully");
	return;	
error:

	dbg("Unable To create At request");
	send_undefine_context_cmd(co_ps,ps_context);
	return;
}

static gboolean on_event_ps_protocol_status(CoreObject *co_ps, const void *data, void *user_data)
{
	struct tnoti_ps_protocol_status noti;
	GSList *tokens=NULL;
	const char *line = NULL;
	int value;
    	GSList *lines = NULL;

	lines = (GSList*)data;
	if (1 != g_slist_length(lines)) {
	  	dbg("unsolicited msg but multiple line");
	    goto OUT;
	}

	line = (const char *)(lines->data);
	tokens = tcore_at_tok_new(line);
	value= atoi(g_slist_nth_data(tokens, 0));	
		switch(value)
		{
			case 1:
			{
				dbg("registered, home network ");
				break;
			}	
			case 0:/*Fall through*/
			case 2:/*Fall through*/
			case 3:/*Fall through*/
			case 4:/*Fall through*/
			case 5:/*Fall through*/
			case 6:/*Fall through*/
			case 7:/*Fall through*/
			case 8:/*Fall through*/
			case 9:/*Fall through*/
			case 10:/*Fall through*/
			default:/*Fall through*/
			dbg("circuit mode registration status : %d",value);
			noti.status = TELEPHONY_HSDPA_OFF;
			tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
				TNOTI_PS_PROTOCOL_STATUS,sizeof(struct tnoti_ps_protocol_status), &noti);
			tcore_at_tok_free(tokens);	
			return TRUE;
		}	
		value= atoi(g_slist_nth_data(tokens,4));	
		switch(value)
		{
			case 4:
			{
				dbg("ACT:HSDPA");
				noti.status = TELEPHONY_HSDPA_ON;
				break;
			}
			case 5:
			{
				dbg("ACT:HSUPA");
				noti.status = TELEPHONY_HSUPA_ON;
				break;
			}
			case 6:
			{
				dbg("ACT:HSPA");
				noti.status = TELEPHONY_HSPA_ON;
				break;
			}
			case 0:/*Fall Through*/
			case 1:/*Fall Through*/
			case 2:/*Fall Through*/
			case 3:/*Fall Through*/
			default:
			{
				dbg("ACT:Unsupported ");
				goto OUT;
			}
		}
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
				TNOTI_PS_PROTOCOL_STATUS,sizeof(struct tnoti_ps_protocol_status), &noti);
OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}

static gboolean on_event_ps_call_status(CoreObject *co_ps, const void *data, void *user_data)
{
	CoreObject *ps_context = (CoreObject *)user_data;
	GSList *tokens=NULL;
    	GSList *lines = NULL;
	const char *line = NULL;
	int value;
	struct tnoti_ps_call_status data_resp;

	lines = (GSList*)data;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}

	line = (const char*)(lines->data);	
	tokens = tcore_at_tok_new(line);

	value = atoi(g_slist_nth_data(tokens,0));
	if(value == 1)
	{
		dbg("Session is resumed");
		data_resp.context_id = tcore_context_get_id(ps_context);
		data_resp.state = 1;
		data_resp.result = 0;
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_resp);
	}	
	else
	{
		dbg("Session is suspended");
		data_resp.context_id = tcore_context_get_id(ps_context);
		data_resp.state = 0;
		data_resp.result = 50;/*To Do: check exact value*/
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_resp);
		if (_pdp_device_control(FALSE, data_resp.context_id) != TCORE_RETURN_SUCCESS) {
		dbg("_pdp_device_control() failed");
		}
	}
OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;
}
static gboolean on_event_cmee_error_handle(CoreObject *co_ps, const void *data, void *user_data)
{
	struct tnoti_ps_call_status data_resp = {0};
	GSList *tokens= NULL;
    GSList *lines = NULL;
	const char *line = NULL;
	int value = 0;

	dbg("Entered");
	lines = (GSList*)data;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}

	line = (const char*)(lines->data);	
	tokens = tcore_at_tok_new(line);
	value = atoi(g_slist_nth_data(tokens,0));

	data_resp.context_id = 1;/*to do have cid extarcted */
	data_resp.state = 0;
	data_resp.result = value;
	dbg("Exiting: Sending Notification Upwards");
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_resp);
OUT:
	if(tokens)
		tcore_at_tok_free(tokens);
	dbg("Ignoring the indications ")
	return TRUE;
}
#endif
static gboolean on_event_dun_call_notification(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens=NULL;
	const char *line = NULL;
	int value;
    	GSList *lines = NULL;


	dbg("Entered");

	lines = (GSList*)data;
	if (1 != g_slist_length(lines)) {
		dbg("unsolicited msg but multiple line");
		goto OUT;
	}

	line = (char*)(lines->data);
		tokens = tcore_at_tok_new(line);
	value = atoi(g_slist_nth_data(tokens, 0));

/*
<status> may be
0: DUN activation in progress
1: DUN deactivation in progress
2: DUN activated
3: DUN deactivated
*/
		switch(value)
		{
			case 0:/*Fall Through*/
			case 1:
			break;	
			case 2:
			{
				/*To Do:- Fill Data structure : data*/
				tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
				TNOTI_PS_EXTERNAL_CALL, sizeof(struct tnoti_ps_external_call), &data);	
			}
			case 3:
			{
				/*To Do:- Fill Data structure : data*/
				tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)), o,
				TNOTI_PS_EXTERNAL_CALL, sizeof(struct tnoti_ps_external_call), &data);
			}
			break;
			default:
			goto OUT;	
		}	
OUT:
	if(NULL!=tokens)
		tcore_at_tok_free(tokens);
	return TRUE;	
}
#if 0
static void on_response_dun_call_notification(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcoreATResponse *resp = data;
	CoreObject *co_ps =  tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	
	if(resp->final_response)
	{
		dbg("Dn notification is Enabled");
				
	}
	else
	{
	
	/*To Do: Need to check that is it to be  reported*/
	dbg("Unable to set the Dun Notifications");
	dbg("Response NOK");
	}
	return;
}
/*This should be called only in case of CID == 1*/

static void send_dun_call_notification(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;

	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);
	
	(void)sprintf(cmd_str, "AT+XNOTIFYDUNSTATUS=%d%c",AT_DUN_NOTIFICATION_ENABLE,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_dun_call_notification,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	return ;
error:	
	/*To Do: Need to check that is it to be  reported*/
		dbg("Unable to set the Dun Notifications");
	return;
}

static int find_free_tbl_entry(CoreObject *co_ps,int cid, struct context *loc[])
{
	struct context *tbl = tcore_object_ref_user_data(co_ps);
	dbg("Entered");
	*loc = tbl + cid;
	if(tbl->isvalid == 0)
	{
		dbg("Entry is free");
		return 1;
	}
	else
	{
		dbg("PDP session is already defined ");
		return 0;
	}
}

#endif /*Not Needed Right Now*/
static void on_response_undefine_context_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = NULL;
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = user_data;
	
	dbg("Entered");
	co_ps = tcore_pending_ref_core_object(p);
	
	if(resp->success)
	{
		dbg("Response Ok");
		/*getting the IP address and DNS from the modem*/
	}
	dbg("Response NOk");
	unable_to_get_pending(co_ps,ps_context);
	return;
}

static void send_undefine_context_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	int cid = 0;

	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	
	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);

	(void)sprintf(cmd_str, "AT+CGDCONT=%d%c",cid,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_undefine_context_cmd,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exit: Successfully");
	return ;

error:
	{
		dbg("Exit: With error");
		unable_to_get_pending(co_ps,ps_context);
		return;
	}
}
static void on_response_data_counter_command(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *ps_context = user_data;
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);

	
	GSList *tokens=NULL;
	GSList *pRespData; 
	const char *line = NULL;

	int no_pdp_active =0;
	int loc = 0;
	unsigned long long Rx;
	unsigned long long Tx;
	int cid = tcore_context_get_id(ps_context);	
	dbg("Entered");
	
	if(resp->final_response)
	{
		dbg("Response OK");
		dbg(" response lines : -%s",resp->lines);
		if(resp->lines) {

			pRespData =  (GSList*)resp->lines;
			no_pdp_active = g_slist_length(pRespData);
			dbg("Total Number of Active PS Context :- %d",no_pdp_active);

			if(no_pdp_active == 0)
				return;
			while(pRespData)
			{
				dbg("Entered the Loop pRespData");

				line = (const char*)pRespData->data;
				dbg("Response->lines->data :%s",line);
				tokens = tcore_at_tok_new(line);	
				if(cid == atoi(g_slist_nth_data(tokens, 0)))
				{
					dbg("Found the data for our CID");
					Tx = (unsigned long long)g_ascii_strtoull((g_slist_nth_data(tokens,1)), NULL, 10);
					dbg("Tx: %d", Tx);

					Rx = (unsigned long long)g_ascii_strtoull((g_slist_nth_data(tokens, 2)), NULL, 10);
					dbg("Rx: %d", Rx);
				
				tcore_at_tok_free(tokens);
				tokens = NULL;
				dbg("Exiting the Loop pRespData");
				break;
				}
			tcore_at_tok_free(tokens);
			tokens = NULL;
			pRespData= pRespData->next;
			
		}
		dbg("Sending Data counter notifications");	
		
		tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
				TNOTI_PS_CURRENT_SESSION_DATA_COUNTER, 0, NULL);
			return;
		}
		else
		{
			dbg("No Active PS Context");
		}
	}
	
	dbg("Response NOK");
ERROR:	/* TODO : What to send to TAPI in failure case? */
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CURRENT_SESSION_DATA_COUNTER, 0, NULL);
	return;
}

static void send_data_counter_command(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;

	dbg("Enetered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);
	
	(void)sprintf(cmd_str, "AT+XGCNTRD%c",CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,"+XGCNTRD",TCORE_AT_MULTILINE,
					on_response_data_counter_command,ps_context );
	if(NULL == pending)
	{
		goto error;
	}
	tcore_pending_set_response_callback(pending, on_response_data_counter_command,ps_context);
	tcore_hal_send_request(hal, pending);
	dbg("Exit : Successfully");
	return ;
error:
	/*Unable to create At request Still the Context is deactivated*/
	err("Unable to create AT request");
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CURRENT_SESSION_DATA_COUNTER, 0,NULL);
	return ;
/*Add code if unable to get the data usage*/
}
static void on_response_deactivate_ps_context(TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	const TcoreATResponse *resp = data;
	int cid ;

	cid = tcore_context_get_id(ps_context);
	if(resp->success)
	{
		dbg("Response OK");
		/*get the data usage and report it application*/
		(void)tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
		send_data_counter_command(co_ps,ps_context);
		
		/*get the HSDPA status and report it to server*/
	}
	else
	{
		dbg("Response NOK");
		_pdp_device_control(TRUE, cid);
		send_undefine_context_cmd(co_ps,ps_context);
	}
	return;
}

static TReturn deactivate_ps_context(CoreObject *co_ps, CoreObject *ps_context, void *user_data)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	unsigned int cid = PS_INVALID_CID;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	struct context *tbl_entry = NULL;
	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);
	
	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	
	tbl_entry = tcore_object_ref_user_data(co_ps);
	
	(void)sprintf(cmd_str, "AT+CGACT=%d,%d%c",AT_PDP_DEACTIVATE,cid,CR);
	dbg("At commands :- %s",cmd_str);

	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_deactivate_ps_context,ps_context );
	if(NULL == pending)
		return TCORE_RETURN_FAILURE;
	
	tcore_hal_send_request(hal, pending);
	(void)tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATING);
	return TCORE_RETURN_SUCCESS;
}

static void on_response_get_dns_cmnd(TcorePending *p, int data_len, const void *data, void *user_data)
{

	int i;
	int loc;	
	int num_tokens;
	int tok_pos = 0;
	struct tnoti_ps_pdp_ipconfiguration noti = {0};
	struct tnoti_ps_call_status data_status = {0};
	char devname[10] = {0,};
	char s_cid[4];
	int found = 0;
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	//const char *addr;

	
	
	GSList *tokens= NULL;
	const char *line = NULL;
	char *token_add = NULL;
	char *token_dns = NULL;
	char dns[50] = {0}; /* 3 characted for each IP address value: 12 for IPv4, 48 for IP6*/;
	
	int cid = tcore_context_get_id(ps_context);

	dbg("Entered");

	(void)sprintf(s_cid,"%d%s",cid,"\0");
#if 1	
	if(resp->final_response)
	{
		dbg("RESPONSE OK");

		if(resp->lines) 
		{
			dbg("Resp->lines present");
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			num_tokens = g_slist_length(tokens);
			if ( num_tokens < 2) 
			{
				msg("invalid message");
				goto exit_case;
			}
			while(tok_pos < num_tokens)
			{
				if(cid == atoi(g_slist_nth_data(tokens,tok_pos)))
				{
					dbg("match found for the CID");	
					found = tok_pos;
					break;
				}
				tok_pos = tok_pos + 3;
				found = 0;
			}
			if(found != tok_pos )
				goto exit_case;
						
			{ /* Read primary DNS */
				token_dns = g_slist_nth_data(tokens, tok_pos + 1);
				/* Strip off starting " and ending " from this token to read actual PDP address */
				strncpy(dns, token_dns+1, strlen(token_dns)-2);
				dbg("Token_dns :%s",token_dns);
				dbg("DNS :- %s",dns);
				i = 0;
				token_add = strtok(dns, ".");
				while(token_add != NULL)
				{
						noti.primary_dns[i++]= atoi(token_add);
						token_add = strtok(NULL, ".");
				}
				//_ps_free(token_add);// This is just reference point, not actual pointer allocated in this function.
			}
			{ /* Read Secondary DNS */
				memset(dns,0x0,50);
				token_dns = g_slist_nth_data(tokens, loc+1);
				/* Strip off starting " and ending " from this token to read actual PDP address */
				strncpy(dns, token_dns+1, strlen(token_dns)-2);

				dbg("Token_dns :%s",token_dns);
				dbg("DNS :- %s",dns);
				i = 0;
				token_add = strtok(dns, ".");
				while(token_add != NULL)
				{
					noti.secondary_dns[i++]= atoi(token_add);
					token_add = strtok(NULL, ".");
				}
				//_ps_free(token_add);.// This is just reference point, not actual pointer allocated in this function.
			}
			
			/*To DO :  Add Code to notify the the Tapi*/
		}
	goto send;	
	}
	else
	{
		dbg("Respons NOK");
		dbg("unable to DNS address so static assigning it");

		/*To Do :- Add code if only One DNS Found*/
	}
#endif
#if 0
#else
exit_case:
	dbg("Adding default DNS");
	tcore_at_tok_free(tokens);
	dbg("Adding the Primary DNS");
	noti.primary_dns[0] = 8;
	noti.primary_dns[1] = 8;
	noti.primary_dns[2] = 8;
	noti.primary_dns[3] = 8;
	dbg("Adding Secondary DNS");
	noti.secondary_dns[0] = 8;
	noti.secondary_dns[1] = 8;
	noti.secondary_dns[2] = 4;
	noti.secondary_dns[3] = 4;

#endif
	
	/* fileds: 
	0x0001 -> IP address
	0x0002 -> Primany DNS
	0x0003 -> Seconday DNS
	*/
send:	
	dbg("Adding flag");
	noti.field_flag = (0x0001 & 0x0002 & 0x0004);
	dbg("Adding Error if Present");
	noti.err = 0;
	noti.context_id = cid;
	dbg("ADDING IP address");
#if 0
	addr = tcore_context_get_address(ps_context);
	memcpy(&noti.ip_address, &addr, 4);
	_ps_free((void *)addr);
#else
	memcpy(&noti.ip_address, &addr, 4);
#endif
	if (_pdp_device_control(TRUE, cid) != TCORE_RETURN_SUCCESS) 
	{
		dbg("_pdp_device_control() failed. errno=%d", errno);
	}
	snprintf(devname, 10, "pdp%d", cid - 1);
	memcpy(noti.devname, devname, 10);
	dbg("devname = [%s]", devname);
	if (tcore_util_netif_up(devname) != TCORE_RETURN_SUCCESS) 
	{
		dbg("util_netif_up() failed. errno=%d", errno);
	}

	dbg("Send Notification upwards of IP address");
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps, TNOTI_PS_PDP_IPCONFIGURATION,
		sizeof(struct tnoti_ps_pdp_ipconfiguration), &noti);

	data_status.context_id = cid;
	data_status.state = 1;
	data_status.result = 0 ;

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
			TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_status);
	dbg("EXIT : Without error");
	return;
}

static void send_get_dns_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	struct tnoti_ps_call_status data = {0};

	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	dbg("Entered");
	hal = tcore_object_get_hal(co_ps);

	(void)sprintf(cmd_str, "AT+XDNS?%c",CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,"+XDNS",TCORE_AT_MULTILINE,
					on_response_get_dns_cmnd,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exit Successfully");
	return ;
error:	
	/*unable to get Ip address so closing the PDP session*/
	dbg("Unable to get the pending");	
	
	data.context_id =tcore_context_get_id(ps_context);
	data.state = AT_SESSION_DOWN;/*check value of state*/
	data.result =0xFF;/*check error value*/
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
	TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data);
	dbg("Exit : Error");
	return;
}

static void on_response_get_pdp_address(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_ps =  tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	int i = 0;
	GSList *tokens=NULL;
	const char *line;
	char *token_pdp_address;
	char *token_add;
	char pdp_address[50] = {0}; /* 3 characted for each IP address value: 12 for IPv4, 48 for IP6*/
	//char addr[4];
	dbg("Enetered");
	if(resp->final_response)
	{
		dbg("RESPONSE OK");
		if(resp->lines != NULL) 
		{
			dbg("resp->lines present ");
			line = (const char*)resp->lines->data;
			tokens = tcore_at_tok_new(line);
			if (g_slist_length(tokens) < 2) 
			{
				msg("invalid message");
				goto error;
			}
			dbg("line:- %s",line);
			/* CID is already stored in ps_context, skip over & read PDP address */
			token_pdp_address = g_slist_nth_data(tokens, 1);

			dbg("token_pdp_address :- %s",token_pdp_address);
			/* Strip off starting " and ending " from this token to read actual PDP address */
			strncpy(pdp_address, token_pdp_address+1, strlen(token_pdp_address)-2);
			dbg("PDP address :- %s",pdp_address);
			/* Store IP address in char array, Telephony expected IP address in this format */
			token_add = strtok(pdp_address, ".");
			i = 0;
			while((token_add != NULL) && (i<4)) /* Currently only IPv4 is supported */
			{
				addr[i++]= atoi(token_add);
				token_add = strtok(NULL, ".");
			}
			dbg("PDP address:- %s",addr);
			}
		//tcore_context_set_address(ps_context,(const char *)addr);
		send_get_dns_cmd(co_ps,ps_context);
	}
	else
	{
		dbg("Response NOK");
		/*without PDP address we will not be able to start packet service*/
		(void)deactivate_ps_context(co_ps,ps_context,NULL);
	}
	error:	
	tcore_at_tok_free(tokens);
}

static void send_get_pdp_address_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	unsigned int cid = PS_INVALID_CID;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};
	struct tnoti_ps_call_status data_resp = {0};
	dbg("Entered");
	hal = tcore_object_get_hal(co_ps);

	cid = tcore_context_get_id(ps_context);
	(void)sprintf(cmd_str, "AT+CGPADDR=%d%c",cid,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,"+CGPADDR",TCORE_AT_SINGLELINE,
					on_response_get_pdp_address,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exiting Successfully");
	return ;

error:
		/*unable to get pending*/
		dbg("Unable to get the pending");	
		unable_to_get_pending(co_ps,ps_context);
		dbg("Exit : Error");
		return;
}

static void on_response_send_pdp_activate_cmd (TcorePending *p, int data_len, const void *data, void *user_data)
{
	CoreObject *co_ps = NULL;
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = user_data;
	
	int cid;
	cid = tcore_context_get_id(ps_context);

	
	dbg("Entered");
	if(!p)
		goto error;
		
	co_ps = tcore_pending_ref_core_object(p);
	
	if(resp->success)
	{
		dbg("Response Ok");
		/*getting the IP address and DNS from the modem*/
		dbg("Getting the IP Address");
		send_get_pdp_address_cmd(co_ps,ps_context);
		return;
	}
	else
	{	
		
		dbg("Unable to actiavte PDP context for CID: %d ",cid);
		dbg("Undefineing the PDP context");
		(void)tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
		send_undefine_context_cmd(co_ps,ps_context);
	}
	return;

error:
	{
		unable_to_get_pending(co_ps,ps_context);
		return;
	}
}

static void send_pdp_activate_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};
	int cid = 0;
	dbg("Entered");
	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	
	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);
	(void)sprintf(cmd_str, "AT+CGACT=%d,%d%c",AT_PDP_ACTIVATE,cid,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_send_pdp_activate_cmd,ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	
	tcore_hal_send_request(hal, pending);
	dbg("Exit: Successfully");
	return ;
	
error:
	{
		dbg("Unable to get the pending");
		unable_to_get_pending(co_ps,ps_context);
		return;
	}
}

static void on_response_xdns_enable_cmd(TcorePending *p, int data_len, const void *data, void *user_data)
{
	TcoreATResponse *resp = (TcoreATResponse *)data;
	CoreObject *co_ps =  tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	dbg("Entered");
	if(resp->success)
	{
		dbg("Response OK");
		dbg("DNS address getting is Enabled");
	}
	else
	{
		dbg("Response NOK");
		/*If response to enable the DNS NOK then we will use google DNS for the PDP context*/
	}
	send_pdp_activate_cmd(co_ps, ps_context);
	dbg("Exiting");
	return;	
}

static void send_xdns_enable_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	int cid = -1 ;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	
	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);
	cid = tcore_context_get_id(ps_context);

	(void)sprintf(cmd_str, "AT+XDNS=%d,%d%c",cid,AT_XDNS_ENABLE,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str, NULL, TCORE_AT_NO_RESULT,
					on_response_xdns_enable_cmd, ps_context );
	if(NULL == pending)
	{
		err("Unable to get the create a AT request ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	dbg("Exiting Successfully");
	return ;

error:
	dbg("Unable to create pending for the AT Request");
	unable_to_get_pending(co_ps,ps_context);
	return;
}

static void on_response_define_pdp_context(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *ps_context = (CoreObject *)user_data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
		
	dbg("Entered");
	if(resp->success)
	{
		dbg("Response OK");
		send_xdns_enable_cmd(co_ps,ps_context);
	}
	else
	{
		dbg("response NOK");
		unable_to_get_pending(co_ps,ps_context);
	}
	dbg("Exiting");
	return;
}

static TReturn send_define_pdp_context_cmd(CoreObject *co_ps, CoreObject *ps_context)
{
	
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char *apn = NULL;
	char *addr = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ={0} ;
	char pdp_type_str[10] = {0};
	unsigned int cid = PS_INVALID_CID;
	enum co_context_type pdp_type;
	enum co_context_d_comp d_comp;
	enum co_context_h_comp h_comp;
		
	dbg("Entered");

	cid = tcore_context_get_id(ps_context);
	
	pdp_type = tcore_context_get_type(ps_context);
	d_comp = tcore_context_get_data_compression(ps_context);
	h_comp = tcore_context_get_header_compression(ps_context);
	apn = tcore_context_get_apn(ps_context);
	//addr = tcore_context_get_address(ps_context);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);
	switch(pdp_type)
	{
		case CONTEXT_TYPE_X25:
		{
			dbg("CONTEXT_TYPE_X25");
			strcpy(pdp_type_str,"X.25");
			break;
		}
		case CONTEXT_TYPE_IP:
		{
			dbg("CONTEXT_TYPE_IP");
			strcpy(pdp_type_str,"IP");
		}
		break;
		case CONTEXT_TYPE_PPP:
		{
			dbg("CONTEXT_TYPE_PPP");
			strcpy(pdp_type_str,"PPP");
		}
		break;
		case CONTEXT_TYPE_IPV6:
		{
			dbg("CONTEXT_TYPE_IPV6");
			strcpy(pdp_type_str,"IPV6");
			break;
		}
		default :
		{
			/*PDP Type not supported supported*/
			dbg("Unsupported PDP type :- %d returning ",pdp_type);
			goto error;
		}
	}
	dbg("Activating context for CID :- %d",cid);
	if(addr)
		(void)sprintf(cmd_str, "AT+CGDCONT=%d,\"%s\",\"%s\",%s,%d,%d%c",cid,pdp_type_str,apn,addr,d_comp,h_comp,CR);
	else
		(void)sprintf(cmd_str, "AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d%c",cid,pdp_type_str,apn,d_comp,h_comp,CR);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_define_pdp_context,ps_context );
	
	if(NULL == pending)
	{
		dbg("Unable to get the create a Pending ");
		goto error;
	}
	tcore_hal_send_request(hal, pending);
	(void)tcore_context_set_state(ps_context, CONTEXT_STATE_ACTIVATING);
	return TCORE_RETURN_SUCCESS;
	
error:
	{
		unable_to_get_pending(co_ps,ps_context);
		return TCORE_RETURN_FAILURE;
	}
}

static TReturn activate_ps_context(CoreObject *co_ps, CoreObject *ps_context, void *user_data)
{
	dbg("Entered");
	return send_define_pdp_context_cmd(co_ps,ps_context);
}


static struct tcore_ps_operations ps_ops =
{
	.activate_context = activate_ps_context,
	.deactivate_context = deactivate_ps_context
};

gboolean s_ps_init(TcorePlugin *p,TcoreHal *hal)
{
	CoreObject *o;
	struct context *context_table = NULL;

	dbg("Entered");
	o = tcore_ps_new(p,"umts_ps", &ps_ops, hal);

	if (!o)
		return FALSE;
	tcore_object_link_user_data(o, (void *)context_table);
	
	tcore_object_add_callback(o, "+CGEV", on_event_cgev_handle,p);
	tcore_object_add_callback(o, "+XNOTIFYDUNSTATUS", on_event_dun_call_notification, p);
	
	dbg("Exiting");
	return TRUE;
}

void s_ps_exit(TcorePlugin *p)
{
	CoreObject *o;

	dbg("Entered");
	o = tcore_plugin_ref_core_object(p,"umts_ps");
	if (!o)
		return;
	
	tcore_ps_free(o);
	dbg("Exiting");
}


