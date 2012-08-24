/**
 * tel-plugin-samsung
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Contact: Arun Shukla <arun.shukla@samsung.com>
 *
 * PROPRIETARY/CONFIDENTIAL
 *
 * This software is the confidential and proprietary information of SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall
 * use it only in accordance with the terms of the license agreement you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not
 * limited to the implied warranties of merchantability, fitness for a particular purpose, or non-infringement.
 * SAMSUNG shall not be liable for any damages suffered by licensee as
 * a result of using, modifying or distributing this software or its derivatives.
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



#define VNET_CH_PATH_BOOT0	"/dev/umts_boot0"
#define IOCTL_CG_DATA_SEND  _IO('o', 0x37)

/*Invalid Session ID*/
#define PS_INVALID_CID	999 /*Need to check */

/*Maximum String length Of the Command*/
#define MAX_AT_CMD_STR_LEN	150

/*Command for PDP activation and Deactivation*/
#define AT_PDP_ACTIVATE 1
#define AT_PDP_DEACTIVATE 0

#define AT_XDNS_ENABLE 1
#define AT_XDNS_DISABLE 0
#define AT_SESSION_DOWN 0
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
static void _unable_to_get_pending(CoreObject *co_ps,CoreObject *ps_context)
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
static TReturn _pdp_device_control(unsigned int cid)
{
	int fd = -1;
	int ret = -1;
	fd = open ( VNET_CH_PATH_BOOT0, O_RDWR );
	if(fd < 0)
	{
		dbg("error : open [ %s ] [ %s ]", VNET_CH_PATH_BOOT0, strerror(errno));
		return -1;
	}
	/*To Do for different Cids*/
	dbg("Send IOCTL: arg 0x05 (0101) HSIC1, cid=%d \n",cid);
	if(cid == 1)
	{
		ret = ioctl(fd, IOCTL_CG_DATA_SEND, 0x05);
	}
	else if(cid == 2)
	{
		ret = ioctl(fd, IOCTL_CG_DATA_SEND, 0xA);
	}
	else
	{
		dbg("More Than 2 context are not supported right Now");
	}
	close(fd);
	if (ret < 0)
	{
		dbg("[ error ] send IOCTL_CG_DATA_SEND (0x%x) fail!! \n",IOCTL_CG_DATA_SEND);
		return TCORE_RETURN_FAILURE;
	}
	else
	{
		dbg("[ ok ] send IOCTL_CG_DATA_SEND (0x%x) success!! \n",IOCTL_CG_DATA_SEND);
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
	struct tnoti_ps_call_status data_resp = {0};

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
				if(0 ==  strcmp(noti_data,"NW CLASS A"))
				{
					dbg("NW Class A notification received");
					goto ignore;
				}
				token = strtok(noti_data, " ");
				while(token != NULL)
				{
					if((i == 0) && (0!=  strcmp(token,"ME")))
					{
						break;
					}
					if((i == 1) && (0!=  strcmp(token,"PDN")))
					{
						break;
					}
					if((i == 2) && (0 ==  strcmp(token,"ACT")))
					{
						state = 1;
					}
					if((i == 2) && (0 ==  strcmp(token,"DEACT")))
					{
						state = 0;
					}
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
					{
						state = 1;
					}
					if((i == 1) && (0!=  strcmp(token,"DEACT")))
					{
						break;
					}
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
				data_resp.context_id = atoi(noti_data);
				data_resp.state = 3;/*check value of state*/
				dbg("State of the service :- %d",data_resp.state);
				data_resp.result =0xFF;/*check error value*/
				dbg("Sending the notification");
				tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(co_ps)), co_ps,
				TNOTI_PS_CALL_STATUS, sizeof(struct tnoti_ps_call_status), &data_resp);
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

static gboolean on_event_dun_call_notification(CoreObject *o, const void *data, void *user_data)
{
	GSList *tokens=NULL;
	const char *line = NULL;
	int value = 0;
	GSList *lines = NULL;
	dbg("Entered");

	lines = (GSList*)data;
	if (1 != g_slist_length(lines))
	{
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
		{
			break;
		}
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
	{
		tcore_at_tok_free(tokens);
	}
	return TRUE;
}
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
	_unable_to_get_pending(co_ps,ps_context);
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

	(void)sprintf(cmd_str, "AT+CGDCONT=%d",cid);
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
		_unable_to_get_pending(co_ps,ps_context);
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
	unsigned long long Rx;
	unsigned long long Tx;
	int cid = tcore_context_get_id(ps_context);
	dbg("Entered");

	if(resp->final_response)
	{
		dbg("Response OK");
		dbg(" response lines : -%s",resp->lines);
		if(resp->lines)
		{
			pRespData =  (GSList*)resp->lines;
			no_pdp_active = g_slist_length(pRespData);
			dbg("Total Number of Active PS Context :- %d",no_pdp_active);

			if(no_pdp_active == 0)
			{
				return;
			}
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
}

static TReturn send_data_counter_command(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;

	dbg("Enetered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);

	(void)sprintf(cmd_str, "AT+XGCNTRD");
	pending = tcore_at_pending_new(co_ps,cmd_str,"+XGCNTRD",TCORE_AT_MULTILINE,
					on_response_data_counter_command,ps_context );
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
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
		(void)send_data_counter_command(co_ps,ps_context);
		/*get the HSDPA status and report it to server*/
	}
	else
	{
		dbg("Response NOK");
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

	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	/*Getting Context ID from Core Object*/
	cid = tcore_context_get_id(ps_context);

	/* FIXME: Before MUX setup, use PHY HAL directly. */
	hal = tcore_object_get_hal(co_ps);

	(void)sprintf(cmd_str, "AT+CGACT=%d,%d",AT_PDP_DEACTIVATE,cid);
	dbg("At commands :- %s",cmd_str);

	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_deactivate_ps_context,ps_context );
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		(void)tcore_context_set_state(ps_context,CONTEXT_STATE_DEACTIVATING);
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
}

static void on_response_get_dns_cmnd(TcorePending *p, int data_len, const void *data, void *user_data)
{

	struct tnoti_ps_pdp_ipconfiguration noti = {0};
	struct tnoti_ps_call_status data_status = {0};
	char devname[10] = {0,};
	char dns[50] = {0}; /* 3 characted for each IP address value: 12 for IPv4, 48 for IP6*/
	char pdp_address[50]={0};
	char addr[4]= {0};
	GSList *tokens=NULL;
	GSList *pRespData;
	const char *line = NULL;
	char *token_dns = NULL;
	char *token_add = NULL;

	char *token_pdp_address = NULL;
	int no_pdp_active =0;
	int index = 0;

	CoreObject *ps_context = user_data;
	const TcoreATResponse *resp = data;
	CoreObject *co_ps = tcore_pending_ref_core_object(p);
	int cid = tcore_context_get_id(ps_context);

	dbg("Entered");

	if(resp->final_response)
	{
		dbg("Response OK");
		if(resp->lines)
		{
			dbg("DNS data present in the Response");
			pRespData =  (GSList*)resp->lines;
			no_pdp_active = g_slist_length(pRespData);
			dbg("Total Number of Active PS Context :- %d",no_pdp_active);
			if(0 == no_pdp_active)
			{
				goto exit_fail;
			}
			while(pRespData)
			{
				dbg("traversing the DNS data for each active context");
				line = (const char*)pRespData->data;
				dbg("Response->lines->data :%s",line);
				tokens = tcore_at_tok_new(line);
				if(cid == atoi(g_slist_nth_data(tokens, 0)))
				{
					dbg("Found the DNS details for the Current context");
					dbg("Context Id of The Context : %d",atoi(g_slist_nth_data(tokens, 0)));
					break;
				}
				tcore_at_tok_free(tokens);
				tokens = NULL;
				pRespData= pRespData->next;
			}
			{ /* Read primary DNS */
				token_dns = g_slist_nth_data(tokens,1);
				/* Strip off starting " and ending " from this token to read actual PDP address */
				strncpy(dns, token_dns+1, strlen(token_dns)-2);
				dbg("Token_dns :%s",token_dns);
				dbg("Primary DNS :- %s",dns);
				index = 0;
				token_add = strtok(dns, ".");
				while(token_add != NULL)
				{
					noti.primary_dns[index++]= atoi(token_add);
					token_add = strtok(NULL, ".");
				}
			}
			{ /* Read Secondary DNS */
				memset(dns,0x0,50);
				token_add = NULL;
				token_dns = g_slist_nth_data(tokens,2);
				/* Strip off starting " and ending " from this token to read actual PDP address */
				strncpy(dns, token_dns+1, strlen(token_dns)-2);

				dbg("Token_dns :%s",token_dns);
				dbg("Secondary DNS :- %s",dns);
				index = 0;
				token_add = strtok(dns, ".");
				while(token_add != NULL)
				{
					noti.secondary_dns[index++]= atoi(token_add);
					token_add = strtok(NULL, ".");
				}
			}
			tcore_at_tok_free(tokens);
			tokens = NULL;
			goto exit_success;
		}
		else
		{
			dbg("No data present in the Response");
		}

	}
	dbg("Response NOK");
	exit_fail:
	{
		dbg("Adding default DNS");
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
	}
	exit_success:
	{
		dbg("Able to get the DNS from the DNS Query");
		token_pdp_address = tcore_context_get_address(ps_context);
		strncpy(pdp_address, token_pdp_address+1, strlen(token_pdp_address)-2);
		_ps_free((void *)token_pdp_address);
		dbg("PDP address :- %s",pdp_address);
		/* Store IP address in char array, Telephony expected IP address in this format */
		token_add = strtok(pdp_address, ".");
		index = 0;
		while((token_add != NULL) && (index<4)) /* Currently only IPv4 is supported */
		{
			addr[index++]= atoi(token_add);
			token_add = strtok(NULL, ".");
		}
		noti.field_flag = (0x0001 & 0x0002 & 0x0004);
		noti.err = 0;
		noti.context_id = cid;
		memcpy(&noti.ip_address, &addr, 4);
		if (_pdp_device_control(cid) != TCORE_RETURN_SUCCESS)
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
}

static TReturn send_get_dns_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	char cmd_str[MAX_AT_CMD_STR_LEN] ;
	
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	dbg("Entered");
	hal = tcore_object_get_hal(co_ps);

	(void)sprintf(cmd_str, "AT+XDNS?");
	pending = tcore_at_pending_new(co_ps,cmd_str,"+XDNS",TCORE_AT_MULTILINE,
					on_response_get_dns_cmnd,ps_context );
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
}

static void on_response_get_pdp_address(TcorePending *p, int data_len, const void *data, void *user_data)
{
	const TcoreATResponse *resp = data;
	CoreObject *co_ps =  tcore_pending_ref_core_object(p);
	CoreObject *ps_context = user_data;
	GSList *tokens=NULL;
	const char *line;
	char *token_pdp_address;
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
			(void)tcore_context_set_address(ps_context,(const char *)token_pdp_address);
		}

		(void)send_get_dns_cmd(co_ps,ps_context);
	}
	else
	{
		dbg("Response NOK");
		/*without PDP address we will not be able to start packet service*/
		(void)deactivate_ps_context(co_ps,ps_context,NULL);
	}
	error:
	tcore_at_tok_free(tokens);
	return;
}

static TReturn send_get_pdp_address_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	unsigned int cid = PS_INVALID_CID;
	char cmd_str[MAX_AT_CMD_STR_LEN] = {0};

	dbg("Entered");
	hal = tcore_object_get_hal(co_ps);

	cid = tcore_context_get_id(ps_context);
	(void)sprintf(cmd_str, "AT+CGPADDR=%d",cid);
	pending = tcore_at_pending_new(co_ps,cmd_str,"+CGPADDR",TCORE_AT_SINGLELINE,
	on_response_get_pdp_address,ps_context );
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
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
	{
		goto error;
	}
	co_ps = tcore_pending_ref_core_object(p);

	if(resp->success)
	{
		dbg("Response Ok");
		/*getting the IP address and DNS from the modem*/
		dbg("Getting the IP Address");
		(void)send_get_pdp_address_cmd(co_ps,ps_context);
		return;
	}
	else
	{

		dbg("Unable to actiavte PDP context for CID: %d ",cid);
		dbg("Undefineing the PDP context");
		(void)tcore_context_set_state(ps_context, CONTEXT_STATE_DEACTIVATED);
		send_undefine_context_cmd(co_ps,ps_context);
		return;
	}
error:
	{
		_unable_to_get_pending(co_ps,ps_context);
		return;
	}
}

static TReturn send_pdp_activate_cmd(CoreObject *co_ps, CoreObject *ps_context)
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
	(void)sprintf(cmd_str, "AT+CGACT=%d,%d",AT_PDP_ACTIVATE,cid);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_send_pdp_activate_cmd,ps_context);
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
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
	(void)send_pdp_activate_cmd(co_ps,ps_context);
	return;
}

static TReturn send_xdns_enable_cmd(CoreObject *co_ps,CoreObject *ps_context)
{
	TcoreHal *hal = NULL;
	TcorePending *pending = NULL;
	int cid = -1 ;
	char cmd_str[MAX_AT_CMD_STR_LEN];

	dbg("Entered");
	memset(cmd_str,0x0,MAX_AT_CMD_STR_LEN);

	hal = tcore_object_get_hal(co_ps);
	cid = tcore_context_get_id(ps_context);

	(void)sprintf(cmd_str, "AT+XDNS=%d,%d",cid,AT_XDNS_ENABLE);
	pending = tcore_at_pending_new(co_ps,cmd_str, NULL, TCORE_AT_NO_RESULT,
					on_response_xdns_enable_cmd, ps_context);
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;
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
		_unable_to_get_pending(co_ps,ps_context);
		dbg("Exiting");
	}
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
	addr = tcore_context_get_address(ps_context);

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
			return TCORE_RETURN_FAILURE;
		}
	}
	dbg("Activating context for CID :- %d",cid);
	if(addr)
		(void)sprintf(cmd_str, "AT+CGDCONT=%d,\"%s\",\"%s\",%s,%d,%d",cid,pdp_type_str,apn,addr,d_comp,h_comp);
	else
		(void)sprintf(cmd_str, "AT+CGDCONT=%d,\"%s\",\"%s\",,%d,%d",cid,pdp_type_str,apn,d_comp,h_comp);
	pending = tcore_at_pending_new(co_ps,cmd_str,NULL,TCORE_AT_NO_RESULT,
					on_response_define_pdp_context,ps_context );
	if(TCORE_RETURN_SUCCESS == tcore_hal_send_request(hal,pending))
	{
		(void)tcore_context_set_state(ps_context,CONTEXT_STATE_ACTIVATING);
		return TCORE_RETURN_SUCCESS;
	}
	_unable_to_get_pending(co_ps,ps_context);
	return TCORE_RETURN_FAILURE;

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


