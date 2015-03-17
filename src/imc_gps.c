/*
 * tel-plugin-imc
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: sharanayya mathapati <sharan.m@samsung.com>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <glib.h>

#include <tcore.h>
#include <hal.h>
#include <core_object.h>
#include <plugin.h>
#include <queue.h>
#include <co_gps.h>
#include <user_request.h>
#include <util.h>
#include <server.h>
#include <at.h>
#include <libxml/xmlreader.h>
#include <libxml/parser.h>
#include <libxml/tree.h>

#include "imc_common.h"
#include "imc_gps.h"


#define FILE_NAME   "/opt/home/root/sample.xml"
#define POSITION_NODE   "pos"
#define POSITION_NODE_ATTR_XSI  "xsi:noNamespaceSchemaLocation"
#define POSITION_NODE_ATTR_VAL_XSI  "pos.xsd"
#define POSITION_NODE_ATTR_XMLNS    "xmlns:xsi"
#define POSITION_NODE_ATTR_VAL_XMLNS    "http://www.w3.org/2001/XMLSchema-instance"

#define MAX_NUM_OF_GPS_REF_TIME_ELEMENT 12 // max number of gps satalite
#define MAX_NUM_OF_GPS_NAV_ELEMENT  16 // max num of navigation gps element.
#define MAX_NUM_OF_GPS_ALMANC_ELEMENTS  64 // Max num of almanc elements.

#define NUM_OF_ELEMENTS(array)  (sizeof(array) / sizeof(*(array)))

static char node_name[128]; // max len of xml node
static char node_value[128]; // max len of xml node value.

// node type of gps assist data
enum gps_assist_element_type {
	REF_TIME = 1,
	LOCATION_PARM,
	DGPS_CORRECTION,
	NAV_MODEL_ELEM,
	IONOSPHERIC_MODEL,
	UTC_MODEL,
	ALMANAC,
	ACQU_ASSIST,
};

// Ref_time
typedef struct {
	unsigned char valid;
	unsigned short bcchCarrier;
	unsigned short bsic;
	unsigned long int frameNumber;
	unsigned short timeSlot;
	unsigned short bitNumber;
} __attribute__((packed)) gps_gsm_time_t;

typedef struct {
	unsigned char valid;
	unsigned long int gpsTimeUncertainty;
} __attribute__((packed)) gps_utran_gps_unc_t;

typedef struct {
	unsigned char valid;
	signed long int driftRate;
} __attribute__((packed)) gps_drift_rate_t;

typedef struct {
	unsigned char valid;
	unsigned long int cellFrames;
	unsigned char choice_mode;
	unsigned long int UtranFdd; // FDD Primary Scrambling Code
	unsigned long int UtranTdd; // TDD Cell Parameter ID
	unsigned long int sfn; // SFN
} __attribute__((packed)) gps_utran_gps_ref_time_t;

typedef struct {
	gps_utran_gps_ref_time_t UtranGpsRefTime;
	gps_utran_gps_unc_t UtranGpsUncertainty;
	unsigned char UtranSfnUncertainty;
	gps_drift_rate_t UtranDriftRate;
} __attribute__((packed)) gps_utran_time_t;

typedef struct {
	unsigned short satID;
	unsigned short tlmWord;
	unsigned char antiSpoofFlag;
	unsigned char alertFlag;
	unsigned char tmlReservedBits;
} __attribute__((packed)) gps_gps_tow_assist_t;

typedef struct {
	unsigned long int gpsTow;
	unsigned long int gpsWeek;
	unsigned char nrOfSats;
	union {                     // Not supported.
		gps_gsm_time_t gsm_time;
		gps_utran_time_t UtranTime;
	} networkTimeInfo;
	gps_gps_tow_assist_t GpsTowAssist[12];
} __attribute__((packed)) gps_ref_time_t;


// Ref - Location.
typedef struct {
	unsigned char shapeType;
	unsigned char hemisphere;
	unsigned short altitude;
	unsigned long int latitude;
	signed long int longitude;
	unsigned char directionOfAlt;
	unsigned char semiMajorUncert;
	unsigned char semiMinorUncert;
	unsigned char majorAxis;
	unsigned char altUncert;
	unsigned char confidence;
} __attribute__((packed)) gps_ref_loc_t;

// DGPS corrections
typedef enum {
	GPS_DGPS_INVALID,
	GPS_DGPS_UDRE_SCALE_1_0,
	GPS_DGPS_UDRE_SCALE_0_75,
	GPS_DGPS_UDRE_SCALE_0_5,
	GPS_DGPS_UDRE_SCALE_0_3,
	GPS_DGPS_UDRE_SCALE_0_2,
	GPS_DGPS_UDRE_SCALE_0_1,
	GPS_DGPS_NO_DATA
} __attribute__((packed)) gps_dgps_status_e_type;

typedef struct {
	unsigned char satId; // Satellite ID
	unsigned short iode;
	unsigned char udre;
	signed short pseudoRangeCor;
	signed short rangeRateCor;
} gps_dgps_sat_list_t;

typedef struct {
	unsigned long int gpsTow;
	gps_dgps_status_e_type status;
	unsigned long int numberOfSat;
	gps_dgps_sat_list_t seqOfSatElement[16];
} __attribute__((packed)) gps_dgps_correction_t;

// Navi model
typedef struct {
	unsigned long int rsv1; // 0~838860
	unsigned long int rsv2; // 0~16777215
	unsigned long int rsv3; // 0~16777215
	unsigned long int rsv4; // 0~65535
} __attribute__((packed)) gps_navi_subframe_rsv_t;

typedef struct {
	unsigned char ephemCodeOnL2;                   // 0~3
	unsigned char ephemUra;                   // 0~15
	unsigned char ephemSvHealth;                   // 0~63
	unsigned short ephemIodc;              // 0~1023
	unsigned char ephemL2PFlag;                   // 0~1
	gps_navi_subframe_rsv_t NavigationSubFrameRsv;
	signed char ephemTgd;                 // -128~127
	unsigned short ephemToc;              // 0~37799
	signed char ephemAf2;                 // -128~12
	signed short ephemAf1;                    // -32768~32767
	signed long int ephemAf0;                 // -2097152~2097151
	signed short ephemCrs;                    // -32768~32767
	signed short ephemDeltaN;                    // -32768~32767
	signed long int ephemM0;                 // -2147483648~2147483647
	signed short ephemCuc;                    // -32768~32767
	unsigned long int ephemE;               // 0~4294967295
	signed short ephemCus;                    // -32768~32767
	unsigned long int ephemAPowrHalf;               // 0~4294967295
	unsigned short ephemToe;              // 0~37799
	signed char ephemFitFlag;                 // 0~1
	unsigned char ephemAoda;                   // 0~31
	signed short ephemCic;                    // -32768~32767
	signed long int ephemOmegaA0;                 // -2147483648~2147483647
	signed short ephemCis;                    // -32768~32767
	signed long int ephemI0;                 // -2147483648~2147483647
	signed short ephemCrc;                    // -32768~32767
	signed long int ephemW;                 // -2147483648~2147483647
	signed long int ephemOmegaADot;                 // -8388608~8388607
	signed short ephemIDot;                    // -8192~8191
} __attribute__((packed)) gps_navi_ephe_t;

typedef enum {
	GPS_NAVIGATION_MODEL_NEW_SATELLITE_NEW_NAVIGATION,
	GPS_NAVIGATION_MODEL_EXIST_SATELLITE_EXIST_NAVIGATION,
	GPS_NAVIGATION_MODEL_EXIST_SATELLITE_NEW_NAVIGATION,
	GPS_NAVIGATION_MODEL_RESERVED
} gps_navigation_sat_status_e_type;

typedef struct {
	unsigned char satId;
	gps_navigation_sat_status_e_type NavigationSatStatus;
	gps_navi_ephe_t NavigationEphemeris;
} __attribute__((packed)) gps_navi_sat_info_t;

typedef struct {
	unsigned long int numberOfSat;
	gps_navi_sat_info_t NavigationSatInfo[16];
} __attribute__((packed)) gps_navi_model_t;

// Iono_model
typedef struct {
	signed char alfa0; // -128~127
	signed char alfa1; // -128~127
	signed char alfa2; // -128~127
	signed char alfa3; // -128~127
	signed char beta0; // -128~127
	signed char beta1; // -128~127
	signed char beta2; // -128~127
	signed char beta3; // -128~127
} __attribute__((packed)) gps_iono_model_t;

// UTC_model
typedef struct {
	signed long int utcA1; // -8388608~8388607
	signed long int utcA0; // -2147483648~2147483647
	unsigned char utcTot; // 0~255
	unsigned char utcWNt; // 0~255
	signed char utcDeltaTls; // -128~127
	unsigned char utcWNlsf; // 0~255
	signed char utcDN; // -128~127
	signed char utcDeltaTlsf; // -128~127
} __attribute__((packed)) gps_utc_model_t;

// Almanac-model
typedef struct {
	signed char dataId; // only for 3G, 0~3, if this value is -1, it means this value is invalid
	unsigned char satId;
	unsigned short almanacE; // 0~65536
	unsigned char almanacToa;   // 0~255
	signed short almanacKsii;    // -32768~3276
	signed short almanacOmegaDot;    // -32768~3276
	unsigned char almanacSvHealth;   // 0~255
	unsigned long int almanacAPowerHalf; // 0~16777215
	signed long int almanacOmega0; // -8388608~8388607
	signed long int almanacW; // -8388608~8388607
	signed long int almanacM0; // -8388608~8388607
	signed short almanacAf0;    // -1024~1023
	signed short almanacAf1;    // -1024~1023
} __attribute__((packed)) gps_almanac_sat_info_t;

typedef struct {
	unsigned char almanacWNa; // 0~255
	unsigned long int numberOfSat;
	gps_almanac_sat_info_t AlmanacSatInfo[64];
} __attribute__((packed)) gps_almanac_model_t;

// acq_assist
typedef struct {
	unsigned char satId;
	signed short doppler0; // -2048~2047 (real value is from -5120 to 5117.5 by step of 2.5)
	unsigned char doppler1; // 0~63 (real value is from -0.966 to 0.483 by step of 0.023)
	unsigned char dopplerUncertainty; // 0~7 (12.5, 25, 50, 100, 200)
	unsigned short codePhase; // 0~1022
	unsigned char intCodePhase; // 0~19
	unsigned char gpsBitNumber; // 0~3
	unsigned char codePhaseSearchWindow; // 0~15 (1023, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192)
	unsigned char azimuth; // 0~31, 11.25 degree resolution
	unsigned char elevation; // 0~7, 11.25 degree resolution
} __attribute__((packed)) gps_acq_sat_info_t;

typedef struct {
	gps_utran_gps_ref_time_t AcqUtranGpsRefTime;
	gps_utran_gps_unc_t AcqUtranGpsUncertainty;
} __attribute__((packed)) gps_acq_utran_time_t;

typedef struct {
	unsigned long int gpsTow;
	union   {
		gps_gsm_time_t gsm_time;
		gps_acq_utran_time_t AcqUtranTime;
	} acquisitionTimeInfo;                      // --- not supported.
	unsigned long int numberOfSat;
	gps_acq_sat_info_t lcsAcquisitionSatInfo[16];
} __attribute__((packed)) gps_acq_assist_t;

typedef struct {
	unsigned char satId[16];
	unsigned char numOfSat;
} __attribute__((packed)) gps_r_time_int_t;


// Assist-data
typedef struct {
	unsigned long int flag;
	gps_ref_time_t ref_time;
	gps_ref_loc_t ref_loc;
	gps_dgps_correction_t dgps_corrections;
	gps_navi_model_t navi_model;
	gps_iono_model_t iono_model;
	gps_utc_model_t utc_model;
	gps_almanac_model_t almanac;
	gps_acq_assist_t acq_assist;
	gps_r_time_int_t r_time_int; // not supported
} __attribute__((packed)) gps_assist_data_noti_t; // APGPS -  GPS Assist Data Message - Notification

typedef struct {
	char *psat_status;
	int stat_status;
} __attribute__((packed)) sat_status_info_t;

const sat_status_info_t sat_status_info_table[] = {
	{ "NS_NN-U", 0}, {"NS_NN", 0}, {"ES_NN-U", 1}, {"ES_SN", 2},
	{ "REVD", 3},
};

typedef struct {
	char *pdoppler_status;
	int doppler_status;
} __attribute__((packed)) doppler_status_info_t;

const doppler_status_info_t doppler_status_info_table[] = {
	{ "hz12-5", 12.5}, {"hz25", 25}, {"hz50", 50}, {"hz100", 100},
	{"hz200", 200},
};

// postion measurement data structure.
// gps_method_e_type
typedef enum {
	GPS_METHODTYPE_INVALID,
	GPS_METHODTYPE_MS_ASSISTED,
	GPS_METHODTYPE_MS_BASED,
	GPS_METHODTYPE_MS_BASED_PREF,
	GPS_METHODTYPE_MS_ASSISTED_PREF
} gps_method_e_type;

// gps_accuracy_t
typedef struct {
	unsigned int flag;
	unsigned char horizontalAccuracy;
	unsigned char vertcalAccuracy;
} __attribute__((packed)) gps_accuracy_t;

// gps_use_multi_sets_e_type
typedef enum {
	GPS_MULTIPLESETS_INVALID,
	GPS_MULTIPLESETS_MULTIPLESETS,
	GPS_MULTIPLESETS_ONESET
} gps_use_multi_sets_e_type;

// gps_env_char_e_type
typedef enum {
	GPS_ENVIRONMENT_INVALID,
	GPS_ENVIRONMENT_BAD_AREA,
	GPS_ENVIRONMENT_NOT_BAD_AREA,
	GPS_ENVIRONMENT_MIXED_AREA
} gps_env_char_e_type;

// gps_cell_timing_wnt_e_type
typedef enum {
	GPS_CELLTIMING_INVALID,
	GPS_CELLTIMING_WANTED,
	GPS_CELLTIMING_NOT_WANTED
} gps_cell_timing_wnt_e_type;

// gps_add_assit_req_e_type
typedef enum {
	GPS_ADDITIONAL_ASSISREQ_INVALID,
	GPS_ADDITIONAL_ASSISREQ_REQ,
	GPS_ADDITIONAL_ASSISREQ_NOT_REQ
} gps_add_assit_req_e_type;

// gps measure position.
typedef struct {
	gps_method_e_type method_type;
	gps_accuracy_t accuracy;
	unsigned char rsp_time;
	gps_use_multi_sets_e_type use_multi_sets;
	gps_env_char_e_type environment_char;
	gps_cell_timing_wnt_e_type cell_timing_wnt;
	gps_add_assit_req_e_type add_assist_req;
} __attribute__((packed)) gps_measure_position_indi_t;


// APGPS - Measure Position message - confirm
typedef enum {
	GPS_MSR_POS_RES_LOCATION,
	GPS_MSR_POS_RES_GPS_MEASUREMENTS,
	GPS_MSR_POS_RES_AID_REQ,
	GPS_MSR_POS_RES_ERROR
} gps_msr_pos_res_e_type;

typedef struct {
	unsigned char sat_id;
	unsigned char iode;
} __attribute__((packed)) gps_sat_info_t;

typedef struct {
	unsigned char beginWeek;
	unsigned char endWeek;
	unsigned char beginTow;
	unsigned char endTow;
} __attribute__((packed)) gps_ext_ephe_chk_t;

typedef struct {
	unsigned long int assistanceFlag;
	unsigned short gpsWeek;
	unsigned char gpsToe;
	unsigned char nSat;
	unsigned char toeLimit;
	gps_sat_info_t satInfo[15];
	unsigned char gpsExtendedEphemeris;
	gps_ext_ephe_chk_t extEphemerisChk;
} __attribute__((packed)) gps_assistance_data_t;

// Measure Position message
typedef struct {
	unsigned char satId; // Satellite ID
	unsigned char cno; // 0~63, unit of dB-Hz
	signed short doppler; // -32768~32767, Hz and scale factor 0.2
	unsigned short wholeChips; // 0~1022
	unsigned short fracChips; // 0~1024
	unsigned char lcsMultiPath;
	unsigned char pseuRangeRmsErr; // 0~63
} __attribute__((packed)) gps_measuremet_element_t;

typedef struct {
	unsigned long int gpsTow; // /< GPS time of week [msec]
	unsigned short gpsWeek; // /< GPS week [0 .. 1023]
	unsigned char nrOfSats; // /< number of satellites [1 .. 16]
	gps_measuremet_element_t GpsMeasure[16];
} __attribute__((packed)) gps_measure_t;

typedef struct {
	signed long int latitude;
	signed long int longitude;
} __attribute__((packed)) gps_ellipsoid_po_t;

typedef struct {
	gps_ellipsoid_po_t point;
	unsigned char uncertainRadius;
} __attribute__((packed)) gps_po_unc_circle_t;

typedef struct {
	gps_ellipsoid_po_t point;
	unsigned char semiMajorAxis;
	unsigned char semiMinorAxis;
	unsigned char orientationAngle;
	unsigned char confidence;
} __attribute__((packed)) gps_po_unc_ellipse_t;

typedef struct {
	gps_ellipsoid_po_t point;
	signed short altitude;
	unsigned char semiMajorAxis;
	unsigned char semiMinorAxis;
	unsigned char orientationAngle;
	unsigned char uncertainAltitude;
	unsigned char confidence;
} __attribute__((packed)) gps_po_alt_unc_ellipse_t;

typedef struct {
	gps_ellipsoid_po_t point;
	unsigned short innerRadius;
	unsigned char uncertainRadius;
	unsigned char offsetAngle;
	unsigned char includedAngle;
	unsigned char confidence;
} __attribute__((packed)) gps_ellipsoid_arc_t;

typedef struct {
	gps_ellipsoid_po_t point;
	signed short altitude;
} __attribute__((packed)) gps_ellipsoid_alt_t;

typedef struct {
	unsigned char noOfPoints;
	gps_ellipsoid_po_t points[15];
} __attribute__((packed)) gps_polygon_t;


typedef struct {
	unsigned char shape_type;
	gps_po_unc_circle_t p_unc_clrcle;
	gps_po_unc_ellipse_t p_unc_ellipse;
	gps_po_alt_unc_ellipse_t p_alt_unc_ellipse;
	gps_ellipsoid_arc_t ellipsoid_arc;
	gps_ellipsoid_po_t ellipsoid_po;
	gps_ellipsoid_alt_t ellipsoid_alt;
	gps_polygon_t polygon;
} __attribute__((packed)) gps_loc_info_t;


typedef struct {
	unsigned long int gpsTow; // /< GPS time of week [msec]
	unsigned short gpsWeek; // /< GPS week [0 .. 1023]
	unsigned char fixType; // /< Fix type. 2D(0x01) or 3D(0x02)
	gps_loc_info_t measured_loc_info;
} __attribute__((packed)) gps_measure_loc_info_t;

typedef struct {
	unsigned char valid;
	unsigned long int cellFrames;
	unsigned char choice_mode;
	unsigned long int UtranFdd; // FDD Primary Scrambling Code
	unsigned long int UtranTdd; // TDD Cell Parameter ID
	unsigned long int sfn; // SFN
} __attribute__((packed)) gps_utrangps_ref_time_t;

typedef struct {
	unsigned char result; // 0x00 : SUCCESS, 0x01 : Fail
	gps_msr_pos_res_e_type response_type; // should be 4 byte
	gps_measure_t gps_measure;
	gps_measure_loc_info_t loc_info;
	gps_assistance_data_t measured_assit_data;
	gps_utrangps_ref_time_t UtranGpsRefTime; // only for 3G
} __attribute__((packed)) gps_measure_position_confirm_t; // APGPS - Measure Position message - confirm

typedef struct {
	char *name;
	int type;
} t_element;

static t_element elements[] = {
	{"ref_time", REF_TIME},
	{"location_parameters", LOCATION_PARM},
	{"DGPS_corrections", DGPS_CORRECTION},
	{"nav_model_elem", NAV_MODEL_ELEM},
	{"ionospheric_model", IONOSPHERIC_MODEL},
	{"UTC_model", UTC_MODEL},
	{"almanac", ALMANAC},
	{"acqu_assist", ACQU_ASSIST},
};


/**************************************************************************
*							Local Function Prototypes
**************************************************************************/

static inline int _modem_sat_status_info_2_tel_sat_info(char *sat_info);

static inline int _modem_acqa_assit_doppler_2_tel_doppler(char *doppler_info);

static int _gps_element_compare(char *element[], char *element_str, int nelem);

static enum gps_assist_element_type _get_element_type(char *element_str);

static void _parse_ref_time_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist, gboolean GPS_TOW_assist, int count);

static void _parse_location_parameters(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist);

static void _parse_dgps_correction_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist);

static void _parse_ionospheric_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist);

static void _parse_utc_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist);

static void _parse_almanc_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist, gboolean alm_elem, int count);

static void _parse_acqu_assist_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist);

static void _parse_nav_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist, gboolean ephem_and_clock, int element_count);

static void _set_coordinate(xmlNodePtr node, gps_ellipsoid_po_t *point, int isalt, int altitude);

static void _set_loc_info_ellipse_elements(xmlNodePtr node, void *elliplse, int is_unc_ellipse);

static xmlChar* _generate_confirm_measure_pos_xml_text(gps_measure_position_confirm_t *gps_measure_position_confirm);

static gboolean on_notification_gps_measure_position_from_modem(CoreObject *o, char *file_name, void *user_data);

/**************************************************************************
*							Local Function Definitions
 **************************************************************************/

static inline int _modem_sat_status_info_2_tel_sat_info(char *sat_info)
{
	int count;

	for (count = 0; count < (int) (sizeof(sat_status_info_table) / sizeof(sat_status_info_t)); count++) {
		if (strcmp(sat_status_info_table[count].psat_status, sat_info) == 0)
			return (sat_status_info_table[count].stat_status);
	}
	return (-1);
}

static inline int _modem_acqa_assit_doppler_2_tel_doppler(char *doppler_info)
{
	int count;

	for (count = 0; count < (int) (sizeof(doppler_status_info_table) / sizeof(doppler_status_info_t)); count++) {
		if (strcmp(doppler_status_info_table[count].pdoppler_status, doppler_info) == 0)
			return (doppler_status_info_table[count].doppler_status);
	}
	return (-1);
}

static int _gps_element_compare(char *element[], char *element_str, int nelem)
{
	int count;

	for (count = 0; count < nelem; count++) {
		if (strcmp(element[count], element_str) == 0)
			return count;
	}

	return -1;
}


static enum gps_assist_element_type _get_element_type(char *element_str)
{
	unsigned int index;

	for (index = 0; index < sizeof(elements) / sizeof(t_element); index++) {
		if (strcmp(elements[index].name, element_str) == 0)
			return elements[index].type;
	}
	return -1;
}

static void _parse_ref_time_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist, gboolean GPS_TOW_assist, int count)
{
	int node_count;
	int nelem;
	static char *element[] = {"GPS_TOW_msec", "GPS_week", "sat_id", "tlm_word", "anti_sp", "alert", "tlm_res"};

	dbg("Enter");
	if (count < 0 || count >= MAX_NUM_OF_GPS_REF_TIME_ELEMENT) {
		dbg("invalid count");
		return;
	}
	nelem = (int) NUM_OF_ELEMENTS(element);
	node_count = _gps_element_compare(element, element_str, nelem);

	if (node_count == 0) {
		gpsdata_assist->ref_time.gpsTow = atoi(element_value);
		dbg("gpsTow - %d\n", gpsdata_assist->ref_time.gpsTow);
		gpsdata_assist->dgps_corrections.gpsTow = gpsdata_assist->ref_time.gpsTow;
		return;
	} else if (node_count == 1) {
		gpsdata_assist->ref_time.gpsWeek = atoi(element_value);
		dbg("gpsWeek - %d\n", gpsdata_assist->ref_time.gpsWeek);
		return;
	}

	if (GPS_TOW_assist) {
		switch (node_count) {
		case 2:
		{
			gpsdata_assist->ref_time.GpsTowAssist[count].satID = atoi(element_value);
			dbg("GpsTowAssist[%d].satID  = %d\n", count, gpsdata_assist->ref_time.GpsTowAssist[count].satID);
			gpsdata_assist->ref_time.nrOfSats = count + 1;
		}
		break;

		case 3:
		{
			gpsdata_assist->ref_time.GpsTowAssist[count].tlmWord = atoi(element_value);
			dbg("GpsTowAssist[%d]-tlmWord  = %d\n", count, gpsdata_assist->ref_time.GpsTowAssist[count].tlmWord);
			gpsdata_assist->ref_time.nrOfSats = count + 1;
		}
		break;

		case 4:
		{
			gpsdata_assist->ref_time.GpsTowAssist[count].antiSpoofFlag = *element_value;
			dbg("GpsTowAssist[%d]-antiSpoofFlag  = 0x%X\n", count, gpsdata_assist->ref_time.GpsTowAssist[count].antiSpoofFlag);
			gpsdata_assist->ref_time.nrOfSats = count + 1;
		}
		break;

		case 5:
		{
			gpsdata_assist->ref_time.GpsTowAssist[count].alertFlag = *element_value;
			dbg("GpsTowAssist[%d]-alertFlag  = 0x%X\n", count, gpsdata_assist->ref_time.GpsTowAssist[count].alertFlag);
			gpsdata_assist->ref_time.nrOfSats = count + 1;
		}
		break;

		case 6:
		{
			gpsdata_assist->ref_time.GpsTowAssist[count].tmlReservedBits = *element_value;
			dbg("GpsTowAssist[%d]-tmlReservedBits  = 0x%X\n", count, gpsdata_assist->ref_time.GpsTowAssist[count].tmlReservedBits);
			gpsdata_assist->ref_time.nrOfSats = count + 1;
		}
		break;

		default:
			dbg("Invalid  gps element");
		}
	}
}

static void _parse_location_parameters(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist)
{
	// unsigned char shapeType;  and unsigned char hemisphere not supported.

	static char *element[] = {
		"north", "degrees", "height_above_surface", "height", "longitude", "uncert_semi_major", "uncert_semi_minor",
		"orient_major", "confidence", "uncert_alt"
	};

	int nelem = (int) NUM_OF_ELEMENTS(element);
	int count;

	count = _gps_element_compare(element, element_str, nelem);

	dbg("Enter");

	switch (count) {
	case 0:
	{
		// gpsdata_assist.ref_loc.latitude_data.north = atoi(element_str_text);
		// dbg("gpsdata_assist.ref_loc.latitude_data.north  - %d\n",gpsdata_assist.ref_loc.latitude_data.north);
	}
	break;

	case 1:
	{
		gpsdata_assist->ref_loc.latitude = atoi(element_value);
		dbg("latitude_data.degrees - %d\n", gpsdata_assist->ref_loc.latitude);
	}
	break;

	case 2:
	{
		// gpsdata_assist.ref_loc.altitude_data.height_above_surface = atoi(element_str_text);
		// dbg("altitude_data.height_above_surface  - %d\n",gpsdata_assist.ref_loc.altitude_data.height_above_surface);
	}
	break;

	case 3:
	{
		gpsdata_assist->ref_loc.altitude = atoi(element_value);      // todo- need to confirm
		dbg("altitude_data.height - %d\n", gpsdata_assist->ref_loc.altitude);
	}
	break;

	case 4:
	{
		gpsdata_assist->ref_loc.longitude = atoi(element_value);
		dbg("longitude  - %d\n", gpsdata_assist->ref_loc.longitude);
	}
	break;

	case 5:
	{
		gpsdata_assist->ref_loc.semiMajorUncert = *element_value;
		dbg("semiMajorUncert  - 0x%X\n", gpsdata_assist->ref_loc.semiMajorUncert);
	}
	break;

	case 6:
	{
		gpsdata_assist->ref_loc.semiMinorUncert = *element_value;
		dbg("uncert_semi_minor - 0x%X\n", gpsdata_assist->ref_loc.semiMinorUncert);
	}
	break;

	case 7:
	{
		gpsdata_assist->ref_loc.majorAxis = *element_value;
		dbg("orient_major - 0x%X\n", gpsdata_assist->ref_loc.majorAxis);
	}
	break;

	case 8:
	{
		gpsdata_assist->ref_loc.confidence = *element_value;
		dbg("confidence - 0x%X\n", gpsdata_assist->ref_loc.confidence);
	}
	break;

	case 9:
	{
		gpsdata_assist->ref_loc.altUncert = *element_value;
		dbg("altUncert - 0x%X\n", gpsdata_assist->ref_loc.altUncert);
	}
	break;

	default:
		dbg("invalid element");
	}
}

static void _parse_dgps_correction_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist)
{
	dbg("Enter");

	if (strcmp(element_str, "sat_id") == 0) {
		gpsdata_assist->dgps_corrections.seqOfSatElement[0].satId = *element_value;
		dbg("seqOfSatElement[0].satId  - %d\n", gpsdata_assist->dgps_corrections.seqOfSatElement[0].satId);
	} else if (strcmp(element_str, "IODE") == 0) {
		gpsdata_assist->dgps_corrections.seqOfSatElement[0].iode = atoi(element_value);
		dbg("seqOfSatElement[0].iode - %d\n", gpsdata_assist->dgps_corrections.seqOfSatElement[0].iode);
	} else if (strcmp(element_str, "UDRE") == 0) {
		gpsdata_assist->dgps_corrections.seqOfSatElement[0].udre = *element_value;
		dbg("seqOfSatElement[0].udre- %d\n", gpsdata_assist->dgps_corrections.seqOfSatElement[0].udre);
	} else if (strcmp(element_str, "PRC") == 0) {
		gpsdata_assist->dgps_corrections.seqOfSatElement[0].pseudoRangeCor = atoi(element_value);
		dbg("seqOfSatElement[0].pseudoRangeCor - %d\n", gpsdata_assist->dgps_corrections.seqOfSatElement[0].pseudoRangeCor);
	} else if (strcmp(element_str, "RRC") == 0) {
		gpsdata_assist->dgps_corrections.seqOfSatElement[0].rangeRateCor = atoi(element_value);
		dbg("seqOfSatElement[0].rangeRateCor - %d\n", gpsdata_assist->dgps_corrections.seqOfSatElement[0].rangeRateCor);
	}
}

static void _parse_ionospheric_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist)
{
	static char *element[] = {"alfa0", "alfa1", "alfa2", "alfa3", "beta0", "beta1", "beta2", "beta3" };
	int nelem = (int) NUM_OF_ELEMENTS(element);
	int count;

	count = _gps_element_compare(element, element_str, nelem);
	dbg("enter");
	switch (count) {
	case 0:
	{
		gpsdata_assist->iono_model.alfa0 = *element_value;
		dbg("alfa0  - 0x%X\n", gpsdata_assist->iono_model.alfa0);
	}
	break;

	case 1:
	{
		gpsdata_assist->iono_model.alfa1 = *element_value;
		dbg("alfa1 - 0x%X\n", gpsdata_assist->iono_model.alfa1);
	}
	break;

	case 2:
	{
		gpsdata_assist->iono_model.alfa2 = *element_value;
		dbg("alfa2  - 0x%X\n", gpsdata_assist->iono_model.alfa2);
	}
	break;

	case 3:
	{
		gpsdata_assist->iono_model.alfa3 = *element_value;
		dbg("alfa3  - 0x%X\n", gpsdata_assist->iono_model.alfa3);
	}
	break;

	case 4:
	{
		gpsdata_assist->iono_model.beta0 = *element_value;
		dbg("beta0  - 0x%X\n", gpsdata_assist->iono_model.beta0);
	}
	break;

	case 5:
	{
		gpsdata_assist->iono_model.beta1 = *element_value;
		dbg("beta1  -0x%X\n", gpsdata_assist->iono_model.beta1);
	}
	break;

	case 6:
	{
		gpsdata_assist->iono_model.beta2 = *element_value;
		dbg("beta2  - 0x%X\n", gpsdata_assist->iono_model.beta2);
	}
	break;

	case 7:
	{
		gpsdata_assist->iono_model.beta3 = *element_value;
		dbg("beta3  - 0x%X\n", gpsdata_assist->iono_model.beta3);
	}
	break;

	default:
		dbg("invalid gps element");
	}
}

void _parse_utc_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist)
{
	static char *element[] = {"a1", "a0", "tot", "wnt", "dtls", "wnlsf", "dn", "dtlsf"};
	int nelem = (int) NUM_OF_ELEMENTS(element);
	int count;

	count = _gps_element_compare(element, element_str, nelem);
	dbg("Enter");

	switch (count) {
	case 0:
	{
		gpsdata_assist->utc_model.utcA1 = atoi(element_value);
		dbg("utcA1  - %d\n", gpsdata_assist->utc_model.utcA1);
	}
	break;

	case 1:
	{
		gpsdata_assist->utc_model.utcA0 = atoi(element_value);
		dbg("utcA0  - %d\n", gpsdata_assist->utc_model.utcA0);
	}
	break;

	case 2:
	{
		gpsdata_assist->utc_model.utcTot = *element_value;
		dbg("utcTot  - 0x%X\n", gpsdata_assist->utc_model.utcTot);
	}
	break;

	case 3:
	{
		gpsdata_assist->utc_model.utcWNt = *element_value;
		dbg("utcWNt  - 0x%X\n", gpsdata_assist->utc_model.utcWNt);
	}
	break;

	case 4:
	{
		gpsdata_assist->utc_model.utcDeltaTls = *element_value;
		dbg("utcDeltaTls  -0x%X\n", gpsdata_assist->utc_model.utcDeltaTls);
	}
	break;

	case 5:
	{
		gpsdata_assist->utc_model.utcWNlsf = *element_value;
		dbg("utcWNlsf  - 0x%X\n", gpsdata_assist->utc_model.utcWNlsf);
	}
	break;

	case 6:
	{
		gpsdata_assist->utc_model.utcDN = *element_value;
		dbg("utcDN  - 0x%X\n", gpsdata_assist->utc_model.utcDN);
	}
	break;

	case 7:
	{
		gpsdata_assist->utc_model.utcDeltaTlsf = *element_value;
		dbg("utcDeltaTlsf  - 0x%X\n", gpsdata_assist->utc_model.utcDeltaTlsf);
	}
	break;

	default:
		dbg("invalid gps element");
	}
}

static void _parse_almanc_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist,
											 gboolean alm_elem, int count)
{
	int nelem;
	int node_count;
	static char *element[] = {
		"wna", "data_id", "sat_id", "alm_ecc", "alm_toa", "alm_ksii", "alm_omega_dot", "alm_sv_health", "alm_power_half",
		"alm_omega0", "alm_omega", "alm_m0", "alm_af0", "alm_af1"
	};

	dbg("Enter");
	if (count < 0 || count >= MAX_NUM_OF_GPS_ALMANC_ELEMENTS) {
		dbg("invalid count");
		return;
	}
	nelem = (int) NUM_OF_ELEMENTS(element);

	node_count = _gps_element_compare(element, element_str, nelem);
	if (node_count == 0) {
		gpsdata_assist->almanac.almanacWNa = *element_value;
		dbg("almanacWNa  - %d\n", gpsdata_assist->almanac.almanacWNa);
		return;
	}

	if (alm_elem) {
		switch (node_count) {
		case 1:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].dataId = *element_value;
			dbg("AlmanacSatInfo[%d].data_id  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].dataId);
		}
		break;

		case 2:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].satId = *element_value;
			dbg("AlmanacSatInfo[%d].sat_id  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].satId);
		}
		break;

		case 3:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacE = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacE  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacE);
		}
		break;

		case 4:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacToa = *element_value;
			dbg("AlmanacSatInfo[%d].almanacToa  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacToa);
		}
		break;

		case 5:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacKsii = *element_value;
			dbg("AlmanacSatInfo[%d].almanacKsii  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacKsii);
		}
		break;

		case 6:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacOmegaDot = *element_value;
			dbg("AlmanacSatInfo[%d].almanacOmegaDot  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacOmegaDot);
		}
		break;

		case 7:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacSvHealth = *element_value;
			dbg("AlmanacSatInfo[%d].almanacSvHealth  - 0x%X\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacSvHealth);
		}
		break;

		case 8:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAPowerHalf = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacAPowerHalf  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAPowerHalf);
		}
		break;

		case 9:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacOmega0 = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacOmega0  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacOmega0);
		}
		break;

		case 10:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacW = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacW  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacW);
		}
		break;

		case 11:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacM0 = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacM0  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacM0);
		}
		break;

		case 12:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAf0 = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacAf0  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAf0);
		}
		break;

		case 13:
		{
			gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAf1 = atoi(element_value);
			dbg("AlmanacSatInfo[%d].almanacAf1  - %d\n", count, gpsdata_assist->almanac.AlmanacSatInfo[count].almanacAf1);
		}
		break;

		default:
			dbg("invalid gps element");
		}
	}
	return;
}

static void _parse_acqu_assist_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t *gpsdata_assist)
{
	static char *element[] = {"tow_msec", "sat_id", "dopl0", "dopl1", "code_ph", "code_ph_int", "GPS_bitno", "srch_w", "az", "elev"};
	int nelem = (int) NUM_OF_ELEMENTS(element);
	int count;

	count = _gps_element_compare(element, element_str, nelem);
	dbg("Enter");

	switch (count) {
	case 0:
		gpsdata_assist->acq_assist.gpsTow = atoi(element_value);
		dbg("acq_assist.gpsTow  - %d\n", gpsdata_assist->acq_assist.gpsTow);
		break;

	case 1:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].satId = *element_value;
		dbg("lcsAcquisitionSatInfo[0].satId  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].satId);
		break;

	case 2:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].doppler0 = atoi(element_value);
		dbg("lcsAcquisitionSatInfo[0].dopl0  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].doppler0);
		break;

	case 3:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].doppler1 = *element_value;
		dbg("lcsAcquisitionSatInfo[0].doppler1  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].doppler1);
		break;

	case 4:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].codePhase = atoi(element_value);
		dbg("lcsAcquisitionSatInfo[0].codePhase  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].codePhase);
		break;

	case 5:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].intCodePhase = *element_value;
		dbg("lcsAcquisitionSatInfo[0].intCodePhase  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].intCodePhase);
		break;

	case 6:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].gpsBitNumber = *element_value;
		dbg("lcsAcquisitionSatInfo[0].GPS_bitno  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].gpsBitNumber);
		break;

	case 7:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].codePhaseSearchWindow = *element_value;
		dbg("lcsAcquisitionSatInfo[0].codePhaseSearchWindow  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].codePhaseSearchWindow);
		break;

	case 8:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].azimuth = *element_value;
		dbg("lcsAcquisitionSatInfo[0].azimuth  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].azimuth);
		break;

	case 9:
		gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].elevation = *element_value;
		dbg("lcsAcquisitionSatInfo[0].elevation  - 0x%X\n", gpsdata_assist->acq_assist.lcsAcquisitionSatInfo[0].elevation);
		break;

	default:
		dbg("invalid gps element");
	}
}

static void _parse_nav_model_gps_elements(char *element_str, char *element_value, gps_assist_data_noti_t
										  *gpsdata_assist, gboolean ephem_and_clock, int element_count)
{
	static char *element[] = {
		"sat_id", "l2_code", "ura", "sv_health", "iodc", "l2p_flag", "esr1", "esr2", "esr3", "esr4", "tgd", "toc", "af2", "af0",
		"crs", "delta_n", "m0", "cuc", "ecc", "cus", "power_half", "toe", "fit_flag", "aoda", "cic", "omega0", "cis", "i0", "crc", "omega", "idot", "omega_dot"
	};

	int nelem = (int) NUM_OF_ELEMENTS(element);
	int count;

	if (element_count < 0 || element_count >= MAX_NUM_OF_GPS_NAV_ELEMENT) {
		dbg("invalid count");
		return;
	}
	count = _gps_element_compare(element, element_str, nelem);

	dbg("Enter");
	if (count == 0) {
		gpsdata_assist->navi_model.NavigationSatInfo[element_count].satId = *element_value;
		dbg("NavigationSatInfo[%d].satId  - 0x%X\n", element_count, gpsdata_assist->navi_model.NavigationSatInfo[element_count].satId);
		return;
	}

	if (ephem_and_clock) {
		switch (count) {
		case 1:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCodeOnL2 = *element_value;
			break;

		case 2:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemUra = *element_value;
			break;

		case 3:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemSvHealth = *element_value;
			break;

		case 4:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemIodc = atoi(element_value);
			break;

		case 5:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemL2PFlag = *element_value;
			break;

		case 6:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.NavigationSubFrameRsv.rsv1 = atoi(element_value);
			break;

		case 7:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.NavigationSubFrameRsv.rsv2 = atoi(element_value);
			break;

		case 8:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.NavigationSubFrameRsv.rsv3 = atoi(element_value);
			break;

		case 9:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.NavigationSubFrameRsv.rsv4 = atoi(element_value);
			break;

		case 10:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemTgd = *element_value;
			break;

		case 11:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemToc = atoi(element_value);
			break;

		case 12:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemAf2 = *element_value;
			break;

		case 13:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemAf1 = atoi(element_value);
			break;

		case 14:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemAf0 = atoi(element_value);
			break;

		case 15:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCrs = atoi(element_value);
			break;

		case 16:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemDeltaN = atoi(element_value);
			break;

		case 17:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemM0 = atoi(element_value);
			break;

		case 18:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCuc = atoi(element_value);
			break;

		case 19:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemE = atoi(element_value);
			break;

		case 20:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCus = atoi(element_value);
			break;

		case 21:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemAPowrHalf = atoi(element_value);
			break;

		case 22:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemToe = atoi(element_value);
			break;

		case 23:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemFitFlag = *element_value;
			break;

		case 24:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemAoda = *element_value;
			break;

		case 25:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCic = atoi(element_value);
			break;

		case 26:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemI0 = atoi(element_value);
			break;

		case 27:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemCrc = atoi(element_value);
			break;

		case 28:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemW = atoi(element_value);
			break;

		case 29:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemIDot = atoi(element_value);
			break;

		case 30:
			gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemOmegaADot = atoi(element_value);
			dbg("NavigationSatInfo[%d].NavigationEphemeris.ephemOmegaADot - 0x%X\n", element_count, gpsdata_assist->navi_model.NavigationSatInfo[element_count].NavigationEphemeris.ephemOmegaADot);
			break;

		default:
			dbg("invalid gps element");
		}
	}
}


// Set coordinate elements  : <latitude> <longitude> <altitude>
static void _set_coordinate(xmlNodePtr node, gps_ellipsoid_po_t *point, int isalt, int altitude)
{
	// <parent_node> .. .. (xmlNodePtr node)
	// <coordinate>  <latitude>  <north>0</north>  <degrees>0</degrees> </latitude> <longitude>0</longitude> </coordinate>
	// <altitude>  <height_above_surface>0</height_above_surface>  <height>0</height> </altitude>
	// .. .. <\parent_node>

	xmlNodePtr coordinate_node = NULL, temp_node = NULL;

	memset(node_name, 0x00, sizeof(node_name));
	memset(node_value, 0x00, sizeof(node_value));

	sprintf(node_name, "%s", "coordinate");
	coordinate_node = xmlNewChild(node, NULL, BAD_CAST node_name, NULL);

	sprintf(node_name, "%s", "latitude");
	temp_node = xmlNewChild(coordinate_node, NULL, BAD_CAST node_name, NULL);

	sprintf(node_name, "%s", "north");
	sprintf(node_value, "%d", 0);
	xmlNewChild(temp_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "degrees");
	sprintf(node_value, "%d", (int) point->latitude);
	xmlNewChild(temp_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "longitude");
	sprintf(node_value, "%d", (int) point->longitude);
	xmlNewChild(coordinate_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	if (isalt) {
		sprintf(node_name, "%s", "altitude");
		temp_node = xmlNewChild(node, NULL, BAD_CAST node_name, NULL);
		sprintf(node_name, "%s", "height_above_surface");
		sprintf(node_value, "%d", 0);
		xmlNewChild(temp_node, NULL, BAD_CAST node_name, BAD_CAST node_value);
		sprintf(node_name, "%s", "height");
		sprintf(node_value, "%d", altitude);
		xmlNewChild(temp_node, NULL, BAD_CAST node_name, BAD_CAST node_value);
	}
	return;
}

static void _set_loc_info_ellipse_elements(xmlNodePtr node, void *elliplse, int is_unc_ellipse)
{
	gps_po_unc_ellipse_t *p_unc_ellipse;
	gps_po_alt_unc_ellipse_t *p_alt_unc_ellipse;
	unsigned char semiMajorAxis, semiMinorAxis, orientationAngle, confidence;

	memset(node_name, 0x00, sizeof(node_name));
	memset(node_value, 0x00, sizeof(node_value));

	if (is_unc_ellipse) {
		p_unc_ellipse = (gps_po_unc_ellipse_t *) elliplse;
		semiMajorAxis = p_unc_ellipse->semiMajorAxis;
		semiMinorAxis = p_unc_ellipse->semiMinorAxis;
		orientationAngle = p_unc_ellipse->orientationAngle;
		confidence = p_unc_ellipse->confidence;
	} else {
		p_alt_unc_ellipse = (gps_po_alt_unc_ellipse_t *) elliplse;
		semiMajorAxis = p_alt_unc_ellipse->semiMajorAxis;
		semiMinorAxis = p_alt_unc_ellipse->semiMinorAxis;
		orientationAngle = p_alt_unc_ellipse->orientationAngle;
		confidence = p_alt_unc_ellipse->confidence;
	}

	sprintf(node_name, "%s", "uncert_semi_major");
	sprintf(node_value, "%d", semiMajorAxis);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "uncert_semi_minor");
	sprintf(node_value, "%d", semiMinorAxis);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "orient_major");
	sprintf(node_value, "%d", orientationAngle);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "confidence");
	sprintf(node_value, "%d", confidence);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);
}

static xmlChar* _generate_confirm_measure_pos_xml_text(gps_measure_position_confirm_t *gps_measure_position_confirm)
{
	xmlDocPtr doc = NULL;
	xmlNodePtr root_node = NULL, node = NULL;
	xmlNodePtr gps_msr_node = NULL, shape_data_node = NULL, loc_child_node = NULL;
	xmlChar *xml = NULL;
	int count = 0, altitude, size;

/*
     Creates a new XML document
================================================================================================================================


    <?xml version="1.0"?>
    <pos xsi:noNamespaceSchemaLocation="pos.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
        <GPS_meas>
            <ref_time_only>
                <tow_msec></tow_msec>
            </ref_time_only>
            <meas_params>
                <sat_id></sat_id><carr2_noise></carr2_noise><dopl></dopl><whole_chips></whole_chips><fract_chips></fract_chips>
                <multi_path literal="xx"></multi_path> <psr_rms_err></psr_rms_err>
            </meas_params>
        </GPS_meas>
        <location>
            <time_of_fix></time_of_fix><
            <location_parameters>
            <shape_data>
             <ellipsoid_point>
                <coordinate>
                    <latitude><north></north><degrees></degrees></latitude><longitude></longitude>
                 </coordinate>
             </ellipsoid_point>
            <ellipsoid_point_uncert_circle>
                <uncert_circle></uncert_circle>
                <coordinate>
                <latitude> <> <\> ...</latitude> <longitude></longitude>
                </coordinate>
            </ellipsoid_point_uncert_circle>
            <ellipsoid_point_uncert_ellipse>
                <coordinate>
                    <latitude><> <\>..<longitude></longitude>
                </coordinate>
                <uncert_ellipse><uncert_semi_major></uncert_semi_major><uncert_semi_minor></uncert_semi_minor>
                <orient_major></orient_major><confidence></confidence></uncert_ellipse>
            </ellipsoid_point_uncert_ellipse>
            <polygon>
                <coordinate*>
                    <latitude><> <\>...</latitude><longitude></longitude>
                </coordinate>
            </polygon>
             <ellipsoid_point_alt>
                <coordinate>
                     <latitude><> <\>..</latitude><longitude></longitude>
                </coordinate>
            <altitude>
                <height_above_surface></height_above_surface><height></height>
            </altitude>
            </ellipsoid_point_alt>
            <ellipsoid_point_alt_uncertellipse>
            <coordinate>
                <latitude> <> <\>.. ..</latitude><longitude></longitude>
            </coordinate>
            <altitude>
                <height_above_surface></height_above_surface><height></height>
            </altitude>
            <uncert_semi_major></uncert_semi_major><uncert_semi_minor></uncert_semi_minor><orient_major></orient_major>
            <confidence></confidence><uncert_alt></uncert_alt>
            </ellipsoid_point_alt_uncertellipse>
            <ellips_arc>
                <coordinate>
                    <latitude><> <\> .. </latitude><longitude></longitude>
                </coordinate><
                <inner_rad></inner_rad>
                <uncert_rad></uncert_rad><offset_angle></offset_angle><included_angle></included_angle>
                <confidence></confidence>
            </ellips_arc>
            </shape_data>
            </location_parameters>
            </location>
            <assist_data>
                <msr_assist_data/>
            </assist_data>
         </pos>
 ================================================================================================================================
 */

	doc = xmlNewDoc(BAD_CAST "1.0");
	dbg("Enter");

	memset(node_name, 0x00, sizeof(node_name));
	memset(node_value, 0x00, sizeof(node_value));
	// root element
	sprintf(node_name, "%s", POSITION_NODE);
	// Creation of a new node element
	root_node = xmlNewNode(NULL, BAD_CAST node_name);
	// Set the root element of the document
	xmlDocSetRootElement(doc, root_node);
	sprintf(node_name, "%s", POSITION_NODE_ATTR_XSI);
	sprintf(node_value, "%s", POSITION_NODE_ATTR_VAL_XSI);
	// Create a new property carried by a node
	xmlNewProp(root_node, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", POSITION_NODE_ATTR_XMLNS);
	sprintf(node_value, "%s", POSITION_NODE_ATTR_VAL_XMLNS);
	xmlNewProp(root_node, BAD_CAST node_name, BAD_CAST node_value);

	// 1.GPS measure.
	// Creation of a new child element, added at the end of @parent children list
	sprintf(node_name, "%s", "GPS_meas");
	gps_msr_node = xmlNewChild(root_node, NULL, BAD_CAST node_name, NULL);

	sprintf(node_name, "%s", "ref_time_only");
	node = xmlNewChild(gps_msr_node, NULL, BAD_CAST node_name, NULL);

	sprintf(node_name, "%s", "tow_msec");
	sprintf(node_value, "%d", (int) gps_measure_position_confirm->gps_measure.gpsTow);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	// creatation of <meas_params> elements.
	for (count = 0; count < gps_measure_position_confirm->gps_measure.nrOfSats; count++) {
		xmlNodePtr multipath_node = NULL;
		sprintf(node_name, "%s", "meas_params");
		node = xmlNewChild(gps_msr_node, NULL, BAD_CAST node_name, NULL);

		sprintf(node_name, "%s", "sat_id");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].satId);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

		sprintf(node_name, "%s", "carr2_noise");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].cno);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

		sprintf(node_name, "%s", "dopl");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].doppler);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

		sprintf(node_name, "%s", "whole_chips");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].wholeChips);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

		sprintf(node_name, "%s", "fract_chips");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].fracChips);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

		sprintf(node_name, "%s", "multi_path");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].lcsMultiPath);
		multipath_node = xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);
		xmlNewProp(multipath_node, BAD_CAST "literal", BAD_CAST "not_measured");

		sprintf(node_name, "%s", "psr_rms_err");
		sprintf(node_value, "%d", gps_measure_position_confirm->gps_measure.GpsMeasure[count].pseuRangeRmsErr);
		xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);
	}

	// 2.Location.
	sprintf(node_name, "%s", "location");
	node = xmlNewChild(root_node, NULL, BAD_CAST node_name, NULL);

	sprintf(node_name, "%s", "time_of_fix");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.fixType);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	// location_parameters
	sprintf(node_name, "%s", "location_parameters");
	node = xmlNewChild(node, NULL, BAD_CAST node_name, NULL);

	// shape_data
	sprintf(node_name, "%s", "shape_data");
	shape_data_node = xmlNewChild(node, NULL, BAD_CAST node_name, NULL);

	// ellipsoid_point
	sprintf(node_name, "%s", "ellipsoid_point");
	node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	// set coordinate.
	_set_coordinate(node, &(gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_po), 0, 0);

	// ellipsoid_point_uncert_circle
	sprintf(node_name, "%s", "ellipsoid_point_uncert_circle");
	node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	sprintf(node_name, "%s", "uncert_circle");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.p_unc_clrcle.uncertainRadius);
	xmlNewChild(node, NULL, BAD_CAST node_name, BAD_CAST node_value);
	// set coordinate parameters.
	_set_coordinate(node, &(gps_measure_position_confirm->loc_info.measured_loc_info.p_unc_clrcle.point), 0, 0);

	// ellipsoid_point_uncert_ellipse
	sprintf(node_name, "%s", "ellipsoid_point_uncert_ellipse");
	loc_child_node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	// set coordinate parameters.
	_set_coordinate(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.p_unc_clrcle.point), 0, 0);

	sprintf(node_name, "%s", "uncert_ellipse");
	node = xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, NULL);
	// set location ellipse parametes.
	_set_loc_info_ellipse_elements(node, &(gps_measure_position_confirm->loc_info.measured_loc_info.p_unc_ellipse), 1);

	sprintf(node_name, "%s", "polygon");
	loc_child_node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	for (count = 0; count < gps_measure_position_confirm->loc_info.measured_loc_info.polygon.noOfPoints; count++) {
		// set coordinate parameters.
		_set_coordinate(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.polygon.points[count]), 0, 0);
	}

	// ellipsoid_point_alt
	sprintf(node_name, "%s", "ellipsoid_point_alt");
	loc_child_node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	altitude = gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_alt.altitude;
	// set coordinate parameters.
	_set_coordinate(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_alt.point), 1, altitude);

	// ellipsoid_point_alt_uncertellipse
	sprintf(node_name, "%s", "ellipsoid_point_alt_uncertellipse");
	loc_child_node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	altitude = gps_measure_position_confirm->loc_info.measured_loc_info.p_alt_unc_ellipse.altitude;
	// set coordinate parameters.
	_set_coordinate(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.p_alt_unc_ellipse.point), 1, altitude);
	// set location ellipse parametes.
	_set_loc_info_ellipse_elements(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.p_alt_unc_ellipse), 0);

	sprintf(node_name, "%s", "uncert_alt");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.p_alt_unc_ellipse.uncertainAltitude);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	// ellipsoid_point_alt_uncertellipse
	sprintf(node_name, "%s", "ellips_arc");
	loc_child_node = xmlNewChild(shape_data_node, NULL, BAD_CAST node_name, NULL);
	_set_coordinate(loc_child_node, &(gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.point), 0, 0);

	sprintf(node_name, "%s", "inner_rad");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.innerRadius);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "uncert_rad");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.uncertainRadius);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "offset_angle");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.offsetAngle);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "included_angle");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.includedAngle);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	sprintf(node_name, "%s", "confidence");
	sprintf(node_value, "%d", gps_measure_position_confirm->loc_info.measured_loc_info.ellipsoid_arc.confidence);
	xmlNewChild(loc_child_node, NULL, BAD_CAST node_name, BAD_CAST node_value);

	// 3. assist data /msr_assist_data
	sprintf(node_name, "%s", "assist_data");
	node = xmlNewChild(root_node, NULL, BAD_CAST node_name, NULL);
	sprintf(node_name, "%s", "msr_assist_data");
	xmlNewChild(node, NULL, BAD_CAST node_name, NULL);

	// Dump an XML document in memory and return the #xmlChar * and it's size in bytes
	xmlDocDumpMemory(doc, &xml, &size);
	dbg("xmlcontetnt:\n");
	dbg("%s", (char *) xml);
	// Free up all the structures used by a document, tree included.
	xmlFreeDoc(doc);
	xmlCleanupParser();
	return xml;
}

static gboolean on_notification_gps_assist_data(CoreObject *o, const void *event_info, void *user_data)
{
	int fd;
	gps_assist_data_noti_t gps_data_assist;
	char *node = NULL, *node_value = NULL;
	char *attribute = NULL, *attr_value = NULL;
	enum gps_assist_element_type node_type = -1, set_element_type = -1;
	int nav_model_node_count = -1;
	int alm_node_count = -1;
	int gps_tow_assist_count = -1;
	char *line = NULL, *pos = NULL;
	char *xml_line = NULL;
	gboolean ret;
	xmlTextReaderPtr reader;
	gboolean _gps_assist_data = FALSE, gps_tow_assist = FALSE;
	gboolean ephem_and_clock = FALSE, alm_elem = FALSE;

	dbg("enter");

/*
    Example:GPS assist XML data will be in below format.
================================================================================================================================
    +CPOSR:<?xml version="1.0" encoding="UTF-8"?>
    <pos xsi:noNamespaceSchemaLocation="pos.xsd" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <assist_data>
    <GPS_assist>
        <ref_time>
            <GPS_time> <> <\>..<\GPS_time> <GPS_TOW_assist*> <> <\> ..<\GPS_TOW_assist>
        </ref_time>

        <location_parameters>
            <shape_data> <ellipsoid_point_alt_uncertellipse> </coordinate> <> <\>...</coordinate> <altitude> <\altitude>
             <uncert_semi_major> </uncert_semi_major> <uncert_semi_minor> </uncert_semi_minor> <orient_major> </orient_major> <confidence> </confidence>
            <uncert_alt> </uncert_alt>  </ellipsoid_point_alt_uncertellipse> </shape_data>
        </location_parameters>

        <DGPS_corrections>
            <sat_id> </sat_id> <IODE> </IODE> <UDRE></UDRE> <PRC></PRC> <RRC></RRC>
        </DGPS_corrections>

        <nav_model_elem*>
            <sat_id> </sat_id> <sat_status literal="xx"></sat_status>
            <ephem_and_clock?> <l2_code></l2_code> <> <\> .. ..  <\ephem_and_clock>
        </nav_model_elem>

        <ionospheric_model> <alfa0> </alfa0> <alfa1> </alfa1> <alfa2> </alfa2>  <alfa3></alfa3>
            <beta0></beta0> <beta1></beta1> <beta2></beta2>  <beta3> </beta3>
        </ionospheric_model>

        <UTC_model>
            <a1></a1><a0></a0><tot></tot><wnt></wnt> <dtls></dtls> <wnlsf></wnlsf> <dn></dn><dtlsf></dtlsf>
        </UTC_model>
        <almanac>
            <wna>0</wna> <alm_elem*> <> <\> ...<\alm_elem>
        </almanac>

        <acqu_assist>
            <tow_msec></tow_msec>  <sat_info> <> <\> ...  <\sat_info>
        </acqu_assist>

    </GPS_assist>
    </assist_data>
    </pos>
================================================================================================================================
*/

	memset((void *) &gps_data_assist, 0x00, sizeof(gps_data_assist));
	xml_line = (char *) ((GSList *) event_info)->data;

	if (g_str_has_prefix((char *) xml_line, "+CPOSR:")) {
		dbg("notification line with prefix");
		pos = (char *) xml_line + strlen("+CPOSR:");
	} else {
		pos = (char *) xml_line;
	}
	line = g_strdup((char *) pos);
	// open file.
	if ((fd = open(FILE_NAME, O_WRONLY | O_CREAT | O_TRUNC | S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH, S_IRWXU)) == -1) {
		dbg("Cannot open file\n");
		g_free(line);
		return FALSE;
	}
	// write gps xml data into file.
	if (write(fd, (const void *) line, strlen(line)) == -1) {
		dbg("Cannot write into file\n");
		close(fd);
		g_free(line);
		return FALSE;
	}
	// free the memory pointed to by line.
	g_free(line);

	dbg("read xml file");
	reader = xmlReaderForFile(FILE_NAME, NULL, 0);

	while (xmlTextReaderRead(reader)) {
		// Get the node type of the current node
		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT:
		{
			// Read the qualified name of the node.
			node = (char *) xmlTextReaderConstName(reader);
			dbg("Element: %s\n ", node);
			if (node != NULL) {
				// check type of sub element of <GPS_assist>
				set_element_type = _get_element_type(node);
				if ((int) set_element_type != -1)     // ignore negative value as excepted element type not set.
					node_type = set_element_type;

				dbg("xml node type  : %d", node_type);

				// Check for position measurement data.
				if (strcmp(node, "pos_meas") == 0) {
					// Deallocate all the resources associated to the reader
					xmlFreeTextReader(reader);
					xmlCleanupParser();
					dbg("gps postion measurement notification ");
					// GPS position measurement notification.
					ret = on_notification_gps_measure_position_from_modem(o, FILE_NAME, user_data);
					// remove file.
					close(fd);
					if (access(FILE_NAME, F_OK) == 0) {
						if (remove(FILE_NAME))
							dbg("file removed");
					}
					return ret;
				}

				// Moves the position of the current instance to the next attribute associated with the current node.
				while (xmlTextReaderMoveToNextAttribute(reader)) {
					// Read the qualified name of the node
					attribute = (char *) xmlTextReaderConstName(reader);
					dbg("attribute value - %s\n", attribute);

					// Provides the text value of the node if present.
					attr_value = (char *) xmlTextReaderConstValue(reader);
					dbg("=\"%s\"\n", attr_value);

					// Read attribute value of <nav_model_elem>
					if (node_type == NAV_MODEL_ELEM) {
						if (strcmp(node, "sat_status") == 0 && strcmp(attribute, "literal") == 0) {
							gps_data_assist.navi_model.NavigationSatInfo[nav_model_node_count].NavigationSatStatus = _modem_sat_status_info_2_tel_sat_info(attr_value);
							dbg("navigation sat status of nav model element - %d\n", gps_data_assist.navi_model.NavigationSatInfo[nav_model_node_count].NavigationSatStatus);
						}
					}
					// Read attribute value of <acqu_assist>
					else if (node_type == ACQU_ASSIST) {
						if (strcmp(node, "dopl1_uncert") == 0 && strcmp(attribute, "literal") == 0) {
							gps_data_assist.acq_assist.lcsAcquisitionSatInfo[0].dopplerUncertainty = _modem_acqa_assit_doppler_2_tel_doppler(attr_value);
							dbg("doppler uncertainty of acqu assist data- %d", gps_data_assist.acq_assist.lcsAcquisitionSatInfo[0].dopplerUncertainty);
						}
					}
				}        // end of attribute check.

				// check GPS data is having GPS_assist data.
				if (strcmp(node, "GPS_assist") == 0) {
					_gps_assist_data = TRUE;
				}

				if (_gps_assist_data == TRUE) {
					// number of GPS_TOW_assist elements.
					if (strcmp(node, "GPS_TOW_assist") == 0) {
						gps_tow_assist_count++;
						gps_tow_assist = TRUE;
					} else if (strcmp(node, "nav_model_elem") == 0) {
						// number of nav_model_elem.
						nav_model_node_count++;
					} else if (strcmp(node, "alm_elem") == 0) {
						// number of alm_elem elements.
						alm_node_count++;
						dbg("alm_elem_count - %d", alm_node_count);
						if (node_type == ALMANAC)
							alm_elem = TRUE;
					} else if (strcmp(node, "ephem_and_clock") == 0 && node_type == NAV_MODEL_ELEM) {
						ephem_and_clock = TRUE;
					}
				}
			}
			xmlTextReaderMoveToElement(reader);
		}     // end of reading node type.
		break;

		case XML_READER_TYPE_TEXT:
		{
			// Provides the text value of the node if present
			node_value = (char *) xmlTextReaderConstValue(reader);
			dbg("node_value: %s\n", node_value);

			if (node_value != NULL) {
				switch (node_type) {
				case REF_TIME:
					_parse_ref_time_gps_elements(node, node_value, &gps_data_assist, gps_tow_assist, gps_tow_assist_count);
					break;

				case LOCATION_PARM:
					_parse_location_parameters(node, node_value, &gps_data_assist);
					break;

				case DGPS_CORRECTION:
					_parse_dgps_correction_gps_elements(node, node_value, &gps_data_assist);
					break;

				case NAV_MODEL_ELEM:
					_parse_nav_model_gps_elements(node, node_value, &gps_data_assist, ephem_and_clock, nav_model_node_count);
					break;

				case IONOSPHERIC_MODEL:
					_parse_ionospheric_model_gps_elements(node, node_value, &gps_data_assist);
					break;

				case UTC_MODEL:
					_parse_utc_model_gps_elements(node, node_value, &gps_data_assist);
					break;

				case ALMANAC:
					_parse_almanc_model_gps_elements(node, node_value, &gps_data_assist, alm_elem, alm_node_count);
					break;

				case ACQU_ASSIST:
					_parse_acqu_assist_gps_elements(node, node_value, &gps_data_assist);
					break;

				default:
					dbg("invalid element");
				}
			}
		}     // end of reading node value.
		break;
		}
	} // end of parsing.

	// Deallocate all the resources associated to the reader
	xmlFreeTextReader(reader);
	xmlCleanupParser();

	// remove xml file.
	close(fd);
	if (access(FILE_NAME, F_OK) == 0) {
		if (remove(FILE_NAME))
			dbg("file removed");
	}

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)),
								   o, TNOTI_GPS_ASSIST_DATA, sizeof(gps_data_assist), &gps_data_assist);
	return TRUE;
}

static gboolean on_notification_gps_measure_position_from_modem(CoreObject *o, char *file_name, void *user_data)
{
	char *node = NULL, *node_value = NULL;
	char *attribute = NULL;
	char *attr_value = NULL;
	gps_measure_position_indi_t gps_measure_position_indi;
	gboolean rep_quant = FALSE;
	xmlTextReaderPtr reader;

	memset(&gps_measure_position_indi, 0x00, sizeof(gps_measure_position_indi));
	reader = xmlReaderForFile(file_name, NULL, 0);

	while (xmlTextReaderRead(reader)) {
		switch (xmlTextReaderNodeType(reader)) {
		case XML_READER_TYPE_ELEMENT:
		{
			node = (char *) xmlTextReaderConstName(reader);
			dbg("Element: %s", node);
			if (node != NULL) {
				// Read attribute value.
				while (xmlTextReaderMoveToNextAttribute(reader)) {
					attribute = (char *) xmlTextReaderConstName(reader);
					dbg("Attribute value - %s\n", attribute);
					attr_value = (char *) xmlTextReaderConstValue(reader);
					dbg("=\"%s\"\n", attr_value);

					if (strcmp(node, "mult_sets") == 0) {
						if (strcmp(attribute, "literal") == 0) {
							if (strcmp(attr_value, "one") == 0)
								gps_measure_position_indi.use_multi_sets = GPS_MULTIPLESETS_ONESET;
							else if (strcmp(attr_value, "multiple") == 0)
								gps_measure_position_indi.use_multi_sets = GPS_MULTIPLESETS_MULTIPLESETS;
						}
						dbg("gps_measure_position_indi.use_multi_sets - 0x%x\n", gps_measure_position_indi.use_multi_sets);
					} else if (strcmp(node, "rep_quant") == 0) {
						rep_quant = TRUE;
						if (strcmp(attribute, "addl_assist_data_req") == 0) {
							if (strcmp(attr_value, "true") == 0)
								gps_measure_position_indi.add_assist_req = GPS_ADDITIONAL_ASSISREQ_REQ;
							else
								gps_measure_position_indi.add_assist_req = GPS_ADDITIONAL_ASSISREQ_NOT_REQ;
						} else if (strcmp(attribute, "gps_timing_of_cell_wanted") == 0) {
							if (strcmp(attr_value, "true") == 0)
								gps_measure_position_indi.cell_timing_wnt = GPS_CELLTIMING_WANTED;
							else
								gps_measure_position_indi.cell_timing_wnt = GPS_CELLTIMING_NOT_WANTED;
						}
					}
				}        // end of attribute check

				if (strcmp(node, "ms_assisted") == 0) {
					gps_measure_position_indi.method_type = GPS_METHODTYPE_MS_ASSISTED;
				} else if (strcmp(node, "ms_assisted_no_accuracy") == 0) {
					gps_measure_position_indi.method_type = GPS_METHODTYPE_MS_ASSISTED;
				} else if (strcmp(node, "ms_based") == 0) {
					gps_measure_position_indi.method_type = GPS_METHODTYPE_MS_BASED;
				} else if (strcmp(node, "ms_based_pref") == 0) {
					gps_measure_position_indi.method_type = GPS_METHODTYPE_MS_BASED_PREF;
				} else if (strcmp(node, "ms_assisted_pref") == 0) {
					gps_measure_position_indi.method_type = GPS_METHODTYPE_MS_ASSISTED_PREF;
				}
			}
			xmlTextReaderMoveToElement(reader);
		}
		break;

		case XML_READER_TYPE_TEXT:
		{
			node_value = (char *) xmlTextReaderConstValue(reader);
			dbg("element-value: %s", node_value);
			if (node_value != NULL) {
				if (strcmp(node, "resp_time_seconds") == 0) {
					gps_measure_position_indi.rsp_time = *node_value;
					dbg("gps_measure_position_indi.rsp_time - 0x%x", gps_measure_position_indi.rsp_time);
				}
				if (rep_quant == TRUE) {
					if (strcmp(node, "hor_acc") == 0)
						gps_measure_position_indi.accuracy.horizontalAccuracy = *node_value;
					else if (strcmp(node, "vert_acc") == 0)
						gps_measure_position_indi.accuracy.vertcalAccuracy = *node_value;
				}
			}
		}
		break;
		}
	}
	xmlFreeTextReader(reader);
	xmlCleanupParser();

	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)),
								   o, TNOTI_GPS_MEASURE_POSITION, sizeof(gps_measure_position_indi), &gps_measure_position_indi);
	return TRUE;
}


// CONFIRMATION
static void on_confirmation_gps_message_send(TcorePending *p, gboolean result, void *user_data)
{
	dbg("Entry");

	if (result == FALSE) {  // Fail
		dbg("SEND FAIL");
	} else {
		dbg("SEND OK");
	}

	dbg("Exit");
	return;
}

static gboolean on_notification_reset_assist_data(CoreObject *o, const void *event_info, void *user_data)
{
	dbg("enter!\n");
	tcore_server_send_notification(tcore_plugin_ref_server(tcore_object_ref_plugin(o)),
								   o, TNOTI_GPS_RESET_ASSIST_DATA, 0, NULL);

	return TRUE;
}
static void on_confirmation_gps_measure_position(TcorePending *p, int data_len, const void *data, void *user_data)
{
	//GPS server does not except confirmation for GPS measure position request.
	dbg("enter");

	dbg("exit");
}

static TReturn gps_confirm_measure_pos(CoreObject *o, UserRequest *ur)
{
	char *raw_str = NULL;
	char *cmd_str = NULL;
	TcorePending *pending = NULL;
	TcoreATRequest *req = NULL;
	TcoreHal *hal = NULL;
	gboolean ret = FALSE;
	xmlChar *xml = NULL;
	unsigned char *data = NULL;
	unsigned int data_len;
	gps_measure_position_confirm_t gps_measure_pos_confirm;

	dbg("enter!");
	if (!o || !ur)
		return TCORE_RETURN_EINVAL;

	data = (unsigned char *) tcore_user_request_ref_data(ur, &data_len);
	memcpy(&gps_measure_pos_confirm, data, data_len);

	// make confirm measure postion request in xml format.
	xml = _generate_confirm_measure_pos_xml_text(&gps_measure_pos_confirm);
	if (!xml) {
		err("xml text generation failed");
		return TCORE_RETURN_EINVAL;
	}

	// AT+CPOS<cr>text is entered<ctrl-z/esc>
	raw_str = g_strdup_printf("AT+CPOS%s", "\r");
	cmd_str = g_strdup_printf("%s%s\x1A", raw_str, xml);

	dbg("command string : %s", cmd_str);
	pending = tcore_pending_new(o, 0);
	req = tcore_at_request_new(cmd_str, NULL, TCORE_AT_NO_RESULT);
	dbg("cmd : %s, prefix(if any) :%s, cmd_len : %d", req->cmd, req->prefix, strlen(req->cmd));
	tcore_pending_set_request_data(pending, strlen(cmd_str), req);
	tcore_pending_set_priority(pending, TCORE_PENDING_PRIORITY_DEFAULT);
	tcore_pending_set_send_callback(pending, on_confirmation_gps_message_send, NULL);
	tcore_pending_set_response_callback(pending, on_confirmation_gps_measure_position, NULL);
	tcore_pending_link_user_request(pending, ur);

	// HAL
	hal = tcore_object_get_hal(o);
	// Send request to HAL
	ret = tcore_hal_send_request(hal, pending);
	if (TCORE_RETURN_SUCCESS != ret) {
		err("Request send failed");
		ret = FALSE;
	}

	dbg("exit");
	g_free(raw_str);
	g_free(cmd_str);
	xmlFree(xml);
	return ret;
}

static struct tcore_gps_operations gps_ops = {
	.confirm_measure_pos = gps_confirm_measure_pos,
};

gboolean imc_gps_init(TcorePlugin *cp, CoreObject *co_gps)
{
	dbg("Enter");

	/* Set operations */
	tcore_gps_set_ops(co_gps, &gps_ops);

	tcore_object_add_callback(co_gps, "+CPOSR", on_notification_gps_assist_data, NULL);
	tcore_object_add_callback(co_gps, "+XCPOSR", on_notification_reset_assist_data, NULL);

	dbg("Exit");

	return TRUE;
}

void imc_gps_exit(TcorePlugin *cp, CoreObject *co_gps)
{
	dbg("Exit");
}
