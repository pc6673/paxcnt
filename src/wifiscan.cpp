// Basic Config
#include "globals.h"
#include "wifiscan.h"
#include <esp_coexist.h>
#include "coexist_internal.h"
#include <stdlib.h>
#include <sstream> //stringstream
#include <string> //string


using namespace std;
// Local logging tag
static const char TAG[] = "wifi";

TimerHandle_t WifiChanTimer;

static wifi_country_t wifi_country = {WIFI_MY_COUNTRY, WIFI_CHANNEL_MIN,
                                      WIFI_CHANNEL_MAX, 100,
                                      WIFI_COUNTRY_POLICY_MANUAL};

// typedef struct frame_ctrl_t
// {
//     unsigned int protoVer:2; /* protocol version*/
//     unsigned int type:2; /*frame type field (Management,Control,Data)*/
//     unsigned int subtype:4; /* frame subtype*/

//     unsigned int toDS:1; /* frame coming from Distribution system */
//     unsigned int fromDS:1; /*frame coming from Distribution system */
//     unsigned int moreFrag:1; /* More fragments?*/
//     unsigned int retry:1; /*was this frame retransmitted*/

//     unsigned int powMgt:1; /*Power Management*/
//     unsigned int moreDate:1; /*More Date*/
//     unsigned int protectedData:1; /*Protected Data*/
//     unsigned int order:1; /*Order*/
// }frame_ctrl;

typedef struct {
  unsigned frame_ctrl : 16;
  //frame_ctrl_t frame_ctrl;
  unsigned duration_id : 16;
  uint8_t addr1[6]; // receiver address
  uint8_t addr2[6]; // sender address
  uint8_t addr3[6]; // filtering address BSSID
  unsigned sequence_ctrl : 16;
  uint8_t addr4[6]; // optional
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; // network data ended with 4 bytes csum (CRC32)
} wifi_ieee80211_packet_t;

typedef enum
{
    ASSOCIATION_REQ,
    ASSOCIATION_RES,
    REASSOCIATION_REQ,
    REASSOCIATION_RES,
    PROBE_REQ,
    PROBE_RES,
    NU1,  /* ......................*/
    NU2,  /* 0110, 0111 not used */
    BEACON,
    ATIM,
    DISASSOCIATION,
    AUTHENTICATION,
    DEAUTHENTICATION,
    ACTION,
    ACTION_NACK,
} wifi_mgmt_subtypes_t;

typedef struct
{
  unsigned interval:16;
  unsigned capability:16;
  unsigned tag_number:8;
  unsigned tag_length:8;
  char ssid[0];
  uint8_t rates[1];
} wifi_mgmt_beacon_t;

static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
const char *
wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
	switch(type) {
	case WIFI_PKT_MGMT: return "MGMT";
	case WIFI_PKT_DATA: return "DATA";
	default:	
	case WIFI_PKT_MISC: return "MISC";
	}
}

//Parses 802.11 packet type-subtype pair into a human-readable string
static const char *wifi_pkt_type2str(wifi_promiscuous_pkt_type_t type, wifi_mgmt_subtypes_t subtype);
const char* 
wifi_pkt_type2str(wifi_promiscuous_pkt_type_t type, wifi_mgmt_subtypes_t subtype)
{
  switch(type)
  {
    case WIFI_PKT_MGMT:
      switch(subtype)
      {
    	   case ASSOCIATION_REQ:
         return "Mgmt: Association request";
         case ASSOCIATION_RES:
         return "Mgmt: Association response";
         case REASSOCIATION_REQ:
         return "Mgmt: Reassociation request";
         case REASSOCIATION_RES:
         return "Mgmt: Reassociation response";
         case PROBE_REQ:
         return "Mgmt: Probe request";
         case PROBE_RES:
         return "Mgmt: Probe response";
         case BEACON:
         return "Mgmt: Beacon frame";
         case ATIM:
         return "Mgmt: ATIM";
         case DISASSOCIATION:
         return "Mgmt: Dissasociation";
         case AUTHENTICATION:
         return "Mgmt: Authentication";
         case DEAUTHENTICATION:
         return "Mgmt: Deauthentication";
         case ACTION:
         return "Mgmt: Action";
         case ACTION_NACK:
         return "Mgmt: Action no ack";
    	default:
        return "Mgmt: Unsupported/error";
      }

    case WIFI_PKT_CTRL:
    return "Control";

    case WIFI_PKT_DATA:
    return "Data";

    default:
      return "Unsupported/error";
  }
}
// using IRAM_:ATTR here to speed up callback function, callback function will then parse each raw packet (buff) as follows:
static IRAM_ATTR void wifi_sniffer_packet_handler(void *buff,
                                           wifi_promiscuous_pkt_type_t type) {

  if (type != WIFI_PKT_MGMT) 
    return;                                           

  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;// Type cast the received buffer into our generic SDK structure
  const wifi_ieee80211_packet_t *ipkt =
      (wifi_ieee80211_packet_t *)ppkt->payload;// pointer to where the sctual 802.11 packet is within the structure
  //define pointers to the 802.11 packet header and payload
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr; 
  const uint8_t *data = ipkt->payload;
  //Pointer to the frame control section within the packet header
  // const frame_ctrl_t *frame_ctrl = 
  //   (frame_ctrl_t *)&hdr->frame_ctrl;

  // printf("PACKET TYPE=%-28s, CHAN=%02d, RSSI=%02d,"
	// 	" ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
	// 	" ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
	// 	" ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
	// 	//wifi_sniffer_packet_type2str(type),
  //   wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)frame_ctrl->type, (wifi_mgmt_subtypes_t)FC->subtype),
	// 	ppkt->rx_ctrl.channel,
	// 	ppkt->rx_ctrl.rssi,
    
	// 	/* ADDR1 */
	// 	hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
	// 	hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
	// 	/* ADDR2 */
	// 	hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
	// 	hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
	// 	/* ADDR3 */
	// 	hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
	// 	hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
	// );
  
  
  unsigned int protocol = (hdr->frame_ctrl  & (0x0003)) ;
  unsigned int type1 = (hdr->frame_ctrl & (0x000C)) >> 2;
  unsigned int subtype1 = (hdr->frame_ctrl & (0x00F0)) >>4;
  unsigned int sequencenumber1 = (hdr->sequence_ctrl  & (0xFFF0)>>4);
 
  if (type1 == WIFI_PKT_MGMT && subtype1 == PROBE_REQ && (macs_cnt < (MAC_ARRAY_SIZE-1)) )
   {
    // Serial.printf("\n%02X:%02X:%02X:%02X:%02X:%02X | %u | %u |%u| %02d \n ",
    // hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    // sequencenumber1,
    // ppkt->rx_ctrl.timestamp,
    // ppkt->rx_ctrl.channel,
    // ppkt->rx_ctrl.rssi );
    // String st_slash;
    // String st_sequencenumber1;
    // String st_timestamp ;
    // String st_channel;
    // String st_rssi ;
    // String st_addr2_0, st_addr2_1, st_addr2_2, st_addr2_3, st_addr2_4,st_addr2_5;
    // String st_combine;
    // st_slash = "|";

    // char ch[20];
  	// sprintf(ch, "%d", sequencenumber1);
    // //string st_sequencenumber1(ch, ch + strlen(ch));
    //  Serial.printf(ch);

  	array_macs[macs_cnt] .mac_addr[0] = hdr->addr2[0];
    array_macs[macs_cnt] .mac_addr[1] = hdr->addr2[1];
    array_macs[macs_cnt] .mac_addr[2] = hdr->addr2[2];
    array_macs[macs_cnt] .mac_addr[3] = hdr->addr2[3];
    array_macs[macs_cnt] .mac_addr[4] = hdr->addr2[4];
    array_macs[macs_cnt] .mac_addr[5] = hdr->addr2[5];
    array_macs[macs_cnt] .sequencenumber = sequencenumber1;
    array_macs[macs_cnt] .timestamp = ppkt->rx_ctrl.timestamp;
    array_macs[macs_cnt] .channel   = ppkt->rx_ctrl.channel;
    array_macs[macs_cnt] .rssi      = ppkt->rx_ctrl.rssi;

    macs_cnt++;

   }
 

  // Serial.printf("\n%02X:%02X:%02X:%02X:%02X:%02X | %02X:%02X:%02X:%02X:%02X:%02X | %02X:%02X:%02X:%02X:%02X:%02X |%u | %u | %02d | %u | %u(%-2u) | %-28s |  ",
  // hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
  // hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
  // hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],hdr->addr3[3],hdr->addr3[4],hdr->addr3[5],
  // sequencenumber1,
  // ppkt->rx_ctrl.channel,
  // ppkt->rx_ctrl.rssi,
  // protocol,
  // type1,
  // subtype1,
  // wifi_pkt_type2str((wifi_promiscuous_pkt_type_t)type1, (wifi_mgmt_subtypes_t)subtype1));

  // Print ESSID if beacon
  // if (type1 == WIFI_PKT_MGMT && subtype1 == BEACON)
  // {
  //   const wifi_mgmt_beacon_t *beacon_frame = (wifi_mgmt_beacon_t*) ipkt->payload;
  //   char ssid[32] = {0};

  //   if (beacon_frame->tag_length >= 32)
  //   {
  //     strncpy(ssid, beacon_frame->ssid, 31);
  //   }
  //   else
  //   {
  //     strncpy(ssid, beacon_frame->ssid, beacon_frame->tag_length);
  //   }
  //   Serial.printf("%s\n", ssid);
  // }

  //  Serial.println("InSnifferPacketHandler");
  //  Serial.println(ppkt->rx_ctrl.channel);
  //  Serial.println(ppkt->rx_ctrl.timestamp);
  //  //printf("%02x:%02x:%02x:%02x:%02x:%02x\n", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
  // char macstr1[18];
  // snprintf(macstr1, 18, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
  // Serial.println(macstr1);
  
  // Serial.print("One Mac is seen as below\n");
  // Serial.print( "sender address is: ");
  // char macstr1[18];
  // snprintf(macstr1, 18, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
  // Serial.println(macstr1);
  // Serial.print( " receiver address is :");
  // char macstr2[18];
  // snprintf(macstr2, 18, "%02x:%02x:%02x:%02x:%02x:%02x", hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],hdr->addr1[3],hdr->addr1[4],hdr->addr1[5]);
  // Serial.println(macstr2);
  // Serial.print( " RSSI is :");
  // char macstr3[10];
  // snprintf(macstr3, 10, "%d", ppkt->rx_ctrl.rssi);
  // Serial.println(macstr3);
  // Serial.print( "Timestamp is :");
  // char macstr4[12];
  // snprintf(macstr4, 12, "%d", ppkt->rx_ctrl.timestamp);
  // Serial.println(macstr4);
  // Serial.print( "Channel is :");
  // char macstr5[10];
  // snprintf(macstr5, 10, "%d", ppkt->rx_ctrl.channel);
  // Serial.println(macstr5);

  // char tbs[100];
  // sprintf(tbs, "In Snifferpackethandler\n");
  // sprintf(tbs, "Channel is %d\n", ppkt->rx_ctrl.channel);
  // sprintf(tbs, "RSS is %d\n", ppkt->rx_ctrl.rssi);
  // sprintf(tbs, " sender address is %02X:%02X:%02X:%02X:%02X:%02X\n",   hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],hdr->addr2[3],hdr->addr2[4],hdr->addr2[5]);
  // sprintf(tbs, " receiver address is %02X:%02X:%02X:%02X:%02X:%02X\n", hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],hdr->addr1[3],hdr->addr1[4],hdr->addr1[5]);
  // Serial.print(tbs);
  //Serial.print("wifisniffer");

  if ((cfg.rssilimit) &&
      (ppkt->rx_ctrl.rssi < cfg.rssilimit)) // rssi is negative value
    {
      
      ESP_LOGD(TAG, "WiFi RSSI %d -> ignoring (limit: %d)", ppkt->rx_ctrl.rssi,
             cfg.rssilimit);
    }
  else // count seen MAC
    {
      mac_add((uint8_t *)hdr->addr2, ppkt->rx_ctrl.rssi, MAC_SNIFF_WIFI);
    }
 
}

// Software-timer driven Wifi channel rotation callback function
void switchWifiChannel(TimerHandle_t xTimer) {

    if (channel_cnt<3) {
      channel = channel_valid[channel_cnt];
      channel =(channel % WIFI_CHANNEL_MAX) + 1; // rotate channel 1..WIFI_CHANNEL_MAX
      //ESP_LOGV(TAG, "Channel is %d", channel);  
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
      channel_cnt++;
    }
    else 
    {
    channel_cnt = 0;
    }
  }

void wifi_sniffer_init(void) {
  wifi_init_config_t wificfg = WIFI_INIT_CONFIG_DEFAULT();
  wificfg.nvs_enable = 0;        // we don't need any wifi settings from NVRAM
  wificfg.wifi_task_core_id = 0; // we want wifi task running on core 0

  // wifi_promiscuous_filter_t filter = {
  //    .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT}; // only MGMT frames
  // .filter_mask = WIFI_PROMIS_FILTER_MASK_ALL}; // we use all frames

  wifi_promiscuous_filter_t filter = {.filter_mask =
                                         WIFI_PROMIS_FILTER_MASK_MGMT |
                                         WIFI_PROMIS_FILTER_MASK_DATA};
  //wifi_promiscuous_filter_t filter = {.filter_mask =
  //                                        WIFI_PROMIS_FILTER_MASK_MGMT};//only MGMT frames

  ESP_ERROR_CHECK(esp_wifi_init(&wificfg)); // configure Wifi with cfg
  ESP_ERROR_CHECK(
      esp_wifi_set_country(&wifi_country)); // set locales for RF and channels
  ESP_ERROR_CHECK(
      esp_wifi_set_storage(WIFI_STORAGE_RAM)); // we don't need NVRAM
  ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
  ESP_ERROR_CHECK(esp_wifi_set_ps(WIFI_PS_NONE)); // no modem power saving
  ESP_ERROR_CHECK(esp_wifi_start()); // must be started to be able to switch ch
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_filter(&filter)); // set frame filter
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler));
  ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true)); // now switch on monitor mode
  //Serial.printf("\n\n    MAC Address 1|      MAC Address 2|      MAC Address 3| Seq| Cha| RSSI| Version| T(S)  |           Frame type         |   SSID\n");
  // setup wifi channel rotation timer
  WifiChanTimer =
      xTimerCreate("WifiChannelTimer", pdMS_TO_TICKS(cfg.wifichancycle * 10),
                   pdTRUE, (void *)0, switchWifiChannel);
  assert(WifiChanTimer);
  xTimerStart(WifiChanTimer, 0);

  }