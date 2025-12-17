/*
 * IDS Node with TinyML - Intrusion Detection System
 * Uses embedded machine learning for traffic classification
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "net/packetbuf.h"
#include "sys/log.h"
#include "random.h"

/* Include TinyML model - use trained weights if available */
#ifdef USE_TRAINED_MODEL
#include "tinyml_model_trained.h"
#include "tinyml_simple_model.h"
#define tinyml_init() simple_model_init()
#define tinyml_predict(x, n) simple_model_predict(x)
#else
#include "tinyml_model.h"
#endif
#include "feature_extractor.h"

#define LOG_MODULE "IDS-Node"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_SERVER_PORT 5678
#define UDP_CLIENT_PORT 8765

/* Feature extraction window */
#define FEATURE_WINDOW_SIZE 10
#define FEATURE_BUFFER_SIZE 32

/* Detection thresholds */
#define ANOMALY_THRESHOLD 0.7f
#define ALERT_COOLDOWN    (CLOCK_SECOND * 5)

/* Traffic flow structure for feature extraction */
typedef struct {
  uip_ipaddr_t src_addr;
  uip_ipaddr_t dst_addr;
  uint16_t src_port;
  uint16_t dst_port;
  uint32_t start_time;
  uint32_t last_time;
  uint32_t packet_count;
  uint32_t total_bytes;
  uint32_t fwd_packets;
  uint32_t bwd_packets;
  uint32_t fwd_bytes;
  uint32_t bwd_bytes;
  uint16_t min_pkt_len;
  uint16_t max_pkt_len;
  uint32_t sum_pkt_len;
  uint32_t iat_sum;       /* Inter-arrival time sum */
  uint32_t iat_min;
  uint32_t iat_max;
  uint8_t flags_syn;
  uint8_t flags_fin;
  uint8_t flags_rst;
  uint8_t flags_psh;
  uint8_t flags_ack;
  uint8_t protocol;
  uint8_t label;          /* 0=normal, 1=attack */
} flow_record_t;

/* Feature buffer for ML model */
static float feature_buffer[FEATURE_BUFFER_SIZE];
static flow_record_t current_flows[FEATURE_WINDOW_SIZE];
static uint8_t flow_count = 0;
static clock_time_t last_alert_time = 0;

/* Statistics */
static uint32_t total_packets_analyzed = 0;
static uint32_t attacks_detected = 0;
static uint32_t false_positives = 0;

static struct simple_udp_connection udp_conn;

PROCESS(ids_process, "IDS Process");
PROCESS(analysis_process, "Analysis Process");
AUTOSTART_PROCESSES(&ids_process, &analysis_process);

/*---------------------------------------------------------------------------*/
/* Extract CICIOT2023-like features from flow */
static void
extract_features(flow_record_t *flow, float *features)
{
  uint32_t duration = flow->last_time - flow->start_time;
  if(duration == 0) duration = 1;  /* Avoid division by zero */
  
  /* Feature 0: Flow duration (normalized) */
  features[0] = (float)duration / 1000.0f;
  
  /* Feature 1: Total forward packets */
  features[1] = (float)flow->fwd_packets / 100.0f;
  
  /* Feature 2: Total backward packets */
  features[2] = (float)flow->bwd_packets / 100.0f;
  
  /* Feature 3: Total length of fwd packets */
  features[3] = (float)flow->fwd_bytes / 10000.0f;
  
  /* Feature 4: Total length of bwd packets */
  features[4] = (float)flow->bwd_bytes / 10000.0f;
  
  /* Feature 5: Fwd packet length mean */
  features[5] = flow->fwd_packets > 0 ? 
                (float)flow->fwd_bytes / flow->fwd_packets / 100.0f : 0.0f;
  
  /* Feature 6: Bwd packet length mean */
  features[6] = flow->bwd_packets > 0 ? 
                (float)flow->bwd_bytes / flow->bwd_packets / 100.0f : 0.0f;
  
  /* Feature 7: Flow bytes/s */
  features[7] = (float)flow->total_bytes / duration;
  
  /* Feature 8: Flow packets/s */
  features[8] = (float)flow->packet_count * 1000.0f / duration;
  
  /* Feature 9: Flow IAT mean */
  features[9] = flow->packet_count > 1 ? 
                (float)flow->iat_sum / (flow->packet_count - 1) / 100.0f : 0.0f;
  
  /* Feature 10: Flow IAT min (normalized) */
  features[10] = (float)flow->iat_min / 100.0f;
  
  /* Feature 11: Flow IAT max (normalized) */
  features[11] = (float)flow->iat_max / 1000.0f;
  
  /* Feature 12: Min packet length */
  features[12] = (float)flow->min_pkt_len / 100.0f;
  
  /* Feature 13: Max packet length */
  features[13] = (float)flow->max_pkt_len / 100.0f;
  
  /* Feature 14: Packet length mean */
  features[14] = flow->packet_count > 0 ? 
                 (float)flow->sum_pkt_len / flow->packet_count / 100.0f : 0.0f;
  
  /* Feature 15: SYN flag count */
  features[15] = (float)flow->flags_syn / 10.0f;
  
  /* Feature 16: FIN flag count */
  features[16] = (float)flow->flags_fin / 10.0f;
  
  /* Feature 17: RST flag count */
  features[17] = (float)flow->flags_rst / 10.0f;
  
  /* Feature 18: PSH flag count */
  features[18] = (float)flow->flags_psh / 10.0f;
  
  /* Feature 19: ACK flag count */
  features[19] = (float)flow->flags_ack / 10.0f;
  
  /* Feature 20-23: Down/Up ratio and other derived features */
  features[20] = flow->fwd_packets > 0 ? 
                 (float)flow->bwd_packets / flow->fwd_packets : 0.0f;
  features[21] = (float)flow->packet_count / 100.0f;
  features[22] = (float)flow->total_bytes / 10000.0f;
  features[23] = features[8] > 10.0f ? 1.0f : 0.0f;  /* High rate indicator */
}
/*---------------------------------------------------------------------------*/
static flow_record_t*
find_or_create_flow(const uip_ipaddr_t *src, const uip_ipaddr_t *dst,
                    uint16_t sport, uint16_t dport)
{
  int i;
  flow_record_t *oldest = &current_flows[0];
  
  /* Search for existing flow */
  for(i = 0; i < flow_count; i++) {
    if(uip_ipaddr_cmp(&current_flows[i].src_addr, src) &&
       uip_ipaddr_cmp(&current_flows[i].dst_addr, dst) &&
       current_flows[i].src_port == sport &&
       current_flows[i].dst_port == dport) {
      return &current_flows[i];
    }
    if(current_flows[i].start_time < oldest->start_time) {
      oldest = &current_flows[i];
    }
  }
  
  /* Create new flow */
  flow_record_t *new_flow;
  if(flow_count < FEATURE_WINDOW_SIZE) {
    new_flow = &current_flows[flow_count++];
  } else {
    new_flow = oldest;  /* Reuse oldest flow */
  }
  
  memset(new_flow, 0, sizeof(flow_record_t));
  uip_ipaddr_copy(&new_flow->src_addr, src);
  uip_ipaddr_copy(&new_flow->dst_addr, dst);
  new_flow->src_port = sport;
  new_flow->dst_port = dport;
  new_flow->start_time = clock_time();
  new_flow->last_time = new_flow->start_time;
  new_flow->min_pkt_len = 0xFFFF;
  new_flow->max_pkt_len = 0;
  new_flow->iat_min = 0xFFFFFFFF;
  new_flow->iat_max = 0;
  new_flow->protocol = 17;  /* UDP */
  
  return new_flow;
}
/*---------------------------------------------------------------------------*/
static void
update_flow(flow_record_t *flow, uint16_t pkt_len, uint8_t is_forward)
{
  clock_time_t now = clock_time();
  uint32_t iat = now - flow->last_time;
  
  /* Update packet counts */
  flow->packet_count++;
  flow->total_bytes += pkt_len;
  
  if(is_forward) {
    flow->fwd_packets++;
    flow->fwd_bytes += pkt_len;
  } else {
    flow->bwd_packets++;
    flow->bwd_bytes += pkt_len;
  }
  
  /* Update packet length stats */
  if(pkt_len < flow->min_pkt_len) flow->min_pkt_len = pkt_len;
  if(pkt_len > flow->max_pkt_len) flow->max_pkt_len = pkt_len;
  flow->sum_pkt_len += pkt_len;
  
  /* Update IAT stats */
  if(flow->packet_count > 1) {
    flow->iat_sum += iat;
    if(iat < flow->iat_min) flow->iat_min = iat;
    if(iat > flow->iat_max) flow->iat_max = iat;
  }
  
  flow->last_time = now;
}
/*---------------------------------------------------------------------------*/
static uint8_t
classify_traffic(flow_record_t *flow)
{
  /* Extract features */
  extract_features(flow, feature_buffer);
  
  /* Run TinyML inference */
  float prediction = tinyml_predict(feature_buffer, 24);
  
  LOG_INFO("ML prediction: %.3f\n", prediction);
  
  return (prediction > ANOMALY_THRESHOLD) ? 1 : 0;
}
/*---------------------------------------------------------------------------*/
static void
raise_alert(flow_record_t *flow, uint8_t attack_type)
{
  clock_time_t now = clock_time();
  
  /* Check cooldown to avoid alert flooding */
  if(now - last_alert_time < ALERT_COOLDOWN) {
    return;
  }
  last_alert_time = now;
  attacks_detected++;
  
  LOG_INFO("*** INTRUSION DETECTED ***\n");
  LOG_INFO("Attack type: %d\n", attack_type);
  LOG_INFO("Source: ");
  LOG_INFO_6ADDR(&flow->src_addr);
  LOG_INFO_("\n");
  LOG_INFO("Packets: %lu, Bytes: %lu, Rate: %.2f pkt/s\n",
           flow->packet_count, flow->total_bytes,
           (float)flow->packet_count * 1000.0f / 
           (flow->last_time - flow->start_time + 1));
  LOG_INFO("Total attacks detected: %lu\n", attacks_detected);
}
/*---------------------------------------------------------------------------*/
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  flow_record_t *flow;
  
  total_packets_analyzed++;
  
  /* Find or create flow record */
  flow = find_or_create_flow(sender_addr, receiver_addr,
                             sender_port, receiver_port);
  
  /* Update flow statistics */
  update_flow(flow, datalen, 1);  /* Forward direction */
  
  /* Analyze every N packets or periodically */
  if(flow->packet_count >= 5 && flow->packet_count % 5 == 0) {
    uint8_t is_attack = classify_traffic(flow);
    
    if(is_attack) {
      raise_alert(flow, 1);
    }
  }
  
  /* Also respond to legitimate sensor data */
  if(datalen == sizeof(uint16_t) * 4 + sizeof(uint32_t) + 2) {
    /* Looks like sensor data - send ACK */
    uint8_t ack = 1;
    simple_udp_sendto(&udp_conn, &ack, 1, sender_addr);
  }
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(analysis_process, ev, data)
{
  static struct etimer stats_timer;
  
  PROCESS_BEGIN();
  
  etimer_set(&stats_timer, CLOCK_SECOND * 60);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&stats_timer));
    
    LOG_INFO("=== IDS Statistics ===\n");
    LOG_INFO("Packets analyzed: %lu\n", total_packets_analyzed);
    LOG_INFO("Attacks detected: %lu\n", attacks_detected);
    LOG_INFO("Active flows: %d\n", flow_count);
    LOG_INFO("======================\n");
    
    etimer_reset(&stats_timer);
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ids_process, ev, data)
{
  PROCESS_BEGIN();
  
  /* Initialize UDP server */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);
  
  LOG_INFO("IDS Node started with TinyML model\n");
  LOG_INFO("Model: %s\n", TINYML_MODEL_NAME);
  LOG_INFO("Features: %d, Threshold: %.2f\n", 
           TINYML_NUM_FEATURES, ANOMALY_THRESHOLD);
  
  /* Initialize TinyML model */
  tinyml_init();
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
