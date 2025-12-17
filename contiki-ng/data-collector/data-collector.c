/*
 * Data Collector Node for IDS Training
 * Collects real network flow data from Contiki-NG testbed
 * Outputs CICIOT2023-like features via serial for dataset creation
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/packetbuf.h"
#include "sys/energest.h"
#include "sys/log.h"
#include "random.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define LOG_MODULE "DataCollector"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define MAX_FLOWS 50
#define FLOW_TIMEOUT (60 * CLOCK_SECOND)
#define FEATURE_OUTPUT_INTERVAL (5 * CLOCK_SECOND)

/* Flow tracking structure - matches CICIOT2023 features */
typedef struct {
  uip_ipaddr_t src_ip;
  uip_ipaddr_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t protocol;
  
  /* Timing */
  clock_time_t start_time;
  clock_time_t last_time;
  clock_time_t last_fwd_time;
  clock_time_t last_bwd_time;
  
  /* Packet counts */
  uint32_t fwd_pkts;
  uint32_t bwd_pkts;
  uint32_t total_pkts;
  
  /* Byte counts */
  uint32_t fwd_bytes;
  uint32_t bwd_bytes;
  uint32_t total_bytes;
  
  /* Packet lengths */
  uint16_t fwd_pkt_len_min;
  uint16_t fwd_pkt_len_max;
  uint32_t fwd_pkt_len_sum;
  uint16_t bwd_pkt_len_min;
  uint16_t bwd_pkt_len_max;
  uint32_t bwd_pkt_len_sum;
  
  /* Inter-arrival times (in clock ticks) */
  clock_time_t fwd_iat_sum;
  clock_time_t fwd_iat_min;
  clock_time_t fwd_iat_max;
  clock_time_t bwd_iat_sum;
  clock_time_t bwd_iat_min;
  clock_time_t bwd_iat_max;
  
  /* Flags */
  uint16_t syn_count;
  uint16_t fin_count;
  uint16_t rst_count;
  uint16_t psh_count;
  uint16_t ack_count;
  uint16_t urg_count;
  
  /* Active/Idle times */
  clock_time_t active_time;
  clock_time_t idle_time;
  clock_time_t last_active;
  
  /* Label: 0=normal, 1=attack (set by simulation scenario) */
  uint8_t label;
  uint8_t active;
} network_flow_t;

static network_flow_t flows[MAX_FLOWS];
static int flow_count = 0;
static uint32_t total_packets_collected = 0;
static uint32_t total_flows_exported = 0;

/* Energy tracking */
static unsigned long last_cpu, last_lpm, last_tx, last_rx;

static struct simple_udp_connection udp_conn;

/*---------------------------------------------------------------------------*/
PROCESS(data_collector_process, "Data Collector");
PROCESS(feature_export_process, "Feature Export");
AUTOSTART_PROCESSES(&data_collector_process, &feature_export_process);
/*---------------------------------------------------------------------------*/

/* Initialize energy tracking */
static void
init_energest(void)
{
  energest_flush();
  last_cpu = energest_type_time(ENERGEST_TYPE_CPU);
  last_lpm = energest_type_time(ENERGEST_TYPE_LPM);
  last_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  last_rx = energest_type_time(ENERGEST_TYPE_LISTEN);
}

/* Get energy consumption in microjoules (approximate) */
static uint32_t
get_energy_uj(void)
{
  energest_flush();
  
  unsigned long cpu = energest_type_time(ENERGEST_TYPE_CPU) - last_cpu;
  unsigned long lpm = energest_type_time(ENERGEST_TYPE_LPM) - last_lpm;
  unsigned long tx = energest_type_time(ENERGEST_TYPE_TRANSMIT) - last_tx;
  unsigned long rx = energest_type_time(ENERGEST_TYPE_LISTEN) - last_rx;
  
  /* Approximate power consumption (platform dependent) */
  /* Using typical values for CC2650: CPU=1.5mA, LPM=1uA, TX=9mA, RX=6mA @ 3V */
  uint32_t energy = (cpu * 45 + lpm * 1 + tx * 270 + rx * 180) / (CLOCK_SECOND / 10);
  
  return energy;
}

/*---------------------------------------------------------------------------*/
/* Find or create flow entry */
static network_flow_t *
find_or_create_flow(const uip_ipaddr_t *src, const uip_ipaddr_t *dst,
                    uint16_t src_port, uint16_t dst_port, uint8_t protocol)
{
  int i;
  clock_time_t now = clock_time();
  
  /* Search existing flows */
  for(i = 0; i < MAX_FLOWS; i++) {
    if(flows[i].active) {
      /* Check for timeout */
      if(now - flows[i].last_time > FLOW_TIMEOUT) {
        flows[i].active = 0;
        continue;
      }
      
      /* Match bidirectional flow */
      if((uip_ipaddr_cmp(&flows[i].src_ip, src) &&
          uip_ipaddr_cmp(&flows[i].dst_ip, dst) &&
          flows[i].src_port == src_port &&
          flows[i].dst_port == dst_port) ||
         (uip_ipaddr_cmp(&flows[i].src_ip, dst) &&
          uip_ipaddr_cmp(&flows[i].dst_ip, src) &&
          flows[i].src_port == dst_port &&
          flows[i].dst_port == src_port)) {
        return &flows[i];
      }
    }
  }
  
  /* Create new flow */
  for(i = 0; i < MAX_FLOWS; i++) {
    if(!flows[i].active) {
      memset(&flows[i], 0, sizeof(network_flow_t));
      uip_ipaddr_copy(&flows[i].src_ip, src);
      uip_ipaddr_copy(&flows[i].dst_ip, dst);
      flows[i].src_port = src_port;
      flows[i].dst_port = dst_port;
      flows[i].protocol = protocol;
      flows[i].start_time = now;
      flows[i].last_time = now;
      flows[i].fwd_pkt_len_min = 0xFFFF;
      flows[i].bwd_pkt_len_min = 0xFFFF;
      flows[i].fwd_iat_min = 0xFFFFFFFF;
      flows[i].bwd_iat_min = 0xFFFFFFFF;
      flows[i].active = 1;
      flows[i].label = 0; /* Default: normal traffic */
      flow_count++;
      return &flows[i];
    }
  }
  
  return NULL;
}

/*---------------------------------------------------------------------------*/
/* Update flow with packet information */
static void
update_flow(network_flow_t *flow, const uip_ipaddr_t *src, uint16_t pkt_len,
            uint8_t flags, uint8_t is_attack)
{
  clock_time_t now = clock_time();
  clock_time_t iat;
  int is_forward = uip_ipaddr_cmp(&flow->src_ip, src);
  
  flow->total_pkts++;
  flow->total_bytes += pkt_len;
  
  if(is_forward) {
    /* Forward packet */
    flow->fwd_pkts++;
    flow->fwd_bytes += pkt_len;
    
    if(pkt_len < flow->fwd_pkt_len_min) flow->fwd_pkt_len_min = pkt_len;
    if(pkt_len > flow->fwd_pkt_len_max) flow->fwd_pkt_len_max = pkt_len;
    flow->fwd_pkt_len_sum += pkt_len;
    
    if(flow->last_fwd_time > 0) {
      iat = now - flow->last_fwd_time;
      flow->fwd_iat_sum += iat;
      if(iat < flow->fwd_iat_min) flow->fwd_iat_min = iat;
      if(iat > flow->fwd_iat_max) flow->fwd_iat_max = iat;
    }
    flow->last_fwd_time = now;
  } else {
    /* Backward packet */
    flow->bwd_pkts++;
    flow->bwd_bytes += pkt_len;
    
    if(pkt_len < flow->bwd_pkt_len_min) flow->bwd_pkt_len_min = pkt_len;
    if(pkt_len > flow->bwd_pkt_len_max) flow->bwd_pkt_len_max = pkt_len;
    flow->bwd_pkt_len_sum += pkt_len;
    
    if(flow->last_bwd_time > 0) {
      iat = now - flow->last_bwd_time;
      flow->bwd_iat_sum += iat;
      if(iat < flow->bwd_iat_min) flow->bwd_iat_min = iat;
      if(iat > flow->bwd_iat_max) flow->bwd_iat_max = iat;
    }
    flow->last_bwd_time = now;
  }
  
  /* Update flags */
  if(flags & 0x02) flow->syn_count++;
  if(flags & 0x01) flow->fin_count++;
  if(flags & 0x04) flow->rst_count++;
  if(flags & 0x08) flow->psh_count++;
  if(flags & 0x10) flow->ack_count++;
  if(flags & 0x20) flow->urg_count++;
  
  /* Update active/idle time */
  if(flow->last_active > 0) {
    clock_time_t gap = now - flow->last_active;
    if(gap > CLOCK_SECOND) {
      flow->idle_time += gap;
    } else {
      flow->active_time += gap;
    }
  }
  flow->last_active = now;
  flow->last_time = now;
  
  /* Set label if attack */
  if(is_attack) {
    flow->label = 1;
  }
  
  total_packets_collected++;
}

/*---------------------------------------------------------------------------*/
/* Export flow features in CSV format for Python training */
static void
export_flow_features(network_flow_t *flow)
{
  if(!flow->active || flow->total_pkts < 2) {
    return;
  }
  
  clock_time_t duration = flow->last_time - flow->start_time;
  if(duration == 0) duration = 1;
  
  /* Calculate derived features */
  uint32_t flow_duration_ms = (duration * 1000) / CLOCK_SECOND;
  uint32_t flow_bytes_s = (flow->total_bytes * CLOCK_SECOND) / duration;
  uint32_t flow_pkts_s = (flow->total_pkts * CLOCK_SECOND) / duration;
  
  uint16_t fwd_pkt_len_mean = flow->fwd_pkts > 0 ? flow->fwd_pkt_len_sum / flow->fwd_pkts : 0;
  uint16_t bwd_pkt_len_mean = flow->bwd_pkts > 0 ? flow->bwd_pkt_len_sum / flow->bwd_pkts : 0;
  
  uint32_t fwd_iat_mean = flow->fwd_pkts > 1 ? (flow->fwd_iat_sum * 1000 / CLOCK_SECOND) / (flow->fwd_pkts - 1) : 0;
  uint32_t bwd_iat_mean = flow->bwd_pkts > 1 ? (flow->bwd_iat_sum * 1000 / CLOCK_SECOND) / (flow->bwd_pkts - 1) : 0;
  
  uint16_t pkt_len_min = flow->fwd_pkt_len_min < flow->bwd_pkt_len_min ? 
                         flow->fwd_pkt_len_min : flow->bwd_pkt_len_min;
  uint16_t pkt_len_max = flow->fwd_pkt_len_max > flow->bwd_pkt_len_max ?
                         flow->fwd_pkt_len_max : flow->bwd_pkt_len_max;
  uint16_t pkt_len_mean = flow->total_pkts > 0 ? 
                          (flow->fwd_pkt_len_sum + flow->bwd_pkt_len_sum) / flow->total_pkts : 0;
  
  uint16_t down_up_ratio = flow->fwd_bytes > 0 ? 
                           (flow->bwd_bytes * 100) / flow->fwd_bytes : 0;
  
  /* Output CSV format: 24 features + label */
  /* This will be captured via serial and processed by Python */
  printf("FLOW_DATA,%lu,%lu,%lu,%lu,%lu,",
         (unsigned long)flow_duration_ms,
         (unsigned long)flow->fwd_pkts,
         (unsigned long)flow->bwd_pkts,
         (unsigned long)flow->fwd_bytes,
         (unsigned long)flow->bwd_bytes);
  
  printf("%u,%u,%lu,%lu,",
         fwd_pkt_len_mean,
         bwd_pkt_len_mean,
         (unsigned long)flow_bytes_s,
         (unsigned long)flow_pkts_s);
  
  printf("%lu,%lu,%lu,",
         (unsigned long)fwd_iat_mean,
         (unsigned long)(flow->fwd_iat_min == 0xFFFFFFFF ? 0 : (flow->fwd_iat_min * 1000 / CLOCK_SECOND)),
         (unsigned long)(flow->fwd_iat_max * 1000 / CLOCK_SECOND));
  
  printf("%u,%u,%u,",
         pkt_len_min == 0xFFFF ? 0 : pkt_len_min,
         pkt_len_max,
         pkt_len_mean);
  
  printf("%u,%u,%u,%u,%u,",
         flow->syn_count,
         flow->fin_count,
         flow->rst_count,
         flow->psh_count,
         flow->ack_count);
  
  printf("%u,%lu,%lu,%u,%u\n",
         down_up_ratio,
         (unsigned long)flow->total_pkts,
         (unsigned long)flow->total_bytes,
         flow_pkts_s > 100 ? 1 : 0,  /* high_rate_flag */
         flow->label);
  
  total_flows_exported++;
}

/*---------------------------------------------------------------------------*/
/* UDP receive callback */
static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  network_flow_t *flow;
  uint8_t is_attack = 0;
  uint8_t flags = 0;
  
  /* Check if this looks like attack traffic */
  /* High packet rate or specific patterns indicate attack */
  if(datalen > 0) {
    /* Check for attack markers in payload */
    if(data[0] == 0xAA) {  /* Attack marker byte */
      is_attack = 1;
    }
  }
  
  /* Extract TCP-like flags from payload if present */
  if(datalen >= 2) {
    flags = data[1];
  }
  
  /* Find or create flow */
  flow = find_or_create_flow(sender_addr, receiver_addr, 
                             sender_port, receiver_port, 17); /* UDP */
  
  if(flow != NULL) {
    update_flow(flow, sender_addr, datalen, flags, is_attack);
  }
  
  LOG_DBG("RX from ");
  LOG_DBG_6ADDR(sender_addr);
  LOG_DBG_(", len=%u, attack=%u\n", datalen, is_attack);
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(data_collector_process, ev, data)
{
  static struct etimer timer;
  
  PROCESS_BEGIN();
  
  LOG_INFO("Data Collector started\n");
  LOG_INFO("Collecting real network flow data for IDS training\n");
  
  /* Initialize */
  memset(flows, 0, sizeof(flows));
  init_energest();
  
  /* Register UDP connection */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);
  
  /* Also listen on common ports */
  simple_udp_register(&udp_conn, 5683, NULL, 0, udp_rx_callback); /* CoAP */
  
  /* Print CSV header */
  printf("# CICIOT2023-like Dataset from Contiki-NG Testbed\n");
  printf("# Features: flow_duration,fwd_pkts,bwd_pkts,fwd_bytes,bwd_bytes,\n");
  printf("#           fwd_pkt_len_mean,bwd_pkt_len_mean,flow_bytes_s,flow_pkts_s,\n");
  printf("#           fwd_iat_mean,fwd_iat_min,fwd_iat_max,\n");
  printf("#           pkt_len_min,pkt_len_max,pkt_len_mean,\n");
  printf("#           syn,fin,rst,psh,ack,\n");
  printf("#           down_up_ratio,pkt_count,byte_count,high_rate_flag,label\n");
  
  etimer_set(&timer, 10 * CLOCK_SECOND);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    
    /* Log collection status */
    LOG_INFO("Collected: %lu packets, %lu flows, Energy: %lu uJ\n",
             (unsigned long)total_packets_collected,
             (unsigned long)flow_count,
             (unsigned long)get_energy_uj());
    
    etimer_reset(&timer);
  }
  
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(feature_export_process, ev, data)
{
  static struct etimer export_timer;
  int i;
  
  PROCESS_BEGIN();
  
  etimer_set(&export_timer, FEATURE_OUTPUT_INTERVAL);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&export_timer));
    
    /* Export completed flows */
    for(i = 0; i < MAX_FLOWS; i++) {
      if(flows[i].active) {
        clock_time_t now = clock_time();
        /* Export if flow has been idle for a while or has enough packets */
        if(now - flows[i].last_time > (2 * CLOCK_SECOND) || 
           flows[i].total_pkts >= 10) {
          export_flow_features(&flows[i]);
          
          /* Reset flow if it's been idle */
          if(now - flows[i].last_time > FLOW_TIMEOUT) {
            flows[i].active = 0;
            flow_count--;
          }
        }
      }
    }
    
    etimer_reset(&export_timer);
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
