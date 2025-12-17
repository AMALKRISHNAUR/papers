/*
 * Attacker Node - Simulates various IoT attack patterns
 * Based on CICIOT2023 attack categories
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "net/ipv6/uip-icmp6.h"
#include "sys/log.h"
#include "random.h"

#define LOG_MODULE "Attacker"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

/* Attack types (similar to CICIOT2023) */
#define ATTACK_NONE           0
#define ATTACK_DDOS_UDP       1
#define ATTACK_DDOS_SYN       2
#define ATTACK_DOS_HTTP       3
#define ATTACK_RECON_SCAN     4
#define ATTACK_SPOOFING       5
#define ATTACK_MITM           6

/* Attack parameters */
#define DDOS_BURST_SIZE       50
#define DDOS_INTERVAL         (CLOCK_SECOND / 20)
#define SCAN_INTERVAL         (CLOCK_SECOND / 5)
#define NORMAL_INTERVAL       (CLOCK_SECOND * 30)

static struct simple_udp_connection udp_conn;
static uint8_t current_attack = ATTACK_NONE;
static uint32_t attack_start_time = 0;
static uint32_t attack_duration = 0;

/* Attack packet structures */
typedef struct {
  uint8_t attack_type;
  uint16_t seq_num;
  uint8_t payload[64];  /* Variable payload */
} attack_packet_t;

PROCESS(attacker_process, "Attacker Process");
PROCESS(attack_scheduler, "Attack Scheduler");
AUTOSTART_PROCESSES(&attacker_process, &attack_scheduler);

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
  /* Silently receive - attackers often don't care about responses */
}
/*---------------------------------------------------------------------------*/
static void
launch_ddos_udp_flood(uip_ipaddr_t *target)
{
  static uint16_t seq = 0;
  attack_packet_t pkt;
  int i;
  
  pkt.attack_type = ATTACK_DDOS_UDP;
  
  /* Send burst of UDP packets */
  for(i = 0; i < DDOS_BURST_SIZE; i++) {
    pkt.seq_num = seq++;
    /* Fill with random data to avoid compression */
    for(int j = 0; j < sizeof(pkt.payload); j++) {
      pkt.payload[j] = random_rand() & 0xFF;
    }
    simple_udp_sendto(&udp_conn, &pkt, sizeof(pkt), target);
  }
  
  LOG_INFO("DDoS UDP flood: sent %d packets\n", DDOS_BURST_SIZE);
}
/*---------------------------------------------------------------------------*/
static void
launch_port_scan(uip_ipaddr_t *target)
{
  static uint16_t current_port = 1;
  attack_packet_t pkt;
  int i;
  
  pkt.attack_type = ATTACK_RECON_SCAN;
  
  /* Scan multiple ports */
  for(i = 0; i < 10; i++) {
    pkt.seq_num = current_port++;
    if(current_port > 1024) current_port = 1;
    
    /* Send probe packet */
    simple_udp_sendto(&udp_conn, &pkt, sizeof(pkt), target);
  }
  
  LOG_INFO("Port scan: probing ports %d-%d\n", current_port - 10, current_port);
}
/*---------------------------------------------------------------------------*/
static void
launch_dos_exhaustion(uip_ipaddr_t *target)
{
  attack_packet_t pkt;
  int i;
  
  pkt.attack_type = ATTACK_DOS_HTTP;
  
  /* Send large packets to exhaust resources */
  for(i = 0; i < 20; i++) {
    pkt.seq_num = i;
    /* Fill entire payload */
    memset(pkt.payload, 0xAA, sizeof(pkt.payload));
    simple_udp_sendto(&udp_conn, &pkt, sizeof(pkt), target);
  }
  
  LOG_INFO("DoS resource exhaustion: sent 20 large packets\n");
}
/*---------------------------------------------------------------------------*/
static void
launch_spoofing_attack(uip_ipaddr_t *target)
{
  attack_packet_t pkt;
  
  pkt.attack_type = ATTACK_SPOOFING;
  pkt.seq_num = random_rand();
  
  /* Spoof legitimate sensor data */
  pkt.payload[0] = 1;  /* Fake sensor type */
  pkt.payload[1] = (random_rand() % 100) + 200;  /* Fake temp */
  pkt.payload[2] = (random_rand() % 300) + 400;  /* Fake humidity */
  
  simple_udp_sendto(&udp_conn, &pkt, sizeof(pkt), target);
  
  LOG_INFO("Spoofing attack: sent fake sensor data\n");
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attack_scheduler, ev, data)
{
  static struct etimer schedule_timer;
  
  PROCESS_BEGIN();
  
  /* Wait for network to stabilize */
  etimer_set(&schedule_timer, CLOCK_SECOND * 60);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&schedule_timer));
  
  while(1) {
    /* Schedule random attacks */
    etimer_set(&schedule_timer, CLOCK_SECOND * (30 + random_rand() % 60));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&schedule_timer));
    
    /* Select random attack type */
    current_attack = 1 + (random_rand() % 5);
    attack_duration = 10 + (random_rand() % 20);  /* 10-30 seconds */
    attack_start_time = clock_seconds();
    
    LOG_INFO("Starting attack type %d for %lu seconds\n", 
             current_attack, attack_duration);
    
    /* Wait for attack to complete */
    etimer_set(&schedule_timer, CLOCK_SECOND * attack_duration);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&schedule_timer));
    
    current_attack = ATTACK_NONE;
    LOG_INFO("Attack ended, entering quiet period\n");
    
    /* Quiet period between attacks */
    etimer_set(&schedule_timer, CLOCK_SECOND * (60 + random_rand() % 120));
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&schedule_timer));
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(attacker_process, ev, data)
{
  static struct etimer attack_timer;
  uip_ipaddr_t dest_ipaddr;
  
  PROCESS_BEGIN();
  
  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);
  
  LOG_INFO("Attacker node initialized\n");
  
  /* Initial wait */
  etimer_set(&attack_timer, CLOCK_SECOND * 30);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));
  
  while(1) {
    clock_time_t interval;
    
    /* Set interval based on attack type */
    switch(current_attack) {
      case ATTACK_DDOS_UDP:
      case ATTACK_DDOS_SYN:
        interval = DDOS_INTERVAL;
        break;
      case ATTACK_RECON_SCAN:
        interval = SCAN_INTERVAL;
        break;
      default:
        interval = NORMAL_INTERVAL;
        break;
    }
    
    etimer_set(&attack_timer, interval);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));
    
    if(NETSTACK_ROUTING.node_is_reachable() && 
       NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      
      /* Execute current attack */
      switch(current_attack) {
        case ATTACK_DDOS_UDP:
          launch_ddos_udp_flood(&dest_ipaddr);
          break;
        case ATTACK_DDOS_SYN:
          launch_ddos_udp_flood(&dest_ipaddr);  /* Simulated */
          break;
        case ATTACK_DOS_HTTP:
          launch_dos_exhaustion(&dest_ipaddr);
          break;
        case ATTACK_RECON_SCAN:
          launch_port_scan(&dest_ipaddr);
          break;
        case ATTACK_SPOOFING:
          launch_spoofing_attack(&dest_ipaddr);
          break;
        default:
          /* No attack - stay quiet */
          break;
      }
    }
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
