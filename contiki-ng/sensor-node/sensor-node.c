/*
 * IoT Sensor Node - Normal Traffic Generator
 * Simulates legitimate IoT sensor behavior similar to CICIOT2023 dataset
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip-ds6.h"
#include "sys/log.h"
#include "random.h"

#define LOG_MODULE "SensorNode"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678

#define SEND_INTERVAL_MIN (10 * CLOCK_SECOND)
#define SEND_INTERVAL_MAX (30 * CLOCK_SECOND)

/* Sensor data structure */
typedef struct {
  uint16_t seq_num;
  uint16_t temperature;
  uint16_t humidity;
  uint16_t light_level;
  uint32_t timestamp;
  uint8_t node_id;
  uint8_t sensor_type;
} sensor_data_t;

static struct simple_udp_connection udp_conn;
static uint16_t sequence_number = 0;

PROCESS(sensor_node_process, "Sensor Node Process");
AUTOSTART_PROCESSES(&sensor_node_process);

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
  LOG_INFO("Received ACK from ");
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}
/*---------------------------------------------------------------------------*/
static void
generate_sensor_data(sensor_data_t *data)
{
  /* Simulate realistic sensor readings */
  data->seq_num = sequence_number++;
  data->temperature = 200 + (random_rand() % 100);  /* 20.0 - 30.0 C */
  data->humidity = 400 + (random_rand() % 300);     /* 40% - 70% */
  data->light_level = random_rand() % 1000;         /* 0 - 999 lux */
  data->timestamp = clock_seconds();
  data->node_id = linkaddr_node_addr.u8[7];
  data->sensor_type = 1;  /* Temperature/Humidity sensor */
}
/*---------------------------------------------------------------------------*/
PROCESS_THREAD(sensor_node_process, ev, data)
{
  static struct etimer periodic_timer;
  static sensor_data_t sensor_data;
  uip_ipaddr_t dest_ipaddr;

  PROCESS_BEGIN();

  /* Initialize UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                      UDP_SERVER_PORT, udp_rx_callback);

  LOG_INFO("Sensor node started. Node ID: %d\n", linkaddr_node_addr.u8[7]);

  /* Wait for network to be ready */
  etimer_set(&periodic_timer, CLOCK_SECOND * 10);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

  while(1) {
    /* Random interval for realistic traffic patterns */
    clock_time_t interval = SEND_INTERVAL_MIN + 
                           (random_rand() % (SEND_INTERVAL_MAX - SEND_INTERVAL_MIN));
    etimer_set(&periodic_timer, interval);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));

    if(NETSTACK_ROUTING.node_is_reachable() && 
       NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      
      /* Generate and send sensor data */
      generate_sensor_data(&sensor_data);
      
      LOG_INFO("Sending sensor data: seq=%u, temp=%u, hum=%u\n",
               sensor_data.seq_num, sensor_data.temperature, sensor_data.humidity);
      
      simple_udp_sendto(&udp_conn, &sensor_data, sizeof(sensor_data), &dest_ipaddr);
    } else {
      LOG_INFO("Not reachable yet, waiting...\n");
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
