/*
 * Border Router - RPL root node for the IoT network
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "BorderRouter"
#define LOG_LEVEL LOG_LEVEL_INFO

PROCESS(border_router_process, "Border Router");
AUTOSTART_PROCESSES(&border_router_process);

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(border_router_process, ev, data)
{
  PROCESS_BEGIN();

  /* Set this node as RPL root */
  NETSTACK_ROUTING.root_start();

  LOG_INFO("Border Router started\n");
  LOG_INFO("IPv6 addresses:\n");
  
  /* Print all IPv6 addresses */
  for(int i = 0; i < UIP_DS6_ADDR_NB; i++) {
    if(uip_ds6_if.addr_list[i].isused) {
      LOG_INFO(" - ");
      LOG_INFO_6ADDR(&uip_ds6_if.addr_list[i].ipaddr);
      LOG_INFO_("\n");
    }
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
