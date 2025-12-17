/* project-conf.h - Border Router Configuration */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_INFO

#define UIP_CONF_BUFFER_SIZE 240

#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST

#define NETSTACK_CONF_RADIO cooja_radio_driver

#define NBR_TABLE_CONF_MAX_NEIGHBORS 20
#define UIP_CONF_MAX_ROUTES 20

#endif /* PROJECT_CONF_H_ */
