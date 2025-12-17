/* project-conf.h - Attacker Node Configuration */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Logging */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_WARN
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_WARN

/* Network configuration */
#define UIP_CONF_BUFFER_SIZE 240

/* RPL configuration */
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST

/* Radio configuration */
#define NETSTACK_CONF_RADIO cooja_radio_driver

#endif /* PROJECT_CONF_H_ */
