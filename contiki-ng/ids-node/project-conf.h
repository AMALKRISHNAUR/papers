/* project-conf.h - IDS Node Configuration */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Enable extensive logging for IDS */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_TCPIP LOG_LEVEL_INFO
#define LOG_CONF_LEVEL_MAC LOG_LEVEL_INFO

/* Increase buffer sizes for IDS processing */
#define UIP_CONF_BUFFER_SIZE 280
#define QUEUEBUF_CONF_NUM 16

/* RPL configuration */
#define RPL_CONF_MOP RPL_MOP_STORING_NO_MULTICAST
#define RPL_CONF_WITH_DAO_ACK 1

/* Radio configuration */
#define NETSTACK_CONF_RADIO cooja_radio_driver

/* Memory optimization */
#define NBR_TABLE_CONF_MAX_NEIGHBORS 20
#define UIP_CONF_MAX_ROUTES 20

#endif /* PROJECT_CONF_H_ */
