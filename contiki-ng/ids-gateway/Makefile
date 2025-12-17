CONTIKI_PROJECT = ids-gateway
all: $(CONTIKI_PROJECT)

CONTIKI = ../../../contiki-ng

# Include the trained model
CFLAGS += -I../ids-node

# Enable logging
CFLAGS += -DLOG_CONF_LEVEL_MAIN=LOG_LEVEL_INFO

# Enable energy estimation
MODULES += os/services/energest

# Math library for exp function
LDFLAGS += -lm

include $(CONTIKI)/Makefile.include
