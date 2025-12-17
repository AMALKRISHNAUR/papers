CONTIKI_PROJECT = data-collector
all: $(CONTIKI_PROJECT)

# Target platform - change based on your hardware
# BOARD ?= launchpad/cc2650
# TARGET ?= cc26x0-cc13x0

# For Cooja simulation
CONTIKI = ../../../contiki-ng

# Enable logging
CFLAGS += -DLOG_CONF_LEVEL_MAIN=LOG_LEVEL_INFO

# Include energy estimation
MODULES += os/services/energest

include $(CONTIKI)/Makefile.include
