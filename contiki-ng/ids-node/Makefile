CONTIKI_PROJECT = ids-node
all: $(CONTIKI_PROJECT)

# Target platform - Cooja simulation
PLATFORMS_ONLY = cooja

# Network configuration
MAKE_MAC = MAKE_MAC_CSMA
MAKE_NET = MAKE_NET_IPV6
MAKE_ROUTING = MAKE_ROUTING_RPL_LITE

# Enable floating point for TinyML
CFLAGS += -DFLOAT_SUPPORT

# Use trained model weights
CFLAGS += -DUSE_TRAINED_MODEL

# Include Contiki-NG Makefile
CONTIKI = ../../contiki-ng
include $(CONTIKI)/Makefile.include
