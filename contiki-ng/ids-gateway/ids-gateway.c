/*
 * IDS Gateway Node with TinyML Model
 * Performs inference on collected data and measures performance metrics
 * Outputs: Detection results, Latency, PDR, Energy consumption
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "net/ipv6/uip.h"
#include "net/ipv6/uip-ds6.h"
#include "net/mac/tsch/tsch.h"
#include "sys/energest.h"
#include "sys/rtimer.h"
#include "sys/log.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define LOG_MODULE "IDS-Gateway"
#define LOG_LEVEL LOG_LEVEL_INFO

/* Include trained TinyML model weights */
#include "tinyml_model_trained.h"

#define UDP_SERVER_PORT 5678
#define UDP_CLIENT_PORT 8765

#define NUM_FEATURES 24
#define HIDDEN1_SIZE 16
#define HIDDEN2_SIZE 8
#define OUTPUT_SIZE 1
#define DETECTION_THRESHOLD 0.5f

/*---------------------------------------------------------------------------*/
/* Performance metrics */
typedef struct {
  /* Detection metrics */
  uint32_t true_positives;
  uint32_t false_positives;
  uint32_t true_negatives;
  uint32_t false_negatives;
  uint32_t total_inferences;
  
  /* Timing metrics (in rtimer ticks) */
  uint32_t total_inference_time;
  uint32_t min_inference_time;
  uint32_t max_inference_time;
  uint32_t inference_count;
  
  /* Network metrics */
  uint32_t packets_received;
  uint32_t packets_expected;
  uint32_t packets_dropped;
  
  /* Energy metrics (in energest ticks) */
  unsigned long cpu_time;
  unsigned long lpm_time;
  unsigned long tx_time;
  unsigned long rx_time;
  unsigned long baseline_cpu;
  unsigned long baseline_lpm;
  unsigned long baseline_tx;
  unsigned long baseline_rx;
} performance_metrics_t;

static performance_metrics_t metrics;

/* Flow features buffer */
static float features[NUM_FEATURES];

/* Neural network buffers */
static float hidden1[HIDDEN1_SIZE];
static float hidden2[HIDDEN2_SIZE];
static float output;

static struct simple_udp_connection udp_conn;

/*---------------------------------------------------------------------------*/
PROCESS(ids_gateway_process, "IDS Gateway");
PROCESS(metrics_report_process, "Metrics Reporter");
AUTOSTART_PROCESSES(&ids_gateway_process, &metrics_report_process);
/*---------------------------------------------------------------------------*/

/* ReLU activation function */
static inline float
relu(float x)
{
  return x > 0 ? x : 0;
}

/* Sigmoid activation function */
static inline float
sigmoid(float x)
{
  if(x > 10.0f) return 1.0f;
  if(x < -10.0f) return 0.0f;
  return 1.0f / (1.0f + expf(-x));
}

/* Simple exp approximation for embedded systems */
static float
expf_approx(float x)
{
  /* Limit range */
  if(x > 10.0f) x = 10.0f;
  if(x < -10.0f) x = -10.0f;
  
  /* Taylor series approximation */
  float result = 1.0f + x;
  float term = x;
  int i;
  for(i = 2; i <= 8; i++) {
    term *= x / i;
    result += term;
  }
  return result;
}

#define expf expf_approx

/*---------------------------------------------------------------------------*/
/* TinyML inference function - measures execution time */
static float
tinyml_inference(float *input, uint32_t *inference_time_ticks)
{
  rtimer_clock_t start, end;
  int i, j;
  
  /* Start timing */
  start = RTIMER_NOW();
  
  /* Layer 1: Input -> Hidden1 (24 -> 16) with ReLU */
  for(i = 0; i < HIDDEN1_SIZE; i++) {
    hidden1[i] = W1_bias[i];
    for(j = 0; j < NUM_FEATURES; j++) {
      hidden1[i] += input[j] * W1[j][i];
    }
    hidden1[i] = relu(hidden1[i]);
  }
  
  /* Layer 2: Hidden1 -> Hidden2 (16 -> 8) with ReLU */
  for(i = 0; i < HIDDEN2_SIZE; i++) {
    hidden2[i] = W2_bias[i];
    for(j = 0; j < HIDDEN1_SIZE; j++) {
      hidden2[i] += hidden1[j] * W2[j][i];
    }
    hidden2[i] = relu(hidden2[i]);
  }
  
  /* Layer 3: Hidden2 -> Output (8 -> 1) with Sigmoid */
  output = W3_bias[0];
  for(j = 0; j < HIDDEN2_SIZE; j++) {
    output += hidden2[j] * W3[j];
  }
  output = sigmoid(output);
  
  /* End timing */
  end = RTIMER_NOW();
  
  *inference_time_ticks = end - start;
  
  return output;
}

/*---------------------------------------------------------------------------*/
/* Initialize performance metrics */
static void
init_metrics(void)
{
  memset(&metrics, 0, sizeof(metrics));
  metrics.min_inference_time = 0xFFFFFFFF;
  
  /* Store baseline energy values */
  energest_flush();
  metrics.baseline_cpu = energest_type_time(ENERGEST_TYPE_CPU);
  metrics.baseline_lpm = energest_type_time(ENERGEST_TYPE_LPM);
  metrics.baseline_tx = energest_type_time(ENERGEST_TYPE_TRANSMIT);
  metrics.baseline_rx = energest_type_time(ENERGEST_TYPE_LISTEN);
}

/*---------------------------------------------------------------------------*/
/* Update energy metrics */
static void
update_energy_metrics(void)
{
  energest_flush();
  metrics.cpu_time = energest_type_time(ENERGEST_TYPE_CPU) - metrics.baseline_cpu;
  metrics.lpm_time = energest_type_time(ENERGEST_TYPE_LPM) - metrics.baseline_lpm;
  metrics.tx_time = energest_type_time(ENERGEST_TYPE_TRANSMIT) - metrics.baseline_tx;
  metrics.rx_time = energest_type_time(ENERGEST_TYPE_LISTEN) - metrics.baseline_rx;
}

/*---------------------------------------------------------------------------*/
/* Parse flow data from received packet */
static int
parse_flow_features(const uint8_t *data, uint16_t len)
{
  /* Expected format: 24 float features as packed binary */
  if(len < NUM_FEATURES * sizeof(float)) {
    return 0;
  }
  
  memcpy(features, data, NUM_FEATURES * sizeof(float));
  return 1;
}

/*---------------------------------------------------------------------------*/
/* Process received flow and perform IDS detection */
static void
process_flow(const uint8_t *data, uint16_t len, uint8_t actual_label)
{
  uint32_t inference_time;
  float prediction;
  uint8_t predicted_label;
  
  /* Parse features */
  if(!parse_flow_features(data, len)) {
    LOG_WARN("Invalid flow data received\n");
    return;
  }
  
  /* Run TinyML inference */
  prediction = tinyml_inference(features, &inference_time);
  predicted_label = prediction > DETECTION_THRESHOLD ? 1 : 0;
  
  /* Update detection metrics */
  metrics.total_inferences++;
  
  if(predicted_label == 1 && actual_label == 1) {
    metrics.true_positives++;
  } else if(predicted_label == 1 && actual_label == 0) {
    metrics.false_positives++;
  } else if(predicted_label == 0 && actual_label == 0) {
    metrics.true_negatives++;
  } else {
    metrics.false_negatives++;
  }
  
  /* Update timing metrics */
  metrics.total_inference_time += inference_time;
  metrics.inference_count++;
  
  if(inference_time < metrics.min_inference_time) {
    metrics.min_inference_time = inference_time;
  }
  if(inference_time > metrics.max_inference_time) {
    metrics.max_inference_time = inference_time;
  }
  
  /* Log detection result */
  if(predicted_label == 1) {
    LOG_WARN("ATTACK DETECTED! Confidence: %.2f, Latency: %lu us\n",
             (double)prediction,
             (unsigned long)(inference_time * 1000000UL / RTIMER_SECOND));
  }
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
  uint8_t actual_label = 0;
  
  metrics.packets_received++;
  
  /* Last byte contains the actual label for validation */
  if(datalen > 0) {
    actual_label = data[datalen - 1];
    datalen--;
  }
  
  /* Process the flow */
  process_flow(data, datalen, actual_label);
}

/*---------------------------------------------------------------------------*/
/* Print detailed performance report */
static void
print_performance_report(void)
{
  uint32_t accuracy, precision, recall, f1;
  uint32_t avg_latency_us;
  uint32_t pdr;
  uint32_t energy_uj;
  
  update_energy_metrics();
  
  printf("\n");
  printf("============================================================\n");
  printf("IDS GATEWAY PERFORMANCE REPORT\n");
  printf("============================================================\n\n");
  
  /* Detection Metrics */
  printf("DETECTION METRICS:\n");
  printf("  Total Inferences:    %lu\n", (unsigned long)metrics.total_inferences);
  printf("  True Positives:      %lu\n", (unsigned long)metrics.true_positives);
  printf("  False Positives:     %lu\n", (unsigned long)metrics.false_positives);
  printf("  True Negatives:      %lu\n", (unsigned long)metrics.true_negatives);
  printf("  False Negatives:     %lu\n", (unsigned long)metrics.false_negatives);
  
  if(metrics.total_inferences > 0) {
    accuracy = ((metrics.true_positives + metrics.true_negatives) * 10000) / metrics.total_inferences;
    printf("  Accuracy:            %lu.%02lu%%\n", 
           (unsigned long)(accuracy / 100), (unsigned long)(accuracy % 100));
  }
  
  if(metrics.true_positives + metrics.false_positives > 0) {
    precision = (metrics.true_positives * 10000) / (metrics.true_positives + metrics.false_positives);
    printf("  Precision:           %lu.%02lu%%\n",
           (unsigned long)(precision / 100), (unsigned long)(precision % 100));
  }
  
  if(metrics.true_positives + metrics.false_negatives > 0) {
    recall = (metrics.true_positives * 10000) / (metrics.true_positives + metrics.false_negatives);
    printf("  Recall:              %lu.%02lu%%\n",
           (unsigned long)(recall / 100), (unsigned long)(recall % 100));
  }
  
  if(precision + recall > 0) {
    f1 = (2 * precision * recall) / (precision + recall);
    printf("  F1 Score:            %lu.%02lu%%\n",
           (unsigned long)(f1 / 100), (unsigned long)(f1 % 100));
  }
  
  printf("\n");
  
  /* Latency Metrics */
  printf("LATENCY METRICS:\n");
  if(metrics.inference_count > 0) {
    avg_latency_us = (metrics.total_inference_time * 1000000UL) / 
                     (metrics.inference_count * RTIMER_SECOND);
    printf("  Avg Inference Time:  %lu us\n", (unsigned long)avg_latency_us);
    printf("  Min Inference Time:  %lu us\n", 
           (unsigned long)(metrics.min_inference_time * 1000000UL / RTIMER_SECOND));
    printf("  Max Inference Time:  %lu us\n",
           (unsigned long)(metrics.max_inference_time * 1000000UL / RTIMER_SECOND));
    printf("  Throughput:          %lu inferences/sec\n",
           (unsigned long)(RTIMER_SECOND / (metrics.total_inference_time / metrics.inference_count)));
  }
  
  printf("\n");
  
  /* Network Metrics (PDR) */
  printf("NETWORK METRICS:\n");
  printf("  Packets Received:    %lu\n", (unsigned long)metrics.packets_received);
  printf("  Packets Expected:    %lu\n", (unsigned long)metrics.packets_expected);
  if(metrics.packets_expected > 0) {
    pdr = (metrics.packets_received * 10000) / metrics.packets_expected;
    printf("  Packet Delivery Rate: %lu.%02lu%%\n",
           (unsigned long)(pdr / 100), (unsigned long)(pdr % 100));
  }
  
  printf("\n");
  
  /* Energy Metrics */
  printf("ENERGY METRICS:\n");
  printf("  CPU Time:            %lu ticks\n", (unsigned long)metrics.cpu_time);
  printf("  LPM Time:            %lu ticks\n", (unsigned long)metrics.lpm_time);
  printf("  TX Time:             %lu ticks\n", (unsigned long)metrics.tx_time);
  printf("  RX Time:             %lu ticks\n", (unsigned long)metrics.rx_time);
  
  /* Estimate energy in microjoules (platform dependent) */
  /* Assuming CC2650: CPU=1.5mA, LPM=1uA, TX=9mA, RX=6mA @ 3V */
  energy_uj = (metrics.cpu_time * 45 + metrics.lpm_time / 10 + 
               metrics.tx_time * 270 + metrics.rx_time * 180) / (CLOCK_SECOND / 100);
  printf("  Estimated Energy:    %lu uJ\n", (unsigned long)energy_uj);
  
  if(metrics.inference_count > 0) {
    printf("  Energy per Inference: %lu uJ\n", 
           (unsigned long)(energy_uj / metrics.inference_count));
  }
  
  printf("\n============================================================\n");
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(ids_gateway_process, ev, data)
{
  PROCESS_BEGIN();
  
  LOG_INFO("IDS Gateway with TinyML started\n");
  LOG_INFO("Model: %d inputs -> %d -> %d -> %d output\n",
           NUM_FEATURES, HIDDEN1_SIZE, HIDDEN2_SIZE, OUTPUT_SIZE);
  LOG_INFO("Detection threshold: %.2f\n", (double)DETECTION_THRESHOLD);
  
  /* Initialize metrics */
  init_metrics();
  
  /* Register UDP connection */
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                      UDP_CLIENT_PORT, udp_rx_callback);
  
  LOG_INFO("Listening on port %d for flow data\n", UDP_SERVER_PORT);
  
  PROCESS_END();
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(metrics_report_process, ev, data)
{
  static struct etimer report_timer;
  
  PROCESS_BEGIN();
  
  /* Report metrics every 30 seconds */
  etimer_set(&report_timer, 30 * CLOCK_SECOND);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&report_timer));
    
    print_performance_report();
    
    etimer_reset(&report_timer);
  }
  
  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
