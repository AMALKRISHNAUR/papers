/*
 * Feature Extractor Header
 * Defines feature extraction utilities for network traffic
 */

#ifndef FEATURE_EXTRACTOR_H_
#define FEATURE_EXTRACTOR_H_

#include <stdint.h>

/* Feature indices (CICIOT2023-like) */
#define FEAT_FLOW_DURATION      0
#define FEAT_FWD_PKTS_TOT       1
#define FEAT_BWD_PKTS_TOT       2
#define FEAT_FWD_DATA_PKTS      3
#define FEAT_BWD_DATA_PKTS      4
#define FEAT_FWD_PKT_LEN_MEAN   5
#define FEAT_BWD_PKT_LEN_MEAN   6
#define FEAT_FLOW_BYTS_S        7
#define FEAT_FLOW_PKTS_S        8
#define FEAT_FLOW_IAT_MEAN      9
#define FEAT_FLOW_IAT_MIN       10
#define FEAT_FLOW_IAT_MAX       11
#define FEAT_PKT_LEN_MIN        12
#define FEAT_PKT_LEN_MAX        13
#define FEAT_PKT_LEN_MEAN       14
#define FEAT_SYN_FLAG_CNT       15
#define FEAT_FIN_FLAG_CNT       16
#define FEAT_RST_FLAG_CNT       17
#define FEAT_PSH_FLAG_CNT       18
#define FEAT_ACK_FLAG_CNT       19
#define FEAT_DOWN_UP_RATIO      20
#define FEAT_PKT_COUNT          21
#define FEAT_BYTE_COUNT         22
#define FEAT_HIGH_RATE_FLAG     23

#define NUM_FEATURES            24

/* Feature normalization parameters (from training data) */
typedef struct {
  float mean;
  float std;
  float min;
  float max;
} feature_stats_t;

/* Default normalization stats (should be updated from training) */
static const feature_stats_t default_stats[NUM_FEATURES] = {
  {5.0f, 10.0f, 0.0f, 100.0f},     /* FLOW_DURATION */
  {10.0f, 20.0f, 0.0f, 500.0f},    /* FWD_PKTS_TOT */
  {5.0f, 10.0f, 0.0f, 200.0f},     /* BWD_PKTS_TOT */
  {500.0f, 1000.0f, 0.0f, 50000.0f}, /* FWD_DATA_PKTS */
  {200.0f, 500.0f, 0.0f, 20000.0f},  /* BWD_DATA_PKTS */
  {50.0f, 30.0f, 0.0f, 1500.0f},     /* FWD_PKT_LEN_MEAN */
  {40.0f, 25.0f, 0.0f, 1500.0f},     /* BWD_PKT_LEN_MEAN */
  {1000.0f, 5000.0f, 0.0f, 100000.0f}, /* FLOW_BYTS_S */
  {20.0f, 50.0f, 0.0f, 1000.0f},     /* FLOW_PKTS_S */
  {100.0f, 200.0f, 0.0f, 5000.0f},   /* FLOW_IAT_MEAN */
  {10.0f, 20.0f, 0.0f, 1000.0f},     /* FLOW_IAT_MIN */
  {500.0f, 1000.0f, 0.0f, 10000.0f}, /* FLOW_IAT_MAX */
  {20.0f, 15.0f, 0.0f, 100.0f},      /* PKT_LEN_MIN */
  {100.0f, 80.0f, 0.0f, 1500.0f},    /* PKT_LEN_MAX */
  {60.0f, 40.0f, 0.0f, 1000.0f},     /* PKT_LEN_MEAN */
  {2.0f, 5.0f, 0.0f, 50.0f},         /* SYN_FLAG_CNT */
  {1.0f, 2.0f, 0.0f, 20.0f},         /* FIN_FLAG_CNT */
  {0.5f, 1.0f, 0.0f, 10.0f},         /* RST_FLAG_CNT */
  {5.0f, 10.0f, 0.0f, 100.0f},       /* PSH_FLAG_CNT */
  {10.0f, 20.0f, 0.0f, 500.0f},      /* ACK_FLAG_CNT */
  {0.5f, 1.0f, 0.0f, 10.0f},         /* DOWN_UP_RATIO */
  {15.0f, 30.0f, 0.0f, 700.0f},      /* PKT_COUNT */
  {700.0f, 1500.0f, 0.0f, 70000.0f}, /* BYTE_COUNT */
  {0.5f, 0.5f, 0.0f, 1.0f}           /* HIGH_RATE_FLAG */
};

/* Normalize a single feature value */
static inline float normalize_feature(float value, int feature_idx) {
  if(feature_idx >= NUM_FEATURES) return 0.0f;
  float range = default_stats[feature_idx].max - default_stats[feature_idx].min;
  if(range == 0.0f) return 0.0f;
  return (value - default_stats[feature_idx].min) / range;
}

/* Z-score normalization */
static inline float zscore_normalize(float value, int feature_idx) {
  if(feature_idx >= NUM_FEATURES) return 0.0f;
  if(default_stats[feature_idx].std == 0.0f) return 0.0f;
  return (value - default_stats[feature_idx].mean) / default_stats[feature_idx].std;
}

#endif /* FEATURE_EXTRACTOR_H_ */
