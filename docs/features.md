# CICIOT2023-like Feature Documentation

## Overview
This testbed generates network traffic features similar to the CICIOT2023 dataset for IoT intrusion detection research.

## Feature List

| # | Feature Name | Description | Unit | Range |
|---|-------------|-------------|------|-------|
| 0 | flow_duration | Duration of the flow | seconds | 0 - ∞ |
| 1 | fwd_pkts_tot | Total packets in forward direction | count | 0 - ∞ |
| 2 | bwd_pkts_tot | Total packets in backward direction | count | 0 - ∞ |
| 3 | fwd_data_pkts | Total bytes in forward direction | bytes | 0 - ∞ |
| 4 | bwd_data_pkts | Total bytes in backward direction | bytes | 0 - ∞ |
| 5 | fwd_pkt_len_mean | Mean packet length (forward) | bytes | 0 - 1500 |
| 6 | bwd_pkt_len_mean | Mean packet length (backward) | bytes | 0 - 1500 |
| 7 | flow_byts_s | Flow bytes per second | bytes/s | 0 - ∞ |
| 8 | flow_pkts_s | Flow packets per second | pkts/s | 0 - ∞ |
| 9 | flow_iat_mean | Mean inter-arrival time | ms | 0 - ∞ |
| 10 | flow_iat_min | Minimum inter-arrival time | ms | 0 - ∞ |
| 11 | flow_iat_max | Maximum inter-arrival time | ms | 0 - ∞ |
| 12 | pkt_len_min | Minimum packet length | bytes | 0 - 1500 |
| 13 | pkt_len_max | Maximum packet length | bytes | 0 - 1500 |
| 14 | pkt_len_mean | Mean packet length | bytes | 0 - 1500 |
| 15 | syn_flag_cnt | SYN flag count | count | 0 - ∞ |
| 16 | fin_flag_cnt | FIN flag count | count | 0 - ∞ |
| 17 | rst_flag_cnt | RST flag count | count | 0 - ∞ |
| 18 | psh_flag_cnt | PSH flag count | count | 0 - ∞ |
| 19 | ack_flag_cnt | ACK flag count | count | 0 - ∞ |
| 20 | down_up_ratio | Download/upload ratio | ratio | 0 - ∞ |
| 21 | pkt_count | Total packet count | count | 0 - ∞ |
| 22 | byte_count | Total byte count | bytes | 0 - ∞ |
| 23 | high_rate_flag | High rate indicator | binary | 0/1 |

## Attack Types

### 1. DDoS Attacks
- **DDoS UDP Flood**: High volume UDP packets
- **DDoS SYN Flood**: TCP SYN flooding (simulated)
- Characteristics: Very high `flow_pkts_s`, low `flow_iat_mean`, high `syn_flag_cnt`

### 2. DoS Attacks
- **Resource Exhaustion**: Large packets to exhaust memory
- Characteristics: High `byte_count`, large `pkt_len_max`

### 3. Reconnaissance
- **Port Scanning**: Sequential port probing
- Characteristics: Low `flow_duration`, high `rst_flag_cnt`, consistent small packets

### 4. Spoofing
- **Address Spoofing**: Fake source addresses
- Characteristics: Unusual `down_up_ratio`, inconsistent flow patterns

### 5. MITM (Man-in-the-Middle)
- **Traffic Interception**: Routing through malicious node
- Characteristics: Duplicate flows, high latency

## Feature Normalization

Features are normalized using min-max scaling:
```
x_norm = (x - x_min) / (x_max - x_min)
```

Normalization statistics are saved in `dataset/normalization_stats.json`.

## Comparison with CICIOT2023

| Aspect | CICIOT2023 | This Testbed |
|--------|------------|--------------|
| Features | 46 | 24 (subset) |
| Attacks | 33 types | 5 categories |
| Protocol | IoT protocols | 6LoWPAN/UDP |
| Environment | Real devices | Cooja simulation |
| Scale | Millions | Configurable |

## Usage Notes

1. **Feature Selection**: The 24 features were selected based on importance for IoT IDS
2. **Normalization**: Always normalize features before ML inference
3. **Imbalanced Data**: Attack ratio is configurable (default 30%)
4. **Simulation Time**: Longer simulations produce more diverse data

## References

- CICIOT2023 Dataset: https://www.unb.ca/cic/datasets/iotdataset-2023.html
- Contiki-NG: https://github.com/contiki-ng/contiki-ng
- TinyML: https://www.tinyml.org/
