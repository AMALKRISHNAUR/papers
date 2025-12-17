#!/usr/bin/env python3
"""
Data Collector for Cooja Simulation
Collects and processes network traffic data from Cooja logs
"""

import re
import csv
import json
import argparse
import numpy as np
from datetime import datetime
from collections import defaultdict

# Feature names matching CICIOT2023 format
FEATURE_NAMES = [
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'fwd_data_pkts',
    'bwd_data_pkts', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_byts_s',
    'flow_pkts_s', 'flow_iat_mean', 'flow_iat_min', 'flow_iat_max',
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'syn_flag_cnt',
    'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt',
    'down_up_ratio', 'pkt_count', 'byte_count', 'high_rate_flag', 'label'
]


class Flow:
    """Represents a network flow"""
    def __init__(self, src, dst, sport, dport, protocol='UDP'):
        self.src = src
        self.dst = dst
        self.sport = sport
        self.dport = dport
        self.protocol = protocol
        
        self.start_time = None
        self.last_time = None
        self.fwd_packets = []
        self.bwd_packets = []
        self.iats = []
        self.flags = defaultdict(int)
        
    def add_packet(self, timestamp, size, direction='fwd', flags=None):
        if self.start_time is None:
            self.start_time = timestamp
        
        if self.last_time is not None:
            self.iats.append(timestamp - self.last_time)
        self.last_time = timestamp
        
        if direction == 'fwd':
            self.fwd_packets.append(size)
        else:
            self.bwd_packets.append(size)
            
        if flags:
            for flag in flags:
                self.flags[flag] += 1
    
    def get_features(self, label=0):
        """Extract CICIOT2023-like features"""
        duration = (self.last_time - self.start_time) if self.start_time else 0
        if duration == 0:
            duration = 0.001  # Avoid division by zero
        
        all_packets = self.fwd_packets + self.bwd_packets
        
        features = {
            'flow_duration': duration,
            'fwd_pkts_tot': len(self.fwd_packets),
            'bwd_pkts_tot': len(self.bwd_packets),
            'fwd_data_pkts': sum(self.fwd_packets),
            'bwd_data_pkts': sum(self.bwd_packets),
            'fwd_pkt_len_mean': np.mean(self.fwd_packets) if self.fwd_packets else 0,
            'bwd_pkt_len_mean': np.mean(self.bwd_packets) if self.bwd_packets else 0,
            'flow_byts_s': sum(all_packets) / duration,
            'flow_pkts_s': len(all_packets) / duration,
            'flow_iat_mean': np.mean(self.iats) if self.iats else 0,
            'flow_iat_min': min(self.iats) if self.iats else 0,
            'flow_iat_max': max(self.iats) if self.iats else 0,
            'pkt_len_min': min(all_packets) if all_packets else 0,
            'pkt_len_max': max(all_packets) if all_packets else 0,
            'pkt_len_mean': np.mean(all_packets) if all_packets else 0,
            'syn_flag_cnt': self.flags.get('SYN', 0),
            'fin_flag_cnt': self.flags.get('FIN', 0),
            'rst_flag_cnt': self.flags.get('RST', 0),
            'psh_flag_cnt': self.flags.get('PSH', 0),
            'ack_flag_cnt': self.flags.get('ACK', 0),
            'down_up_ratio': len(self.bwd_packets) / len(self.fwd_packets) if self.fwd_packets else 0,
            'pkt_count': len(all_packets),
            'byte_count': sum(all_packets),
            'high_rate_flag': 1 if len(all_packets) / duration > 50 else 0,
            'label': label
        }
        
        return features


class CoojaLogParser:
    """Parse Cooja simulation logs"""
    
    # Log patterns
    PACKET_PATTERN = re.compile(
        r'(\d+):(\d+\.\d+)\s+ID:(\d+)\s+.*?(Sending|Received).*?(\d+)\s+bytes'
    )
    ATTACK_PATTERN = re.compile(
        r'(\d+):(\d+\.\d+)\s+ID:(\d+)\s+.*?(DDoS|DoS|Port scan|Spoofing|MITM|attack)'
    )
    IDS_ALERT_PATTERN = re.compile(
        r'(\d+):(\d+\.\d+)\s+.*?INTRUSION DETECTED.*?type:\s*(\d+)'
    )
    
    def __init__(self):
        self.flows = {}
        self.alerts = []
        self.attack_nodes = set()
        
    def parse_log_file(self, log_path):
        """Parse a Cooja log file"""
        with open(log_path, 'r') as f:
            for line in f:
                self._parse_line(line)
        
        return self._extract_all_features()
    
    def _parse_line(self, line):
        # Check for packet events
        match = self.PACKET_PATTERN.search(line)
        if match:
            sim_time = float(match.group(2))
            node_id = int(match.group(3))
            direction = 'fwd' if match.group(4) == 'Sending' else 'bwd'
            size = int(match.group(5))
            
            # Create flow key
            flow_key = f"{node_id}"
            
            if flow_key not in self.flows:
                self.flows[flow_key] = Flow(node_id, 0, 0, 0)
            
            self.flows[flow_key].add_packet(sim_time, size, direction)
            return
        
        # Check for attack indicators
        match = self.ATTACK_PATTERN.search(line)
        if match:
            node_id = int(match.group(3))
            self.attack_nodes.add(node_id)
            return
        
        # Check for IDS alerts
        match = self.IDS_ALERT_PATTERN.search(line)
        if match:
            sim_time = float(match.group(2))
            attack_type = int(match.group(3))
            self.alerts.append({'time': sim_time, 'type': attack_type})
    
    def _extract_all_features(self):
        """Extract features from all flows"""
        dataset = []
        
        for flow_key, flow in self.flows.items():
            # Determine label based on source node
            src_node = int(flow_key.split('_')[0]) if '_' in flow_key else int(flow_key)
            label = 1 if src_node in self.attack_nodes else 0
            
            features = flow.get_features(label)
            dataset.append(features)
        
        return dataset


def generate_synthetic_cooja_log(output_path='cooja_test.log', duration=300):
    """Generate a synthetic Cooja log for testing"""
    import random
    
    with open(output_path, 'w') as f:
        # Normal sensor nodes (1-5)
        for node_id in range(1, 6):
            t = 10.0
            while t < duration:
                size = random.randint(20, 80)
                f.write(f"0:{t:.3f}\tID:{node_id}\t[INFO: SensorNode] Sending sensor data: {size} bytes\n")
                t += random.uniform(10, 30)
                
                # Occasional response
                if random.random() > 0.7:
                    resp_size = random.randint(10, 20)
                    f.write(f"0:{t+0.1:.3f}\tID:{node_id}\t[INFO: SensorNode] Received ACK: {resp_size} bytes\n")
        
        # Attacker node (node 6)
        attack_start = 60.0
        attack_end = 120.0
        t = attack_start
        
        while t < attack_end:
            # DDoS attack - many packets
            for _ in range(50):
                size = random.randint(60, 100)
                f.write(f"0:{t:.3f}\tID:6\t[INFO: Attacker] DDoS attack Sending flood packet: {size} bytes\n")
                t += 0.02
            t += 0.5
        
        # Port scan attack
        t = 150.0
        while t < 180.0:
            f.write(f"0:{t:.3f}\tID:6\t[INFO: Attacker] Port scan probe: 44 bytes\n")
            t += 0.2
        
        # IDS alerts
        f.write(f"0:65.000\tID:7\t[INFO: IDS-Node] *** INTRUSION DETECTED *** type: 1\n")
        f.write(f"0:155.000\tID:7\t[INFO: IDS-Node] *** INTRUSION DETECTED *** type: 4\n")
    
    print(f"Generated synthetic log: {output_path}")


def save_dataset(dataset, output_path, format='csv'):
    """Save dataset to file"""
    if format == 'csv':
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=FEATURE_NAMES)
            writer.writeheader()
            writer.writerows(dataset)
    elif format == 'json':
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)
    elif format == 'npz':
        X = np.array([[d[f] for f in FEATURE_NAMES[:-1]] for d in dataset])
        y = np.array([d['label'] for d in dataset])
        np.savez(output_path, X=X, y=y, feature_names=FEATURE_NAMES[:-1])
    
    print(f"Saved {len(dataset)} samples to {output_path}")


def main():
    parser = argparse.ArgumentParser(description='Collect data from Cooja simulation')
    parser.add_argument('--log', type=str, help='Path to Cooja log file')
    parser.add_argument('--output', type=str, default='ids_dataset.csv', 
                        help='Output file path')
    parser.add_argument('--format', choices=['csv', 'json', 'npz'], default='csv',
                        help='Output format')
    parser.add_argument('--generate', action='store_true',
                        help='Generate synthetic test data')
    
    args = parser.parse_args()
    
    if args.generate:
        print("Generating synthetic data for testing...")
        generate_synthetic_cooja_log('test_cooja.log')
        
        parser = CoojaLogParser()
        dataset = parser.parse_log_file('test_cooja.log')
        save_dataset(dataset, args.output, args.format)
        
        print(f"\nDataset statistics:")
        labels = [d['label'] for d in dataset]
        print(f"  Total samples: {len(dataset)}")
        print(f"  Normal: {labels.count(0)}")
        print(f"  Attack: {labels.count(1)}")
        
    elif args.log:
        print(f"Parsing log file: {args.log}")
        parser = CoojaLogParser()
        dataset = parser.parse_log_file(args.log)
        save_dataset(dataset, args.output, args.format)
    else:
        print("Please specify --log <path> or --generate")
        parser.print_help()


if __name__ == "__main__":
    main()
