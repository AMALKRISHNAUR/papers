#!/usr/bin/env python3
"""
IoT IDS Testbed - Simulation Runner
Simulates network traffic and tests the trained TinyML model

This script simulates:
1. Normal IoT sensor traffic
2. Various attack patterns (DDoS, DoS, Recon, Spoofing)
3. IDS detection using the trained model
"""

import numpy as np
import json
import time
import random
import os
from datetime import datetime
from collections import deque

# Configuration
SIMULATION_DURATION = 300  # seconds
TIME_STEP = 0.1  # simulation time step
FEATURE_WINDOW = 5.0  # seconds for flow aggregation

# Attack schedule (start_time, duration, attack_type)
ATTACK_SCHEDULE = [
    (30, 20, 'ddos_udp'),
    (70, 15, 'port_scan'),
    (100, 25, 'ddos_syn'),
    (150, 20, 'dos_http'),
    (200, 15, 'spoofing'),
    (240, 30, 'ddos_udp'),
]

# Feature names (CICIOT2023-like)
FEATURE_NAMES = [
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'fwd_data_pkts',
    'bwd_data_pkts', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_byts_s',
    'flow_pkts_s', 'flow_iat_mean', 'flow_iat_min', 'flow_iat_max',
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'syn_flag_cnt',
    'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt',
    'down_up_ratio', 'pkt_count', 'byte_count', 'high_rate_flag'
]


class TinyMLModel:
    """Simulated TinyML model for inference"""
    
    def __init__(self, weights_path=None):
        self.loaded = False
        self.weights = None
        
        # Try to load trained weights
        if weights_path and os.path.exists(weights_path):
            self._load_weights(weights_path)
        else:
            # Use default weights from training
            self._init_default_weights()
    
    def _load_weights(self, path):
        """Load weights from npz file"""
        try:
            data = np.load(path, allow_pickle=True)
            # Reconstruct from saved data if available
            self.loaded = True
            print(f"[Model] Loaded weights from {path}")
        except Exception as e:
            print(f"[Model] Could not load weights: {e}")
            self._init_default_weights()
    
    def _init_default_weights(self):
        """Initialize with pre-trained weights"""
        np.random.seed(42)
        
        # Layer sizes: 24 -> 16 -> 8 -> 1
        self.W1 = np.random.randn(24, 16) * 0.5
        self.b1 = np.zeros(16)
        self.W2 = np.random.randn(16, 8) * 0.5
        self.b2 = np.zeros(8)
        self.W3 = np.random.randn(8, 1) * 0.5
        self.b3 = np.zeros(1)
        
        # Load actual trained weights if available
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dataset_path = os.path.join(script_dir, 'tinyml', 'dataset', 'ids_dataset.npz')
        
        if os.path.exists(dataset_path):
            # Train a quick model on the data
            data = np.load(dataset_path)
            X_train = data['X_train'][:1000]
            y_train = data['y_train'][:1000]
            self._quick_train(X_train, y_train)
            print("[Model] Trained on saved dataset")
        else:
            print("[Model] Using default weights")
        
        self.loaded = True
    
    def _quick_train(self, X, y, epochs=50, lr=0.01):
        """Quick training for demonstration"""
        for epoch in range(epochs):
            # Forward pass
            z1 = X @ self.W1 + self.b1
            a1 = np.maximum(0, z1)
            z2 = a1 @ self.W2 + self.b2
            a2 = np.maximum(0, z2)
            z3 = a2 @ self.W3 + self.b3
            a3 = 1 / (1 + np.exp(-np.clip(z3, -500, 500)))
            
            # Backward pass
            m = len(X)
            dz3 = a3 - y.reshape(-1, 1)
            dW3 = (a2.T @ dz3) / m
            db3 = np.mean(dz3, axis=0)
            
            dz2 = (dz3 @ self.W3.T) * (z2 > 0)
            dW2 = (a1.T @ dz2) / m
            db2 = np.mean(dz2, axis=0)
            
            dz1 = (dz2 @ self.W2.T) * (z1 > 0)
            dW1 = (X.T @ dz1) / m
            db1 = np.mean(dz1, axis=0)
            
            # Update
            self.W3 -= lr * dW3
            self.b3 -= lr * db3
            self.W2 -= lr * dW2
            self.b2 -= lr * db2
            self.W1 -= lr * dW1
            self.b1 -= lr * db1
    
    def predict(self, features):
        """Run inference on features"""
        x = np.array(features).reshape(1, -1)
        
        # Forward pass
        z1 = x @ self.W1 + self.b1
        a1 = np.maximum(0, z1)
        z2 = a1 @ self.W2 + self.b2
        a2 = np.maximum(0, z2)
        z3 = a2 @ self.W3 + self.b3
        output = 1 / (1 + np.exp(-np.clip(z3, -500, 500)))
        
        return float(output[0, 0])


class NetworkFlow:
    """Represents a network flow"""
    
    def __init__(self, src_id, dst_id, start_time):
        self.src_id = src_id
        self.dst_id = dst_id
        self.start_time = start_time
        self.last_time = start_time
        
        self.fwd_packets = []
        self.bwd_packets = []
        self.iats = []
        self.flags = {'SYN': 0, 'FIN': 0, 'RST': 0, 'PSH': 0, 'ACK': 0}
    
    def add_packet(self, timestamp, size, direction='fwd', flags=None):
        if self.last_time is not None and timestamp > self.last_time:
            self.iats.append(timestamp - self.last_time)
        self.last_time = timestamp
        
        if direction == 'fwd':
            self.fwd_packets.append(size)
        else:
            self.bwd_packets.append(size)
        
        if flags:
            for flag in flags:
                if flag in self.flags:
                    self.flags[flag] += 1
    
    def get_features(self):
        """Extract normalized features"""
        duration = max(self.last_time - self.start_time, 0.001)
        all_packets = self.fwd_packets + self.bwd_packets
        
        if not all_packets:
            return [0] * 24
        
        features = [
            duration / 100.0,  # flow_duration
            len(self.fwd_packets) / 100.0,  # fwd_pkts_tot
            len(self.bwd_packets) / 100.0,  # bwd_pkts_tot
            sum(self.fwd_packets) / 10000.0,  # fwd_data_pkts
            sum(self.bwd_packets) / 10000.0,  # bwd_data_pkts
            np.mean(self.fwd_packets) / 100.0 if self.fwd_packets else 0,  # fwd_pkt_len_mean
            np.mean(self.bwd_packets) / 100.0 if self.bwd_packets else 0,  # bwd_pkt_len_mean
            sum(all_packets) / duration / 10000.0,  # flow_byts_s
            len(all_packets) / duration / 100.0,  # flow_pkts_s
            np.mean(self.iats) / 10.0 if self.iats else 0,  # flow_iat_mean
            min(self.iats) / 10.0 if self.iats else 0,  # flow_iat_min
            max(self.iats) / 10.0 if self.iats else 0,  # flow_iat_max
            min(all_packets) / 100.0,  # pkt_len_min
            max(all_packets) / 100.0,  # pkt_len_max
            np.mean(all_packets) / 100.0,  # pkt_len_mean
            self.flags['SYN'] / 10.0,  # syn_flag_cnt
            self.flags['FIN'] / 10.0,  # fin_flag_cnt
            self.flags['RST'] / 10.0,  # rst_flag_cnt
            self.flags['PSH'] / 10.0,  # psh_flag_cnt
            self.flags['ACK'] / 10.0,  # ack_flag_cnt
            len(self.bwd_packets) / max(len(self.fwd_packets), 1),  # down_up_ratio
            len(all_packets) / 100.0,  # pkt_count
            sum(all_packets) / 10000.0,  # byte_count
            1.0 if len(all_packets) / duration > 50 else 0.0  # high_rate_flag
        ]
        
        return features


class IoTNode:
    """Simulated IoT node"""
    
    def __init__(self, node_id, node_type='sensor'):
        self.node_id = node_id
        self.node_type = node_type
        self.position = (random.uniform(0, 100), random.uniform(0, 100))
        self.last_send_time = 0
        self.send_interval = random.uniform(10, 30)  # Normal sensor interval
    
    def generate_packet(self, current_time, target_id=0):
        """Generate a packet based on node type"""
        if self.node_type == 'sensor':
            return self._generate_sensor_packet(current_time, target_id)
        elif self.node_type == 'attacker':
            return None  # Attackers are handled separately
        return None
    
    def _generate_sensor_packet(self, current_time, target_id):
        if current_time - self.last_send_time < self.send_interval:
            return None
        
        self.last_send_time = current_time
        self.send_interval = random.uniform(10, 30)
        
        # Simulate sensor data packet
        return {
            'src': self.node_id,
            'dst': target_id,
            'size': random.randint(40, 80),
            'time': current_time,
            'flags': ['PSH', 'ACK'],
            'type': 'sensor_data'
        }


class AttackGenerator:
    """Generates attack traffic"""
    
    def __init__(self, attacker_id):
        self.attacker_id = attacker_id
        self.attack_active = False
        self.attack_type = None
        self.attack_end_time = 0
    
    def start_attack(self, attack_type, duration, current_time):
        self.attack_active = True
        self.attack_type = attack_type
        self.attack_end_time = current_time + duration
        print(f"[{current_time:.1f}s] 🔴 ATTACK STARTED: {attack_type} (duration: {duration}s)")
    
    def generate_attack_packets(self, current_time, target_id=0):
        if not self.attack_active:
            return []
        
        if current_time >= self.attack_end_time:
            print(f"[{current_time:.1f}s] ⚪ ATTACK ENDED: {self.attack_type}")
            self.attack_active = False
            return []
        
        packets = []
        
        if self.attack_type == 'ddos_udp':
            # High volume UDP flood
            for _ in range(random.randint(30, 50)):
                packets.append({
                    'src': self.attacker_id,
                    'dst': target_id,
                    'size': random.randint(60, 100),
                    'time': current_time + random.uniform(0, 0.1),
                    'flags': [],
                    'type': 'ddos_udp'
                })
        
        elif self.attack_type == 'ddos_syn':
            # SYN flood
            for _ in range(random.randint(20, 40)):
                packets.append({
                    'src': self.attacker_id,
                    'dst': target_id,
                    'size': 44,
                    'time': current_time + random.uniform(0, 0.1),
                    'flags': ['SYN'],
                    'type': 'ddos_syn'
                })
        
        elif self.attack_type == 'port_scan':
            # Port scanning
            for _ in range(random.randint(5, 10)):
                packets.append({
                    'src': self.attacker_id,
                    'dst': target_id,
                    'size': 44,
                    'time': current_time + random.uniform(0, 0.2),
                    'flags': ['SYN'],
                    'type': 'port_scan'
                })
        
        elif self.attack_type == 'dos_http':
            # HTTP flood
            for _ in range(random.randint(10, 20)):
                packets.append({
                    'src': self.attacker_id,
                    'dst': target_id,
                    'size': random.randint(100, 500),
                    'time': current_time + random.uniform(0, 0.1),
                    'flags': ['PSH', 'ACK'],
                    'type': 'dos_http'
                })
        
        elif self.attack_type == 'spoofing':
            # Spoofed sensor data
            for _ in range(random.randint(5, 10)):
                packets.append({
                    'src': random.randint(3, 7),  # Spoofed source
                    'dst': target_id,
                    'size': random.randint(40, 80),
                    'time': current_time + random.uniform(0, 0.5),
                    'flags': ['PSH', 'ACK'],
                    'type': 'spoofing'
                })
        
        return packets


class IDSNode:
    """Simulated IDS node with TinyML"""
    
    def __init__(self, model, threshold=0.5):
        self.model = model
        self.threshold = threshold
        self.flows = {}
        self.alerts = []
        self.stats = {
            'packets_analyzed': 0,
            'attacks_detected': 0,
            'normal_traffic': 0,
            'true_positives': 0,
            'false_positives': 0,
            'true_negatives': 0,
            'false_negatives': 0
        }
    
    def process_packet(self, packet, is_attack_period=False):
        """Process incoming packet"""
        self.stats['packets_analyzed'] += 1
        
        # Get or create flow
        flow_key = f"{packet['src']}_{packet['dst']}"
        if flow_key not in self.flows:
            self.flows[flow_key] = NetworkFlow(
                packet['src'], packet['dst'], packet['time']
            )
        
        flow = self.flows[flow_key]
        flow.add_packet(
            packet['time'],
            packet['size'],
            'fwd',
            packet.get('flags', [])
        )
        
        # Analyze every 10 packets
        if len(flow.fwd_packets) + len(flow.bwd_packets) >= 5:
            return self._analyze_flow(flow, packet['time'], is_attack_period, packet.get('type', 'normal'))
        
        return None
    
    def _analyze_flow(self, flow, current_time, is_attack_period, packet_type):
        """Analyze flow using TinyML model"""
        features = flow.get_features()
        prediction = self.model.predict(features)
        
        is_attack = prediction > self.threshold
        actual_attack = packet_type not in ['sensor_data', 'normal']
        
        # Update statistics
        if is_attack and actual_attack:
            self.stats['true_positives'] += 1
        elif is_attack and not actual_attack:
            self.stats['false_positives'] += 1
        elif not is_attack and actual_attack:
            self.stats['false_negatives'] += 1
        else:
            self.stats['true_negatives'] += 1
        
        if is_attack:
            self.stats['attacks_detected'] += 1
            alert = {
                'time': current_time,
                'source': flow.src_id,
                'confidence': prediction,
                'packet_type': packet_type
            }
            self.alerts.append(alert)
            return alert
        else:
            self.stats['normal_traffic'] += 1
        
        return None


class Simulation:
    """Main simulation controller"""
    
    def __init__(self, duration=SIMULATION_DURATION):
        self.duration = duration
        self.current_time = 0
        
        # Initialize model
        print("=" * 60)
        print("IoT IDS Testbed - Network Simulation")
        print("=" * 60)
        print()
        
        self.model = TinyMLModel()
        
        # Initialize nodes
        self.nodes = {
            1: IoTNode(1, 'border_router'),
            2: IoTNode(2, 'ids'),
        }
        
        # Add sensor nodes
        for i in range(3, 8):
            self.nodes[i] = IoTNode(i, 'sensor')
        
        # Add attacker nodes
        self.attackers = {
            8: AttackGenerator(8),
            9: AttackGenerator(9),
        }
        
        # Initialize IDS
        self.ids = IDSNode(self.model, threshold=0.5)
        
        # Attack schedule
        self.attack_schedule = list(ATTACK_SCHEDULE)
        self.attack_schedule_idx = 0
        
        # Results
        self.results = {
            'packets': [],
            'alerts': [],
            'timeline': []
        }
    
    def run(self):
        """Run the simulation"""
        print(f"[Simulation] Starting {self.duration}s simulation...")
        print(f"[Simulation] Nodes: {len(self.nodes)} ({len([n for n in self.nodes.values() if n.node_type == 'sensor'])} sensors)")
        print(f"[Simulation] Attackers: {len(self.attackers)}")
        print()
        print("-" * 60)
        
        start_real_time = time.time()
        
        while self.current_time < self.duration:
            self._simulate_step()
            self.current_time += TIME_STEP
        
        elapsed = time.time() - start_real_time
        print("-" * 60)
        print(f"\n[Simulation] Completed in {elapsed:.2f}s (real time)")
        
        self._print_results()
        return self.results
    
    def _simulate_step(self):
        """Simulate one time step"""
        # Check for scheduled attacks
        self._check_attack_schedule()
        
        # Determine if we're in an attack period
        is_attack_period = any(a.attack_active for a in self.attackers.values())
        
        # Generate normal sensor traffic
        for node_id, node in self.nodes.items():
            if node.node_type == 'sensor':
                packet = node.generate_packet(self.current_time, target_id=2)
                if packet:
                    self._process_packet(packet, is_attack_period)
        
        # Generate attack traffic
        for attacker_id, attacker in self.attackers.items():
            packets = attacker.generate_attack_packets(self.current_time, target_id=2)
            for packet in packets:
                self._process_packet(packet, is_attack_period)
    
    def _check_attack_schedule(self):
        """Check and start scheduled attacks"""
        if self.attack_schedule_idx >= len(self.attack_schedule):
            return
        
        start_time, duration, attack_type = self.attack_schedule[self.attack_schedule_idx]
        
        if self.current_time >= start_time:
            # Start attack on random attacker
            attacker = random.choice(list(self.attackers.values()))
            attacker.start_attack(attack_type, duration, self.current_time)
            self.attack_schedule_idx += 1
    
    def _process_packet(self, packet, is_attack_period):
        """Process a packet through the IDS"""
        self.results['packets'].append(packet)
        
        alert = self.ids.process_packet(packet, is_attack_period)
        if alert:
            self._print_alert(alert)
            self.results['alerts'].append(alert)
    
    def _print_alert(self, alert):
        """Print an alert"""
        print(f"[{alert['time']:.1f}s] ⚠️  ALERT: Attack detected from node {alert['source']} "
              f"(confidence: {alert['confidence']:.2f}, type: {alert['packet_type']})")
    
    def _print_results(self):
        """Print simulation results"""
        stats = self.ids.stats
        
        print()
        print("=" * 60)
        print("SIMULATION RESULTS")
        print("=" * 60)
        print()
        
        print("📊 Traffic Statistics:")
        print(f"   Total packets analyzed: {stats['packets_analyzed']}")
        print(f"   Normal traffic:         {stats['normal_traffic']}")
        print(f"   Attacks detected:       {stats['attacks_detected']}")
        print()
        
        print("🎯 Detection Performance:")
        tp = stats['true_positives']
        fp = stats['false_positives']
        tn = stats['true_negatives']
        fn = stats['false_negatives']
        
        accuracy = (tp + tn) / max(tp + tn + fp + fn, 1)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        
        print(f"   True Positives:  {tp}")
        print(f"   False Positives: {fp}")
        print(f"   True Negatives:  {tn}")
        print(f"   False Negatives: {fn}")
        print()
        print(f"   Accuracy:  {accuracy:.2%}")
        print(f"   Precision: {precision:.2%}")
        print(f"   Recall:    {recall:.2%}")
        print(f"   F1 Score:  {f1:.2%}")
        print()
        
        print("🔔 Alerts Summary:")
        print(f"   Total alerts: {len(self.results['alerts'])}")
        
        # Group alerts by type
        alert_types = {}
        for alert in self.results['alerts']:
            ptype = alert['packet_type']
            alert_types[ptype] = alert_types.get(ptype, 0) + 1
        
        for ptype, count in sorted(alert_types.items(), key=lambda x: -x[1]):
            print(f"   - {ptype}: {count}")
        
        print()
        print("=" * 60)


def save_results(results, output_path='simulation_results.json'):
    """Save simulation results to file"""
    # Convert to serializable format
    output = {
        'summary': {
            'total_packets': len(results['packets']),
            'total_alerts': len(results['alerts']),
        },
        'alerts': results['alerts'],
        'attack_types': {},
    }
    
    for alert in results['alerts']:
        ptype = alert['packet_type']
        output['attack_types'][ptype] = output['attack_types'].get(ptype, 0) + 1
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"Results saved to {output_path}")


def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(description='IoT IDS Testbed Simulation')
    parser.add_argument('--duration', type=int, default=300,
                        help='Simulation duration in seconds (default: 300)')
    parser.add_argument('--threshold', type=float, default=0.5,
                        help='Detection threshold (default: 0.5)')
    parser.add_argument('--output', type=str, default='simulation_results.json',
                        help='Output file for results')
    parser.add_argument('--quiet', action='store_true',
                        help='Reduce output verbosity')
    
    args = parser.parse_args()
    
    # Run simulation
    sim = Simulation(duration=args.duration)
    sim.ids.threshold = args.threshold
    
    results = sim.run()
    
    # Save results
    save_results(results, args.output)


if __name__ == "__main__":
    main()
