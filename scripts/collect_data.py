#!/usr/bin/env python3
"""
Serial Data Collector for Contiki-NG IDS Testbed
Captures flow data from Cooja simulation via serial output
Creates training dataset from real testbed traffic
"""

import serial
import csv
import argparse
import time
import sys
import os
import re
from datetime import datetime

# Feature names matching CICIOT2023
FEATURE_NAMES = [
    'flow_duration', 'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes',
    'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_bytes_s', 'flow_pkts_s',
    'fwd_iat_mean', 'fwd_iat_min', 'fwd_iat_max',
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean',
    'syn', 'fin', 'rst', 'psh', 'ack',
    'down_up_ratio', 'pkt_count', 'byte_count', 'high_rate_flag',
    'label'
]

class SerialDataCollector:
    def __init__(self, port=None, baudrate=115200, log_file=None):
        self.port = port
        self.baudrate = baudrate
        self.log_file = log_file
        self.serial_conn = None
        self.data_buffer = []
        self.start_time = None
        
        # Statistics
        self.normal_count = 0
        self.attack_count = 0
        self.total_flows = 0
        
    def connect(self):
        """Connect to serial port"""
        if self.port:
            try:
                self.serial_conn = serial.Serial(self.port, self.baudrate, timeout=1)
                print(f"Connected to {self.port} at {self.baudrate} baud")
                return True
            except serial.SerialException as e:
                print(f"Error connecting to serial port: {e}")
                return False
        return False
    
    def parse_flow_data(self, line):
        """Parse FLOW_DATA line from serial output"""
        # Expected format: FLOW_DATA,value1,value2,...,value24,label
        if not line.startswith('FLOW_DATA,'):
            return None
        
        try:
            parts = line.strip().split(',')
            if len(parts) != 26:  # FLOW_DATA + 24 features + label
                return None
            
            values = [float(x) for x in parts[1:]]
            return values
        except ValueError as e:
            print(f"Parse error: {e}")
            return None
    
    def collect_from_serial(self, duration_seconds=300):
        """Collect data from serial port for specified duration"""
        if not self.serial_conn:
            print("Not connected to serial port")
            return
        
        self.start_time = time.time()
        end_time = self.start_time + duration_seconds
        
        print(f"Collecting data for {duration_seconds} seconds...")
        print("Press Ctrl+C to stop early")
        
        try:
            while time.time() < end_time:
                if self.serial_conn.in_waiting:
                    line = self.serial_conn.readline().decode('utf-8', errors='ignore')
                    
                    # Log raw output if specified
                    if self.log_file:
                        with open(self.log_file, 'a') as f:
                            f.write(line)
                    
                    # Parse flow data
                    flow_data = self.parse_flow_data(line)
                    if flow_data:
                        self.data_buffer.append(flow_data)
                        self.total_flows += 1
                        
                        label = int(flow_data[-1])
                        if label == 0:
                            self.normal_count += 1
                        else:
                            self.attack_count += 1
                        
                        if self.total_flows % 100 == 0:
                            elapsed = time.time() - self.start_time
                            print(f"[{elapsed:.1f}s] Collected {self.total_flows} flows "
                                  f"(Normal: {self.normal_count}, Attack: {self.attack_count})")
                
                time.sleep(0.01)
                
        except KeyboardInterrupt:
            print("\nCollection stopped by user")
        
        elapsed = time.time() - self.start_time
        print(f"\nCollection complete: {self.total_flows} flows in {elapsed:.1f} seconds")
    
    def collect_from_file(self, input_file):
        """Collect data from a log file (for replay/testing)"""
        print(f"Reading data from {input_file}...")
        
        with open(input_file, 'r') as f:
            for line in f:
                flow_data = self.parse_flow_data(line)
                if flow_data:
                    self.data_buffer.append(flow_data)
                    self.total_flows += 1
                    
                    label = int(flow_data[-1])
                    if label == 0:
                        self.normal_count += 1
                    else:
                        self.attack_count += 1
        
        print(f"Loaded {self.total_flows} flows from file")
    
    def save_dataset(self, output_file):
        """Save collected data to CSV file"""
        if not self.data_buffer:
            print("No data to save")
            return
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(FEATURE_NAMES)
            writer.writerows(self.data_buffer)
        
        print(f"Saved {len(self.data_buffer)} flows to {output_file}")
    
    def print_statistics(self):
        """Print collection statistics"""
        print("\n" + "="*60)
        print("DATA COLLECTION STATISTICS")
        print("="*60)
        print(f"Total flows collected: {self.total_flows}")
        print(f"Normal traffic flows:  {self.normal_count} ({100*self.normal_count/max(self.total_flows,1):.1f}%)")
        print(f"Attack traffic flows:  {self.attack_count} ({100*self.attack_count/max(self.total_flows,1):.1f}%)")
        print("="*60)
    
    def close(self):
        """Close serial connection"""
        if self.serial_conn:
            self.serial_conn.close()


def collect_from_cooja_log(cooja_log_path, output_csv):
    """Parse Cooja simulation log file to extract flow data"""
    collector = SerialDataCollector()
    
    print(f"Parsing Cooja log: {cooja_log_path}")
    
    flow_pattern = re.compile(r'FLOW_DATA,(.+)')
    
    with open(cooja_log_path, 'r') as f:
        for line in f:
            match = flow_pattern.search(line)
            if match:
                flow_line = "FLOW_DATA," + match.group(1)
                flow_data = collector.parse_flow_data(flow_line)
                if flow_data:
                    collector.data_buffer.append(flow_data)
                    collector.total_flows += 1
                    label = int(flow_data[-1])
                    if label == 0:
                        collector.normal_count += 1
                    else:
                        collector.attack_count += 1
    
    collector.print_statistics()
    collector.save_dataset(output_csv)
    return collector.total_flows


def main():
    parser = argparse.ArgumentParser(description='Collect IDS training data from Contiki-NG testbed')
    parser.add_argument('--port', '-p', help='Serial port (e.g., /dev/ttyUSB0, COM3)')
    parser.add_argument('--baud', '-b', type=int, default=115200, help='Baud rate')
    parser.add_argument('--duration', '-d', type=int, default=300, help='Collection duration in seconds')
    parser.add_argument('--output', '-o', default='testbed_dataset.csv', help='Output CSV file')
    parser.add_argument('--log', '-l', help='Raw serial log file')
    parser.add_argument('--input', '-i', help='Input file to parse (instead of serial)')
    parser.add_argument('--cooja-log', help='Cooja simulation log file to parse')
    
    args = parser.parse_args()
    
    if args.cooja_log:
        # Parse Cooja simulation log
        collect_from_cooja_log(args.cooja_log, args.output)
    elif args.input:
        # Parse from existing log file
        collector = SerialDataCollector()
        collector.collect_from_file(args.input)
        collector.print_statistics()
        collector.save_dataset(args.output)
    elif args.port:
        # Collect from serial port
        collector = SerialDataCollector(args.port, args.baud, args.log)
        if collector.connect():
            collector.collect_from_serial(args.duration)
            collector.print_statistics()
            collector.save_dataset(args.output)
            collector.close()
    else:
        print("Please specify either --port, --input, or --cooja-log")
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
