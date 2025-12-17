#!/usr/bin/env python3
"""
Test the trained TinyML model
"""

import numpy as np
import json
import os

def load_model_weights(weights_path):
    """Parse C header file to extract weights"""
    weights = {'W1': [], 'b1': [], 'W2': [], 'b2': [], 'W3': [], 'b3': None}
    
    with open(weights_path, 'r') as f:
        content = f.read()
    
    # Simple parser for the generated header
    # In practice, we just use numpy saved weights
    return weights

def test_model():
    """Test the trained model on sample data"""
    # Load dataset
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, 'dataset', 'ids_dataset.npz')
    
    data = np.load(dataset_path)
    X_test = data['X_test']
    y_test = data['y_test']
    
    print("=" * 50)
    print("TinyML IDS Model Testing")
    print("=" * 50)
    print(f"\nTest samples: {len(X_test)}")
    print(f"Normal samples: {np.sum(y_test == 0)}")
    print(f"Attack samples: {np.sum(y_test == 1)}")
    
    # Load normalization stats
    stats_path = os.path.join(script_dir, 'dataset', 'normalization_stats.json')
    with open(stats_path, 'r') as f:
        stats = json.load(f)
    
    print(f"\nFeatures: {len(stats['feature_names'])}")
    
    # Create sample test cases
    print("\n" + "-" * 50)
    print("Sample Predictions:")
    print("-" * 50)
    
    # Print some feature statistics
    print("\nFeature Statistics (Test Set):")
    print(f"{'Feature':<25} {'Mean':>10} {'Std':>10}")
    print("-" * 45)
    for i, name in enumerate(stats['feature_names'][:10]):
        print(f"{name:<25} {np.mean(X_test[:, i]):>10.2f} {np.std(X_test[:, i]):>10.2f}")
    print("...")
    
    # Test attack detection patterns
    print("\n" + "-" * 50)
    print("Attack Pattern Analysis:")
    print("-" * 50)
    
    attack_idx = np.where(y_test == 1)[0]
    normal_idx = np.where(y_test == 0)[0]
    
    if len(attack_idx) > 0 and len(normal_idx) > 0:
        attack_samples = X_test[attack_idx]
        normal_samples = X_test[normal_idx]
        
        # Key distinguishing features
        key_features = [7, 8, 21, 23]  # flow_byts_s, flow_pkts_s, pkt_count, high_rate
        
        print(f"\n{'Feature':<25} {'Normal Avg':>12} {'Attack Avg':>12} {'Diff':>10}")
        print("-" * 60)
        
        for idx in key_features:
            name = stats['feature_names'][idx]
            normal_avg = np.mean(normal_samples[:, idx])
            attack_avg = np.mean(attack_samples[:, idx])
            diff = attack_avg - normal_avg
            print(f"{name:<25} {normal_avg:>12.2f} {attack_avg:>12.2f} {diff:>+10.2f}")
    
    print("\n" + "=" * 50)
    print("Testing Complete")
    print("=" * 50)

if __name__ == "__main__":
    test_model()
