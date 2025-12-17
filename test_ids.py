#!/usr/bin/env python3
"""
Real-time IDS Testing with Visualization
Tests the trained TinyML model with live traffic visualization
"""

import numpy as np
import time
import os
import sys
from datetime import datetime

# Try to import visualization libraries
try:
    import matplotlib
    matplotlib.use('Agg')  # Use non-interactive backend
    import matplotlib.pyplot as plt
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False

# Configuration
NUM_FEATURES = 24
THRESHOLD = 0.5


class TinyMLInference:
    """TinyML model inference engine"""
    
    def __init__(self):
        self.W1 = None
        self.b1 = None
        self.W2 = None
        self.b2 = None
        self.W3 = None
        self.b3 = None
        
        self._load_model()
    
    def _load_model(self):
        """Load the trained model"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        # Check both possible locations
        dataset_path = os.path.join(script_dir, 'iot-ids-testbed', 'tinyml', 'dataset', 'ids_dataset.npz')
        if not os.path.exists(dataset_path):
            dataset_path = os.path.join(script_dir, 'tinyml', 'dataset', 'ids_dataset.npz')
        
        if os.path.exists(dataset_path):
            print("[Model] Loading trained model...")
            data = np.load(dataset_path)
            X_train = data['X_train']
            y_train = data['y_train']
            
            # Initialize and train
            self._initialize_weights()
            self._train(X_train, y_train, epochs=100)
            
            # Evaluate
            X_test = data['X_test']
            y_test = data['y_test']
            self._evaluate(X_test, y_test)
        else:
            print("[Model] No saved dataset found, using random weights")
            self._initialize_weights()
    
    def _initialize_weights(self):
        """Initialize neural network weights"""
        np.random.seed(42)
        self.W1 = np.random.randn(24, 16) * np.sqrt(2.0 / 24)
        self.b1 = np.zeros(16)
        self.W2 = np.random.randn(16, 8) * np.sqrt(2.0 / 16)
        self.b2 = np.zeros(8)
        self.W3 = np.random.randn(8, 1) * np.sqrt(2.0 / 8)
        self.b3 = np.zeros(1)
    
    def _train(self, X, y, epochs=100, batch_size=32, lr=0.01):
        """Train the model"""
        print(f"[Model] Training on {len(X)} samples...")
        
        for epoch in range(epochs):
            # Shuffle
            idx = np.random.permutation(len(X))
            X_shuffled = X[idx]
            y_shuffled = y[idx]
            
            for i in range(0, len(X), batch_size):
                X_batch = X_shuffled[i:i+batch_size]
                y_batch = y_shuffled[i:i+batch_size]
                
                # Forward
                z1 = X_batch @ self.W1 + self.b1
                a1 = np.maximum(0, z1)
                z2 = a1 @ self.W2 + self.b2
                a2 = np.maximum(0, z2)
                z3 = a2 @ self.W3 + self.b3
                a3 = 1 / (1 + np.exp(-np.clip(z3, -500, 500)))
                
                # Backward
                m = len(X_batch)
                dz3 = a3 - y_batch.reshape(-1, 1)
                dW3 = (a2.T @ dz3) / m
                db3 = np.mean(dz3, axis=0)
                
                dz2 = (dz3 @ self.W3.T) * (z2 > 0)
                dW2 = (a1.T @ dz2) / m
                db2 = np.mean(dz2, axis=0)
                
                dz1 = (dz2 @ self.W2.T) * (z1 > 0)
                dW1 = (X_batch.T @ dz1) / m
                db1 = np.mean(dz1, axis=0)
                
                # Update
                self.W3 -= lr * dW3
                self.b3 -= lr * db3
                self.W2 -= lr * dW2
                self.b2 -= lr * db2
                self.W1 -= lr * dW1
                self.b1 -= lr * db1
            
            if (epoch + 1) % 20 == 0:
                pred = self.predict_batch(X)
                acc = np.mean((pred > 0.5) == y)
                print(f"        Epoch {epoch+1}/{epochs} - Accuracy: {acc:.4f}")
    
    def _evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        predictions = self.predict_batch(X_test)
        pred_labels = (predictions > 0.5).astype(int)
        
        tp = np.sum((pred_labels == 1) & (y_test == 1))
        tn = np.sum((pred_labels == 0) & (y_test == 0))
        fp = np.sum((pred_labels == 1) & (y_test == 0))
        fn = np.sum((pred_labels == 0) & (y_test == 1))
        
        accuracy = (tp + tn) / len(y_test)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        
        print(f"[Model] Test Results:")
        print(f"        Accuracy:  {accuracy:.4f}")
        print(f"        Precision: {precision:.4f}")
        print(f"        Recall:    {recall:.4f}")
        print(f"        F1 Score:  {f1:.4f}")
    
    def predict(self, features):
        """Run inference on single sample"""
        x = np.array(features).reshape(1, -1)
        return float(self.predict_batch(x)[0])
    
    def predict_batch(self, X):
        """Run inference on batch"""
        z1 = X @ self.W1 + self.b1
        a1 = np.maximum(0, z1)
        z2 = a1 @ self.W2 + self.b2
        a2 = np.maximum(0, z2)
        z3 = a2 @ self.W3 + self.b3
        return (1 / (1 + np.exp(-np.clip(z3, -500, 500)))).flatten()


def generate_normal_traffic():
    """Generate normal traffic features"""
    return [
        np.random.exponential(5) / 100,  # flow_duration
        np.random.poisson(5) / 100,  # fwd_pkts
        np.random.poisson(3) / 100,  # bwd_pkts
        np.random.poisson(300) / 10000,  # fwd_data
        np.random.poisson(150) / 10000,  # bwd_data
        np.random.normal(60, 20) / 100,  # fwd_pkt_len_mean
        np.random.normal(50, 15) / 100,  # bwd_pkt_len_mean
        np.random.exponential(500) / 100000,  # flow_byts_s
        np.random.exponential(10) / 1000,  # flow_pkts_s
        np.random.exponential(200) / 5000,  # flow_iat_mean
        np.random.exponential(50) / 1000,  # flow_iat_min
        np.random.exponential(1000) / 10000,  # flow_iat_max
        np.random.uniform(20, 60) / 100,  # pkt_len_min
        np.random.uniform(80, 200) / 1500,  # pkt_len_max
        np.random.normal(80, 30) / 1000,  # pkt_len_mean
        np.random.poisson(1) / 50,  # syn
        np.random.poisson(0.5) / 20,  # fin
        np.random.poisson(0.1) / 10,  # rst
        np.random.poisson(3) / 100,  # psh
        np.random.poisson(5) / 500,  # ack
        np.random.uniform(0.3, 0.8),  # down_up_ratio
        np.random.poisson(8) / 700,  # pkt_count
        np.random.poisson(450) / 70000,  # byte_count
        0.0  # high_rate_flag
    ]


def generate_attack_traffic(attack_type='ddos'):
    """Generate attack traffic features"""
    if attack_type == 'ddos':
        return [
            np.random.uniform(0.1, 2) / 100,  # short duration
            np.random.poisson(100) / 100,  # many fwd packets
            np.random.poisson(5) / 100,  # few responses
            np.random.poisson(5000) / 10000,  # high data
            np.random.poisson(100) / 10000,  # low bwd data
            np.random.normal(50, 10) / 100,  # fwd_pkt_len_mean
            np.random.normal(40, 10) / 100,  # bwd_pkt_len_mean
            np.random.exponential(10000) / 100000,  # high rate
            np.random.exponential(200) / 1000,  # high pkt rate
            np.random.uniform(1, 10) / 5000,  # very low IAT
            np.random.uniform(0.1, 2) / 1000,
            np.random.uniform(5, 20) / 10000,
            np.random.uniform(40, 64) / 100,
            np.random.uniform(64, 100) / 1500,
            np.random.normal(50, 10) / 1000,
            np.random.poisson(20) / 50,  # many SYNs
            np.random.poisson(0.2) / 20,
            np.random.poisson(0.1) / 10,
            np.random.poisson(1) / 100,
            np.random.poisson(2) / 500,
            np.random.uniform(0.01, 0.1),  # low ratio
            np.random.poisson(100) / 700,  # high pkt count
            np.random.poisson(5000) / 70000,  # high bytes
            1.0  # high_rate_flag
        ]
    elif attack_type == 'scan':
        return [
            np.random.uniform(0.01, 0.5) / 100,
            np.random.poisson(1) / 100,
            np.random.poisson(0.5) / 100,
            np.random.poisson(50) / 10000,
            np.random.poisson(20) / 10000,
            np.random.normal(40, 5) / 100,
            np.random.normal(40, 5) / 100,
            np.random.exponential(200) / 100000,
            np.random.exponential(5) / 1000,
            np.random.uniform(1, 50) / 5000,
            np.random.uniform(0.5, 5) / 1000,
            np.random.uniform(10, 100) / 10000,
            np.random.uniform(40, 50) / 100,
            np.random.uniform(40, 60) / 1500,
            np.random.normal(44, 5) / 1000,
            np.random.poisson(5) / 50,
            np.random.poisson(0.1) / 20,
            np.random.poisson(2) / 10,  # RST flags
            np.random.poisson(0.5) / 100,
            np.random.poisson(1) / 500,
            np.random.uniform(0.5, 2),
            np.random.poisson(2) / 700,
            np.random.poisson(70) / 70000,
            0.0
        ]
    else:
        return generate_normal_traffic()


def run_live_test(model, duration=60, interval=0.5):
    """Run live testing simulation"""
    print("\n" + "=" * 60)
    print("LIVE IDS TESTING")
    print("=" * 60)
    print(f"Duration: {duration}s, Check interval: {interval}s")
    print("-" * 60)
    
    results = {
        'normal_detected': 0,
        'attack_detected': 0,
        'timestamps': [],
        'predictions': [],
        'labels': []
    }
    
    start_time = time.time()
    sample_count = 0
    
    # Attack schedule: (start, end, type)
    attacks = [
        (10, 20, 'ddos'),
        (30, 40, 'scan'),
        (50, 55, 'ddos'),
    ]
    
    while time.time() - start_time < duration:
        elapsed = time.time() - start_time
        
        # Determine if we're in attack period
        current_attack = None
        for start, end, atype in attacks:
            if start <= elapsed < end:
                current_attack = atype
                break
        
        # Generate traffic
        if current_attack:
            features = generate_attack_traffic(current_attack)
            label = 1
            traffic_type = f"ATTACK ({current_attack})"
        else:
            features = generate_normal_traffic()
            label = 0
            traffic_type = "Normal"
        
        # Run inference
        prediction = model.predict(features)
        is_attack = prediction > THRESHOLD
        
        # Update results
        results['timestamps'].append(elapsed)
        results['predictions'].append(prediction)
        results['labels'].append(label)
        
        if is_attack:
            results['attack_detected'] += 1
        else:
            results['normal_detected'] += 1
        
        # Display
        sample_count += 1
        status = "🔴 ALERT" if is_attack else "🟢 OK"
        
        if is_attack or sample_count % 10 == 0:
            print(f"[{elapsed:6.1f}s] {status} | Traffic: {traffic_type:15} | "
                  f"Prediction: {prediction:.3f} | "
                  f"{'✓ Correct' if (is_attack == (label == 1)) else '✗ Wrong'}")
        
        time.sleep(interval)
    
    # Summary
    print("-" * 60)
    print("\nTEST SUMMARY:")
    
    predictions = np.array(results['predictions'])
    labels = np.array(results['labels'])
    pred_labels = (predictions > THRESHOLD).astype(int)
    
    tp = np.sum((pred_labels == 1) & (labels == 1))
    fp = np.sum((pred_labels == 1) & (labels == 0))
    tn = np.sum((pred_labels == 0) & (labels == 0))
    fn = np.sum((pred_labels == 0) & (labels == 1))
    
    accuracy = (tp + tn) / len(labels) if len(labels) > 0 else 0
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    
    print(f"  Samples processed: {len(labels)}")
    print(f"  True Positives:    {tp}")
    print(f"  False Positives:   {fp}")
    print(f"  True Negatives:    {tn}")
    print(f"  False Negatives:   {fn}")
    print(f"  Accuracy:          {accuracy:.2%}")
    print(f"  Precision:         {precision:.2%}")
    print(f"  Recall:            {recall:.2%}")
    
    return results


def create_visualization(results, output_path='test_results.png'):
    """Create visualization of results"""
    if not HAS_MATPLOTLIB:
        print("Matplotlib not available, skipping visualization")
        return
    
    fig, axes = plt.subplots(2, 1, figsize=(12, 8))
    
    timestamps = np.array(results['timestamps'])
    predictions = np.array(results['predictions'])
    labels = np.array(results['labels'])
    
    # Plot 1: Predictions over time
    ax1 = axes[0]
    ax1.plot(timestamps, predictions, 'b-', alpha=0.7, label='Prediction')
    ax1.axhline(y=THRESHOLD, color='r', linestyle='--', label=f'Threshold ({THRESHOLD})')
    ax1.fill_between(timestamps, 0, 1, where=labels == 1, 
                     alpha=0.3, color='red', label='Attack Period')
    ax1.set_xlabel('Time (s)')
    ax1.set_ylabel('Prediction Score')
    ax1.set_title('IDS Detection Over Time')
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Plot 2: Confusion matrix style
    ax2 = axes[1]
    pred_labels = (predictions > THRESHOLD).astype(int)
    
    tp = np.sum((pred_labels == 1) & (labels == 1))
    fp = np.sum((pred_labels == 1) & (labels == 0))
    tn = np.sum((pred_labels == 0) & (labels == 0))
    fn = np.sum((pred_labels == 0) & (labels == 1))
    
    matrix = np.array([[tn, fp], [fn, tp]])
    im = ax2.imshow(matrix, cmap='Blues')
    
    ax2.set_xticks([0, 1])
    ax2.set_yticks([0, 1])
    ax2.set_xticklabels(['Predicted Normal', 'Predicted Attack'])
    ax2.set_yticklabels(['Actual Normal', 'Actual Attack'])
    ax2.set_title('Confusion Matrix')
    
    for i in range(2):
        for j in range(2):
            ax2.text(j, i, str(matrix[i, j]), ha='center', va='center', fontsize=20)
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=150)
    print(f"Visualization saved to {output_path}")


def main():
    """Main entry point"""
    print("=" * 60)
    print("IoT IDS - TinyML Model Testing")
    print("=" * 60)
    print()
    
    # Load model
    model = TinyMLInference()
    
    print()
    
    # Run live test
    results = run_live_test(model, duration=60, interval=0.3)
    
    # Create visualization
    create_visualization(results)
    
    print("\nTest complete!")


if __name__ == "__main__":
    main()
