#!/usr/bin/env python3
"""
TinyML IDS Model Training Script
Trains a lightweight neural network for IoT intrusion detection
Compatible with CICIOT2023-like features
"""

import numpy as np
import os
import json
from datetime import datetime

# Try to import TensorFlow, fallback to simple numpy implementation
try:
    import tensorflow as tf
    from tensorflow import keras
    HAS_TF = True
except ImportError:
    HAS_TF = False
    print("TensorFlow not available, using numpy-only implementation")

# Feature configuration (CICIOT2023-like)
FEATURE_NAMES = [
    'flow_duration', 'fwd_pkts_tot', 'bwd_pkts_tot', 'fwd_data_pkts',
    'bwd_data_pkts', 'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_byts_s',
    'flow_pkts_s', 'flow_iat_mean', 'flow_iat_min', 'flow_iat_max',
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean', 'syn_flag_cnt',
    'fin_flag_cnt', 'rst_flag_cnt', 'psh_flag_cnt', 'ack_flag_cnt',
    'down_up_ratio', 'pkt_count', 'byte_count', 'high_rate_flag'
]

NUM_FEATURES = len(FEATURE_NAMES)
HIDDEN_SIZE_1 = 16
HIDDEN_SIZE_2 = 8

# Attack type labels
ATTACK_TYPES = {
    0: 'Normal',
    1: 'DDoS_UDP',
    2: 'DDoS_SYN',
    3: 'DoS_HTTP',
    4: 'Reconnaissance',
    5: 'Spoofing',
    6: 'MITM'
}


def generate_synthetic_dataset(num_samples=10000, attack_ratio=0.3):
    """
    Generate synthetic CICIOT2023-like dataset for training
    """
    np.random.seed(42)
    
    num_attacks = int(num_samples * attack_ratio)
    num_normal = num_samples - num_attacks
    
    # Normal traffic characteristics
    normal_data = np.zeros((num_normal, NUM_FEATURES))
    normal_data[:, 0] = np.random.exponential(5, num_normal)  # flow_duration
    normal_data[:, 1] = np.random.poisson(5, num_normal)  # fwd_pkts_tot
    normal_data[:, 2] = np.random.poisson(3, num_normal)  # bwd_pkts_tot
    normal_data[:, 3] = np.random.poisson(300, num_normal)  # fwd_data_pkts
    normal_data[:, 4] = np.random.poisson(150, num_normal)  # bwd_data_pkts
    normal_data[:, 5] = np.random.normal(60, 20, num_normal)  # fwd_pkt_len_mean
    normal_data[:, 6] = np.random.normal(50, 15, num_normal)  # bwd_pkt_len_mean
    normal_data[:, 7] = np.random.exponential(500, num_normal)  # flow_byts_s
    normal_data[:, 8] = np.random.exponential(10, num_normal)  # flow_pkts_s
    normal_data[:, 9] = np.random.exponential(200, num_normal)  # flow_iat_mean
    normal_data[:, 10] = np.random.exponential(50, num_normal)  # flow_iat_min
    normal_data[:, 11] = np.random.exponential(1000, num_normal)  # flow_iat_max
    normal_data[:, 12] = np.random.uniform(20, 60, num_normal)  # pkt_len_min
    normal_data[:, 13] = np.random.uniform(80, 200, num_normal)  # pkt_len_max
    normal_data[:, 14] = np.random.normal(80, 30, num_normal)  # pkt_len_mean
    normal_data[:, 15] = np.random.poisson(1, num_normal)  # syn_flag_cnt
    normal_data[:, 16] = np.random.poisson(0.5, num_normal)  # fin_flag_cnt
    normal_data[:, 17] = np.random.poisson(0.1, num_normal)  # rst_flag_cnt
    normal_data[:, 18] = np.random.poisson(3, num_normal)  # psh_flag_cnt
    normal_data[:, 19] = np.random.poisson(5, num_normal)  # ack_flag_cnt
    normal_data[:, 20] = np.random.uniform(0.3, 0.8, num_normal)  # down_up_ratio
    normal_data[:, 21] = normal_data[:, 1] + normal_data[:, 2]  # pkt_count
    normal_data[:, 22] = normal_data[:, 3] + normal_data[:, 4]  # byte_count
    normal_data[:, 23] = 0  # high_rate_flag
    
    # Attack traffic characteristics (various attack types)
    attack_data = np.zeros((num_attacks, NUM_FEATURES))
    
    # DDoS attacks - high packet rate, many packets
    ddos_count = num_attacks // 3
    attack_data[:ddos_count, 0] = np.random.uniform(0.1, 2, ddos_count)  # short duration
    attack_data[:ddos_count, 1] = np.random.poisson(100, ddos_count)  # many fwd packets
    attack_data[:ddos_count, 2] = np.random.poisson(5, ddos_count)  # few responses
    attack_data[:ddos_count, 3] = np.random.poisson(5000, ddos_count)  # high data
    attack_data[:ddos_count, 4] = np.random.poisson(100, ddos_count)
    attack_data[:ddos_count, 5] = np.random.normal(50, 10, ddos_count)
    attack_data[:ddos_count, 6] = np.random.normal(40, 10, ddos_count)
    attack_data[:ddos_count, 7] = np.random.exponential(10000, ddos_count)  # high rate
    attack_data[:ddos_count, 8] = np.random.exponential(200, ddos_count)  # high pkt rate
    attack_data[:ddos_count, 9] = np.random.uniform(1, 10, ddos_count)  # very low IAT
    attack_data[:ddos_count, 10] = np.random.uniform(0.1, 2, ddos_count)
    attack_data[:ddos_count, 11] = np.random.uniform(5, 20, ddos_count)
    attack_data[:ddos_count, 12] = np.random.uniform(40, 64, ddos_count)
    attack_data[:ddos_count, 13] = np.random.uniform(64, 100, ddos_count)
    attack_data[:ddos_count, 14] = np.random.normal(50, 10, ddos_count)
    attack_data[:ddos_count, 15] = np.random.poisson(20, ddos_count)  # many SYNs
    attack_data[:ddos_count, 16] = np.random.poisson(0.2, ddos_count)
    attack_data[:ddos_count, 17] = np.random.poisson(0.1, ddos_count)
    attack_data[:ddos_count, 18] = np.random.poisson(1, ddos_count)
    attack_data[:ddos_count, 19] = np.random.poisson(2, ddos_count)
    attack_data[:ddos_count, 20] = np.random.uniform(0.01, 0.1, ddos_count)  # low ratio
    attack_data[:ddos_count, 21] = attack_data[:ddos_count, 1] + attack_data[:ddos_count, 2]
    attack_data[:ddos_count, 22] = attack_data[:ddos_count, 3] + attack_data[:ddos_count, 4]
    attack_data[:ddos_count, 23] = 1  # high rate flag
    
    # Reconnaissance attacks - port scanning
    recon_start = ddos_count
    recon_count = num_attacks // 3
    attack_data[recon_start:recon_start+recon_count, 0] = np.random.uniform(0.01, 0.5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 1] = np.random.poisson(1, recon_count)
    attack_data[recon_start:recon_start+recon_count, 2] = np.random.poisson(0.5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 3] = np.random.poisson(50, recon_count)
    attack_data[recon_start:recon_start+recon_count, 4] = np.random.poisson(20, recon_count)
    attack_data[recon_start:recon_start+recon_count, 5] = np.random.normal(40, 5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 6] = np.random.normal(40, 5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 7] = np.random.exponential(200, recon_count)
    attack_data[recon_start:recon_start+recon_count, 8] = np.random.exponential(5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 9] = np.random.uniform(1, 50, recon_count)
    attack_data[recon_start:recon_start+recon_count, 10] = np.random.uniform(0.5, 5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 11] = np.random.uniform(10, 100, recon_count)
    attack_data[recon_start:recon_start+recon_count, 12] = np.random.uniform(40, 50, recon_count)
    attack_data[recon_start:recon_start+recon_count, 13] = np.random.uniform(40, 60, recon_count)
    attack_data[recon_start:recon_start+recon_count, 14] = np.random.normal(44, 5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 15] = np.random.poisson(5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 16] = np.random.poisson(0.1, recon_count)
    attack_data[recon_start:recon_start+recon_count, 17] = np.random.poisson(2, recon_count)  # RST flags
    attack_data[recon_start:recon_start+recon_count, 18] = np.random.poisson(0.5, recon_count)
    attack_data[recon_start:recon_start+recon_count, 19] = np.random.poisson(1, recon_count)
    attack_data[recon_start:recon_start+recon_count, 20] = np.random.uniform(0.5, 2, recon_count)
    attack_data[recon_start:recon_start+recon_count, 21] = attack_data[recon_start:recon_start+recon_count, 1] + attack_data[recon_start:recon_start+recon_count, 2]
    attack_data[recon_start:recon_start+recon_count, 22] = attack_data[recon_start:recon_start+recon_count, 3] + attack_data[recon_start:recon_start+recon_count, 4]
    attack_data[recon_start:recon_start+recon_count, 23] = 0
    
    # Spoofing/DoS attacks - rest
    spoof_start = recon_start + recon_count
    spoof_count = num_attacks - ddos_count - recon_count
    attack_data[spoof_start:, 0] = np.random.uniform(1, 5, spoof_count)
    attack_data[spoof_start:, 1] = np.random.poisson(20, spoof_count)
    attack_data[spoof_start:, 2] = np.random.poisson(2, spoof_count)
    attack_data[spoof_start:, 3] = np.random.poisson(1000, spoof_count)
    attack_data[spoof_start:, 4] = np.random.poisson(50, spoof_count)
    attack_data[spoof_start:, 5] = np.random.normal(50, 15, spoof_count)
    attack_data[spoof_start:, 6] = np.random.normal(25, 10, spoof_count)
    attack_data[spoof_start:, 7] = np.random.exponential(2000, spoof_count)
    attack_data[spoof_start:, 8] = np.random.exponential(30, spoof_count)
    attack_data[spoof_start:, 9] = np.random.uniform(10, 100, spoof_count)
    attack_data[spoof_start:, 10] = np.random.uniform(5, 20, spoof_count)
    attack_data[spoof_start:, 11] = np.random.uniform(50, 300, spoof_count)
    attack_data[spoof_start:, 12] = np.random.uniform(40, 64, spoof_count)
    attack_data[spoof_start:, 13] = np.random.uniform(64, 128, spoof_count)
    attack_data[spoof_start:, 14] = np.random.normal(55, 15, spoof_count)
    attack_data[spoof_start:, 15] = np.random.poisson(3, spoof_count)
    attack_data[spoof_start:, 16] = np.random.poisson(0.5, spoof_count)
    attack_data[spoof_start:, 17] = np.random.poisson(0.5, spoof_count)
    attack_data[spoof_start:, 18] = np.random.poisson(5, spoof_count)
    attack_data[spoof_start:, 19] = np.random.poisson(8, spoof_count)
    attack_data[spoof_start:, 20] = np.random.uniform(0.05, 0.3, spoof_count)
    attack_data[spoof_start:, 21] = attack_data[spoof_start:, 1] + attack_data[spoof_start:, 2]
    attack_data[spoof_start:, 22] = attack_data[spoof_start:, 3] + attack_data[spoof_start:, 4]
    attack_data[spoof_start:, 23] = 1
    
    # Combine and create labels
    X = np.vstack([normal_data, attack_data])
    y = np.hstack([np.zeros(num_normal), np.ones(num_attacks)])
    
    # Ensure non-negative values
    X = np.maximum(X, 0)
    
    # Shuffle
    indices = np.random.permutation(len(X))
    X = X[indices]
    y = y[indices]
    
    return X, y


def normalize_data(X, save_stats=True, stats_path=None):
    """
    Normalize features using min-max scaling
    """
    if stats_path is None:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        stats_path = os.path.join(script_dir, '..', 'dataset', 'normalization_stats.json')
    
    mins = X.min(axis=0)
    maxs = X.max(axis=0)
    ranges = maxs - mins
    ranges[ranges == 0] = 1  # Avoid division by zero
    
    X_norm = (X - mins) / ranges
    
    if save_stats:
        os.makedirs(os.path.dirname(os.path.abspath(stats_path)), exist_ok=True)
        stats = {
            'mins': mins.tolist(),
            'maxs': maxs.tolist(),
            'means': X.mean(axis=0).tolist(),
            'stds': X.std(axis=0).tolist(),
            'feature_names': FEATURE_NAMES
        }
        with open(stats_path, 'w') as f:
            json.dump(stats, f, indent=2)
    
    return X_norm, mins, maxs


class TinyMLModel:
    """
    Simple neural network for numpy-only training
    """
    def __init__(self, input_size=NUM_FEATURES, hidden1=HIDDEN_SIZE_1, hidden2=HIDDEN_SIZE_2):
        self.input_size = input_size
        self.hidden1 = hidden1
        self.hidden2 = hidden2
        
        # Initialize weights with Xavier initialization
        self.W1 = np.random.randn(input_size, hidden1) * np.sqrt(2.0 / input_size)
        self.b1 = np.zeros(hidden1)
        self.W2 = np.random.randn(hidden1, hidden2) * np.sqrt(2.0 / hidden1)
        self.b2 = np.zeros(hidden2)
        self.W3 = np.random.randn(hidden2, 1) * np.sqrt(2.0 / hidden2)
        self.b3 = np.zeros(1)
    
    def relu(self, x):
        return np.maximum(0, x)
    
    def relu_derivative(self, x):
        return (x > 0).astype(float)
    
    def sigmoid(self, x):
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))
    
    def forward(self, X):
        self.z1 = X @ self.W1 + self.b1
        self.a1 = self.relu(self.z1)
        self.z2 = self.a1 @ self.W2 + self.b2
        self.a2 = self.relu(self.z2)
        self.z3 = self.a2 @ self.W3 + self.b3
        self.a3 = self.sigmoid(self.z3)
        return self.a3
    
    def backward(self, X, y, learning_rate=0.01):
        m = len(X)
        y = y.reshape(-1, 1)
        
        # Output layer
        dz3 = self.a3 - y
        dW3 = (self.a2.T @ dz3) / m
        db3 = np.mean(dz3, axis=0)
        
        # Hidden layer 2
        dz2 = (dz3 @ self.W3.T) * self.relu_derivative(self.z2)
        dW2 = (self.a1.T @ dz2) / m
        db2 = np.mean(dz2, axis=0)
        
        # Hidden layer 1
        dz1 = (dz2 @ self.W2.T) * self.relu_derivative(self.z1)
        dW1 = (X.T @ dz1) / m
        db1 = np.mean(dz1, axis=0)
        
        # Update weights
        self.W3 -= learning_rate * dW3
        self.b3 -= learning_rate * db3
        self.W2 -= learning_rate * dW2
        self.b2 -= learning_rate * db2
        self.W1 -= learning_rate * dW1
        self.b1 -= learning_rate * db1
    
    def train(self, X, y, epochs=100, batch_size=32, learning_rate=0.01, verbose=True):
        losses = []
        
        for epoch in range(epochs):
            # Mini-batch training
            indices = np.random.permutation(len(X))
            X_shuffled = X[indices]
            y_shuffled = y[indices]
            
            epoch_loss = 0
            for i in range(0, len(X), batch_size):
                X_batch = X_shuffled[i:i+batch_size]
                y_batch = y_shuffled[i:i+batch_size]
                
                # Forward pass
                predictions = self.forward(X_batch)
                
                # Compute loss (binary cross-entropy)
                epsilon = 1e-7
                loss = -np.mean(y_batch.reshape(-1, 1) * np.log(predictions + epsilon) + 
                               (1 - y_batch.reshape(-1, 1)) * np.log(1 - predictions + epsilon))
                epoch_loss += loss
                
                # Backward pass
                self.backward(X_batch, y_batch, learning_rate)
            
            epoch_loss /= (len(X) // batch_size)
            losses.append(epoch_loss)
            
            if verbose and (epoch + 1) % 10 == 0:
                predictions = self.forward(X)
                accuracy = np.mean((predictions > 0.5).flatten() == y)
                print(f"Epoch {epoch+1}/{epochs} - Loss: {epoch_loss:.4f} - Accuracy: {accuracy:.4f}")
        
        return losses
    
    def predict(self, X):
        return self.forward(X)
    
    def evaluate(self, X, y):
        predictions = self.predict(X)
        pred_labels = (predictions > 0.5).flatten()
        
        accuracy = np.mean(pred_labels == y)
        
        # Confusion matrix components
        tp = np.sum((pred_labels == 1) & (y == 1))
        tn = np.sum((pred_labels == 0) & (y == 0))
        fp = np.sum((pred_labels == 1) & (y == 0))
        fn = np.sum((pred_labels == 0) & (y == 1))
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1': f1,
            'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn
        }


def train_keras_model(X_train, y_train, X_val, y_val):
    """
    Train using TensorFlow/Keras if available
    """
    if not HAS_TF:
        print("TensorFlow not available")
        return None
    
    model = keras.Sequential([
        keras.layers.Dense(HIDDEN_SIZE_1, activation='relu', input_shape=(NUM_FEATURES,)),
        keras.layers.Dense(HIDDEN_SIZE_2, activation='relu'),
        keras.layers.Dense(1, activation='sigmoid')
    ])
    
    model.compile(
        optimizer=keras.optimizers.Adam(learning_rate=0.001),
        loss='binary_crossentropy',
        metrics=['accuracy']
    )
    
    early_stop = keras.callbacks.EarlyStopping(
        monitor='val_loss', patience=10, restore_best_weights=True
    )
    
    history = model.fit(
        X_train, y_train,
        validation_data=(X_val, y_val),
        epochs=100,
        batch_size=32,
        callbacks=[early_stop],
        verbose=1
    )
    
    return model


def export_weights_to_c(model, output_path=None):
    """
    Export model weights to C header file
    """
    if output_path is None:
        # Get the script directory and construct absolute path
        script_dir = os.path.dirname(os.path.abspath(__file__))
        output_path = os.path.join(script_dir, '..', '..', 'contiki-ng', 'ids-node', 'tinyml_model_trained.h')
    
    # Ensure output directory exists
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    
    if HAS_TF and hasattr(model, 'layers'):
        # TensorFlow model
        W1 = model.layers[0].get_weights()[0]
        b1 = model.layers[0].get_weights()[1]
        W2 = model.layers[1].get_weights()[0]
        b2 = model.layers[1].get_weights()[1]
        W3 = model.layers[2].get_weights()[0]
        b3 = model.layers[2].get_weights()[1]
    else:
        # Numpy model
        W1 = model.W1
        b1 = model.b1
        W2 = model.W2
        b2 = model.b2
        W3 = model.W3
        b3 = model.b3
    
    with open(output_path, 'w') as f:
        f.write("/*\n")
        f.write(" * TinyML Model Weights - Auto-generated\n")
        f.write(f" * Generated: {datetime.now().isoformat()}\n")
        f.write(" */\n\n")
        f.write("#ifndef TINYML_MODEL_TRAINED_H_\n")
        f.write("#define TINYML_MODEL_TRAINED_H_\n\n")
        
        # Layer 1 weights
        f.write(f"#define L1_INPUT {W1.shape[0]}\n")
        f.write(f"#define L1_OUTPUT {W1.shape[1]}\n\n")
        
        f.write("static const float trained_layer1_weights[L1_INPUT][L1_OUTPUT] = {\n")
        for i in range(W1.shape[0]):
            f.write("  {" + ", ".join([f"{w:.6f}f" for w in W1[i]]) + "},\n")
        f.write("};\n\n")
        
        f.write("static const float trained_layer1_bias[L1_OUTPUT] = {\n")
        f.write("  " + ", ".join([f"{b:.6f}f" for b in b1]) + "\n")
        f.write("};\n\n")
        
        # Layer 2 weights
        f.write(f"#define L2_INPUT {W2.shape[0]}\n")
        f.write(f"#define L2_OUTPUT {W2.shape[1]}\n\n")
        
        f.write("static const float trained_layer2_weights[L2_INPUT][L2_OUTPUT] = {\n")
        for i in range(W2.shape[0]):
            f.write("  {" + ", ".join([f"{w:.6f}f" for w in W2[i]]) + "},\n")
        f.write("};\n\n")
        
        f.write("static const float trained_layer2_bias[L2_OUTPUT] = {\n")
        f.write("  " + ", ".join([f"{b:.6f}f" for b in b2]) + "\n")
        f.write("};\n\n")
        
        # Layer 3 weights
        f.write(f"#define L3_INPUT {W3.shape[0]}\n")
        f.write("#define L3_OUTPUT 1\n\n")
        
        f.write("static const float trained_layer3_weights[L3_INPUT] = {\n")
        f.write("  " + ", ".join([f"{w:.6f}f" for w in W3.flatten()]) + "\n")
        f.write("};\n\n")
        
        f.write(f"static const float trained_layer3_bias = {b3[0] if hasattr(b3, '__len__') else b3:.6f}f;\n\n")
        
        f.write("#endif /* TINYML_MODEL_TRAINED_H_ */\n")
    
    print(f"Weights exported to {output_path}")


def main():
    print("=" * 60)
    print("TinyML IDS Model Training")
    print("=" * 60)
    
    # Generate dataset
    print("\n[1] Generating synthetic CICIOT2023-like dataset...")
    X, y = generate_synthetic_dataset(num_samples=10000, attack_ratio=0.3)
    print(f"    Dataset shape: {X.shape}")
    print(f"    Normal samples: {np.sum(y == 0)}")
    print(f"    Attack samples: {np.sum(y == 1)}")
    
    # Normalize
    print("\n[2] Normalizing features...")
    X_norm, mins, maxs = normalize_data(X, save_stats=True)
    
    # Split data
    split_idx = int(0.8 * len(X))
    X_train, X_test = X_norm[:split_idx], X_norm[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    print(f"    Training samples: {len(X_train)}")
    print(f"    Test samples: {len(X_test)}")
    
    # Train model
    print("\n[3] Training TinyML model...")
    
    if HAS_TF:
        print("    Using TensorFlow/Keras...")
        model = train_keras_model(X_train, y_train, X_test, y_test)
        
        # Evaluate
        loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
        print(f"\n    Test Accuracy: {accuracy:.4f}")
    else:
        print("    Using numpy implementation...")
        model = TinyMLModel()
        model.train(X_train, y_train, epochs=100, batch_size=32, learning_rate=0.01)
        
        # Evaluate
        metrics = model.evaluate(X_test, y_test)
        print(f"\n    Test Results:")
        print(f"    - Accuracy:  {metrics['accuracy']:.4f}")
        print(f"    - Precision: {metrics['precision']:.4f}")
        print(f"    - Recall:    {metrics['recall']:.4f}")
        print(f"    - F1 Score:  {metrics['f1']:.4f}")
    
    # Export weights
    print("\n[4] Exporting weights to C header...")
    export_weights_to_c(model)
    
    # Save dataset for reference
    print("\n[5] Saving dataset...")
    script_dir = os.path.dirname(os.path.abspath(__file__))
    dataset_path = os.path.join(script_dir, '..', 'dataset', 'ids_dataset.npz')
    os.makedirs(os.path.dirname(dataset_path), exist_ok=True)
    np.savez(dataset_path, 
             X_train=X_train, y_train=y_train,
             X_test=X_test, y_test=y_test,
             feature_names=FEATURE_NAMES)
    
    print("\n" + "=" * 60)
    print("Training complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
