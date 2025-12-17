#!/usr/bin/env python3
"""
TinyML Model Training from Real Testbed Data
Trains neural network from collected CICIOT2023-like data
Exports to C header for Contiki-NG deployment
"""

import numpy as np
import csv
import os
import sys
import argparse
from datetime import datetime

# Feature names
FEATURE_NAMES = [
    'flow_duration', 'fwd_pkts', 'bwd_pkts', 'fwd_bytes', 'bwd_bytes',
    'fwd_pkt_len_mean', 'bwd_pkt_len_mean', 'flow_bytes_s', 'flow_pkts_s',
    'fwd_iat_mean', 'fwd_iat_min', 'fwd_iat_max',
    'pkt_len_min', 'pkt_len_max', 'pkt_len_mean',
    'syn', 'fin', 'rst', 'psh', 'ack',
    'down_up_ratio', 'pkt_count', 'byte_count', 'high_rate_flag'
]

NUM_FEATURES = 24
HIDDEN1_SIZE = 16
HIDDEN2_SIZE = 8
OUTPUT_SIZE = 1


class TinyMLTrainer:
    def __init__(self, learning_rate=0.01, epochs=200, batch_size=32):
        self.lr = learning_rate
        self.epochs = epochs
        self.batch_size = batch_size
        
        # Network weights
        self.W1 = None
        self.b1 = None
        self.W2 = None
        self.b2 = None
        self.W3 = None
        self.b3 = None
        
        # Normalization parameters
        self.mean = None
        self.std = None
        
        # Training history
        self.loss_history = []
        self.accuracy_history = []
    
    def initialize_weights(self):
        """Initialize network weights using He initialization"""
        np.random.seed(42)
        self.W1 = np.random.randn(NUM_FEATURES, HIDDEN1_SIZE) * np.sqrt(2.0 / NUM_FEATURES)
        self.b1 = np.zeros(HIDDEN1_SIZE)
        self.W2 = np.random.randn(HIDDEN1_SIZE, HIDDEN2_SIZE) * np.sqrt(2.0 / HIDDEN1_SIZE)
        self.b2 = np.zeros(HIDDEN2_SIZE)
        self.W3 = np.random.randn(HIDDEN2_SIZE, OUTPUT_SIZE) * np.sqrt(2.0 / HIDDEN2_SIZE)
        self.b3 = np.zeros(OUTPUT_SIZE)
    
    def relu(self, x):
        return np.maximum(0, x)
    
    def relu_derivative(self, x):
        return (x > 0).astype(float)
    
    def sigmoid(self, x):
        x = np.clip(x, -500, 500)
        return 1 / (1 + np.exp(-x))
    
    def normalize_data(self, X, fit=False):
        """Normalize features using z-score normalization"""
        if fit:
            self.mean = np.mean(X, axis=0)
            self.std = np.std(X, axis=0) + 1e-8
        return (X - self.mean) / self.std
    
    def forward(self, X):
        """Forward pass through network"""
        self.z1 = X @ self.W1 + self.b1
        self.a1 = self.relu(self.z1)
        
        self.z2 = self.a1 @ self.W2 + self.b2
        self.a2 = self.relu(self.z2)
        
        self.z3 = self.a2 @ self.W3 + self.b3
        self.a3 = self.sigmoid(self.z3)
        
        return self.a3
    
    def backward(self, X, y):
        """Backward pass - compute gradients"""
        m = X.shape[0]
        
        # Output layer
        dz3 = self.a3 - y.reshape(-1, 1)
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
        
        return dW1, db1, dW2, db2, dW3, db3
    
    def update_weights(self, gradients):
        """Update weights using gradient descent"""
        dW1, db1, dW2, db2, dW3, db3 = gradients
        
        self.W1 -= self.lr * dW1
        self.b1 -= self.lr * db1
        self.W2 -= self.lr * dW2
        self.b2 -= self.lr * db2
        self.W3 -= self.lr * dW3
        self.b3 -= self.lr * db3
    
    def compute_loss(self, y_pred, y_true):
        """Binary cross-entropy loss"""
        y_pred = np.clip(y_pred, 1e-7, 1 - 1e-7)
        return -np.mean(y_true * np.log(y_pred) + (1 - y_true) * np.log(1 - y_pred))
    
    def train(self, X_train, y_train, X_val=None, y_val=None):
        """Train the model"""
        print(f"Training TinyML model...")
        print(f"  Architecture: {NUM_FEATURES} -> {HIDDEN1_SIZE} -> {HIDDEN2_SIZE} -> {OUTPUT_SIZE}")
        print(f"  Training samples: {len(X_train)}")
        print(f"  Learning rate: {self.lr}")
        print(f"  Epochs: {self.epochs}")
        print(f"  Batch size: {self.batch_size}")
        print()
        
        self.initialize_weights()
        
        # Normalize training data
        X_train_norm = self.normalize_data(X_train, fit=True)
        if X_val is not None:
            X_val_norm = self.normalize_data(X_val)
        
        n_samples = X_train_norm.shape[0]
        n_batches = max(1, n_samples // self.batch_size)
        
        for epoch in range(self.epochs):
            # Shuffle data
            indices = np.random.permutation(n_samples)
            X_shuffled = X_train_norm[indices]
            y_shuffled = y_train[indices]
            
            epoch_loss = 0
            
            for batch in range(n_batches):
                start = batch * self.batch_size
                end = min(start + self.batch_size, n_samples)
                
                X_batch = X_shuffled[start:end]
                y_batch = y_shuffled[start:end]
                
                # Forward pass
                y_pred = self.forward(X_batch)
                
                # Compute loss
                loss = self.compute_loss(y_pred, y_batch)
                epoch_loss += loss
                
                # Backward pass
                gradients = self.backward(X_batch, y_batch)
                
                # Update weights
                self.update_weights(gradients)
            
            avg_loss = epoch_loss / n_batches
            self.loss_history.append(avg_loss)
            
            # Compute training accuracy
            train_pred = self.forward(X_train_norm)
            train_acc = np.mean((train_pred > 0.5) == y_train.reshape(-1, 1))
            self.accuracy_history.append(train_acc)
            
            if (epoch + 1) % 20 == 0 or epoch == 0:
                val_str = ""
                if X_val is not None:
                    val_pred = self.forward(X_val_norm)
                    val_acc = np.mean((val_pred > 0.5) == y_val.reshape(-1, 1))
                    val_str = f", Val Acc: {val_acc:.4f}"
                
                print(f"  Epoch {epoch+1:3d}/{self.epochs}: Loss={avg_loss:.4f}, "
                      f"Train Acc={train_acc:.4f}{val_str}")
        
        print("\nTraining complete!")
    
    def evaluate(self, X_test, y_test):
        """Evaluate model on test set"""
        X_test_norm = self.normalize_data(X_test)
        y_pred = self.forward(X_test_norm)
        y_pred_label = (y_pred > 0.5).astype(int).flatten()
        
        tp = np.sum((y_pred_label == 1) & (y_test == 1))
        fp = np.sum((y_pred_label == 1) & (y_test == 0))
        tn = np.sum((y_pred_label == 0) & (y_test == 0))
        fn = np.sum((y_pred_label == 0) & (y_test == 1))
        
        accuracy = (tp + tn) / len(y_test)
        precision = tp / max(tp + fp, 1)
        recall = tp / max(tp + fn, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        
        print("\nTest Results:")
        print(f"  Accuracy:  {accuracy:.4f}")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1 Score:  {f1:.4f}")
        print(f"  TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
        
        return accuracy, precision, recall, f1
    
    def export_to_c_header(self, output_path):
        """Export trained model to C header file for Contiki-NG"""
        
        # Calculate model size
        total_params = (NUM_FEATURES * HIDDEN1_SIZE + HIDDEN1_SIZE +
                       HIDDEN1_SIZE * HIDDEN2_SIZE + HIDDEN2_SIZE +
                       HIDDEN2_SIZE * OUTPUT_SIZE + OUTPUT_SIZE)
        model_size_bytes = total_params * 4  # float32
        
        with open(output_path, 'w') as f:
            f.write("/*\n")
            f.write(" * TinyML IDS Model - Trained from Real Testbed Data\n")
            f.write(f" * Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f" * Architecture: {NUM_FEATURES} -> {HIDDEN1_SIZE} -> {HIDDEN2_SIZE} -> {OUTPUT_SIZE}\n")
            f.write(f" * Total parameters: {total_params}\n")
            f.write(f" * Model size: {model_size_bytes} bytes ({model_size_bytes/1024:.2f} KB)\n")
            f.write(" */\n\n")
            f.write("#ifndef TINYML_MODEL_TRAINED_H\n")
            f.write("#define TINYML_MODEL_TRAINED_H\n\n")
            f.write("#include <stdint.h>\n\n")
            
            # Network dimensions
            f.write(f"#define NUM_FEATURES {NUM_FEATURES}\n")
            f.write(f"#define HIDDEN1_SIZE {HIDDEN1_SIZE}\n")
            f.write(f"#define HIDDEN2_SIZE {HIDDEN2_SIZE}\n")
            f.write(f"#define OUTPUT_SIZE {OUTPUT_SIZE}\n\n")
            
            # Normalization parameters
            f.write("/* Feature normalization parameters */\n")
            f.write("static const float feature_mean[NUM_FEATURES] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.mean]))
            f.write("\n};\n\n")
            
            f.write("static const float feature_std[NUM_FEATURES] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.std]))
            f.write("\n};\n\n")
            
            # Layer 1 weights
            f.write("/* Layer 1: Input -> Hidden1 */\n")
            f.write(f"static const float W1[NUM_FEATURES][HIDDEN1_SIZE] = {{\n")
            for i in range(NUM_FEATURES):
                f.write("  {" + ", ".join([f"{x:.6f}f" for x in self.W1[i]]) + "}")
                f.write(",\n" if i < NUM_FEATURES - 1 else "\n")
            f.write("};\n\n")
            
            f.write("static const float W1_bias[HIDDEN1_SIZE] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.b1]))
            f.write("\n};\n\n")
            
            # Layer 2 weights
            f.write("/* Layer 2: Hidden1 -> Hidden2 */\n")
            f.write(f"static const float W2[HIDDEN1_SIZE][HIDDEN2_SIZE] = {{\n")
            for i in range(HIDDEN1_SIZE):
                f.write("  {" + ", ".join([f"{x:.6f}f" for x in self.W2[i]]) + "}")
                f.write(",\n" if i < HIDDEN1_SIZE - 1 else "\n")
            f.write("};\n\n")
            
            f.write("static const float W2_bias[HIDDEN2_SIZE] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.b2]))
            f.write("\n};\n\n")
            
            # Layer 3 weights
            f.write("/* Layer 3: Hidden2 -> Output */\n")
            f.write("static const float W3[HIDDEN2_SIZE] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.W3.flatten()]))
            f.write("\n};\n\n")
            
            f.write("static const float W3_bias[OUTPUT_SIZE] = {\n  ")
            f.write(", ".join([f"{x:.6f}f" for x in self.b3]))
            f.write("\n};\n\n")
            
            f.write("#endif /* TINYML_MODEL_TRAINED_H */\n")
        
        print(f"\nExported model to {output_path}")
        print(f"  Model size: {model_size_bytes} bytes ({model_size_bytes/1024:.2f} KB)")


def load_dataset(csv_path):
    """Load dataset from CSV file"""
    print(f"Loading dataset from {csv_path}...")
    
    data = []
    labels = []
    
    with open(csv_path, 'r') as f:
        reader = csv.reader(f)
        header = next(reader)  # Skip header
        
        for row in reader:
            if len(row) == 25:  # 24 features + 1 label
                try:
                    features = [float(x) for x in row[:-1]]
                    label = int(float(row[-1]))
                    data.append(features)
                    labels.append(label)
                except ValueError:
                    continue
    
    X = np.array(data, dtype=np.float32)
    y = np.array(labels, dtype=np.float32)
    
    print(f"  Loaded {len(X)} samples")
    print(f"  Normal: {np.sum(y == 0)}, Attack: {np.sum(y == 1)}")
    
    return X, y


def main():
    parser = argparse.ArgumentParser(description='Train TinyML model from testbed data')
    parser.add_argument('--input', '-i', required=True, help='Input CSV dataset')
    parser.add_argument('--output', '-o', default='tinyml_model_trained.h', 
                       help='Output C header file')
    parser.add_argument('--epochs', '-e', type=int, default=200, help='Training epochs')
    parser.add_argument('--lr', type=float, default=0.01, help='Learning rate')
    parser.add_argument('--batch-size', '-b', type=int, default=32, help='Batch size')
    parser.add_argument('--test-split', type=float, default=0.2, help='Test split ratio')
    
    args = parser.parse_args()
    
    # Load dataset
    X, y = load_dataset(args.input)
    
    if len(X) < 100:
        print("Warning: Dataset too small for reliable training")
    
    # Split data
    n_test = int(len(X) * args.test_split)
    indices = np.random.permutation(len(X))
    
    X_train = X[indices[n_test:]]
    y_train = y[indices[n_test:]]
    X_test = X[indices[:n_test]]
    y_test = y[indices[:n_test]]
    
    print(f"\nDataset split:")
    print(f"  Training: {len(X_train)} samples")
    print(f"  Testing:  {len(X_test)} samples")
    
    # Train model
    trainer = TinyMLTrainer(learning_rate=args.lr, epochs=args.epochs, 
                           batch_size=args.batch_size)
    trainer.train(X_train, y_train)
    
    # Evaluate
    trainer.evaluate(X_test, y_test)
    
    # Export
    trainer.export_to_c_header(args.output)


if __name__ == '__main__':
    main()
