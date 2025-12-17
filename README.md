# IoT Intrusion Detection System Testbed

## Overview
This project implements a complete IoT Intrusion Detection System (IDS) testbed using:
- **Contiki-NG**: Operating system for IoT devices (C-based)
- **Cooja Simulator**: Network simulation environment (C-based)
- **TinyML**: Lightweight machine learning for embedded devices (C deployment)
- **CICIOT2023-like features**: Network traffic features similar to the CICIOT2023 dataset

## ⚠️ Important: Proper Workflow

### Why NOT Python Simulation?
| Aspect | Python Simulation | Cooja + C |
|--------|------------------|-----------|
| Network Stack | Simplified | Real RPL, 6LoWPAN |
| Timing | Approximate | Cycle-accurate |
| Energy | Estimated | Energest (real) |
| Radio | None | UDGM, MRM models |
| Deployment | No | Same code runs on hardware |

### Data Collection: From Testbed, NOT Synthetic
❌ **Wrong**: `np.random.uniform()` - generates fake distributions  
✅ **Correct**: Collect real traffic from Cooja simulation or hardware

## Correct Workflow

### Step 1: Run Data Collection in Cooja
```bash
# Start Cooja
cd contiki-ng/tools/cooja && ./gradlew run
# Load: cooja/data_collection_simulation.csc
```

### Step 2: Collect Flow Data
```bash
# From Cooja log
python scripts/collect_data.py --cooja-log COOJA.testlog -o testbed_dataset.csv

# Or from serial (real hardware)
python scripts/collect_data.py --port /dev/ttyUSB0 -o testbed_dataset.csv
```

### Step 3: Train TinyML Model
```bash
python scripts/train_from_testbed.py \
    --input testbed_dataset.csv \
    --output contiki-ng/ids-node/tinyml_model_trained.h
```

### Step 4: Deploy and Evaluate
```bash
# Compile IDS with trained model
cd contiki-ng/ids-gateway && make TARGET=cooja
# Run evaluation simulation to measure metrics
```

## Project Structure
```
iot-ids-testbed/
├── contiki-ng/
│   ├── sensor-node/          # Normal IoT sensor nodes
│   ├── attacker-node/        # Nodes simulating attacks
│   ├── ids-node/             # IDS node with TinyML model
│   ├── ids-gateway/          # Gateway with metrics collection
│   ├── data-collector/       # Flow data collector
│   └── border-router/        # RPL border router
├── cooja/
│   ├── data_collection_simulation.csc  # For training data
│   ├── ids_evaluation_simulation.csc   # For metrics
│   └── scripts/
│       └── collect_simulation_data.js
├── scripts/
│   ├── collect_data.py       # Parse Cooja/serial output
│   └── train_from_testbed.py # Train from real data
└── README.md
```

## Performance Metrics

### Detection Metrics
- Accuracy, Precision, Recall, F1 Score
- True/False Positives/Negatives

### Latency Metrics
- Inference time (microseconds)
- Throughput (inferences/second)

### Network Metrics
- Packet Delivery Ratio (PDR)
- Packets dropped

### Energy Metrics
- CPU/LPM/TX/RX time
- Energy per inference (microjoules)

## Network Topology
```
                    [Border Router]
                         |
                    [IDS Node]
                    /    |    \
            [Sensor] [Sensor] [Sensor]
               |        |        |
          [Sensor]  [Attacker] [Attacker]
```

## CICIOT2023-like Features (24 features)
The testbed captures network features similar to CICIOT2023:
- Flow duration, packet counts (forward/backward)
- Packet lengths (min/max/mean)
- Inter-arrival times
- Flag counts (SYN, FIN, RST, PSH, ACK)
- Flow bytes/packets per second
- Download/upload ratio

## Attack Types Simulated
1. **DDoS UDP Flood**: High volume UDP packet flooding
2. **DDoS SYN Flood**: TCP SYN flooding (simulated over UDP)
3. **DoS Resource Exhaustion**: Large packets to exhaust memory
4. **Reconnaissance/Port Scanning**: Sequential port probing
5. **Spoofing**: Fake sensor data injection

## TinyML Model
- **Architecture**: 24 → 16 → 8 → 1 (sigmoid)
- **Parameters**: ~700 parameters
- **Size**: ~3KB (suitable for constrained devices)
- **Accuracy**: >99% on synthetic data

## Requirements
- Contiki-NG (latest version)
- Cooja Simulator (included with Contiki-NG)
- Python 3.8+
- NumPy
- ARM GCC Toolchain (for native builds)

## Installation

```bash
# Clone Contiki-NG (if not already installed)
git clone https://github.com/contiki-ng/contiki-ng.git
cd contiki-ng
git submodule update --init --recursive

# Install Python dependencies
pip install -r requirements.txt

# Run setup script
chmod +x setup.sh
./setup.sh
```

## Quick Start

### 1. Train the Model
```bash
cd tinyml/training
python train_model.py
```

This will:
- Generate synthetic CICIOT2023-like data (10,000 samples)
- Train a TinyML neural network
- Export weights to C header file

### 2. Test the Model
```bash
cd tinyml
python test_model.py
```

### 3. Build Contiki-NG Nodes
```bash
# Update CONTIKI path in Makefiles to your Contiki-NG installation
cd contiki-ng/sensor-node && make TARGET=cooja
cd ../attacker-node && make TARGET=cooja
cd ../ids-node && make TARGET=cooja
cd ../border-router && make TARGET=cooja
```

### 4. Run Cooja Simulation
```bash
# From Contiki-NG directory
cd tools/cooja
./gradlew run
# Open: cooja/simulation.csc
```

### 5. Collect Data from Simulation
```bash
# After running simulation
python scripts/data_collector.py --log cooja_output.log --output dataset.csv
```

## Customization

### Adding New Attack Types
Edit `contiki-ng/attacker-node/attacker-node.c`:
```c
#define ATTACK_NEW_TYPE  7

static void launch_new_attack(uip_ipaddr_t *target) {
    // Implement attack logic
}
```

### Modifying Model Architecture
Edit `tinyml/training/train_model.py`:
```python
HIDDEN_SIZE_1 = 16  # First hidden layer
HIDDEN_SIZE_2 = 8   # Second hidden layer
```

### Adjusting Detection Threshold
Edit `contiki-ng/ids-node/ids-node.c`:
```c
#define ANOMALY_THRESHOLD 0.7f  // 0.0-1.0
```

## Output Files

After training:
- `tinyml/dataset/ids_dataset.npz` - Training/test data
- `tinyml/dataset/normalization_stats.json` - Feature normalization parameters
- `contiki-ng/ids-node/tinyml_model_trained.h` - Trained weights in C format

## Performance Metrics

On synthetic data:
- Accuracy: ~100%
- Precision: ~100%
- Recall: ~100%
- F1-Score: ~100%

Note: Real-world performance will vary. Train on actual network data for production use.

## References

- [CICIOT2023 Dataset](https://www.unb.ca/cic/datasets/iotdataset-2023.html)
- [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
- [TinyML Foundation](https://www.tinyml.org/)
- [6LoWPAN](https://tools.ietf.org/html/rfc4944)

## License
MIT License
