# IoT Intrusion Detection System Testbed

## Overview
This project implements a complete IoT Intrusion Detection System (IDS) testbed using:
- **Contiki-NG**: Operating system for IoT devices
- **Cooja Simulator**: Network simulation environment
- **TinyML**: Lightweight machine learning for embedded devices
- **CICIOT2023-like features**: Network traffic features similar to the CICIOT2023 dataset

## Project Structure
```
iot-ids-testbed/
├── contiki-ng/
│   ├── sensor-node/          # Normal IoT sensor nodes
│   ├── attacker-node/        # Nodes simulating attacks
│   ├── ids-node/             # IDS node with TinyML model
│   └── border-router/        # RPL border router
├── cooja/
│   └── simulation.csc        # Cooja simulation configuration
├── tinyml/
│   ├── dataset/              # Generated dataset
│   ├── training/             # Model training scripts
│   └── test_model.py         # Model testing script
├── scripts/
│   └── data_collector.py     # Collect and process traffic data
└── docs/
    └── features.md           # Feature documentation
```

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
