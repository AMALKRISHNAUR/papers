#!/bin/bash
# Setup script for IoT IDS Testbed

set -e

echo "========================================"
echo "IoT IDS Testbed Setup Script"
echo "========================================"

# Check for required tools
echo ""
echo "[1] Checking requirements..."

check_command() {
    if command -v $1 &> /dev/null; then
        echo "    ✓ $1 found"
        return 0
    else
        echo "    ✗ $1 not found"
        return 1
    fi
}

MISSING=0
check_command python3 || MISSING=1
check_command pip3 || MISSING=1
check_command git || MISSING=1

# Check for Contiki-NG (optional)
if [ -d "../contiki-ng" ] || [ -d "../../contiki-ng" ]; then
    echo "    ✓ Contiki-NG found"
else
    echo "    ⚠ Contiki-NG not found (will need to be configured)"
fi

if [ $MISSING -eq 1 ]; then
    echo ""
    echo "Some requirements are missing. Please install them first."
    exit 1
fi

# Install Python dependencies
echo ""
echo "[2] Installing Python dependencies..."

pip3 install numpy --quiet || true
pip3 install tensorflow --quiet 2>/dev/null || echo "    Note: TensorFlow not installed (optional)"

# Create directory structure
echo ""
echo "[3] Creating directory structure..."

mkdir -p tinyml/dataset
mkdir -p tinyml/model
mkdir -p logs

# Generate synthetic dataset
echo ""
echo "[4] Generating synthetic training data..."

cd scripts
python3 data_collector.py --generate --output ../tinyml/dataset/synthetic_data.csv
cd ..

# Train the model
echo ""
echo "[5] Training TinyML model..."

cd tinyml/training
python3 train_model.py
cd ../..

# Check if weights were generated
if [ -f "contiki-ng/ids-node/tinyml_model_trained.h" ]; then
    echo "    ✓ Model weights exported to C header"
else
    echo "    ⚠ Model weights not generated"
fi

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "1. Configure Contiki-NG path in Makefiles"
echo "2. Build nodes: cd contiki-ng/<node-type> && make TARGET=cooja"
echo "3. Run simulation: cooja cooja/simulation.csc"
echo ""
echo "For more information, see README.md"
