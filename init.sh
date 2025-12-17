#!/bin/bash
#
# IoT IDS Testbed - Initialization Script
# Installs all required packages and dependencies
#

set -e

echo "========================================"
echo "IoT IDS Testbed - Initialization"
echo "========================================"
echo ""

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    OS=$(uname -s)
    VER=$(uname -r)
fi

echo "Detected OS: $OS $VER"
echo ""

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to install packages based on OS
install_packages() {
    echo "[1/5] Installing system packages..."
    
    if command_exists apt-get; then
        # Debian/Ubuntu
        sudo apt-get update
        sudo apt-get install -y \
            build-essential \
            gcc-arm-none-eabi \
            git \
            python3 \
            python3-pip \
            python3-venv \
            openjdk-11-jdk \
            ant \
            curl \
            wget \
            unzip
    elif command_exists yum; then
        # RHEL/CentOS
        sudo yum install -y \
            gcc \
            gcc-c++ \
            make \
            git \
            python3 \
            python3-pip \
            java-11-openjdk \
            ant \
            curl \
            wget \
            unzip
    elif command_exists pacman; then
        # Arch Linux
        sudo pacman -Sy --noconfirm \
            base-devel \
            arm-none-eabi-gcc \
            git \
            python \
            python-pip \
            jdk11-openjdk \
            ant \
            curl \
            wget \
            unzip
    elif command_exists brew; then
        # macOS
        brew install \
            git \
            python3 \
            openjdk@11 \
            ant \
            curl \
            wget
        # ARM toolchain for macOS
        brew install --cask gcc-arm-embedded
    else
        echo "Warning: Package manager not recognized. Please install dependencies manually."
    fi
}

# Install Python dependencies
install_python_deps() {
    echo ""
    echo "[2/5] Installing Python dependencies..."
    
    # Create virtual environment (optional)
    if [ ! -d "venv" ]; then
        python3 -m venv venv 2>/dev/null || true
    fi
    
    # Install packages
    pip3 install --upgrade pip
    pip3 install numpy
    pip3 install tensorflow 2>/dev/null || echo "Note: TensorFlow not installed (optional)"
    pip3 install scikit-learn 2>/dev/null || true
    pip3 install matplotlib 2>/dev/null || true
    pip3 install pandas 2>/dev/null || true
}

# Clone and setup Contiki-NG
setup_contiki() {
    echo ""
    echo "[3/5] Setting up Contiki-NG..."
    
    CONTIKI_PATH="../contiki-ng"
    
    if [ -d "$CONTIKI_PATH" ]; then
        echo "Contiki-NG already exists at $CONTIKI_PATH"
    else
        echo "Cloning Contiki-NG..."
        git clone --recursive https://github.com/contiki-ng/contiki-ng.git "$CONTIKI_PATH"
    fi
    
    # Update Makefiles with correct path
    CONTIKI_ABS_PATH=$(cd "$CONTIKI_PATH" && pwd)
    
    echo "Updating Makefiles with Contiki-NG path: $CONTIKI_ABS_PATH"
    
    for makefile in contiki-ng/*/Makefile; do
        if [ -f "$makefile" ]; then
            sed -i "s|CONTIKI = .*|CONTIKI = $CONTIKI_ABS_PATH|g" "$makefile" 2>/dev/null || \
            sed -i '' "s|CONTIKI = .*|CONTIKI = $CONTIKI_ABS_PATH|g" "$makefile" 2>/dev/null || true
        fi
    done
}

# Train the TinyML model
train_model() {
    echo ""
    echo "[4/5] Training TinyML model..."
    
    cd tinyml/training
    python3 train_model.py
    cd ../..
}

# Verify installation
verify_installation() {
    echo ""
    echo "[5/5] Verifying installation..."
    
    echo ""
    echo "Checking components:"
    
    # Python
    if command_exists python3; then
        echo "  ✓ Python3: $(python3 --version)"
    else
        echo "  ✗ Python3 not found"
    fi
    
    # NumPy
    if python3 -c "import numpy" 2>/dev/null; then
        echo "  ✓ NumPy installed"
    else
        echo "  ✗ NumPy not found"
    fi
    
    # TensorFlow (optional)
    if python3 -c "import tensorflow" 2>/dev/null; then
        echo "  ✓ TensorFlow installed"
    else
        echo "  ○ TensorFlow not installed (optional)"
    fi
    
    # Git
    if command_exists git; then
        echo "  ✓ Git: $(git --version | cut -d' ' -f3)"
    else
        echo "  ✗ Git not found"
    fi
    
    # Java
    if command_exists java; then
        echo "  ✓ Java: $(java -version 2>&1 | head -1)"
    else
        echo "  ✗ Java not found (needed for Cooja)"
    fi
    
    # Contiki-NG
    if [ -d "../contiki-ng" ]; then
        echo "  ✓ Contiki-NG found"
    else
        echo "  ✗ Contiki-NG not found"
    fi
    
    # Trained model
    if [ -f "contiki-ng/ids-node/tinyml_model_trained.h" ]; then
        echo "  ✓ TinyML model trained"
    else
        echo "  ✗ TinyML model not trained"
    fi
}

# Main execution
main() {
    cd "$(dirname "$0")"
    
    # Parse arguments
    SKIP_PACKAGES=false
    SKIP_CONTIKI=false
    SKIP_TRAINING=false
    
    for arg in "$@"; do
        case $arg in
            --skip-packages)
                SKIP_PACKAGES=true
                ;;
            --skip-contiki)
                SKIP_CONTIKI=true
                ;;
            --skip-training)
                SKIP_TRAINING=true
                ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --skip-packages    Skip system package installation"
                echo "  --skip-contiki     Skip Contiki-NG setup"
                echo "  --skip-training    Skip model training"
                echo "  --help, -h         Show this help"
                exit 0
                ;;
        esac
    done
    
    # Run installation steps
    if [ "$SKIP_PACKAGES" = false ]; then
        install_packages
    fi
    
    install_python_deps
    
    if [ "$SKIP_CONTIKI" = false ]; then
        setup_contiki
    fi
    
    if [ "$SKIP_TRAINING" = false ]; then
        train_model
    fi
    
    verify_installation
    
    echo ""
    echo "========================================"
    echo "Installation Complete!"
    echo "========================================"
    echo ""
    echo "Next steps:"
    echo "  1. Build nodes: cd contiki-ng/<node> && make TARGET=cooja"
    echo "  2. Run Cooja: Open cooja/simulation.csc"
    echo ""
    echo "For help: ./init.sh --help"
}

main "$@"
