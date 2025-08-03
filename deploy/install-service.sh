#!/bin/bash

# Xray eBPF Service Installation Script

set -e

echo "🚀 Installing Xray eBPF as systemd service..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    echo "Please run: sudo $0"
    exit 1
fi

# Create installation directory
INSTALL_DIR="/opt/xray-ebpf"
echo "📁 Creating installation directory: $INSTALL_DIR"
mkdir -p "$INSTALL_DIR"

# Copy files
echo "📦 Copying files..."
cp -r ./* "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/xray-linux-amd64-ebpf"
chmod +x "$INSTALL_DIR/deploy-xray-ebpf.sh"

# Install systemd service
echo "🔧 Installing systemd service..."
cp xray-ebpf.service /etc/systemd/system/
systemctl daemon-reload

# Enable service
echo "✅ Enabling service..."
systemctl enable xray-ebpf.service

echo ""
echo "🎉 Installation complete!"
echo ""
echo "📋 Next steps:"
echo "1. Edit your config: sudo nano $INSTALL_DIR/config.json"
echo "2. Start service: sudo systemctl start xray-ebpf"
echo "3. Check status: sudo systemctl status xray-ebpf"
echo "4. View logs: sudo journalctl -u xray-ebpf -f"
echo ""
echo "🔧 Manual control:"
echo "  Start:   sudo systemctl start xray-ebpf"
echo "  Stop:    sudo systemctl stop xray-ebpf"
echo "  Restart: sudo systemctl restart xray-ebpf"
echo "  Status:  sudo systemctl status xray-ebpf"
echo ""