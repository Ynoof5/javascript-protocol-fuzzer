#!/bin/bash

# JavaScript Protocol Fuzzer Runner
# This script runs the fuzzer against a target URL

echo "🚀 Starting JavaScript Protocol Fuzzer"
echo "======================================"

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Error: Python 3 is required but not installed"
    exit 1
fi

# Check if requirements are installed
echo "📦 Checking dependencies..."
python3 -c "import requests, colorama" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "📦 Installing dependencies..."
    pip3 install -r requirements.txt
fi

# Check if target URL is provided
if [ -z "$1" ]; then
    echo "❌ Error: Please provide a target URL"
    echo "Usage: ./run_fuzzer.sh <target_url> [domain]"
    echo "Example: ./run_fuzzer.sh https://example.com/page example.com"
    exit 1
fi

# Target URL
TARGET_URL="$1"
DOMAIN="$2"

echo "🎯 Target: $TARGET_URL"
if [ -n "$DOMAIN" ]; then
    echo "🌐 Domain: $DOMAIN"
fi
echo "⚙️  Configuration: 10 threads, 0.1s delay, 10s timeout"
echo ""

# Run the fuzzer
if [ -n "$DOMAIN" ]; then
    python3 javascript_protocol_fuzzer.py "$TARGET_URL" --domain "$DOMAIN" --threads 10 --delay 0.1 --timeout 10
else
    python3 javascript_protocol_fuzzer.py "$TARGET_URL" --threads 10 --delay 0.1 --timeout 10
fi

echo ""
echo "✅ Fuzzing completed!"
echo "📁 Check the generated JSON file for detailed results" 