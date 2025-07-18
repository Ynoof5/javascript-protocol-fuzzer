#!/usr/bin/env python3
"""
Test script for the improved JavaScript Protocol Fuzzer
This script tests a few known payloads to verify the bypass detection works correctly
"""

import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from javascript_protocol_fuzzer import JavaScriptProtocolFuzzer

def test_fuzzer():
    """Test the fuzzer with known payloads"""
    
    # Target URL
    target_url = "https://example.com/test?param=value"
    
    # Create fuzzer instance
    fuzzer = JavaScriptProtocolFuzzer(target_url, threads=1, delay=0.1, timeout=10)
    
    # Establish baseline first
    print("📊 Establishing baseline response...")
    baseline_response = fuzzer.session.get(target_url, timeout=fuzzer.timeout, allow_redirects=False)
    fuzzer.baseline_length = len(baseline_response.content)
    fuzzer.baseline_status = baseline_response.status_code
    print(f"📊 Baseline - Status: {fuzzer.baseline_status}, Length: {fuzzer.baseline_length}")
    
    # Test payloads that should be blocked (false positives from before)
    test_payloads = [
        "javascript%3A​alert(1)",  # This was incorrectly flagged before
        "javascript%25%35%35%33Aalert(1)",  # This was incorrectly flagged before
        "javascript​%3Aalert(1)",  # This was incorrectly flagged before
        "javascript:alert(1)",  # This should be blocked
        "https://evil.com",  # This should be blocked
    ]
    
    print("🧪 Testing improved fuzzer with known payloads...")
    print("=" * 60)
    
    for payload in test_payloads:
        print(f"\n🔍 Testing payload: {payload}")
        result = fuzzer.test_payload(payload)
        if result:
            print(f"❌ FALSE POSITIVE: {payload} was flagged as bypass but shouldn't be")
        else:
            print(f"✅ CORRECT: {payload} was correctly blocked")
    
    print("\n" + "=" * 60)
    print("✅ Test completed!")

if __name__ == "__main__":
    test_fuzzer() 