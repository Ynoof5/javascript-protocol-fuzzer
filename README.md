# 🚀 JavaScript Protocol Fuzzer

A comprehensive security testing tool designed to test bypass techniques for `javascript:` protocol filtering in web applications. This tool helps security researchers and penetration testers identify potential vulnerabilities in URL validation and filtering mechanisms.

## 📋 Features

- **Advanced Bypass Techniques**: Tests hundreds of different bypass methods including:
  - Unicode normalization bypasses
  - URL encoding variations
  - Case variations
  - Null byte injection
  - Protocol confusion techniques
  - Recollapse-style payloads
  - Expert/creative bypass methods

- **Multi-threaded Testing**: Configurable threading for efficient testing
- **Comprehensive Detection**: Advanced detection algorithms to identify real bypasses vs false positives
- **Parameter Testing**: Tests multiple parameter names automatically
- **Detailed Reporting**: Generates detailed reports with bypass details
- **Easy to Use**: Simple command-line interface with configurable options

## 🛠️ Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/javascript-protocol-fuzzer.git
   cd javascript-protocol-fuzzer
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## 🚀 Usage

### Basic Usage

```bash
python3 javascript_protocol_fuzzer.py "https://target-url.com/page?param=value"
```

### Advanced Usage

```bash
# With custom threading and delay
python3 javascript_protocol_fuzzer.py "https://target-url.com/page" --threads 20 --delay 0.05

# With custom timeout
python3 javascript_protocol_fuzzer.py "https://target-url.com/page" --timeout 15

# Using the shell script
./run_fuzzer.sh
```

### Parameters

- `target_url`: The URL to test (required)
- `--threads`: Number of concurrent threads (default: 10)
- `--delay`: Delay between requests in seconds (default: 0.1)
- `--timeout`: Request timeout in seconds (default: 10)

## 📁 Project Structure

```
javascript-protocol-fuzzer/
├── javascript_protocol_fuzzer.py    # Main fuzzer tool
├── test_fuzzer.py                   # Test script for validation
├── bypass_verifier.py               # Bypass verification tool
├── run_fuzzer.sh                    # Shell script for easy execution
├── requirements.txt                 # Python dependencies
├── LICENSE                          # License file
├── README.md                        # This file
└── .gitignore                       # Git ignore file
```

## 🔧 Bypass Techniques Tested

### Basic Techniques
- Standard `javascript:` protocol
- Case variations (`JaVaScRiPt:`)
- URL encoding (`javascript%3A`)

### Advanced Techniques
- Unicode normalization bypasses
- Null byte injection
- Control character injection
- Mathematical Unicode characters
- Protocol confusion
- Fragment and query tricks
- Recollapse-style payloads

### Expert Techniques
- Mixed encoding layers
- Exotic Unicode and homoglyphs
- Protocol smuggling
- Server-side bypass tricks
- Parameter pollution

## 📊 Output

The tool provides:
- Real-time progress updates
- Detailed bypass information
- JSON results file
- Status codes and response analysis
- Redirect location tracking

## ⚠️ Legal and Ethical Use

This tool is designed for:
- **Security Research**: Testing your own applications
- **Penetration Testing**: Authorized security assessments
- **Educational Purposes**: Learning about web security

**⚠️ Important**: Only use this tool on systems you own or have explicit permission to test. Unauthorized testing may be illegal.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by various security research and bypass techniques
- Built with security testing best practices in mind
- Designed for educational and authorized security research

## 📞 Support

If you encounter any issues or have questions, please open an issue on GitHub.

---

**Remember**: Always use security tools responsibly and ethically! 