# DevScrub 🔒

**Advanced Security Scanner with Semantic Code Analysis**

A comprehensive security scanning tool that combines traditional pattern matching with semantic analysis to detect vulnerabilities, secrets, and security issues across multiple programming languages and frameworks.

## 🚀 Installation

### Docker (Recommended)
```bash
# Build the Alpine-based image
./scripts/build.sh
```

### Native Installation
```bash
# Install Python dependencies
pip install -r requirements.txt

# Install additional tools (optional)
npm install -g yarn
```

## 📖 Usage

### Docker (Recommended)
```bash
# Scan current directory
./scripts/scan.sh

# Scan specific project
./scripts/scan.sh /path/to/project

# Custom output format
./scripts/scan.sh /path/to/project ./reports json
./scripts/scan.sh /path/to/project ./reports html
./scripts/scan.sh /path/to/project ./reports all

# Direct Docker usage
docker run --rm -v /path/to/project:/scan:ro -v $(pwd)/reports:/reports devscrub-scanner
```

### Native Usage
```bash
# Scan current directory
python3 -m src.security_scanner

# Scan specific project
python3 -m src.security_scanner /path/to/project

# Custom format
python3 -m src.security_scanner . --format json
python3 -m src.security_scanner . --format html
python3 -m src.security_scanner . --format all

# Filter by severity
python3 -m src.security_scanner . --severity high

# Skip linting scans
python3 -m src.security_scanner . --no-linting
```

## 🛠️ What It Scans

### Security Tools
- **Secret Detection**: TruffleHog, DeepSecrets, manual pattern matching
- **Vulnerability Scanning**: Grype, Bandit, pip-audit, Semgrep
- **SBOM Generation**: Syft for dependency inventory
- **Code Quality**: Ruff, Pylint, npm audit, yarn audit, ESLint
- **Container Security**: Trivy, Hadolint for Docker scanning
- **Shell Security**: ShellCheck for shell script analysis

### Supported Languages & Technologies
- **Python**: Bandit (security), pip-audit (dependencies), Semgrep (SAST), Ruff (linting), Pylint (code quality)
- **JavaScript/TypeScript**: npm audit, yarn audit, ESLint (linting)
- **Docker**: Hadolint (Dockerfile linting), Trivy (container scanning)
- **Shell Scripts**: ShellCheck (shell script analysis)
- **General**: Semgrep (multi-language SAST), TruffleHog (secrets), DeepSecrets (semantic analysis)

## 📊 Report Formats

- **JSON**: Machine-readable detailed report with complete scan results
- **HTML**: Interactive dashboard with filtering, documentation links (including Ruff, Pylint, Bandit, etc.), and CVE/CWE links
- **All**: Generates both JSON and HTML formats


## 🔧 Configuration

No configuration file needed. The scanner automatically detects project types and runs appropriate tools. Use command-line arguments to customize behavior.

## 🤝 Development

### Setup
```bash
# Clone the repository
git clone https://github.com/zaydons/DevScrub.git
cd DevScrub

# Install dependencies
pip install -r requirements.txt

# Make scripts executable
chmod +x scripts/*.sh
```

### Contributing
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Project Structure
```
DevScrub/
├── src/                    # Source code
│   ├── security_scanner.py # Main scanner logic
│   ├── html_report.py      # HTML report generator
│   └── scanners/           # Scanner modules
│       ├── base_scanner.py      # Base scanner class
│       ├── python_scanner.py    # Python security scanning
│       ├── javascript_scanner.py # JavaScript/TypeScript scanning
│       ├── docker_scanner.py    # Docker/container scanning
│       ├── shell_scanner.py     # Shell script scanning
│       ├── secrets_scanner.py   # Secret detection
│       ├── sbom_scanner.py      # SBOM generation
│       └── vulnerability_scanner.py # Vulnerability scanning
├── scripts/               # Build and utility scripts
│   ├── build.sh          # Docker image build
│   ├── scan.sh           # Main scan script
│   ├── install.sh        # Installation script
│   └── entrypoint.sh     # Docker entrypoint
├── .github/workflows/    # CI/CD pipelines
│   └── docker-build-tag-push.yml # Docker build workflow
├── security-reports/     # Generated security reports
├── Dockerfile            # Docker container definition
├── docker-compose.yml    # Docker Compose configuration
├── requirements.txt      # Python dependencies
├── VERSION              # Version file
├── CHANGELOG.md         # Change log
└── README.md            # This file
```

## 📄 License

MIT License - see [LICENSE](LICENSE) for details.

---

**DevScrub** - Scrubbing your code for security issues since 2025 🔒