# Changelog

## [0.0.3] - 20250701

### Added
- Multi-language security scanner supporting Python, JavaScript/TypeScript, Docker, and shell scripts
- Comprehensive security tools integration including Bandit, pip-audit, Semgrep, Ruff, Pylint, npm audit, yarn audit, ESLint, Hadolint, Trivy, ShellCheck, TruffleHog, DeepSecrets, Syft, and Grype
- Advanced secret detection with TruffleHog, DeepSecrets, and manual pattern matching
- Vulnerability scanning with Grype and SBOM generation with Syft
- Interactive HTML reports with filtering, documentation links, CVE/CWE references, and responsive design
- Modular scanner architecture for easy extension and maintenance
- Complete Docker containerization with Alpine Linux base
- Flexible command-line interface with format options and severity filtering
- Automatic project type detection and appropriate tool selection
- Comprehensive file filtering with intelligent directory and binary file skipping
- Robust error handling and graceful tool failure management
- JSON output standardization across all tools
- Security-first design with command injection prevention
- Performance optimization with efficient file scanning
- Cross-platform support via Docker
- GitHub Actions CI/CD pipeline for automated builds and releases
- Comprehensive documentation with usage examples and project structure
- Build, scan, and installation scripts for easy deployment
