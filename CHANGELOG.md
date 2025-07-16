# Changelog

## [0.0.5] - 20250714

### Added
- **Smart build triggers**: Workflow only runs for relevant code changes (ignores docs, markdown, etc.)
- **Parallel multi-architecture builds**: Builds for x86_64 and ARM64 in parallel using matrix jobs
- **Advanced caching**: Uses GitHub Actions and registry cache for persistent, faster builds
- **BuildKit cache mounts**: Dockerfile uses BuildKit cache mounts for pip, npm, and apk
- **QEMU emulation support**: Enables cross-platform builds using QEMU for ARM64 emulation on x86_64 runners

### Changed
- **Python version**: Upgraded to Python 3.12.11 for all builds
- **Dockerfile optimization**: Combined RUN commands, optimized tool installation, and leveraged multi-stage builds for better cache utilization
- **Conditional multi-arch builds**: Only builds both architectures on main/release, single-arch for feature branches
- **Manifest creation**: Multi-arch manifest is created and pushed for main/release
- **Build performance**: Dramatically reduced build times for most scenarios

## [0.0.4] - 20250702

### Fixed
- **Grype findings now properly documented in HTML reports**: Fixed issue where Grype vulnerability findings were not being extracted and displayed in HTML reports

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
