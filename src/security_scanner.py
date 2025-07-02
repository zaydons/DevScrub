#!/usr/bin/env python3
"""
DevScrub Security Scanner
Advanced security scanning with modular architecture
"""

# pylint: disable=R0902,R0903,R0913

import os
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

# Import modular scanners
from .scanners import (
    PythonScanner,
    JavaScriptScanner,
    DockerScanner,
    ShellScanner,
    SecretsScanner,
    SBOMScanner,
    VulnerabilityScanner
)

# Import report generators
from .html_report import generate_html_report


@dataclass
class ScannerConfig:
    """Configuration for scanner components"""
    target_dir: Path
    output_dir: Path
    timestamp: str
    python_scanner: PythonScanner
    js_scanner: JavaScriptScanner
    docker_scanner: DockerScanner
    shell_scanner: ShellScanner
    secrets_scanner: SecretsScanner
    sbom_scanner: SBOMScanner
    vuln_scanner: VulnerabilityScanner


class SecurityScanner:  # pylint: disable=R0902,R0903
    """Optimized security scanner with modular architecture"""

    def __init__(self, target_dir: str, output_dir: str = "security-reports"):  # pylint: disable=R0913
        self.target_dir = Path(target_dir).resolve()
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.results = {}

        # Create output directory
        self.output_dir.mkdir(exist_ok=True)

        # Initialize scanners
        self.python_scanner = PythonScanner(self.target_dir)
        self.js_scanner = JavaScriptScanner(self.target_dir)
        self.docker_scanner = DockerScanner(self.target_dir)
        self.shell_scanner = ShellScanner(self.target_dir)
        self.secrets_scanner = SecretsScanner(self.target_dir)
        self.sbom_scanner = SBOMScanner(self.target_dir)
        self.vuln_scanner = VulnerabilityScanner(self.target_dir)

    def detect_project_types(self) -> Dict[str, List[Path]]:
        """Detect different project types in the target directory"""
        project_types = {
            'python': [],
            'javascript': [],
            'typescript': [],
            'docker': [],
            'general': []
        }

        # Walk through directory tree
        for root, dirs, files in os.walk(self.target_dir):
            root_path = Path(root)

            # Skip common ignore directories
            dirs[:] = [d for d in dirs if d not in {'.git', 'node_modules', '__pycache__', '.venv', 'venv', 'dist', 'build'}]  # pylint: disable=C0301

            for file in files:
                self._classify_file(file, root_path, files, project_types)

        return project_types

    def _classify_file(self, file: str, root_path: Path, files: List[str], project_types: Dict[str, List[Path]]) -> None:  # pylint: disable=C0301
        """Classify a file into project types"""
        # Python detection
        if self._is_python_file(file):
            if root_path not in project_types['python']:
                project_types['python'].append(root_path)

        # JavaScript/TypeScript detection
        elif self._is_javascript_file(file, root_path, files, project_types):
            pass  # Handled within the method

        # Docker detection
        elif self._is_docker_file(file):
            if root_path not in project_types['docker']:
                project_types['docker'].append(root_path)

    def _is_python_file(self, file: str) -> bool:
        """Check if file is Python-related"""
        return file.endswith(('.py', '.pyw')) or file in {'requirements.txt', 'Pipfile', 'pyproject.toml'}  # pylint: disable=C0301

    def _is_javascript_file(self, file: str, root_path: Path, files: List[str], project_types: Dict[str, List[Path]]) -> bool:  # pylint: disable=C0301
        """Check if file is JavaScript/TypeScript-related"""
        if file == 'package.json':
            if root_path not in project_types['javascript']:
                project_types['javascript'].append(root_path)
            # Check if it's TypeScript
            if (root_path / 'tsconfig.json').exists() or any(f.endswith('.ts') or f.endswith('.tsx') for f in files):  # pylint: disable=C0301
                if root_path not in project_types['typescript']:
                    project_types['typescript'].append(root_path)
            return True
        if file.endswith(('.js', '.jsx', '.ts', '.tsx')):
            # Standalone JavaScript/TypeScript files
            if root_path not in project_types['javascript']:
                project_types['javascript'].append(root_path)
            if file.endswith(('.ts', '.tsx')) and root_path not in project_types['typescript']:  # pylint: disable=C0301
                project_types['typescript'].append(root_path)
            return True
        return False

    def _is_docker_file(self, file: str) -> bool:
        """Check if file is Docker-related"""
        return file in {'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml'}

    def run_scan(self, include_linting: bool = True) -> str:
        """Run comprehensive security scan"""
        print("🔒 Starting DevScrub Security Scan")
        print(f"📁 Target: {self.target_dir}")
        print(f"⏰ Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)

        # Detect project types
        project_types = self.detect_project_types()

        # Run scans based on detected project types
        if project_types['python']:
            print(f"\n🐍 Found {len(project_types['python'])} Python project(s)")
            self.results['python'] = self.python_scanner.scan(project_types['python'], include_linting=include_linting)  # pylint: disable=C0301

        if project_types['javascript']:
            print(f"\n📦 Found {len(project_types['javascript'])} JavaScript project(s)")
            self.results['javascript'] = self.js_scanner.scan(project_types['javascript'], include_linting=include_linting)  # pylint: disable=C0301

        if project_types['docker']:
            print(f"\n🐳 Found {len(project_types['docker'])} Docker project(s)")
            self.results['docker'] = self.docker_scanner.scan(project_types['docker'])

        # Run shell scanning (always include linting for shell scripts)
        print("\n🐚 Found shell scripts in project")
        self.results['shell'] = self.shell_scanner.scan([self.target_dir])

        # Run general scans
        print("\n🔐 Running secrets scan...")
        self.results['secrets'] = self.secrets_scanner.scan()

        print("\n📦 Running SBOM generation...")
        self.results['sbom'] = self.sbom_scanner.scan()

        print("\n🔍 Running vulnerability scan...")
        self.results['vulnerabilities'] = self.vuln_scanner.scan()

        # Generate summary
        summary = self._generate_summary()

        # Create final report structure
        report = {
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'target_directory': str(self.target_dir),
                'scanner_version': '0.0.4'
            },
            'project_types': {k: [str(p) for p in v] for k, v in project_types.items()},
            'tool_availability': self.python_scanner.tools,  # All scanners share the same tools
            'results': self.results,
            'summary': summary
        }

        # Save JSON report
        json_report_path = self.output_dir / f"security_report_{self.timestamp}.json"
        with open(json_report_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print("\n✅ Scan completed successfully!")
        print(f"📊 JSON Report: {json_report_path}")

        return str(json_report_path)

    def _generate_summary(self) -> Dict:
        """Generate summary statistics"""
        summary = {
            'total_issues': 0,
            'by_severity': {'high': 0, 'medium': 0, 'low': 0, 'info': 0},
            'by_tool': {},
            'recommendations': []
        }

        # Count issues from different tools
        for tool_name, tool_results in self.results.items():
            if isinstance(tool_results, dict):
                self._process_tool_results(tool_name, tool_results, summary)

        return summary

    def _process_tool_results(self, tool_name: str, tool_results: Dict[str, Any], summary: Dict[str, Any]) -> None:  # pylint: disable=C0301
        """Process results from a specific tool to update summary"""
        for scan_type, scans in tool_results.items():
            if isinstance(scans, list):
                for scan in scans:
                    self._process_scan_result(tool_name, scan_type, scan, summary)

    def _process_scan_result(self, tool_name: str, scan_type: str, scan: Dict[str, Any], summary: Dict[str, Any]) -> None:  # pylint: disable=C0301
        """Process a single scan result to update summary"""
        if 'issues_count' in scan:
            summary['total_issues'] += scan['issues_count']
            summary['by_tool'][f"{tool_name}_{scan_type}"] = scan['issues_count']
        elif 'vulnerabilities_count' in scan:
            summary['total_issues'] += scan['vulnerabilities_count']
            summary['by_tool'][f"{tool_name}_{scan_type}"] = scan['vulnerabilities_count']
        elif 'findings_count' in scan:
            summary['total_issues'] += scan['findings_count']
            summary['by_tool'][f"{tool_name}_{scan_type}"] = scan['findings_count']
        elif 'matches_count' in scan:
            summary['total_issues'] += scan['matches_count']
            summary['by_tool'][f"{tool_name}_{scan_type}"] = scan['matches_count']
        elif 'artifacts_count' in scan:
            # SBOM artifacts are informational, not issues
            summary['by_tool'][f"{tool_name}_{scan_type}"] = scan['artifacts_count']

    def generate_html_report(self, scan_results: Dict[str, Any]) -> str:
        """Generate HTML report"""
        # Create scan results structure for HTML generator
        scan_results = {
            'findings': scan_results['findings'],
            'scan_info': {
                'timestamp': datetime.now().isoformat(),
                'target_directory': str(self.target_dir)
            }
        }
        html_report_path = self.output_dir / f"security_report_{self.timestamp}.html"
        return generate_html_report(scan_results, str(html_report_path))

    def extract_findings_for_html(self) -> List[Dict[str, Any]]:
        """Extract findings from scan results for HTML report"""
        findings = []

        # Process Python scan results
        if 'python' in self.results:
            python_findings = self._extract_python_findings()
            findings.extend(python_findings)

        # Process JavaScript scan results
        if 'javascript' in self.results:
            js_findings = self._extract_javascript_findings()
            findings.extend(js_findings)

        # Process secrets scan results
        if 'secrets' in self.results:
            secrets_findings = self._extract_secrets_findings()
            findings.extend(secrets_findings)

        # Process vulnerability scan results
        if 'vulnerabilities' in self.results:
            vuln_findings = self._extract_vulnerability_findings()
            findings.extend(vuln_findings)

        # Process shell scan results
        if 'shell' in self.results:
            shell_findings = self._extract_shell_findings()
            findings.extend(shell_findings)

        return findings

    def _extract_python_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from Python scan results"""
        findings = []
        python_results = self.results['python']

        # Process each tool's findings
        findings.extend(self._extract_bandit_findings(python_results))
        findings.extend(self._extract_pip_audit_findings(python_results))
        findings.extend(self._extract_pylint_findings(python_results))
        findings.extend(self._extract_ruff_findings(python_results))

        return findings

    def _extract_bandit_findings(self, python_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Bandit findings"""
        findings = []
        for bandit_scan in python_results.get('bandit', []):
            if not isinstance(bandit_scan, dict):
                continue
            if 'data' in bandit_scan and 'results' in bandit_scan['data']:
                for issue in bandit_scan['data']['results']:
                    if not isinstance(issue, dict):
                        continue
                    findings.append({
                        'title': f"Bandit: {issue.get('issue_text', 'Security Issue')}",
                        'description': issue.get('issue_text', ''),
                        'severity': issue.get('issue_severity', 'medium').lower(),
                        'tool': 'Bandit',
                        'file_path': issue.get('filename', ''),
                        'line_number': issue.get('line_number'),
                        'line_range': [issue.get('line_number', 0)] if issue.get('line_number') else [],  # pylint: disable=C0301
                        'confidence': issue.get('issue_confidence', 'medium').lower(),
                        'cwe': issue.get('more_info', ''),
                        'cve': None,
                        'file_content': None
                    })
        return findings

    def _extract_pip_audit_findings(self, python_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract pip-audit findings"""
        findings = []
        for audit_scan in python_results.get('pip-audit', []):
            if not isinstance(audit_scan, dict):
                continue
            if 'data' in audit_scan:
                for vuln in audit_scan['data']:
                    if not isinstance(vuln, dict):
                        continue
                    findings.append({
                        'title': f"pip-audit: {vuln.get('package', 'Unknown')}",
                        'description': vuln.get('description', ''),
                        'severity': vuln.get('severity', 'medium').lower(),
                        'tool': 'pip-audit',
                        'file_path': 'requirements.txt',
                        'line_number': None,
                        'line_range': [],
                        'confidence': 'high',
                        'cwe': vuln.get('cwe', ''),
                        'cve': vuln.get('cve', ''),
                        'file_content': None
                    })
        return findings

    def _extract_pylint_findings(self, python_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Pylint findings"""
        findings = []
        for pylint_scan in python_results.get('pylint', []):
            if not isinstance(pylint_scan, dict):
                continue
            if 'data' in pylint_scan:
                for issue in pylint_scan['data']:
                    if not isinstance(issue, dict):
                        continue
                    findings.append({
                        'title': f"Pylint: {issue.get('message', 'Code Quality Issue')}",
                        'description': issue.get('message', ''),
                        'severity': 'low',
                        'tool': 'Pylint',
                        'file_path': issue.get('path', 'Unknown'),
                        'line_number': issue.get('line', 0),
                        'line_range': [issue.get('line', 0)] if issue.get('line') else [],
                        'confidence': 'high',
                        'cwe': '',
                        'cve': '',
                        'pylint_code': issue.get('symbol', ''),
                        'file_content': None
                    })
        return findings

    def _extract_ruff_findings(self, python_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract Ruff findings"""
        findings = []

        for ruff_scan in python_results.get('ruff', []):
            if not isinstance(ruff_scan, dict):
                continue

            if 'data' in ruff_scan:
                for issue in ruff_scan['data']:
                    if not isinstance(issue, dict):
                        continue

                    findings.append({
                        'title': f"Ruff: {str(issue.get('message', 'Code Quality Issue') or '')}",
                        'description': str(issue.get('message', '') or ''),
                        'severity': 'low',
                        'tool': 'Ruff',
                        'file_path': str(issue.get('filename', '') or ''),
                        'line_number': issue.get('location', {}).get('row', 0),
                        'line_range': [issue.get('location', {}).get('row', 0)] if issue.get('location', {}).get('row') else [],  # pylint: disable=C0301
                        'confidence': 'high',
                        'cwe': '',
                        'cve': '',
                        'ruff_code': issue.get('code', ''),
                        'ruff_url': issue.get('url', ''),
                        'file_content': None
                    })

        return findings

    def _extract_javascript_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from JavaScript scan results"""
        findings = []
        js_results = self.results['javascript']

        # npm audit findings
        for npm_scan in js_results.get('npm_audit', []):
            if not isinstance(npm_scan, dict):
                continue
            if 'data' in npm_scan and 'advisories' in npm_scan['data']:
                for _, vuln in npm_scan['data']['advisories'].items():
                    if not isinstance(vuln, dict):
                        continue
                    findings.append({
                        'title': f"npm audit: {str(vuln.get('title', 'Vulnerability') or '')}",
                        'description': str(vuln.get('overview', '') or ''),
                        'severity': str(vuln.get('severity', 'medium')).lower() if vuln.get('severity') else 'medium',  # pylint: disable=C0301
                        'tool': 'npm audit',
                        'file_path': 'package.json',
                        'line_number': None,
                        'line_range': [],
                        'confidence': 'high',
                        'cwe': str(vuln.get('cwe', '') or ''),
                        'cve': str(vuln.get('cve', '') or ''),
                        'file_content': None
                    })

        # ESLint findings
        for eslint_scan in js_results.get('eslint', []):
            if not isinstance(eslint_scan, dict):
                continue
            if 'data' in eslint_scan:
                for issue in eslint_scan['data']:
                    if not isinstance(issue, dict):
                        continue
                    findings.append({
                        'title': f"ESLint: {str(issue.get('message', 'Linting Issue') or '')}",
                        'description': str(issue.get('message', '') or ''),
                        'severity': 'low',
                        'tool': 'ESLint',
                        'file_path': str(issue.get('filePath', '') or ''),
                        'line_number': issue.get('line', 0),
                        'line_range': [issue.get('line', 0)] if issue.get('line') else [],
                        'confidence': 'medium',
                        'cwe': '',
                        'cve': '',
                        'file_content': None
                    })

        return findings

    def _extract_secrets_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from secrets scan results"""
        findings = []
        secrets_results = self.results['secrets']

        # TruffleHog findings
        for truffle_scan in secrets_results.get('trufflehog', []):
            if not isinstance(truffle_scan, dict):
                continue
            if 'matches' in truffle_scan:
                for match in truffle_scan['matches']:
                    if not isinstance(match, dict):
                        continue
                    findings.append({
                        'title': f"Secret Detected: {match.get('type', 'Unknown')}",
                        'description': f"Potential secret found in {match.get('path', 'unknown file')}",  # pylint: disable=C0301
                        'severity': 'high',
                        'tool': 'TruffleHog',
                        'file_path': match.get('path', ''),
                        'line_number': match.get('line', 0),
                        'line_range': [match.get('line', 0)] if match.get('line') else [],
                        'confidence': 'medium',
                        'cwe': 'CWE-532',
                        'cve': None,
                        'file_content': None
                    })

        return findings

    def _extract_vulnerability_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from vulnerability scan results"""
        findings = []
        vuln_results = self.results['vulnerabilities']

        # Grype findings
        for grype_scan in vuln_results.get('grype', []):
            if not isinstance(grype_scan, dict):
                continue
            
            if 'data' in grype_scan and 'matches' in grype_scan['data']:
                matches = grype_scan['data']['matches']
                
                for match in matches:
                    if not isinstance(match, dict):
                        continue
                    
                    # Map Grype severity to standard severity levels
                    grype_severity = match.get('vulnerability', {}).get('severity', 'medium').lower()
                    severity = self._map_grype_severity(grype_severity)
                    
                    # Extract file path more robustly
                    artifact = match.get('artifact', {})
                    locations = artifact.get('locations', [])
                    file_path = ''
                    if locations and isinstance(locations, list) and len(locations) > 0:
                        file_path = locations[0].get('path', '')
                    
                    # Extract package information
                    artifact = match.get('artifact', {})
                    package_name = artifact.get('name', 'Unknown Package')
                    package_version = artifact.get('version', 'Unknown Version')
                    
                    # Create more informative title and description
                    vuln_id = match.get('vulnerability', {}).get('id', 'Unknown')
                    vuln_description = match.get('vulnerability', {}).get('description', '')
                    
                    title = f"Vulnerability: {vuln_id} in {package_name} {package_version}"
                    description = f"{vuln_description}\n\nPackage: {package_name} {package_version}"
                    if file_path:
                        description += f"\nFile: {file_path}"
                    
                    # Extract dataSource URL for the vulnerability
                    data_source_url = match.get('vulnerability', {}).get('dataSource', '')
                    
                    findings.append({
                        'title': title,
                        'description': description,
                        'severity': severity,
                        'tool': 'Grype',
                        'file_path': file_path,
                        'line_number': None,
                        'line_range': [],
                        'confidence': 'high',
                        'cwe': match.get('vulnerability', {}).get('cwe', ''),
                        'cve': match.get('vulnerability', {}).get('id', ''),
                        'file_content': None,
                        'grype_data_source': data_source_url
                    })

        return findings

    def _map_grype_severity(self, grype_severity: str) -> str:
        """Map Grype severity levels to standard severity levels"""
        severity_mapping = {
            'critical': 'critical',
            'high': 'high',
            'medium': 'medium',
            'low': 'low',
            'negligible': 'info'
        }
        return severity_mapping.get(grype_severity, 'medium')

    def _extract_shell_findings(self) -> List[Dict[str, Any]]:
        """Extract findings from shell scan results"""
        findings = []
        shell_results = self.results['shell']

        # ShellCheck findings
        for shellcheck_scan in shell_results.get('shellcheck', []):
            if not isinstance(shellcheck_scan, dict):
                continue
            if 'data' in shellcheck_scan:
                for issue in shellcheck_scan['data']:
                    if not isinstance(issue, dict):
                        continue
                    findings.append({
                        'title': f"ShellCheck: {issue.get('message', 'Shell Script Issue')}",
                        'description': issue.get('message', ''),
                        'severity': issue.get('level', 'style').lower(),
                        'tool': 'ShellCheck',
                        'file_path': issue.get('file', ''),
                        'line_number': issue.get('line', 0),
                        'line_range': [issue.get('line', 0)] if issue.get('line') else [],
                        'confidence': 'high',
                        'cwe': '',
                        'cve': '',
                        'file_content': None
                    })

        return findings


def main():
    """Main entry point for the DevScrub Security Scanner."""
    parser = argparse.ArgumentParser(description='DevScrub Security Scanner')
    parser.add_argument('target', nargs='?', default='.', help='Target directory to scan (default: current directory)')  # pylint: disable=C0301
    parser.add_argument('--format', choices=['json', 'html', 'all'], default='all', help='Output format')  # pylint: disable=C0301
    parser.add_argument('--severity', choices=['low', 'medium', 'high'], help='Filter by severity level')  # pylint: disable=C0301
    parser.add_argument('--output', default='security-reports', help='Output directory for reports')  # pylint: disable=C0301
    parser.add_argument('--no-linting', action='store_true', help='Skip linting scans (Pylint, Ruff, ESLint)')  # pylint: disable=C0301

    args = parser.parse_args()

    # Initialize scanner
    scanner = SecurityScanner(args.target, args.output)

    # Run scan
    try:
        json_report = scanner.run_scan(include_linting=not args.no_linting)
        print(f"📊 Check reports in: {scanner.output_dir}")

        # Generate additional reports based on format
        if args.format == 'all':
            # Generate HTML format
            html_report = scanner.generate_html_report({'findings': scanner.extract_findings_for_html()})  # pylint: disable=C0301
            print("📄 Reports generated:")
            print(f"  JSON: {json_report}")
            print(f"  HTML: {html_report}")
        elif args.format == 'html':
            # Generate HTML format only
            html_report = scanner.generate_html_report({'findings': scanner.extract_findings_for_html()})  # pylint: disable=C0301
            print(f"📄 HTML Report: {html_report}")

    except KeyboardInterrupt:
        print("\n❌ Scan interrupted by user")
        sys.exit(1)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"\n❌ Scan failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
