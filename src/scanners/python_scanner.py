"""
Python Security Scanner
Handles Python-specific security scanning tools
"""

import json
from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class PythonScanner(BaseScanner):
    """Scanner for Python projects"""

    def scan(self, project_dirs: List[Path], include_linting: bool = True) -> Dict[str, Any]:
        """Run Python security scans"""
        results = {'bandit': [], 'pip-audit': [], 'semgrep': [], 'pylint': [], 'ruff': []}

        # Run project-specific scans (Bandit, pip-audit, Semgrep)
        for project_dir in project_dirs:
            print(f"🐍 Scanning Python project: {project_dir.relative_to(self.target_dir)}")

            # Bandit scan
            if self.tools['bandit']:
                results['bandit'].extend(self._run_bandit(project_dir))

            # pip-audit scan
            if self.tools['pip-audit'] and (project_dir / 'requirements.txt').exists():
                results['pip-audit'].extend(self._run_pip_audit(project_dir))

            # Semgrep scan
            if self.tools['semgrep']:
                results['semgrep'].extend(self._run_semgrep(project_dir))

        # Run linting scans on all Python files
        if include_linting:
            # Pylint scan on all Python files
            if self.tools['pylint']:
                results['pylint'].extend(self._run_pylint_all_files())

            # Ruff scan on all Python files
            if self.tools['ruff']:
                results['ruff'].extend(self._run_ruff_all_files())

        return results

    def _get_all_python_files(self) -> List[Path]:
        """Get all Python files under the target directory, excluding ignored directories"""
        python_files = []
        ignored_dirs = {
            '__pycache__', '.venv', 'venv', 'migrations', 'tests', 
            '.ruff_cache', 'test-reports', 'security-reports', '.git',
            'node_modules', 'dist', 'build', '.pytest_cache'
        }

        for py_file in self.target_dir.rglob("*.py"):
            # Skip files in ignored directories
            if not any(ignored_dir in py_file.parts for ignored_dir in ignored_dirs):
                python_files.append(py_file)

        return python_files

    def _run_bandit(self, project_dir: Path) -> List[Dict]:
        """Run Bandit security scan"""
        print("  🔍 Running Bandit...")
        cmd = ['bandit', '-r', '.', '-f', 'json']
        return self._execute_json_command(cmd, project_dir, 'issues_count', 'Failed to parse Bandit output') # pylint: disable=C0301

    def _run_pip_audit(self, project_dir: Path) -> List[Dict]:
        """Run pip-audit dependency scan"""
        print("  🔍 Running pip-audit...")
        cmd = ['pip-audit', '-f', 'json']
        return self._execute_json_command(cmd, project_dir, 'vulnerabilities_count', 'Failed to parse pip-audit output') # pylint: disable=C0301

    def _run_semgrep(self, project_dir: Path) -> List[Dict]:
        """Run Semgrep SAST scan"""
        print("  🔍 Running Semgrep...")
        cmd = ['semgrep', '--config=auto', '.', '--json']
        return self._execute_json_command(cmd, project_dir, 'findings_count', 'Failed to parse Semgrep output') # pylint: disable=C0301

    def _run_pylint_all_files(self) -> List[Dict]:
        """Run Pylint on all Python files"""
        print("  🔍 Running Pylint on all Python files...")

        python_files = self._get_all_python_files()
        print(f"    Found {len(python_files)} Python files to scan")

        if not python_files:
            return []

        # Create a list of relative file paths for Pylint
        file_paths = [str(f.relative_to(self.target_dir)) for f in python_files]

        cmd = ['pylint', '--output-format=json', '--reports=no'] + file_paths
        _, stdout, _ = self.run_command(cmd, self.target_dir)

        if stdout:
            data = self._parse_json_output(stdout)
            if data:
                # Filter for security-related issues
                security_keywords = ['security', 'unsafe', 'dangerous', 'eval', 'exec', 'import']
                security_issues = [
                    issue for issue in data
                    if any(keyword in issue.get('message-id', '').lower() or
                          keyword in issue.get('message', '').lower()
                          for keyword in security_keywords)
                ]

                return [{
                    'project': 'all_python_files',
                    'data': data,
                    'security_issues': security_issues,
                    'total_issues_count': len(data),
                    'security_issues_count': len(security_issues)
                }]

            # Try to parse line by line for non-JSON output
            lines = stdout.strip().split('\n')
            issues = []
            for line in lines:
                if line.strip() and ':' in line:
                    try:
                        issue_data = json.loads(line)
                        issues.append(issue_data)
                    except json.JSONDecodeError:
                        continue

            if issues:
                security_keywords = ['security', 'unsafe', 'dangerous', 'eval', 'exec', 'import']
                security_issues = [
                    issue for issue in issues
                    if any(keyword in issue.get('message-id', '').lower() or
                          keyword in issue.get('message', '').lower()
                          for keyword in security_keywords)
                ]

                return [{
                    'project': 'all_python_files',
                    'data': issues,
                    'security_issues': security_issues,
                    'total_issues_count': len(issues),
                    'security_issues_count': len(security_issues)
                }]

            return [{
                'project': 'all_python_files',
                'error': 'Failed to parse Pylint output',
                'raw_output': stdout[:500]
            }]
        return []

    def _run_ruff_all_files(self) -> List[Dict]:
        """Run Ruff on all Python files"""
        print("  🔍 Running Ruff on all Python files...")

        python_files = self._get_all_python_files()
        print(f"    Found {len(python_files)} Python files to scan")

        if not python_files:
            return []

        # Run Ruff on the entire target directory (it will automatically find all .py files)
        cmd = ['ruff', 'check', '.', '--output-format=json', '--no-cache']
        return self._execute_json_command(cmd, self.target_dir, 'linting_issues_count', 'Failed to parse Ruff output') # pylint: disable=C0301

    def _run_pylint(self, project_dir: Path) -> List[Dict]:
        """Run Pylint security-focused scan (legacy method - kept for compatibility)"""
        print("  🔍 Running Pylint...")

        # Find Python files to scan
        python_files = []
        for py_file in project_dir.rglob("*.py"):
            # Skip common directories and files
            skip_dirs = {'__pycache__', '.venv', 'venv', 'migrations', 'tests'}
            if not any(skip in py_file.parts for skip in skip_dirs):
                python_files.append(str(py_file.relative_to(project_dir)))

        if not python_files:
            return []

        cmd = ['pylint', '--output-format=json', '--reports=no'] + python_files
        _, stdout, _ = self.run_command(cmd, project_dir)

        if stdout:
            data = self._parse_json_output(stdout)
            if data:
                # Filter for security-related issues
                security_keywords = ['security', 'unsafe', 'dangerous', 'eval', 'exec', 'import']
                security_issues = [
                    issue for issue in data
                    if any(keyword in issue.get('message-id', '').lower() or
                          keyword in issue.get('message', '').lower()
                          for keyword in security_keywords)
                ]

                return [{
                    'project': str(project_dir.relative_to(self.target_dir)),
                    'data': data,
                    'security_issues': security_issues,
                    'total_issues_count': len(data),
                    'security_issues_count': len(security_issues)
                }]

            # Try to parse line by line for non-JSON output
            lines = stdout.strip().split('\n')
            issues = []
            for line in lines:
                if line.strip() and ':' in line:
                    try:
                        issue_data = json.loads(line)
                        issues.append(issue_data)
                    except json.JSONDecodeError:
                        continue

            if issues:
                security_keywords = ['security', 'unsafe', 'dangerous', 'eval', 'exec', 'import']
                security_issues = [
                    issue for issue in issues
                    if any(keyword in issue.get('message-id', '').lower() or
                          keyword in issue.get('message', '').lower()
                          for keyword in security_keywords)
                ]

                return [{
                    'project': str(project_dir.relative_to(self.target_dir)),
                    'data': issues,
                    'security_issues': security_issues,
                    'total_issues_count': len(issues),
                    'security_issues_count': len(security_issues)
                }]

            return [{
                'project': str(project_dir.relative_to(self.target_dir)),
                'error': 'Failed to parse Pylint output',
                'raw_output': stdout[:500]
            }]
        return []

    def _run_ruff(self, project_dir: Path) -> List[Dict]:
        """Run Ruff linting scan (legacy method - kept for compatibility)"""
        print("  🔍 Running Ruff...")
        cmd = ['ruff', 'check', '.', '--output-format=json', '--no-cache']
        return self._execute_json_command(cmd, project_dir, 'linting_issues_count', 'Failed to parse Ruff output') # pylint: disable=C0301
