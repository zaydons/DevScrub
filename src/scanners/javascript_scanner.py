"""
JavaScript Security Scanner
Handles JavaScript/Node.js security scanning tools
"""

from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class JavaScriptScanner(BaseScanner):
    """Scanner for JavaScript/Node.js projects"""

    def scan(self, project_dirs: List[Path], include_linting: bool = True) -> Dict[str, Any]:
        """Run JavaScript security scans"""
        results = {'npm_audit': [], 'yarn_audit': [], 'eslint': []}

        for project_dir in project_dirs:
            print(f"📦 Scanning JavaScript project: {project_dir.relative_to(self.target_dir)}")

            # npm audit
            if self.tools['npm'] and (project_dir / 'package.json').exists():
                results['npm_audit'].extend(self._run_npm_audit(project_dir))

            # yarn audit
            if self.tools['yarn'] and (project_dir / 'package.json').exists():
                results['yarn_audit'].extend(self._run_yarn_audit(project_dir))

            # ESLint scan (optional)
            if include_linting and self.tools['eslint']:
                results['eslint'].extend(self._run_eslint(project_dir))

        return results

    def _run_npm_audit(self, project_dir: Path) -> List[Dict]:
        """Run npm audit"""
        print("  🔍 Running npm audit...")
        cmd = ['npm', 'audit', '--json']
        return self._execute_json_command(cmd, project_dir, 'vulnerabilities', 'Failed to parse npm audit output') # pylint: disable=C0301

    def _run_yarn_audit(self, project_dir: Path) -> List[Dict]:
        """Run yarn audit"""
        print("  🔍 Running yarn audit...")
        cmd = ['yarn', 'audit', '--json']
        return self._execute_json_command(cmd, project_dir, 'vulnerabilities', 'Failed to parse yarn audit output') # pylint: disable=C0301

    def _run_eslint(self, project_dir: Path) -> List[Dict]:
        """Run ESLint scan"""
        print("  🔍 Running ESLint...")
        cmd = ['eslint', '.', '--format=json']
        return self._execute_json_command(cmd, project_dir, 'linting_issues_count', 'Failed to parse ESLint output') # pylint: disable=C0301
