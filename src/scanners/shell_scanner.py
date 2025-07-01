"""
Shell Security Scanner
Handles shell script security scanning tools
"""

from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class ShellScanner(BaseScanner):
    """Scanner for shell scripts"""

    def scan(self, project_dirs: List[Path]) -> Dict[str, Any]:
        """Run shell security scans"""
        results = {'shellcheck': []}

        for project_dir in project_dirs:
            print(f"🐚 Scanning shell scripts in: {project_dir.relative_to(self.target_dir)}")

            # ShellCheck scan
            if self.tools['shellcheck']:
                results['shellcheck'].extend(self._run_shellcheck(project_dir))

        return results

    def _run_shellcheck(self, project_dir: Path) -> List[Dict]:
        """Run ShellCheck on shell scripts"""
        print("  🔍 Running ShellCheck...")

        # Find shell scripts
        shell_files = []
        for shell_file in project_dir.rglob("*.sh"):
            # Skip common directories
            if not any(skip in shell_file.parts for skip in ['__pycache__', '.venv', 'venv', 'node_modules']):  # pylint: disable=C0301
                shell_files.append(str(shell_file.relative_to(project_dir)))

        if not shell_files:
            return []

        # Run ShellCheck on all shell files
        cmd = ['shellcheck', '--format=json'] + shell_files
        return self._execute_json_command(cmd, project_dir, 'issues_count', 'Failed to parse ShellCheck output') # pylint: disable=C0301
