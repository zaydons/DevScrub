"""
Docker Security Scanner
Handles Docker-specific security scanning tools
"""

from pathlib import Path
from typing import Dict, List, Any
from .base_scanner import BaseScanner


class DockerScanner(BaseScanner):
    """Scanner for Docker projects"""

    def scan(self, project_dirs: List[Path]) -> Dict[str, Any]:
        """Run Docker security scans"""
        results = {'hadolint': [], 'trivy': []}

        for project_dir in project_dirs:
            print(f"🐳 Scanning Docker project: {project_dir.relative_to(self.target_dir)}")

            # Hadolint scan
            if self.tools['hadolint']:
                results['hadolint'].extend(self._run_hadolint(project_dir))

            # Trivy scan
            if self.tools['trivy']:
                results['trivy'].extend(self._run_trivy(project_dir))

        return results

    def _run_hadolint(self, project_dir: Path) -> List[Dict]:
        """Run Hadolint Dockerfile linting"""
        print("  🔍 Running Hadolint...")

        dockerfiles = list(project_dir.glob("Dockerfile*"))
        if not dockerfiles:
            return []

        results = []
        for dockerfile in dockerfiles:
            cmd = ['hadolint', '--format', 'json', str(dockerfile)]
            _, stdout, _ = self.run_command(cmd, project_dir)

            if stdout:
                data = self._parse_json_output(stdout)
                if data:
                    results.append({
                        'project': str(project_dir.relative_to(self.target_dir)),
                        'dockerfile': str(dockerfile.relative_to(self.target_dir)),
                        'data': data,
                        'issues_count': len(data)
                    })
                else:
                    results.append({
                        'project': str(project_dir.relative_to(self.target_dir)),
                        'dockerfile': str(dockerfile.relative_to(self.target_dir)),
                        'error': 'Failed to parse Hadolint output',
                        'raw_output': stdout[:500]
                    })

        return results

    def _run_trivy(self, project_dir: Path) -> List[Dict]:
        """Run Trivy filesystem scan"""
        print("  🔍 Running Trivy...")
        cmd = ['trivy', 'fs', '--format', 'json', '.']
        return self._execute_json_command(cmd, project_dir, 'vulnerabilities_count', 'Failed to parse Trivy output') # pylint: disable=C0301
