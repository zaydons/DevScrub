"""
SBOM Scanner
Handles Software Bill of Materials generation
"""

from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner


class SBOMScanner(BaseScanner):
    """Scanner for SBOM generation"""

    def scan(self, project_dirs: Optional[List[Path]] = None) -> Dict[str, Any]:
        """Generate Software Bill of Materials"""
        results = {'syft': []}

        if not self.tools['syft']:
            print("⚠️  Syft not available - skipping SBOM generation")
            return results

        print("📦 Generating Software Bill of Materials with Syft...")

        # Generate SBOM for the entire project
        cmd = ['syft', '.', '-o', 'json']
        _, stdout, stderr = self.run_command(cmd)

        if stdout:
            data = self._parse_json_output(stdout)
            if data:
                results['syft'].append({
                    'project': str(self.target_dir),
                    'data': data,
                    'artifacts_count': len(data.get('artifacts', [])),
                    'source_type': data.get('source', {}).get('type', 'unknown')
                })
                print(f"  ✅ Generated SBOM with {len(data.get('artifacts', []))} artifacts")
            else:
                results['syft'].append({
                    'project': str(self.target_dir),
                    'error': 'Failed to parse Syft output',
                    'raw_output': stdout[:500]
                })
                print("  ❌ Failed to parse Syft output")
        else:
            results['syft'].append({
                'project': str(self.target_dir),
                'error': 'Syft command failed',
                'stderr': stderr
            })
            print(f"  ❌ Syft command failed: {stderr}")

        return results
