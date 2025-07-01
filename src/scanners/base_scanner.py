"""
Base Scanner Class
Common functionality for all security scanners
"""

import json
import subprocess  # nosec B404 - Required for security scanner functionality
import shutil
import shlex
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from abc import ABC, abstractmethod


class BaseScanner(ABC):
    """Base class for all security scanners"""

    def __init__(self, target_dir: Path):
        self.target_dir = target_dir
        self.tools = self._check_tool_availability()

    def _check_tool_availability(self) -> Dict[str, bool]:
        """Check which tools are available"""
        return {
            # Python tools
            'bandit': shutil.which('bandit') is not None,
            'pip-audit': shutil.which('pip-audit') is not None,
            'semgrep': shutil.which('semgrep') is not None,
            'pylint': shutil.which('pylint') is not None,
            'ruff': shutil.which('ruff') is not None,

            # JavaScript/Node tools
            'npm': shutil.which('npm') is not None,
            'yarn': shutil.which('yarn') is not None,
            'eslint': shutil.which('eslint') is not None,

            # Docker tools
            'docker': shutil.which('docker') is not None,
            'trivy': shutil.which('trivy') is not None,
            'hadolint': shutil.which('hadolint') is not None,

            # Shell tools
            'shellcheck': shutil.which('shellcheck') is not None,

            # General tools
            'git': shutil.which('git') is not None,
            'trufflehog': shutil.which('trufflehog') is not None,

            # Secret scanning tools
            'deepsecrets': shutil.which('deepsecrets') is not None,

            # SBOM and vulnerability scanning tools
            'syft': shutil.which('syft') is not None,
            'grype': shutil.which('grype') is not None,
        }

    def run_command(self, cmd: List[str], cwd: Optional[Path] = None, capture_output: bool = True) -> Tuple[int, str, str]:  # pylint: disable=C0301
        """Run a command safely with proper error handling"""
        # Validate command to prevent CWE-78
        if not cmd or not isinstance(cmd, list):
            return -1, "", "Invalid command format"

        # Ensure all command arguments are strings
        for i, arg in enumerate(cmd):
            if not isinstance(arg, str):
                return -1, "", f"Invalid command argument type at position {i}: {type(arg)}"

        # Validate command arguments using shlex.quote
        try:
            ' '.join(shlex.quote(arg) for arg in cmd)
        except (ValueError, TypeError) as e:
            return -1, "", f"Failed to validate command arguments: {e}"

        # Execute command with error handling
        return self._execute_command_safely(cmd, cwd, capture_output)

    def _execute_command_safely(self, cmd: List[str], cwd: Optional[Path], capture_output: bool) -> Tuple[int, str, str]: # pylint: disable=C0301
        """Execute command with consolidated error handling"""
        try:
            result = subprocess.run(  # nosec B603 - Legitimate use in security scanner
                cmd,
                cwd=cwd or self.target_dir,
                capture_output=capture_output,
                text=True,
                timeout=300,  # 5 minutes
                shell=False,  # Disable shell to prevent injection
                check=False   # Don't raise exception on non-zero exit codes
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            return -1, "", "Command timed out"
        except FileNotFoundError:
            return -1, "", f"Command not found: {cmd[0]}"
        except PermissionError:
            return -1, "", f"Permission denied executing: {cmd[0]}"
        except (OSError, ValueError) as e:
            return -1, "", f"Command execution failed: {str(e)}"

    def _parse_json_output(self, stdout: str) -> Optional[Dict]:
        """Safely parse JSON output from command"""
        if not stdout:
            return None

        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return None

    def _execute_json_command(self, cmd: List[str], project_dir: Path, success_field: str = 'data', error_msg: str = 'Failed to parse output') -> List[Dict[str, Any]]:  # pylint: disable=C0301
        """Execute a command and return standardized JSON results

        Args:
            cmd: Command to execute
            project_dir: Project directory
            success_field: Field name for successful results
            error_msg: Error message for failed parsing

        Returns:
            List of result dictionaries with standardized format
        """
        _, stdout, _ = self.run_command(cmd, project_dir)

        if stdout:
            data = self._parse_json_output(stdout)
            if data:
                return [{
                    'project': str(project_dir.relative_to(self.target_dir)),
                    'data': data,
                    success_field: len(data) if isinstance(data, list) else 1
                }]
            return [{
                'project': str(project_dir.relative_to(self.target_dir)),
                'error': error_msg,
                'raw_output': stdout[:500]
            }]
        return []

    @abstractmethod
    def scan(self, project_dirs: List[Path]) -> Dict[str, Any]:
        """Abstract method that each scanner must implement"""
        pass  # pylint: disable=W0107
