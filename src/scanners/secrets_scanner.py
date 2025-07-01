"""
Secrets Scanner
Handles secret detection tools
"""

import re
import json
import tempfile
import os
import mimetypes
from pathlib import Path
from typing import Dict, List, Any, Optional
from .base_scanner import BaseScanner


class SecretsScanner(BaseScanner):
    """Scanner for secrets detection"""

    # Comprehensive list of binary/compiled extensions to skip
    BINARY_EXTENSIONS = {
        # Compiled Python
        '.pyc', '.pyo', '.pyd',
        # Executables
        '.exe', '.bin', '.app', '.dmg', '.deb', '.rpm', '.msi',
        # Libraries
        '.so', '.dll', '.dylib', '.a', '.lib',
        # Object files
        '.o', '.obj', '.elf',
        # Archives
        '.zip', '.tar.gz', '.rar', '.7z', '.bz2', '.gz', '.xz',
        # Images/Videos
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp',
        '.mp4', '.avi', '.mov', '.wmv', '.flv', '.mkv', '.webm',
        # Audio
        '.mp3', '.wav', '.flac', '.aac', '.ogg',
        # Documents
        '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        # Database files
        '.db', '.sqlite', '.sqlite3', '.mdb', '.accdb',
        # Logs
        '.log', '.out', '.err',
        # Cache
        '.cache', '.tmp', '.temp',
        # Fonts
        '.ttf', '.otf', '.woff', '.woff2',
        # Other binary
        '.class', '.jar', '.war', '.ear', '.apk', '.ipa'
    }

    # Comprehensive directory categories to skip
    SKIP_DIRS = {
        # Version control
        '.git', '.svn', '.hg', '.bzr',
        # Dependencies
        'node_modules', '.venv', 'venv', 'env', 'virtualenv', 'vendor', 'bower_components',
        # Build artifacts
        'dist', 'build', 'target', 'out', 'bin', 'obj', 'coverage',
        # Cache
        '.cache', '.pytest_cache', '__pycache__', '.mypy_cache', '.ruff_cache', '.tox',
        # IDE
        '.vscode', '.idea', '.vs', '.eclipse', '.vscode-server',
        # OS files
        '.DS_Store', 'Thumbs.db', '.Trash', 'desktop.ini',
        # Logs and temp
        'logs', 'log', 'tmp', 'temp', '.tmp',
        # Backups
        '.backup', '.bak', '.old', '.orig', 'backup',
        # Package managers
        '.npm', '.yarn', '.pip', '.cargo', '.maven', '.gradle',
        # Containers
        '.docker', 'docker-data', 'container-data',
        # Other
        '.terraform', '.serverless', '.aws', '.azure'
    }

    def scan(self, project_dirs: Optional[List[Path]] = None) -> Dict[str, Any]:
        """Run secrets scanning"""
        results = {'trufflehog': [], 'deepsecrets': [], 'manual_patterns': []}

        print("🔐 Scanning for secrets...")

        # TruffleHog scan
        if self.tools['trufflehog']:
            results['trufflehog'].extend(self._run_trufflehog())

        # DeepSecrets scan
        if self.tools['deepsecrets']:
            results['deepsecrets'].extend(self._run_deepsecrets())

        # Manual pattern scanning
        results['manual_patterns'].extend(self._run_manual_patterns())

        return results

    def _run_trufflehog(self) -> List[Dict]:
        """Run TruffleHog secrets scan"""
        print("  🔍 Running TruffleHog...")
        cmd = ['trufflehog', '--no-update', '--json', 'filesystem', str(self.target_dir)]
        _, stdout, _ = self.run_command(cmd)

        if stdout:
            lines = stdout.strip().split('\n')
            matches = []
            for line in lines:
                if line.strip():
                    try:
                        match_data = json.loads(line)
                        matches.append(match_data)
                    except json.JSONDecodeError:
                        continue

            if matches:
                return [{
                    'project': str(self.target_dir),
                    'matches': matches,
                    'secrets_count': len(matches)
                }]
            return [{
                'project': str(self.target_dir),
                'error': 'Failed to parse TruffleHog output',
                'raw_output': stdout[:500]
            }]
        return []

    def _run_deepsecrets(self) -> List[Dict]:
        """Run DeepSecrets semantic analysis"""
        print("  🔍 Running DeepSecrets...")

        # Create a secure temporary file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp_file:
            tmp_file_path = tmp_file.name

        try:
            cmd = [
                'deepsecrets', '--target-dir', str(self.target_dir),
                '--outfile', tmp_file_path, '--outformat', 'json'
            ]
            _, _, _ = self.run_command(cmd)

            # Try to read the output file
            try:
                with open(tmp_file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    return [{
                        'project': str(self.target_dir),
                        'matches': data.get('matches', []),
                        'secrets_count': len(data.get('matches', []))
                    }]
            except (FileNotFoundError, json.JSONDecodeError):
                return [{
                    'project': str(self.target_dir),
                    'error': 'Failed to parse DeepSecrets output'
                }]
        finally:
            # Clean up the temporary file
            try:
                os.unlink(tmp_file_path)
            except OSError:
                pass  # File may already be deleted

    def _run_manual_patterns(self) -> List[Dict]:
        """Run manual pattern matching for secrets"""
        print("  🔍 Running manual pattern scanning...")

        # Common secret patterns
        patterns = {
            'api_key': r'api[_-]?key["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
            'password': r'password["\s]*[:=]["\s]*[^\s]{8,}',
            'secret': r'secret["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
            'token': r'token["\s]*[:=]["\s]*[a-zA-Z0-9]{20,}',
            'private_key': r'-----BEGIN PRIVATE KEY-----',
            'ssh_key': r'-----BEGIN OPENSSH PRIVATE KEY-----',
            'aws_key': r'AKIA[0-9A-Z]{16}',
            'aws_secret': r'[0-9a-zA-Z/+]{40}',
        }

        matches = []

        # Scan all files
        for file_path in self.target_dir.rglob('*'):
            if file_path.is_file() and not self._should_skip_file(file_path):
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                        for pattern_name, pattern in patterns.items():
                            for match in re.finditer(pattern, content, re.IGNORECASE):
                                matches.append({
                                    'file': str(file_path.relative_to(self.target_dir)),
                                    'pattern': pattern_name,
                                    'line': content[:match.start()].count('\n') + 1,
                                    'match': match.group()[:50] + '...' if len(match.group()) > 50 else match.group()  # pylint: disable=C0301
                                })
                except (OSError, IOError, UnicodeDecodeError) as e:
                    # Log specific file reading errors but continue processing
                    print(f"  ⚠️  Error reading file {file_path}: {e}")
                    continue

        return [{
            'project': str(self.target_dir),
            'matches': matches,
            'secrets_count': len(matches)
        }]

    def _should_skip_file(self, file_path: Path) -> bool:
        """Determine if file should be skipped for secrets scanning using hybrid approach"""

        # Skip directories using comprehensive set
        if any(skip_dir in file_path.parts for skip_dir in self.SKIP_DIRS):
            return True

        # Quick check for known binary extensions
        if file_path.suffix.lower() in self.BINARY_EXTENSIONS:
            return True

        # Skip large files (likely binary or not useful for secrets)
        try:
            file_size = file_path.stat().st_size
            if file_size > 10 * 1024 * 1024:  # 10MB
                return True
        except OSError:
            return True

        # MIME type check for edge cases
        try:
            mime_type, _ = mimetypes.guess_type(str(file_path))
            if mime_type:
                # Skip binary files, archives, media, etc.
                return mime_type.startswith((
                    'application/octet-stream',  # Generic binary
                    'application/zip',           # Archives
                    'application/x-rar',         # RAR archives
                    'application/x-7z-compressed', # 7z archives
                    'image/',                    # Images
                    'video/',                    # Videos
                    'audio/',                    # Audio
                    'application/pdf',           # PDFs
                    'application/msword',        # Office documents
                    'application/vnd.openxmlformats-officedocument'
                ))
        except Exception: # pylint: disable=W0718
            # If MIME type detection fails, continue with the file
            pass

        return False
