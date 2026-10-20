"""Deterministic bare Git fixtures, using object plumbing and no worktree.

Only tests use Git writers. All identities, timestamps, raw byte streams, modes,
SHA-1 format and locale are explicit so fixture commit IDs are cross-OS stable.
"""
import os
from pathlib import Path
import subprocess

from ci_contract.gitsource import _resolve_git


class SyntheticGit:
    def __init__(self, directory):
        self.path = Path(directory)
        self.path.mkdir(parents=True, exist_ok=True)
        self._git_executable = _resolve_git(self.path)
        self.run('init', '--bare', '--object-format=sha1', '--initial-branch=synthetic',
                 '--template=', '.')

    def run(self, *args, input=None):
        env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
        env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': os.devnull,
                    'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
                    'GIT_AUTHOR_NAME': 'Synthetic Author',
                    'GIT_AUTHOR_EMAIL': 'synthetic@example.invalid',
                    'GIT_COMMITTER_NAME': 'Synthetic Author',
                    'GIT_COMMITTER_EMAIL': 'synthetic@example.invalid',
                    'GIT_AUTHOR_DATE': '2000-01-01T00:00:00 +0000',
                    'GIT_COMMITTER_DATE': '2000-01-01T00:00:00 +0000',
                    'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
                    'GIT_ALLOW_PROTOCOL': '', 'LC_ALL': 'C', 'LANG': 'C'})
        result = subprocess.run([self._git_executable, '-c', 'core.autocrlf=false',
                                 '-c', 'core.filemode=true', '-c', 'commit.gpgSign=false',
                                 '-c', 'core.hooksPath=' + os.devnull,
                                 '-c', 'core.quotepath=false', '-c', 'protocol.allow=never',
                                 *args], cwd=self.path, env=env, input=input,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                shell=False, check=True)
        return result.stdout

    def commit(self, files, parents=(), message='synthetic commit'):
        root = {}
        for path, (mode, data) in files.items():
            path = path.encode('utf-8') if type(path) is str else path
            current = root
            components = path.split(b'/')
            for component in components[:-1]:
                current = current.setdefault(component, {})
            if mode == '040000':
                if data != b'':
                    raise ValueError('empty directory marker requires empty bytes')
                current[components[-1]] = {}
                continue
            if mode == '160000':
                oid = data.decode('ascii') if type(data) is bytes else data
                kind = 'commit'
            else:
                oid = self.run('hash-object', '-w', '--stdin', input=data).strip().decode('ascii')
                kind = 'blob'
            current[components[-1]] = (mode, kind, oid)

        def make_tree(node):
            records = []
            for name, value in node.items():
                if isinstance(value, dict):
                    mode, kind, oid = '040000', 'tree', make_tree(value)
                else:
                    mode, kind, oid = value
                records.append((name + (b'/' if kind == 'tree' else b''),
                                f'{mode} {kind} {oid}\t'.encode('ascii') + name + b'\x00'))
            data = b''.join(record for _, record in sorted(records))
            return self.run('mktree', '-z', '--missing', input=data).strip().decode('ascii')

        tree = make_tree(root)
        args = ['commit-tree', tree]
        for parent in parents:
            args.extend(('-p', parent))
        return self.run(*args, input=(message + '\n').encode('utf-8')).strip().decode('ascii')
