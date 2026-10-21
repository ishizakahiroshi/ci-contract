"""Read fixed commit objects using only four read-only Git plumbing commands.

No worktree file, index, filter, hook, network transport, or Git writer is used.
Inherited GIT_* variables are discarded before a fixed environment is applied.
Local config cannot enable external diffs, replacement objects, lazy fetching,
text conversion, or filesystem monitoring for these operations.
"""
import hashlib
import os
import re
import subprocess
from collections import deque
from contextlib import contextmanager, suppress

from .errors import BlockedError, InputError
from .inventory import build_inventory, source_digest, validate_path, validate_paths

_SHA = re.compile(r'[0-9a-f]{40}')
_MAX_SOURCE_ENTRIES = 10000
_MAX_ANCESTRY_DEPTH = 256
_MAX_ANCESTRY_COMMITS = 10000
_MAX_ANCESTRY_DISCOVERED = 10000
_MAX_ANCESTRY_COMMIT_BYTES = 1024 * 1024
_BATCH_EXIT_SECONDS = 10
_SIDES = frozenset(('base', 'target', 'projection-anchor'))
# Command-line config wins over repository config, without writing any config.
_SETTINGS = (
    'core.quotepath=false', 'core.fsmonitor=false', 'core.untrackedCache=false',
    'core.attributesFile=' + os.devnull, 'core.hooksPath=' + os.devnull,
    'core.pager=cat', 'color.ui=false', 'diff.renames=false', 'diff.external=',
    'diff.ignoreSubmodules=none', 'diff.orderFile=' + os.devnull,
    'diff.relative=false', 'protocol.allow=never', 'protocol.file.allow=never',
    'protocol.ext.allow=never', 'maintenance.auto=false', 'gc.auto=0',
    'safe.bareRepository=all',
)


def _environment():
    env = {key: value for key, value in os.environ.items() if not key.upper().startswith('GIT_')}
    env.update({'GIT_CONFIG_NOSYSTEM': '1', 'GIT_CONFIG_SYSTEM': os.devnull,
                'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_TERMINAL_PROMPT': '0',
                'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_NO_LAZY_FETCH': '1',
                'GIT_OPTIONAL_LOCKS': '0', 'GIT_ATTR_NOSYSTEM': '1',
                'GIT_ALLOW_PROTOCOL': '', 'GIT_PROTOCOL_FROM_USER': '0',
                'GIT_PAGER': 'cat', 'LC_ALL': 'C', 'LANG': 'C'})
    return env


def _sha(value):
    if type(value) is not str or _SHA.fullmatch(value) is None:
        raise InputError('full lowercase commit SHA required')
    return value



def _within(path, root):
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:  # Different Windows drives cannot contain one another.
        return False


def _windows_device_path(path):
    return path.replace('/', '\\').startswith(('\\\\?\\', '\\\\.\\'))


def _windows_unc_path(path):
    return os.name == 'nt' and path.replace('/', '\\').startswith('\\\\')


def _resolve_git(repo_path, *, path=None, cwd=None):
    """Resolve once from absolute PATH entries, never OS current-dir lookup.

    Exclude the current directory and repository descendants by lexical,
    resolved and filesystem identities. CWD descendants remain eligible.
    Quotes, Windows UNC entries and device/extended prefixes are skipped,
    not stripped. Unstatable entries/ancestors are skipped; unavailable root
    identities block resolution rather than weaken the exclusions.
    Do not use shutil.which: Windows may prepend CWD to its search.
    """
    cwd = os.getcwd() if cwd is None else cwd

    def root_identities(root):
        root = os.fspath(root)
        if _windows_device_path(root):
            raise BlockedError('git-unavailable')
        identities = set()
        for resolve in (os.path.abspath, os.path.realpath):
            identity = resolve(root)
            if _windows_device_path(identity):
                raise BlockedError('git-unavailable')
            identities.add(os.path.normcase(identity))
        return identities

    cwd_roots = root_identities(cwd)
    repo_roots = root_identities(repo_path)

    def filesystem_identity(directory):
        metadata = os.stat(directory)
        return metadata.st_dev, metadata.st_ino

    try:
        cwd_identity = filesystem_identity(cwd)
        repo_identity = filesystem_identity(repo_path)
    except (OSError, ValueError):
        raise BlockedError('git-unavailable') from None

    def excluded(directory):
        if (directory in cwd_roots or
                any(_within(directory, root) for root in repo_roots)):
            return True
        try:
            identity = filesystem_identity(directory)
            if identity == cwd_identity:
                return True
            # Check ancestors too: an alternate spelling of the repository
            # root must not make its descendants eligible.
            while True:
                if identity == repo_identity:
                    return True
                parent = os.path.dirname(directory)
                if parent == directory:
                    return False
                directory = parent
                identity = filesystem_identity(directory)
        except (OSError, ValueError):
            return True

    path = os.environ.get('PATH', '') if path is None else path
    executable = 'git.exe' if os.name == 'nt' else 'git'
    for directory in path.split(os.pathsep):
        # Reject before normalization/comparison, including under Windows path
        # emulation. Forward slashes can spell Windows device prefixes too.
        if (not directory or '"' in directory or '\x00' in directory
                or _windows_device_path(directory)
                or _windows_unc_path(directory)
                or not os.path.isabs(directory)):
            continue
        try:
            lexical = os.path.normcase(os.path.abspath(directory))
            directory = os.path.normcase(os.path.realpath(directory))
        except (OSError, ValueError):
            continue
        if (_windows_device_path(directory)
                or _windows_unc_path(directory)
                or any(excluded(location) for location in (lexical, directory))):
            continue
        try:
            candidate = os.path.realpath(os.path.join(directory, executable))
        except (OSError, ValueError):
            continue
        if (_windows_device_path(candidate)
                or _windows_unc_path(candidate)
                or excluded(os.path.normcase(os.path.dirname(candidate)))):
            continue
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return os.path.abspath(candidate)
    raise BlockedError('git-unavailable')


class GitSource:
    """A repository object reader. All public commit arguments are exact SHA-1."""

    def __init__(self, repo_path):
        try:
            self.repo_path = os.fspath(repo_path)
        except TypeError:
            raise InputError('invalid repository location') from None
        if type(self.repo_path) is not str or not self.repo_path or '\x00' in self.repo_path:
            raise InputError('invalid repository location')
        self.repo_path = os.path.abspath(self.repo_path)
        self._git_dir = None
        self._git_executable = None
        self._entries_cache = {}
        self._directories_cache = {}
        self._verified = set()

    def _command(self, git_dir, args):
        command = [self._git_executable, '--no-pager']
        for setting in _SETTINGS:
            command.extend(('-c', setting))
        return [*command, '--git-dir=' + git_dir, *args]

    def _prepare(self):
        if self._git_dir is not None:
            return
        # .git metadata has exclusive priority. Never let checkout-root HEAD,
        # refs or objects shadow it, or follow gitfile indirection on any OS.
        metadata = os.path.join(self.repo_path, '.git')
        candidate = metadata if os.path.lexists(metadata) else self.repo_path
        if not os.path.isdir(candidate):
            raise BlockedError('repository-unavailable')
        self._git_executable = _resolve_git(self.repo_path)
        # An empty batch validates this exact object database. There is no
        # upward discovery, fallback candidate or reliance on a trailing dot.
        self._invoke(self._command(candidate, ['cat-file', '--batch']), b'',
                     'repository-unavailable')
        self._git_dir = candidate

    def _run(self, args, *, data=None, reason='source-input-unavailable'):
        # A closed internal allowlist prevents accidentally growing a Git writer
        # as new features are added. Public input never supplies command options.
        permitted = (
            args[:2] == ['rev-parse', '--verify'] or
            args[:2] in (['cat-file', '-e'], ['cat-file', '-t'], ['cat-file', '--batch']) or
            args[:6] == ['ls-tree', '-r', '-z', '--full-tree', '-t', '--'] or
            args[:4] == ['diff-tree', '-r', '-z', '--no-renames']
        )
        if not permitted:
            raise InputError('unsupported git operation')
        self._prepare()
        return self._invoke(self._command(self._git_dir, args), data, reason)

    def _invoke(self, command, data, reason):
        try:
            result = subprocess.run(command, cwd=self.repo_path, env=_environment(),
                                    input=data, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL, shell=False, check=False)
        except (OSError, ValueError):
            raise BlockedError('repository-unavailable') from None
        if result.returncode:
            raise BlockedError(reason)
        return result.stdout

    def verify_commit(self, sha, side='target'):
        sha = _sha(sha)
        if side not in _SIDES:
            raise InputError('invalid commit side')
        if sha not in self._verified:
            kind = self._run(['cat-file', '-t', sha], reason=side + '-not-recoverable')
            if kind != b'commit\n':
                raise InputError('commit object required')
            self._verified.add(sha)
        return sha

    def _entries(self, commit, side):
        commit = self.verify_commit(commit, side)
        if commit in self._entries_cache:
            return self._entries_cache[commit]
        raw = self._run(['ls-tree', '-r', '-z', '--full-tree', '-t', '--', commit],
                        reason=side + '-not-recoverable')
        if raw and not raw.endswith(b'\x00'):
            raise InputError('invalid git tree output')
        result = {}
        directories = []
        paths = []
        for record in raw.split(b'\x00')[:-1]:
            # Count file AND directory entries before any blob request. The
            # source schema bounds the complete inventory, not only files.
            if len(paths) >= _MAX_SOURCE_ENTRIES:
                raise InputError('source inventory exceeds schema limit')
            try:
                header, raw_path = record.split(b'\t', 1)
                mode, kind, oid = header.decode('ascii').split(' ')
            except (ValueError, UnicodeError):
                raise InputError('invalid git tree output') from None
            path = validate_path(raw_path)
            if _SHA.fullmatch(oid) is None:
                raise InputError('unsupported source entry')
            paths.append(path)
            if mode == '040000' and kind == 'tree':
                directories.append(path)
            elif mode in ('100644', '100755') and kind == 'blob':
                result[path] = (mode, oid)
            else:
                raise InputError('unsupported source entry')
        validate_paths(paths)
        self._entries_cache[commit] = result
        self._directories_cache[commit] = directories
        return result

    def entries(self, commit, side='target'):
        """Return a fresh file path -> (100644/100755, object ID) mapping."""
        return dict(self._entries(commit, side))

    def paths(self, commit, side='target'):
        """Return file AND directory paths for one-time inventory role filtering."""
        entries = self._entries(commit, side)
        return frozenset(entries) | frozenset(self._directories_cache[commit])

    def _objects(self, oids, kind, reason='source-input-unavailable'):
        """Read one batch without quadratic slicing of the remaining response.

        Even a syntactically valid batch header is not proof of object identity:
        verify Git's SHA-1 header+payload hash for every object read. Raw tree
        objects are not independently rehashed by the ls-tree inventory reader.
        """
        oids = list(dict.fromkeys(oids))
        if not oids:
            return {}
        raw = self._run(['cat-file', '--batch'],
                        data=''.join(oid + '\n' for oid in oids).encode('ascii'),
                        reason=reason)
        offset = 0
        result = {}
        for oid in oids:
            end = raw.find(b'\n', offset)
            if end < 0:
                raise BlockedError(reason)
            try:
                actual, actual_kind, size_text = raw[offset:end].split(b' ')
                size = int(size_text)
            except ValueError:
                raise BlockedError(reason) from None
            start = end + 1
            end = start + size
            if (actual != oid.encode('ascii') or actual_kind != kind.encode('ascii')
                    or size < 0 or str(size).encode('ascii') != size_text
                    or end >= len(raw) or raw[end:end + 1] != b'\n'):
                raise BlockedError(reason)
            payload = raw[start:end]
            identity = hashlib.sha1(kind.encode('ascii') + b' ' + size_text + b'\0' + payload).hexdigest()
            if identity != oid:
                raise BlockedError(reason)
            result[oid] = payload
            offset = end + 1
        if offset != len(raw):
            raise BlockedError(reason)
        return result

    def _blob(self, oid):
        return self._objects((oid,), 'blob')[oid]

    def read_blob(self, commit, path, side='target'):
        path = validate_path(path)
        entry = self._entries(commit, side).get(path)
        if entry is None:
            raise BlockedError('source-input-unavailable')
        return self._blob(entry[1])

    @contextmanager
    def _commit_batch(self):
        """One binary, read-only session; request and drain each object in turn.

        The command is fixed rather than caller-supplied. Incremental exchange
        avoids both per-generation processes and pipe-capacity deadlocks.
        """
        self._prepare()
        reason = 'projection-ancestry-unavailable'
        try:
            process = subprocess.Popen(
                self._command(self._git_dir, ['cat-file', '--batch']),
                cwd=self.repo_path, env=_environment(), stdin=subprocess.PIPE,
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, shell=False)
        except (OSError, ValueError):
            raise BlockedError('repository-unavailable') from None

        def read(oid):
            process.stdin.write((oid + '\n').encode('ascii'))
            process.stdin.flush()
            header = process.stdout.readline(256)
            if not header.endswith(b'\n'):
                raise BlockedError(reason)
            try:
                actual, kind, size_text = header[:-1].split(b' ')
                size = int(size_text)
            except ValueError:
                raise BlockedError(reason) from None
            if (actual != oid.encode('ascii') or kind != b'commit' or size < 0
                    or str(size).encode('ascii') != size_text):
                raise BlockedError(reason)
            if size > _MAX_ANCESTRY_COMMIT_BYTES:
                raise BlockedError('projection-ancestry-limit-exceeded')
            payload = process.stdout.read(size)
            if len(payload) != size or process.stdout.read(1) != b'\n':
                raise BlockedError(reason)
            identity = hashlib.sha1(b'commit ' + size_text + b'\0' + payload).hexdigest()
            if identity != oid:
                raise BlockedError(reason)
            return payload

        try:
            yield read
            process.stdin.close()
            if process.wait():
                raise BlockedError(reason)
        except OSError:
            raise BlockedError(reason) from None
        finally:
            # Close the pipes before waiting: Git sees end of input (or a broken
            # output pipe) and exits on its own, so wait() returns only after
            # every process it started has ended. Killing first would end only
            # the started process; Git for Windows' cmd launcher then leaves the
            # git.exe it started holding the object files for a moment. The
            # kill below is only for a git that has not exited in time, and on
            # Windows it has the same limitation.
            with suppress(OSError):
                process.stdin.close()
            with suppress(OSError):
                process.stdout.close()
            try:
                process.wait(timeout=_BATCH_EXIT_SECONDS)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def require_ancestor(self, anchor, base):
        """Require an available projection anchor in raw base commit ancestry.

        Read parent headers from commit objects, not refs or revision walking:
        replacement refs, graft files and shallow boundaries cannot invent the
        anchor relationship. At most 256 parent edges, 10,000 distinct
        discovered commits (including base), and 10,000 commit reads of at
        most 1 MiB each are permitted. Missing ancestry and exhausted bounds
        fail closed.
        """
        anchor = self.verify_commit(anchor, 'projection-anchor')
        base = self.verify_commit(base, 'base')
        pending = deque(((base, 0),))
        visited = {base}
        read_count = 0
        depth_exceeded = False
        with self._commit_batch() as read:
            while pending:
                if read_count >= _MAX_ANCESTRY_COMMITS:
                    raise BlockedError('projection-ancestry-limit-exceeded')
                oid, depth = pending.popleft()
                data = read(oid)
                read_count += 1
                if oid == anchor:
                    return
                headers, separator, _ = data.partition(b'\n\n')
                if not separator:
                    raise InputError('invalid git commit output')
                for line in headers.split(b'\n'):
                    if line.startswith(b'parent '):
                        try:
                            parent = line[7:].decode('ascii')
                        except UnicodeError:
                            raise InputError('invalid git commit output') from None
                        if _SHA.fullmatch(parent) is None:
                            raise InputError('invalid git commit output')
                        if parent not in visited:
                            if depth >= _MAX_ANCESTRY_DEPTH:
                                depth_exceeded = True
                            else:
                                if len(visited) >= _MAX_ANCESTRY_DISCOVERED:
                                    raise BlockedError('projection-ancestry-limit-exceeded')
                                visited.add(parent)
                                pending.append((parent, depth + 1))
        if depth_exceeded:
            raise BlockedError('projection-ancestry-limit-exceeded')
        raise BlockedError('projection-anchor-not-ancestor')

    def changes(self, base, target):
        """Return Git file-entry changes; rename is delete+add.

        Explicit empty-tree additions have no Git file delta. They are still
        committed by source inventory/digest; directory-only selection is not
        implemented by this file-change adapter.
        """
        base = self.verify_commit(base, 'base')
        target = self.verify_commit(target, 'target')
        self._entries(base, 'base')
        self._entries(target, 'target')
        raw = self._run(['diff-tree', '-r', '-z', '--no-renames', '--no-commit-id',
                         '--name-status', '--no-ext-diff', '--no-textconv',
                         '--ignore-submodules=none', '--no-relative', base, target, '--'])
        if raw and not raw.endswith(b'\x00'):
            raise InputError('invalid git diff output')
        fields = raw.split(b'\x00')[:-1]
        if len(fields) % 2:
            raise InputError('invalid git diff output')
        result = []
        statuses = {b'A': 'add', b'M': 'modify', b'D': 'delete', b'T': 'modify'}
        for i in range(0, len(fields), 2):
            if fields[i] not in statuses:
                raise InputError('unsupported git change')
            result.append({'status': statuses[fields[i]], 'path': validate_path(fields[i + 1])})
        if len({change['path'] for change in result}) != len(result):
            raise InputError('duplicate git change')
        return sorted(result, key=lambda change: (change['path'], change['status']))

    def source(self, base, target, roles=None, side='target'):
        base = self.verify_commit(base, 'base')
        target = self.verify_commit(target, side)
        entries = self._entries(target, side)
        blobs = self._objects((oid for _, oid in entries.values()), 'blob')
        files = {path: (mode, blobs[oid]) for path, (mode, oid) in entries.items()}
        inventory = build_inventory(files, roles, self._directories_cache[target])
        tree = self._run(['rev-parse', '--verify', target + '^{tree}'],
                         reason=side + '-not-recoverable')
        try:
            tree = tree.removesuffix(b'\n').decode('ascii')
        except UnicodeError:
            raise InputError('invalid git tree output') from None
        if _SHA.fullmatch(tree) is None:
            raise InputError('invalid git tree output')
        return {'mode': 'commit', 'baseCommit': base, 'targetCommit': target,
                'tree': tree, 'digest': source_digest(inventory),
                'inputs': inventory['entries'], 'immutable': True,
                'comparison': 'head'}
