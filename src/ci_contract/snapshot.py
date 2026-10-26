"""Local snapshot target (M8 C2): a working directory as an explicit, immutable inventory.

A snapshot plan reads its trusted controls from the base commit, exactly as a
commit plan does, and its target files from a directory. The inventory is the
base commit's file paths that still exist in the directory plus explicitly
included paths (untracked or ignored inputs are never picked up silently); a
base path that no longer exists is a deletion. Links, reparse points, hardlinks
and non-regular entries, in the file or any parent folder, are refused. The
snapshot never claims a target commit or tree (spec section 3: the working tree
is not "the previous commit").

A new file's mode is 100755 only when the POSIX owner-execute bit is set; on
Windows a new file is 100644 and an existing file keeps its base mode.
"""
import hashlib
import os
import stat
from .errors import InputError, BlockedError
from .inventory import build_inventory, source_digest, validate_path, validate_paths

_REPARSE = getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)


def _git_blob_id(data):
    return hashlib.sha1(b'blob ' + str(len(data)).encode('ascii') + b'\0' + data).hexdigest()


def _unsupported(info):
    if getattr(info, 'st_file_attributes', 0) & _REPARSE:
        return True
    return stat.S_ISLNK(info.st_mode)


class SnapshotTarget:
    """The target side of a snapshot plan; read once, at construction."""

    def __init__(self, directory, git, base, include=()):
        if type(directory) is not str or not os.path.isabs(directory):
            raise InputError('snapshot directory must be absolute')
        if type(include) not in (list, tuple):
            raise InputError('invalid snapshot include list')
        self.directory = directory
        try:
            root = os.lstat(directory)
        except OSError:
            raise BlockedError('snapshot-unavailable') from None
        if _unsupported(root) or not stat.S_ISDIR(root.st_mode):
            raise BlockedError('snapshot-unsupported-entry')
        self._base_entries = git.entries(base, 'base')
        included = [validate_path(path) for path in include]
        if len(set(included)) != len(included) or set(included) & set(self._base_entries):
            raise InputError('invalid snapshot include list')
        validate_paths([*self._base_entries, *included])
        self._files = {}
        for path in sorted(self._base_entries):
            found = self._read(path, required=False)
            if found is not None:
                self._files[path] = (self._base_entries[path][0], found[0])
        for path in included:
            data, bits = self._read(path, required=True)
            mode = '100755' if os.name != 'nt' and bits & stat.S_IXUSR else '100644'
            self._files[path] = (mode, data)
        if not self._files:
            raise BlockedError('snapshot-empty')

    def _locate(self, path, *, required):
        """(full path, lstat) of a regular single-link file under plain folders, or None when absent."""
        current = self.directory
        for part in path.split('/')[:-1]:
            current = os.path.join(current, part)
            try:
                info = os.lstat(current)
            except FileNotFoundError:
                if required:
                    raise BlockedError('snapshot-input-missing') from None
                return None
            except OSError:
                raise BlockedError('snapshot-unavailable') from None
            if _unsupported(info) or not stat.S_ISDIR(info.st_mode):
                raise BlockedError('snapshot-unsupported-entry')
        full = os.path.join(current, path.split('/')[-1])
        try:
            info = os.lstat(full)
        except FileNotFoundError:
            if required:
                raise BlockedError('snapshot-input-missing') from None
            return None
        except OSError:
            raise BlockedError('snapshot-unavailable') from None
        if _unsupported(info) or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise BlockedError('snapshot-unsupported-entry')
        return full, info

    def _read(self, path, *, required):
        located = self._locate(path, required=required)
        if located is None:
            return None
        full, info = located
        try:
            with open(full, 'rb') as handle:
                data = handle.read()
            after = os.lstat(full)
        except OSError:
            raise BlockedError('snapshot-unavailable') from None
        if (after.st_size != len(data) or after.st_mtime_ns != info.st_mtime_ns
                or getattr(after, 'st_ino', 0) != getattr(info, 'st_ino', 0)):
            raise BlockedError('snapshot-changed-while-read')
        return data, info.st_mode

    def read_blob(self, commit, path, side='target'):
        """Same interface as GitSource.read_blob for the target side; commit is ignored."""
        entry = self._files.get(validate_path(path))
        if entry is None:
            raise BlockedError('source-input-unavailable')
        return entry[1]

    def paths(self, commit=None, side='target'):
        result = set(self._files)
        for path in self._files:
            parts = path.split('/')
            result.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        return frozenset(result)

    def files(self):
        """A fresh path -> (mode, bytes) mapping of every snapshot file."""
        return dict(self._files)

    def changes(self):
        """File changes against the base commit (as GitSource.changes; rename is delete+add)."""
        result = []
        for path, (mode, oid) in self._base_entries.items():
            entry = self._files.get(path)
            if entry is None:
                result.append({'status': 'delete', 'path': path})
            elif entry[0] != mode or _git_blob_id(entry[1]) != oid:
                result.append({'status': 'modify', 'path': path})
        for path in self._files:
            if path not in self._base_entries:
                result.append({'status': 'add', 'path': path})
        return sorted(result, key=lambda change: (change['path'], change['status']))

    def source(self, base, roles=None):
        inventory = build_inventory(self._files, roles)
        return {'mode': 'snapshot', 'baseCommit': base, 'targetCommit': None, 'tree': None,
                'digest': source_digest(inventory), 'inputs': inventory['entries'], 'immutable': True,
                'comparison': 'snapshot'}


def _roles(source):
    return {entry['path']: entry['role'] for entry in source['inputs']}


def _declared_files(source):
    return [entry for entry in source['inputs'] if entry['kind'] == 'file']


def _digest(files, source):
    directories = [entry['path'] for entry in source['inputs'] if entry['kind'] == 'directory']
    inventory = build_inventory(files, _roles(source), directories)
    return source_digest(inventory), inventory['entries']


def materialize(source, destination, *, repo_path=None, snapshot_dir=None):
    """Write the plan's declared inputs to a new private folder and return their digest.

    A commit source is read from the repository's target commit; a snapshot source
    from its directory, with the same link and hardlink refusals as planning. The
    written files must reproduce the plan's inventory exactly (paths, modes, bytes
    and roles); any difference is stale (5): the source changed after planning.
    """
    from .request import StaleError
    if os.path.lexists(destination):
        raise InputError('materialization folder must not exist')
    files = {}
    if source['mode'] == 'commit':
        if repo_path is None or snapshot_dir is not None:
            raise InputError('a commit source needs the repository path')
        from .gitsource import GitSource
        git = GitSource(repo_path)
        entries = git.entries(source['targetCommit'])
        wanted = {entry['path']: entries.get(entry['path']) for entry in _declared_files(source)}
        if any(value is None for value in wanted.values()):
            raise StaleError('source-changed')
        blobs = git._objects((oid for _, oid in wanted.values()), 'blob')
        files = {path: (mode, blobs[oid]) for path, (mode, oid) in wanted.items()}
    else:
        if snapshot_dir is None or repo_path is not None:
            raise InputError('a snapshot source needs its directory')
        reader = _SnapshotReader(snapshot_dir)
        for entry in _declared_files(source):
            found = reader.read(entry['path'])
            if found is None:
                raise StaleError('source-changed')
            files[entry['path']] = (entry['mode'], found)
    digest, entries = _digest(files, source)
    if digest != source['digest'] or entries != source['inputs']:
        raise StaleError('source-changed')
    os.mkdir(destination)
    for entry in source['inputs']:
        if entry['kind'] == 'directory':
            os.makedirs(os.path.join(destination, *entry['path'].split('/')), exist_ok=True)
    for path, (mode, data) in files.items():
        target = os.path.join(destination, *path.split('/'))
        os.makedirs(os.path.dirname(target), exist_ok=True)
        with open(target, 'xb') as handle:
            handle.write(data)
        if mode == '100755' and os.name != 'nt':
            os.chmod(target, 0o755)
    return digest


def digest_after(source, destination, tick=None):
    """The declared inventory as it stands in the private folder after the checks ran.

    A changed declared file gives another digest; a declared file that is missing
    or replaced by a directory, a link, a reparse point or a hardlink gives None.
    The caller treats both as stale. Files the checks created outside the declared
    paths are outputs. ``tick`` is called before each file (the supervisor renews
    its claim there; whatever it raises ends the measurement).
    """
    reader = _SnapshotReader(destination)
    files = {}
    for entry in _declared_files(source):
        if tick is not None:
            tick()
        try:
            found = reader.read(entry['path'])
        except BlockedError:
            return None  # a directory, link, reparse point or hardlink: not the planned input
        if found is None:
            return None
        files[entry['path']] = (entry['mode'], found)
    try:
        return _digest(files, source)[0]
    except InputError:
        return None


_CHUNK = 1024 * 1024


def stream_declared(directory, path, *, limit, sink=None, tick=None):
    """Hash one file of a private folder in chunks, with the snapshot refusals.

    Returns (sha256, size), or None when the file is missing, a link, a reparse
    point, a hardlink or not a regular file (itself or a parent folder), larger
    than ``limit`` bytes, unreadable, or changed while read. ``sink`` receives
    every chunk (its errors are None too); ``tick`` is called before each chunk
    and whatever it raises propagates. No more than one chunk is held at a time.
    """
    reader = _SnapshotReader(directory)
    try:
        located = reader._locate(validate_path(path), required=False)
    except (InputError, BlockedError):
        return None
    if located is None:
        return None
    full, info = located
    if info.st_size > limit:
        return None
    digest, size = hashlib.sha256(), 0
    try:
        with open(full, 'rb') as handle:
            while True:
                if tick is not None:
                    tick()
                chunk = handle.read(_CHUNK)
                if not chunk:
                    break
                size += len(chunk)
                if size > limit:
                    return None
                digest.update(chunk)
                if sink is not None:
                    sink(chunk)
        after = os.lstat(full)
    except OSError:
        return None
    if (after.st_size != size or after.st_mtime_ns != info.st_mtime_ns
            or getattr(after, 'st_ino', 0) != getattr(info, 'st_ino', 0)):
        return None
    return digest.hexdigest(), size


class _SnapshotReader(SnapshotTarget):
    """Reads single declared files with the snapshot refusals, without a base commit."""

    def __init__(self, directory):
        self.directory = directory

    def read(self, path):
        found = self._read(validate_path(path), required=False)
        return None if found is None else found[0]
