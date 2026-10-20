"""Portable source inventory semantics and the pinned M1 inventory hash.

Git object IDs never stand in for file-byte digests. Paths are logical POSIX
strings, not host filesystem paths; rejecting aliases is deliberately identical
on every host. Directory entries describe all parents, without reading a tree.
"""
import re
import unicodedata
from collections.abc import Mapping

from . import hashing
from .errors import InputError

_ROLES = frozenset(('source', 'fixture', 'generator', 'schema', 'lock',
                    'configuration', 'tool', 'generated', 'policy'))
_FIELDS = frozenset(('path', 'kind', 'mode', 'size', 'bytesSha256', 'role'))
_HASH = re.compile(r'[0-9a-f]{64}')
_RESERVED = frozenset(('con', 'prn', 'aux', 'nul', 'conin$', 'conout$')) | frozenset(
    prefix + suffix for prefix in ('com', 'lpt') for suffix in '123456789¹²³')
# Git v2.54.0 utf8.c next_hfs_char/is_hfs_dotgit ignores these code points.
# https://github.com/git/git/blob/v2.54.0/utf8.c
# This is only a metadata-alias rejection, not general HFS normalization.
_HFS_DOTGIT_IGNORED = frozenset(chr(value) for value in (
    *range(0x200c, 0x2010), *range(0x202a, 0x202f),
    *range(0x206a, 0x2070), 0xfeff))


def validate_path(path):
    """Return the exact path or reject it; never repair or normalize input."""
    if type(path) is bytes:
        try:
            path = path.decode('utf-8', errors='strict')
        except UnicodeError:
            raise InputError('invalid inventory path') from None
    if type(path) is not str or not 1 <= len(path) <= 512:
        raise InputError('invalid inventory path')
    if unicodedata.normalize('NFC', path) != path:
        raise InputError('invalid inventory path')
    if any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f or
           0xd800 <= ord(ch) <= 0xdfff or ch in '\\:<>"|?*' for ch in path):
        raise InputError('invalid inventory path')
    for component in path.split('/'):
        if component in ('', '.', '..') or component[-1] in '. ':
            raise InputError('invalid inventory path')
        hfs_name = ''.join(ch for ch in component if ch not in _HFS_DOTGIT_IGNORED)
        if (component.casefold() in ('.git', 'git~1') or hfs_name.casefold() == '.git'
                or component.split('.', 1)[0].casefold() in _RESERVED):
            raise InputError('invalid inventory path')
    return path


def _parents(path):
    components = path.split('/')
    return ['/'.join(components[:i]) for i in range(1, len(components))]


def validate_paths(paths):
    """Check exact and Unicode-casefold collisions, including parent paths."""
    seen = set()
    folded = {}
    for value in paths:
        path = validate_path(value)
        if path in seen:
            raise InputError('duplicate inventory path')
        seen.add(path)
        for candidate in [*_parents(path), path]:
            key = candidate.casefold()
            if key in folded and folded[key] != candidate:
                raise InputError('inventory path collision')
            folded[key] = candidate
    return seen


def normalize_inventory(entries):
    """Validate a complete entry list and return its canonical inventory wrapper.

    Parents must be explicit here. build_inventory creates them from file data.
    This rejects redundant entries and file/directory aliasing before hashing.
    """
    if type(entries) is not list or not 1 <= len(entries) <= 100000:
        raise InputError('invalid inventory entries')
    paths = []
    by_path = {}
    for entry in entries:
        if type(entry) is not dict or set(entry) != _FIELDS:
            raise InputError('invalid inventory entry')
        path = validate_path(entry['path'])
        if type(entry['path']) is not str or type(entry['role']) is not str or entry['role'] not in _ROLES:
            raise InputError('invalid inventory entry')
        if type(entry['size']) is not int or not 0 <= entry['size'] <= 9007199254740991:
            raise InputError('invalid inventory entry')
        if entry['kind'] == 'file':
            if entry['mode'] not in ('100644', '100755') or type(entry['bytesSha256']) is not str or _HASH.fullmatch(entry['bytesSha256']) is None:
                raise InputError('invalid inventory entry')
        elif entry['kind'] == 'directory':
            if entry['mode'] != '040755' or entry['size'] != 0 or entry['bytesSha256'] is not None:
                raise InputError('invalid inventory entry')
        else:
            raise InputError('invalid inventory entry')
        paths.append(path)
        by_path[path] = entry
    validate_paths(paths)
    for path in paths:
        for parent in _parents(path):
            if parent not in by_path or by_path[parent]['kind'] != 'directory':
                raise InputError('inventory parent missing or not directory')
    wrapper = {'kind': 'source-inventory', 'version': 1,
               'canonicalizationVersion': 'ci-cjson-v1',
               'entries': [dict(entry) for entry in entries]}
    return hashing.project('inventory', wrapper)


def is_lfs_pointer(data):
    """Reject LFS marker bytes without asking Git to run filters or fetch data.

    Both current and historical pointer version URLs are recognized. The marker
    itself is sufficient to reject malformed pointers too, rather than pretend
    their text bytes are the large file promised by the source tree.
    """
    return data.startswith((b'version https://git-lfs.github.com/spec/v1',
                            b'version https://hawser.github.com/spec/v1'))


def build_inventory(files, roles=None, directories=()):
    """Build the complete inventory from path -> (Git mode, exact blob bytes)."""
    if not isinstance(files, Mapping) or (roles is not None and not isinstance(roles, Mapping)):
        raise InputError('invalid inventory input')
    roles = {} if roles is None else dict(roles)
    entries = {}
    directory_paths = [validate_path(path) for path in directories]
    validate_paths([*files, *directory_paths])
    for path in directory_paths:
        for directory in [*_parents(path), path]:
            entries[directory] = {'path': directory, 'kind': 'directory', 'mode': '040755',
                                  'size': 0, 'bytesSha256': None,
                                  'role': roles.get(directory, 'source')}
    for raw_path, value in files.items():
        path = validate_path(raw_path)
        if type(value) not in (tuple, list) or len(value) != 2:
            raise InputError('invalid inventory input')
        mode, data = value
        if mode not in ('100644', '100755') or type(data) is not bytes:
            raise InputError('unsupported source entry')
        if is_lfs_pointer(data):
            raise InputError('unsupported source entry')
        entries[path] = {'path': path, 'kind': 'file', 'mode': mode,
                         'size': len(data), 'bytesSha256': hashing.raw_hash(data),
                         'role': roles.get(path, 'source')}
        for parent in _parents(path):
            if parent not in entries:
                entries[parent] = {'path': parent, 'kind': 'directory', 'mode': '040755',
                                   'size': 0, 'bytesSha256': None,
                                   'role': roles.get(parent, 'source')}
    if any(type(path) is not str or path not in entries for path in roles):
        raise InputError('unknown inventory role path')
    return normalize_inventory(list(entries.values()))


def source_digest(inventory):
    """Hash a validated complete inventory with the pinned M1 domain prefix."""
    if type(inventory) is not dict or set(inventory) != {'kind', 'version', 'canonicalizationVersion', 'entries'}:
        raise InputError('invalid inventory wrapper')
    normalized = normalize_inventory(inventory['entries'])
    if any(inventory[key] != normalized[key] or type(inventory[key]) is not type(normalized[key])
           for key in ('kind', 'version', 'canonicalizationVersion')):
        raise InputError('invalid inventory wrapper')
    return hashing.domain_hash('inventory', normalized)
