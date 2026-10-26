"""Local single-supervisor authority journal (spec F05, local side only).

The journal is the authority record for CLI-local execution and explicit
dispatch. It is written only at the location the caller names. No default
location, directory or configuration is created. Every transaction takes an OS
advisory lock on a sidecar lock file, re-reads and verifies every record, and
only then decides and appends. A lock file's existence or a matching hash is not
evidence of acquisition: only the OS lock held for the transaction is.

Each record is ci-cjson-v1 canonical bytes followed by LF. The record hash is
the pinned ``journal-record`` domain hash of the closed header and typed payload
projection. ``recordSha256`` and the current-record backlinks
(``claim.ledgerRecordSha256``, ``attemptAuthority.adoptionRecordSha256``) are the
only excluded fields. Records are never rewritten, truncated, reordered or
renumbered. A journal that cannot be verified is reported as unknown, never
repaired.

No network, Git, worktree or child process is used here. Operating-system
queries are behind a replaceable probe so tests can supply synthetic values.

An optional anchor (M8 C2) is a small file at a second caller path, in another
directory than the journal. It names the journal and its last record (sequence
and hash) and is rewritten after every append. Opening a journal whose records
end before, beside or more than one record past the anchor is unknown (8), and a
journal cannot be created again while its anchor exists. One record past the
anchor is a crash between the two writes and is caught up. Without an anchor the
deletion of whole trailing records and a recreated journal stay undetected.
"""
import copy
from contextlib import contextmanager
from functools import lru_cache
import ntpath
import os
import posixpath
import re
import stat
from . import cjson
from .errors import InputError, BlockedError
from .hashing import domain_hash
from .request_binding import check_binding_times, _utc
from .schema import load_schema, make_validator

AUTHORITY_KIND = 'local-single-supervisor-v1'
RECORD_KEYS = frozenset({'sequence', 'fence', 'previousRecordSha256', 'recordType',
                         'payloadKind', 'payloadProjection', 'recordSha256'})
# Record type -> pinned payload kind. The pinned projection has no request
# document payload, so a request's state is the type of its latest record.
RECORD_TYPES = {
    'request': 'requestBinding',
    'claim-acquired': 'claim',
    'claim-coalesced': 'claim',
    'claim-heartbeat': 'claim',
    'claim-orphaned': 'claim',
    'claim-closed': 'claim',
    'submit-unknown': 'claim',
    'adoption': 'attemptAuthority',
    'retry-approval': 'requestBinding',
    'receipt': 'result',
    'receipt-conflict': 'result',
}
PAYLOAD_DEFINITIONS = {'requestBinding': 'requestBinding', 'claim': 'localSupervisorClaim',
                       'attemptAuthority': 'attemptAuthority', 'result': 'result'}
DRIVE_FIXED = 3
DRIVE_REMOTE = 4
_DEVICE_NAMES = frozenset(['con', 'prn', 'aux', 'nul', 'conin$', 'conout$']
                          + ['com' + digit for digit in '0123456789']
                          + ['lpt' + digit for digit in '0123456789'])
_PENDING = '0' * 64
ANCHOR_KIND = 'ci-contract-journal-anchor'
ANCHOR_KEYS = frozenset({'kind', 'version', 'authorityId', 'journal', 'sequence', 'recordSha256'})
LOCK_ATTEMPTS = 6
_BINARY = getattr(os, 'O_BINARY', 0)
_NOFOLLOW = getattr(os, 'O_NOFOLLOW', 0)


class AuthorityUnknown(RuntimeError):
    """What was acquired or sent cannot be established (exit 8). Fixed reason code."""

    def __init__(self, reason_code):
        super().__init__(reason_code)
        self.reason_code = reason_code


@lru_cache(maxsize=None)
def _validator(definition):
    schema = load_schema()
    return make_validator({'$schema': schema['$schema'], '$defs': schema['$defs'],
                           '$ref': '#/$defs/' + definition})


def conforms(definition, value):
    """True when value matches one pinned schema definition (closed, offline)."""
    cjson.dumps(value)
    return next(_validator(definition).iter_errors(value), None) is None


class SystemProbe:
    """Operating-system queries for the placement check. Tests replace this object."""
    windows = os.name == 'nt'
    path = ntpath if os.name == 'nt' else posixpath

    def abspath(self, value):
        return os.path.abspath(value)

    def realpath(self, value):
        return os.path.realpath(value, strict=True)

    def isdir(self, value):
        return os.path.isdir(value)

    def exists(self, value):
        return os.path.lexists(value)

    def unsafe_entry(self, value):
        """An existing entry that is not one plain regular file (link, reparse, hardlink...)."""
        try:
            info = os.lstat(value)
        except FileNotFoundError:
            return False
        except OSError:
            return True
        attributes = getattr(info, 'st_file_attributes', 0)
        return (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or bool(attributes & getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0x400)))

    def samefile(self, left, right):
        try:
            return os.path.samefile(left, right)
        except OSError:
            return False

    def drive_type(self, root):
        import ctypes
        function = ctypes.WinDLL('kernel32', use_last_error=True).GetDriveTypeW
        function.argtypes = [ctypes.c_wchar_p]
        function.restype = ctypes.c_uint
        return function(root)

    def owner_mode(self, value):
        info = os.stat(value)
        return info.st_uid, stat.S_IMODE(info.st_mode)

    def effective_uid(self):
        return os.geteuid()


class Location:
    """Checked journal, lock and directory paths, resolved through the probe."""

    def __init__(self, journal, lock, directory):
        self.journal, self.lock, self.directory = journal, lock, directory


def _spelling(value, windows):
    if windows:
        text = value.replace('/', '\\')
        if text.startswith('\\\\'):
            if text[2:4] in ('?\\', '.\\'):
                raise BlockedError('journal-location-device-path')
            raise BlockedError('journal-location-unc')
        drive, rest = ntpath.splitdrive(text)
        if re.fullmatch('[A-Za-z]:', drive) is None or not rest.startswith('\\'):
            raise BlockedError('journal-location-relative')
        for part in rest.split('\\'):
            if ':' in part:
                raise BlockedError('journal-location-device-path')
            if part.split('.')[0].rstrip(' ').lower() in _DEVICE_NAMES:
                raise BlockedError('journal-location-device-path')
    else:
        if value.startswith('//'):
            raise BlockedError('journal-location-unc')
        if not value.startswith('/'):
            raise BlockedError('journal-location-relative')


def _inside(flavor, child, parent):
    child, parent = flavor.normcase(child), flavor.normcase(parent)
    try:
        return flavor.commonpath([child, parent]) == parent
    except ValueError:
        return False


def _identity_inside(probe, flavor, child, root):
    current = child
    while True:
        if probe.samefile(current, root):
            return True
        parent = flavor.dirname(current)
        if parent == current:
            return False
        current = parent


def check_location(journal_path, repository_roots, probe=None):
    """Return a Location or raise BlockedError with a fixed reason code.

    Rejected: relative paths; UNC, extended/device prefixes, reserved device
    names and stream syntax; a remote or non-fixed Windows drive; a directory
    that does not already exist; links, reparse points or hardlinks as journal
    or lock entries; anything at or below a supplied repository root (lexically
    after resolution, or by filesystem identity of an ancestor); on POSIX, a
    directory or entry not owned by the effective user, or writable by group or
    other. Cloud-synchronized folders cannot be reliably identified through
    these queries and are not claimed to be detected.

    An exception raised by the probe itself is not a verdict on the location:
    it is reported as journal-location-unverified (4) (fix 4, F4).
    """
    probe = SystemProbe() if probe is None else probe
    try:
        return _check_location(journal_path, repository_roots, probe)
    except (InputError, BlockedError):
        raise
    except Exception:
        raise BlockedError('journal-location-unverified') from None


def _check_location(journal_path, repository_roots, probe):
    flavor = probe.path
    if type(journal_path) is not str or not journal_path or '\x00' in journal_path:
        raise InputError('invalid journal path')
    if (type(repository_roots) is not list or not repository_roots
            or any(type(root) is not str or '\x00' in root for root in repository_roots)):
        raise InputError('invalid repository roots')
    if any(not flavor.isabs(root) for root in repository_roots):
        raise InputError('repository roots must be absolute')
    _spelling(journal_path, probe.windows)
    absolute = probe.abspath(journal_path)
    directory = flavor.dirname(absolute)
    if not probe.isdir(directory):
        raise BlockedError('journal-location-missing-directory')
    try:
        resolved = probe.realpath(directory)
    except OSError:
        raise BlockedError('journal-location-missing-directory') from None
    _spelling(resolved, probe.windows)
    if probe.windows:
        for value in (absolute, resolved):
            kind = probe.drive_type(flavor.splitdrive(value)[0] + '\\')
            if kind == DRIVE_REMOTE:
                raise BlockedError('journal-location-remote-drive')
            if kind != DRIVE_FIXED:
                raise BlockedError('journal-location-drive-unsupported')
    journal = flavor.join(resolved, flavor.basename(absolute))
    lock = journal + '.lock'
    for entry in (journal, lock):
        if probe.unsafe_entry(entry):
            raise BlockedError('journal-location-unsafe-entry')
    for root in repository_roots:
        try:
            resolved_root = probe.realpath(root)
        except OSError:
            raise BlockedError('journal-location-repository-unresolved') from None
        if _inside(flavor, resolved, resolved_root):
            raise BlockedError('journal-location-inside-repository')
        if _identity_inside(probe, flavor, resolved, resolved_root):
            raise BlockedError('journal-location-inside-repository')
    if not probe.windows:
        user = probe.effective_uid()
        for entry in (resolved, journal, lock):
            if entry != resolved and not probe.exists(entry):
                continue
            owner, mode = probe.owner_mode(entry)
            if owner != user:
                raise BlockedError('journal-location-foreign-owner')
            if mode & 0o020:
                raise BlockedError('journal-location-shared-writable')
            if mode & 0o002:
                raise BlockedError('journal-location-shared-writable')
    return Location(journal, lock, resolved)


def durable_sync(descriptor):
    """Flush written bytes to stable storage before any acknowledgement.

    Windows: FlushFileBuffers on the handle. POSIX: fsync. The journal writes
    with unbuffered os.write, so no user-space buffer remains to flush first.
    """
    if os.name == 'nt':
        import ctypes
        import msvcrt
        from ctypes import wintypes
        flush = ctypes.WinDLL('kernel32', use_last_error=True).FlushFileBuffers
        flush.argtypes = [wintypes.HANDLE]
        flush.restype = wintypes.BOOL
        if not flush(msvcrt.get_osfhandle(descriptor)):
            raise ctypes.WinError(ctypes.get_last_error())
    else:
        os.fsync(descriptor)


def _sync_directory(directory):
    # POSIX persists the new directory entry separately. Windows has no
    # directory handle through this interface; the file flush is relied upon.
    if os.name != 'nt':
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _lock(descriptor):
    """Exclusive OS advisory lock: flock on POSIX, a byte-range lock on Windows.

    One Windows LK_LOCK call retries for about ten seconds before it fails, so
    the wait is bounded at LOCK_ATTEMPTS calls (about a minute); the failure is
    then reported by the caller as blocked. POSIX flock waits without a bound.
    """
    if os.name == 'nt':
        import msvcrt
        for attempt in range(1, LOCK_ATTEMPTS + 1):
            os.lseek(descriptor, 0, os.SEEK_SET)
            try:
                msvcrt.locking(descriptor, msvcrt.LK_LOCK, 1)
                return
            except OSError:
                if attempt == LOCK_ATTEMPTS:
                    raise
    else:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_EX)


def _unlock(descriptor):
    if os.name == 'nt':
        import msvcrt
        os.lseek(descriptor, 0, os.SEEK_SET)
        msvcrt.locking(descriptor, msvcrt.LK_UNLCK, 1)
    else:
        import fcntl
        fcntl.flock(descriptor, fcntl.LOCK_UN)


def _validate_record(value, index, previous, fence):
    """Verify one parsed record against its position, predecessor and fence."""
    if type(value) is not dict or set(value) != RECORD_KEYS:
        raise AuthorityUnknown('journal-record-invalid')
    kind = RECORD_TYPES.get(value['recordType']) if type(value['recordType']) is str else None
    if kind is None:
        raise AuthorityUnknown('journal-record-invalid')
    if value['payloadKind'] != kind:
        raise AuthorityUnknown('journal-record-invalid')
    if type(value['sequence']) is not int:
        raise AuthorityUnknown('journal-record-invalid')
    if type(value['fence']) is not int:
        raise AuthorityUnknown('journal-record-invalid')
    if not conforms(PAYLOAD_DEFINITIONS[value['payloadKind']], value['payloadProjection']):
        raise AuthorityUnknown('journal-record-invalid')
    if value['sequence'] != index + 1:
        raise AuthorityUnknown('journal-sequence-gap')
    if value['previousRecordSha256'] != previous:
        raise AuthorityUnknown('journal-chain-mismatch')
    try:
        digest = domain_hash('journal-record', value)
    except InputError:
        raise AuthorityUnknown('journal-record-invalid') from None
    if digest != value['recordSha256']:
        raise AuthorityUnknown('journal-record-hash-mismatch')
    payload = value['payloadProjection']
    if kind == 'claim' and payload['ledgerSequence'] != value['sequence']:
        raise AuthorityUnknown('journal-backlink-mismatch')
    if kind == 'claim' and payload['ledgerRecordSha256'] != digest:
        raise AuthorityUnknown('journal-backlink-mismatch')
    if kind == 'attemptAuthority' and payload['adoptionRecordSha256'] != digest:
        raise AuthorityUnknown('journal-backlink-mismatch')
    if value['recordType'] == 'claim-acquired':
        if value['fence'] != fence + 1:
            raise AuthorityUnknown('journal-fence-invalid')
        if payload['fence'] != value['fence']:
            raise AuthorityUnknown('journal-fence-invalid')
    elif value['fence'] != fence:
        raise AuthorityUnknown('journal-fence-invalid')
    # Fix 5 (B): the schema fixes only the shape of a UTC text. A record must also pass the
    # write path's own time checks (the schema was checked above), so an impossible calendar
    # time in a resealed journal is an invalid record (8), never invalid input (3) later.
    try:
        if kind == 'requestBinding':
            check_binding_times(payload)
        elif kind == 'claim':
            _utc(payload['leaseUntil'])
        elif kind == 'result':
            from .verify import _utc_shapes
            _utc_shapes(payload)
    except InputError:
        raise AuthorityUnknown('journal-record-invalid') from None


def parse_records(data):
    """Verify complete journal bytes; never drop, repair or renumber a record."""
    if type(data) is not bytes:
        raise InputError('journal bytes required')
    if not data:
        return []
    if not data.endswith(b'\n'):
        raise AuthorityUnknown('journal-unterminated-record')
    records, previous, fence = [], None, 0
    for index, line in enumerate(data[:-1].split(b'\n')):
        try:
            value = cjson.loads(line)
        except InputError:
            raise AuthorityUnknown('journal-record-invalid') from None
        if cjson.dumps(value) != line:
            raise AuthorityUnknown('journal-record-noncanonical')
        _validate_record(value, index, previous, fence)
        previous, fence = value['recordSha256'], value['fence']
        records.append(value)
    return records


def read_records(path):
    with open(path, 'rb') as handle:
        return parse_records(handle.read())


# Records whose payload names an authority (requestBinding, claim, attemptAuthority).
AUTHORITY_CARRYING_KINDS = frozenset({'requestBinding', 'claim', 'attemptAuthority'})


def check_authority(records, authority_id):
    """One journal belongs to one authority: every record that names one must name this one.

    Any other value makes the journal unknown (8) before a decision is taken on
    it, so the same file opened under another authority ID is never coalesced
    into the first authority's claim. The format is unchanged.
    """
    for record in records:
        if record['payloadKind'] in AUTHORITY_CARRYING_KINDS:
            if record['payloadProjection']['authorityId'] != authority_id:
                raise AuthorityUnknown('journal-authority-mismatch')


def check_anchor_location(anchor_path, journal_location, repository_roots, probe=None):
    """The anchor follows the journal's placement rules, in another directory (decision A).

    A rollback of one folder (a backup or a sync that restores an older version)
    then cannot take the journal and its anchor back together. A location
    refusal keeps its reason with the ``journal-anchor-`` prefix.
    """
    try:
        location = check_location(anchor_path, repository_roots, probe)
    except BlockedError as error:
        raise BlockedError('journal-anchor-' + error.reason_code[len('journal-'):]) from None
    flavor = (SystemProbe() if probe is None else probe).path
    if flavor.normcase(location.directory) == flavor.normcase(journal_location.directory):
        raise BlockedError('journal-anchor-same-directory')
    return location


def _anchor_document(authority_id, journal, records):
    return {'kind': ANCHOR_KIND, 'version': 1, 'authorityId': authority_id, 'journal': journal,
            'sequence': len(records), 'recordSha256': records[-1]['recordSha256'] if records else None}


def read_anchor(path):
    """The anchor document, or None when no anchor file exists. Anything else is unknown (8)."""
    try:
        with open(path, 'rb') as handle:
            data = handle.read()
    except FileNotFoundError:
        return None
    except OSError:
        raise AuthorityUnknown('journal-anchor-unreadable') from None
    try:
        value = cjson.loads(data)
        if cjson.dumps(value) != data or type(value) is not dict or set(value) != ANCHOR_KEYS:
            raise InputError('anchor')
        if value['kind'] != ANCHOR_KIND or value['version'] != 1 or type(value['version']) is not int:
            raise InputError('anchor')
        if type(value['authorityId']) is not str or type(value['journal']) is not str:
            raise InputError('anchor')
        if type(value['sequence']) is not int or value['sequence'] < 0:
            raise InputError('anchor')
        digest = value['recordSha256']
        if (digest is None) != (value['sequence'] == 0):
            raise InputError('anchor')
        if digest is not None and (type(digest) is not str or re.fullmatch('[0-9a-f]{64}', digest) is None):
            raise InputError('anchor')
    except InputError:
        raise AuthorityUnknown('journal-anchor-invalid') from None
    return value


def write_anchor(path, document, sync):
    """Replace the anchor with a synced new file; a failure is unknown (8), never ignored."""
    temporary = path + '.tmp'
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | _BINARY | _NOFOLLOW, 0o600)
        try:
            view = memoryview(cjson.dumps(document))
            while view:
                view = view[os.write(descriptor, view):]
            sync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
        _sync_directory(os.path.dirname(path))
    except Exception:
        raise AuthorityUnknown('journal-anchor-write-failed') from None


def check_anchor(records, anchor, authority_id, journal, flavor):
    """True when the journal is exactly one record past the anchor (a crash to catch up).

    Fewer records, another record at the anchored sequence, or more than one
    record past the anchor make the journal unverifiable (8).
    """
    if anchor is None:
        raise AuthorityUnknown('journal-anchor-missing')
    if anchor['authorityId'] != authority_id or flavor.normcase(anchor['journal']) != flavor.normcase(journal):
        raise AuthorityUnknown('journal-anchor-foreign')
    count = anchor['sequence']
    if len(records) < count:
        raise AuthorityUnknown('journal-truncated')
    if count and records[count - 1]['recordSha256'] != anchor['recordSha256']:
        raise AuthorityUnknown('journal-anchor-mismatch')
    if len(records) > count + 1:
        raise AuthorityUnknown('journal-anchor-stale')
    return len(records) == count + 1


class Transaction:
    """Appends under the held lock. Each record and LF is synced before return."""

    def __init__(self, path, records, sync, after_append=None):
        self.path, self.records, self._sync = path, records, sync
        self._after_append = after_append
        self._descriptor = None

    @property
    def fence(self):
        return self.records[-1]['fence'] if self.records else 0

    def append(self, record_type, payload):
        kind = RECORD_TYPES[record_type]
        payload = copy.deepcopy(payload)
        sequence = len(self.records) + 1
        previous = self.records[-1]['recordSha256'] if self.records else None
        record = {'sequence': sequence,
                  'fence': self.fence + (1 if record_type == 'claim-acquired' else 0),
                  'previousRecordSha256': previous, 'recordType': record_type,
                  'payloadKind': kind, 'payloadProjection': payload, 'recordSha256': _PENDING}
        if kind == 'claim':
            payload['ledgerSequence'] = sequence
            payload['ledgerRecordSha256'] = _PENDING
        if kind == 'attemptAuthority':
            payload['adoptionRecordSha256'] = _PENDING
        digest = domain_hash('journal-record', record)
        record['recordSha256'] = digest
        if kind == 'claim':
            payload['ledgerRecordSha256'] = digest
        if kind == 'attemptAuthority':
            payload['adoptionRecordSha256'] = digest
        try:
            _validate_record(record, len(self.records), previous, self.fence)
        except AuthorityUnknown:
            raise InputError('invalid journal record') from None
        line = cjson.dumps(record) + b'\n'
        try:
            if self._descriptor is None:
                self._descriptor = os.open(self.path, os.O_WRONLY | os.O_APPEND | _BINARY | _NOFOLLOW)
            view = memoryview(line)
            while view:
                view = view[os.write(self._descriptor, view):]
        except OSError:
            raise AuthorityUnknown('journal-write-failed') from None
        try:
            self._sync(self._descriptor)
        except Exception:
            raise AuthorityUnknown('journal-sync-failed') from None
        self.records.append(record)
        if self._after_append is not None:
            # The record is durable; the anchor follows it. A failed anchor write is unknown (8),
            # and the next transaction catches up the single record it lags by.
            self._after_append(self.records)
        return copy.deepcopy(record)

    def close(self):
        if self._descriptor is not None:
            os.close(self._descriptor)
            self._descriptor = None


class LocalJournal:
    """One journal for one local authority, at an explicit caller path.

    The file is created with mode 0600; on Windows that mode does not restrict
    access and the directory's inherited ACL applies (not checked here).
    """

    def __init__(self, path, *, authority_id, repository_roots, probe=None, sync=None, anchor_path=None):
        if not conforms('id', authority_id):
            raise InputError('invalid authority id')
        if anchor_path is not None and (type(anchor_path) is not str or not anchor_path):
            raise InputError('invalid anchor path')
        self.path, self.authority_id = path, authority_id
        self.repository_roots, self.probe = repository_roots, probe
        self.anchor_path = anchor_path
        self._sync = durable_sync if sync is None else sync

    def _anchor_location(self, location):
        if self.anchor_path is None:
            return None
        return check_anchor_location(self.anchor_path, location, self.repository_roots, self.probe)

    @classmethod
    def create(cls, path, *, authority_id, repository_roots, probe=None, sync=None, anchor_path=None):
        """Create an empty journal file; its directory must already exist.

        With an anchor, an existing anchor file refuses the creation: it names a
        journal that existed at this place, so a recreated journal could reuse
        its request IDs (hole 5).
        """
        journal = cls(path, authority_id=authority_id, repository_roots=repository_roots,
                      probe=probe, sync=sync, anchor_path=anchor_path)
        location = check_location(path, repository_roots, probe)
        anchor = journal._anchor_location(location)
        if anchor is not None and os.path.lexists(anchor.journal):
            raise BlockedError('journal-anchor-exists')
        try:
            descriptor = os.open(location.journal,
                                 os.O_WRONLY | os.O_CREAT | os.O_EXCL | _BINARY | _NOFOLLOW, 0o600)
        except FileExistsError:
            raise BlockedError('journal-exists') from None
        except OSError:
            raise BlockedError('journal-location-unwritable') from None
        try:
            journal._sync(descriptor)
        except Exception:
            raise AuthorityUnknown('journal-sync-failed') from None
        finally:
            os.close(descriptor)
        _sync_directory(location.directory)
        if anchor is not None:
            write_anchor(anchor.journal, _anchor_document(authority_id, location.journal, []), journal._sync)
        return journal

    @contextmanager
    def transaction(self):
        location = check_location(self.path, self.repository_roots, self.probe)
        anchor = self._anchor_location(location)
        if not os.path.isfile(location.journal):
            if anchor is not None and os.path.lexists(anchor.journal):
                # The anchor shows that a journal existed here: it was removed (hole 5).
                raise AuthorityUnknown('journal-missing-anchored')
            raise BlockedError('journal-missing')
        try:
            descriptor = os.open(location.lock, os.O_RDWR | os.O_CREAT | _BINARY | _NOFOLLOW, 0o600)
        except OSError:
            raise BlockedError('journal-lock-unavailable') from None
        try:
            try:
                _lock(descriptor)
            except OSError:
                raise BlockedError('journal-lock-unavailable') from None
            try:
                try:
                    records = read_records(location.journal)
                except OSError:
                    # Present at the existence check, unreadable at the read (removed, locked, denied).
                    raise BlockedError('journal-unreadable') from None
                check_authority(records, self.authority_id)
                after_append = None
                if anchor is not None:
                    flavor = (SystemProbe() if self.probe is None else self.probe).path
                    if check_anchor(records, read_anchor(anchor.journal), self.authority_id,
                                    location.journal, flavor):
                        write_anchor(anchor.journal,
                                     _anchor_document(self.authority_id, location.journal, records), self._sync)

                    def after_append(current):
                        write_anchor(anchor.journal,
                                     _anchor_document(self.authority_id, location.journal, current), self._sync)
                transaction = Transaction(location.journal, records, self._sync, after_append)
                try:
                    yield transaction
                finally:
                    transaction.close()
            finally:
                _unlock(descriptor)
        finally:
            os.close(descriptor)

    def records(self):
        """A verified copy of every record, read under the lock."""
        with self.transaction() as transaction:
            return copy.deepcopy(transaction.records)
