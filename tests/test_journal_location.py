"""Journal placement. Synthetic probes answer every OS query; real-host tests are separate.

The synthetic probe exercises the Windows and POSIX decision branches on any
host. It does not run the real GetDriveTypeW, os.stat ownership or geteuid
calls; the real-host tests below run only the queries this host supports.
"""
import ntpath
import os
from pathlib import Path
import posixpath
import tempfile
import unittest
from ci_contract.errors import BlockedError, InputError
from ci_contract.journal import SystemProbe, check_location


class FakeProbe:
    """Every answer is supplied; nothing touches the real filesystem."""

    def __init__(self, windows, directories, files=(), real=None, same=(), drives=None, owners=None,
                 unsafe=(), unresolvable=(), uid=1000):
        self.windows = windows
        self.path = ntpath if windows else posixpath
        self.directories, self.files = set(directories), set(files)
        self.real, self.same = dict(real or {}), {frozenset(pair) for pair in same}
        self.drives, self.owners = dict(drives or {}), dict(owners or {})
        self.unsafe, self.unresolvable, self.uid = set(unsafe), set(unresolvable), uid

    def abspath(self, value):
        return self.path.normpath(value)

    def realpath(self, value):
        value = self.path.normpath(value)
        if value in self.unresolvable or (value not in self.directories and value not in self.real):
            raise OSError('synthetic unresolvable path')
        return self.real.get(value, value)

    def isdir(self, value):
        return self.path.normpath(value) in self.directories

    def exists(self, value):
        return value in self.files

    def unsafe_entry(self, value):
        return value in self.unsafe

    def samefile(self, left, right):
        return frozenset((left, right)) in self.same

    def drive_type(self, root):
        if not self.windows:
            raise AssertionError('drive type is a Windows query')
        return self.drives.get(root, 3)

    def owner_mode(self, value):
        if self.windows:
            raise AssertionError('ownership is a POSIX query')
        if value not in self.directories and value not in self.files:
            raise FileNotFoundError('synthetic absent entry')
        return self.owners.get(value, (self.uid, 0o700 if value in self.directories else 0o600))

    def effective_uid(self):
        return self.uid


def windows(**options):
    directories = options.pop('directories', set()) | {'C:\\authority', 'C:\\repository'}
    return FakeProbe(True, directories, **options)


def posix(**options):
    directories = options.pop('directories', set()) | {'/srv/synthetic/authority', '/srv/synthetic/repository'}
    return FakeProbe(False, directories, **options)


WIN_JOURNAL, WIN_REPO = 'C:\\authority\\journal.jsonl', ['C:\\repository']
POSIX_JOURNAL, POSIX_REPO = '/srv/synthetic/authority/journal.jsonl', ['/srv/synthetic/repository']


class SyntheticLocationTests(unittest.TestCase):
    def blocked(self, reason, path, roots, probe):
        with self.assertRaises(BlockedError) as raised:
            check_location(path, roots, probe)
        self.assertEqual(raised.exception.reason_code, reason)

    def test_valid_windows_and_posix_locations(self):
        location = check_location(WIN_JOURNAL, WIN_REPO, windows())
        self.assertEqual((location.journal, location.lock), (WIN_JOURNAL, WIN_JOURNAL + '.lock'))
        location = check_location(POSIX_JOURNAL, POSIX_REPO, posix())
        self.assertEqual((location.journal, location.lock), (POSIX_JOURNAL, POSIX_JOURNAL + '.lock'))

    def test_input_shapes_are_invalid_before_location_decisions(self):
        for path, roots in [(b'C:\\authority\\journal.jsonl', WIN_REPO), ('', WIN_REPO),
                            ('C:\\authority\\jour\x00nal', WIN_REPO), (WIN_JOURNAL, tuple(WIN_REPO)),
                            (WIN_JOURNAL, []), (WIN_JOURNAL, [b'C:\\repository']), (WIN_JOURNAL, ['']),
                            (WIN_JOURNAL, ['C:\\repo\x00sitory']), (WIN_JOURNAL, ['repository'])]:
            with self.subTest(path=path, roots=roots), self.assertRaises(InputError):
                check_location(path, roots, windows())

    def test_unc_and_network_share_spellings(self):
        for path in ('\\\\server\\share\\journal.jsonl', '//server/share/journal.jsonl',
                     '\\/server\\share\\journal.jsonl'):
            with self.subTest(path=path):
                self.blocked('journal-location-unc', path, WIN_REPO, windows())
        self.blocked('journal-location-unc', '//server/journal.jsonl', POSIX_REPO, posix())

    def test_extended_and_device_prefixes(self):
        for path in ('\\\\?\\C:\\authority\\journal.jsonl', '\\\\.\\C:\\authority\\journal.jsonl',
                     '//?/C:/authority/journal.jsonl', '//./C:/authority/journal.jsonl'):
            with self.subTest(path=path):
                self.blocked('journal-location-device-path', path, WIN_REPO, windows())

    def test_reserved_device_names_and_streams(self):
        for path in ('C:\\authority\\NUL', 'C:\\authority\\nul.jsonl', 'C:\\CON \\journal.jsonl',
                     'C:\\authority\\COM1.txt', 'C:\\authority\\journal.jsonl:stream'):
            with self.subTest(path=path):
                self.blocked('journal-location-device-path', path, WIN_REPO, windows())

    def test_relative_spellings(self):
        for path in ('journal.jsonl', 'C:journal.jsonl', '\\authority\\journal.jsonl'):
            with self.subTest(path=path):
                self.blocked('journal-location-relative', path, WIN_REPO, windows())
        self.blocked('journal-location-relative', 'authority/journal.jsonl', POSIX_REPO, posix())

    def test_missing_or_unresolvable_directory_is_not_created(self):
        probe = windows()
        self.blocked('journal-location-missing-directory', 'C:\\missing\\journal.jsonl', WIN_REPO, probe)
        self.assertNotIn('C:\\missing', probe.directories)
        self.blocked('journal-location-missing-directory', WIN_JOURNAL, WIN_REPO,
                     windows(unresolvable={'C:\\authority'}))

    def test_parent_that_is_a_file_is_not_a_directory(self):
        probe = windows(real={'C:\\afile': 'C:\\afile'})
        self.blocked('journal-location-missing-directory', 'C:\\afile\\journal.jsonl', WIN_REPO, probe)

    def test_remote_spelling_with_a_local_resolution_is_still_remote(self):
        probe = windows(directories={'Z:\\authority'}, real={'Z:\\authority': 'C:\\authority'}, drives={'Z:\\': 4})
        self.blocked('journal-location-remote-drive', 'Z:\\authority\\journal.jsonl', WIN_REPO, probe)

    def test_resolved_directory_spelling_is_checked(self):
        probe = windows(directories={'C:\\alias'}, real={'C:\\alias': '\\\\server\\share\\authority'})
        self.blocked('journal-location-unc', 'C:\\alias\\journal.jsonl', WIN_REPO, probe)

    def test_remote_and_non_fixed_drives(self):
        self.blocked('journal-location-remote-drive', WIN_JOURNAL, WIN_REPO, windows(drives={'C:\\': 4}))
        for kind in (0, 1, 2, 5, 6):
            with self.subTest(kind=kind):
                self.blocked('journal-location-drive-unsupported', WIN_JOURNAL, WIN_REPO, windows(drives={'C:\\': kind}))
        # A local-looking spelling whose resolved directory is on a remote drive.
        probe = windows(directories={'C:\\alias'}, real={'C:\\alias': 'Z:\\authority'}, drives={'Z:\\': 4})
        self.blocked('journal-location-remote-drive', 'C:\\alias\\journal.jsonl', WIN_REPO, probe)

    def test_unsafe_journal_and_lock_entries(self):
        for entry in (WIN_JOURNAL, WIN_JOURNAL + '.lock'):
            with self.subTest(entry=entry):
                self.blocked('journal-location-unsafe-entry', WIN_JOURNAL, WIN_REPO, windows(unsafe={entry}))

    def test_unresolved_repository_root(self):
        self.blocked('journal-location-repository-unresolved', WIN_JOURNAL, ['C:\\absent'], windows())

    def test_inside_repository_lexically_with_case_and_separator_differences(self):
        # The synthetic samefile answers False here, so only the resolved lexical test applies.
        probe = windows(directories={'C:\\Repository\\Data', 'c:\\repository'})
        self.blocked('journal-location-inside-repository', 'C:/Repository/Data/journal.jsonl', ['c:\\repository'], probe)
        self.blocked('journal-location-inside-repository', 'C:\\repository\\journal.jsonl', WIN_REPO, windows())

    def test_inside_repository_by_identity_of_an_ancestor(self):
        probe = windows(directories={'D:\\alias\\data'}, same={('D:\\alias', 'C:\\repository')})
        self.blocked('journal-location-inside-repository', 'D:\\alias\\data\\journal.jsonl', WIN_REPO, probe)
        probe = posix(directories={'/mnt/alias/data'}, same={('/mnt/alias', '/srv/synthetic/repository')})
        self.blocked('journal-location-inside-repository', '/mnt/alias/data/journal.jsonl', POSIX_REPO, probe)

    def test_other_drive_is_outside_and_does_not_raise(self):
        probe = windows(directories={'D:\\authority'})
        self.assertEqual(check_location('D:\\authority\\journal.jsonl', WIN_REPO, probe).directory, 'D:\\authority')

    def test_posix_foreign_owner(self):
        directory = '/srv/synthetic/authority'
        self.blocked('journal-location-foreign-owner', POSIX_JOURNAL, POSIX_REPO, posix(owners={directory: (0, 0o700)}))
        for entry in (POSIX_JOURNAL, POSIX_JOURNAL + '.lock'):
            with self.subTest(entry=entry):
                self.blocked('journal-location-foreign-owner', POSIX_JOURNAL, POSIX_REPO,
                             posix(files={entry}, owners={entry: (0, 0o600)}))

    def test_posix_group_or_other_write_permission(self):
        directory = '/srv/synthetic/authority'
        for mode in (0o770, 0o720, 0o702, 0o777):
            with self.subTest(mode=oct(mode)):
                self.blocked('journal-location-shared-writable', POSIX_JOURNAL, POSIX_REPO,
                             posix(owners={directory: (1000, mode)}))
        for mode in (0o620, 0o602):
            with self.subTest(file_mode=oct(mode)):
                self.blocked('journal-location-shared-writable', POSIX_JOURNAL, POSIX_REPO,
                             posix(files={POSIX_JOURNAL}, owners={POSIX_JOURNAL: (1000, mode)}))

    def test_posix_read_and_execute_bits_are_allowed(self):
        directory = '/srv/synthetic/authority'
        check_location(POSIX_JOURNAL, POSIX_REPO, posix(owners={directory: (1000, 0o755)},
                                                        files={POSIX_JOURNAL}, ))

    def test_flavor_specific_queries_are_not_mixed(self):
        # FakeProbe raises if a Windows query is used for POSIX or the reverse.
        check_location(WIN_JOURNAL, WIN_REPO, windows())
        check_location(POSIX_JOURNAL, POSIX_REPO, posix(files={POSIX_JOURNAL}))


class RealHostLocationTests(unittest.TestCase):
    """Native queries of this host only; unsupported mechanisms are skipped, not passed."""

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix='synthetic-location-')
        self.root = Path(self.folder.name)
        (self.root / 'repository').mkdir()
        (self.root / 'authority').mkdir()
        self.repo = [str(self.root / 'repository')]
        self.journal = str(self.root / 'authority' / 'journal.jsonl')

    def tearDown(self):
        self.folder.cleanup()

    def blocked(self, reason, path, roots=None, probe=None):
        with self.assertRaises(BlockedError) as raised:
            check_location(path, self.repo if roots is None else roots, probe)
        self.assertEqual(raised.exception.reason_code, reason)

    def test_temporary_folder_is_accepted(self):
        location = check_location(self.journal, self.repo)
        self.assertTrue(os.path.samefile(location.directory, self.root / 'authority'))

    def test_inside_repository_is_rejected(self):
        self.blocked('journal-location-inside-repository', str(self.root / 'repository' / 'journal.jsonl'))

    def test_alias_into_repository_is_rejected(self):
        alias = self.root / 'alias'
        try:
            if os.name == 'nt':
                import _winapi
                _winapi.CreateJunction(str(self.root / 'repository'), str(alias))
            else:
                os.symlink(self.root / 'repository', alias, target_is_directory=True)
        except (OSError, AttributeError, NotImplementedError):
            self.skipTest('directory alias not creatable on this host')
        self.blocked('journal-location-inside-repository', str(alias / 'journal.jsonl'))

    def test_short_name_alias_into_repository_is_rejected(self):
        if os.name != 'nt':
            self.skipTest('8.3 short names are a Windows mechanism')
        import ctypes
        buffer = ctypes.create_unicode_buffer(32768)
        length = ctypes.windll.kernel32.GetShortPathNameW(str(self.root / 'repository'), buffer, 32768)
        if not length or buffer.value.lower() == str(self.root / 'repository').lower():
            self.skipTest('no distinct short name on this volume')
        self.blocked('journal-location-inside-repository', buffer.value + '\\journal.jsonl')
        self.blocked('journal-location-inside-repository', self.journal.replace('authority', 'repository'),
                     roots=[buffer.value])

    def test_hardlinked_journal_is_rejected(self):
        inside = self.root / 'repository' / 'data'
        inside.write_bytes(b'')
        try:
            os.link(inside, self.journal)
        except OSError:
            self.skipTest('hard links not creatable on this host')
        self.blocked('journal-location-unsafe-entry', self.journal)

    def test_symlinked_journal_is_rejected(self):
        target = self.root / 'authority' / 'target'
        target.write_bytes(b'')
        try:
            os.symlink(target, self.journal)
        except (OSError, NotImplementedError):
            self.skipTest('file symlinks not creatable without privilege on this host')
        self.blocked('journal-location-unsafe-entry', self.journal)

    def test_unc_spelling_is_rejected_before_any_access(self):
        path = '\\\\localhost\\synthetic\\journal.jsonl' if os.name == 'nt' else '//localhost/journal.jsonl'
        self.blocked('journal-location-unc', path)

    def test_remote_drive_answer_from_a_replaced_probe(self):
        if os.name != 'nt':
            self.skipTest('drive type is a Windows query')

        class Remote(SystemProbe):
            def drive_type(self, root):
                return 4
        self.blocked('journal-location-remote-drive', self.journal, probe=Remote())

    def test_real_posix_ownership_and_permissions(self):
        if os.name == 'nt':
            self.skipTest('POSIX ownership and mode bits are not queried on Windows')
        os.chmod(self.root / 'authority', 0o700)
        check_location(self.journal, self.repo)
        os.chmod(self.root / 'authority', 0o770)
        self.blocked('journal-location-shared-writable', self.journal)
        os.chmod(self.root / 'authority', 0o700)


if __name__ == '__main__':
    unittest.main()
