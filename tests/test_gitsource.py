"""M3 object-reader and inventory unit tests using only temporary synthetic Git."""
import copy
import hashlib
import io
import ntpath
import os
import stat
from pathlib import Path
import subprocess
import tempfile
import unittest
import zlib
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import patch

from ci_contract import cjson, hashing, inventory, schema
from ci_contract.errors import BlockedError, InputError
from ci_contract.gitsource import (GitSource, _resolve_git, _BATCH_EXIT_SECONDS,
                                   _MAX_ANCESTRY_DEPTH, _MAX_ANCESTRY_COMMIT_BYTES,
                                   _MAX_ANCESTRY_DISCOVERED)
from synthetic_git import SyntheticGit


DETERMINISTIC_FILES = {'src/a.txt': ('100644', b'hello\r\n')}
DETERMINISTIC_BASE = 'adb1f6c50c42d4d5ff0df1a13233af4b6e9cbb8c'
DETERMINISTIC_TARGET = 'b9c00f5a82e34592a47096d53990bf71439a933c'


class _ExitedPipe(io.BytesIO):
    """A pipe to a process that already exited: close() closes, then raises.

    On Windows, flushing or closing the stdin of an exited child raises
    OSError(22) rather than BrokenPipeError. With fail_flush, flush() raises
    too, as when git exits before reading the request.
    """
    def __init__(self, fail_flush=False):
        super().__init__()
        self.fail_flush = fail_flush

    def flush(self):
        if self.fail_flush:
            raise OSError(22, 'Invalid argument')
        super().flush()

    def close(self):
        self.fail_flush = False
        super().close()
        raise OSError(22, 'Invalid argument')


class BatchProcessStub:
    """In-memory binary protocol only; never starts an executable.

    A hung stub never exits on its own: a bounded wait times out and an
    unbounded wait fails the test instead of blocking it. As with a real
    process, kill() only signals; the return code arrives with the next wait.
    """
    def __init__(self, data, exit_status=0, hangs=False, exited_stdin=False, fail_flush=False):
        self.stdin = _ExitedPipe(fail_flush) if exited_stdin else io.BytesIO()
        self.stdout = io.BytesIO(data)
        self.returncode = None
        self.exit_status = exit_status
        self.hangs = hangs
        self.killed = False
        self.waits = 0
        self.wait_timeouts = []
        self.pipes_closed_at_wait = []

    def poll(self):
        return self.returncode

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waits += 1
        self.wait_timeouts.append(timeout)
        self.pipes_closed_at_wait.append(self.stdin.closed and self.stdout.closed)
        if self.returncode is None:
            if self.killed:
                self.returncode = -9
            elif self.hangs:
                if timeout is None:
                    raise AssertionError('unbounded wait on a process that never exits')
                raise subprocess.TimeoutExpired('git', timeout)
            else:
                self.returncode = self.exit_status
        return self.returncode

    def assert_closed_then_ended(self, case):
        """Both pipes close before the bounded wait; only a hung process is killed."""
        case.assertTrue(self.stdin.closed)
        case.assertTrue(self.stdout.closed)
        case.assertTrue(self.pipes_closed_at_wait[0])
        case.assertEqual(self.wait_timeouts[0], _BATCH_EXIT_SECONDS)
        case.assertEqual(self.killed, self.hangs)
        case.assertIsNotNone(self.returncode)


class GitSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = SyntheticGit(self.root / 'repo.git')
        self.reader = GitSource(self.repo.path)
        self.base = self.repo.commit(DETERMINISTIC_FILES)

    def test_fixed_commits_reproduce_across_separate_repositories(self):
        target = self.repo.commit({'src/b.txt': ('100755', b'hello\r\n')}, parents=(self.base,))
        other = SyntheticGit(self.root / 'other.git')
        other_base = other.commit(DETERMINISTIC_FILES)
        other_target = other.commit({'src/b.txt': ('100755', b'hello\r\n')}, parents=(other_base,))
        self.assertEqual(self.base, DETERMINISTIC_BASE)
        self.assertEqual(target, DETERMINISTIC_TARGET)
        self.assertEqual((other_base, other_target), (self.base, target))
        self.assertEqual(self.reader.source(self.base, target), GitSource(other.path).source(other_base, other_target))

    def test_exact_commit_is_accepted(self):
        self.assertEqual(self.reader.verify_commit(self.base, 'base'), self.base)
        self.assertEqual(self.reader.verify_commit(self.base, 'target'), self.base)

    def test_explicit_roots_work_but_upward_discovery_is_blocked(self):
        # Only a bare object database and empty wrapper directories: no checkout.
        wrapper = self.root / 'synthetic-wrapper'
        nested = SyntheticGit(wrapper / '.git')
        sha = nested.commit({'a': ('100644', b'synthetic')})
        child = wrapper / 'not-a-repository'; child.mkdir()
        for location in (wrapper, nested.path):
            with self.subTest(location=location.name):
                self.assertEqual(GitSource(location).read_blob(sha, 'a'), b'synthetic')
        with self.assertRaises(BlockedError): GitSource(child).read_blob(sha, 'a')

    def test_symlink_to_nested_directory_cannot_borrow_parent_repository(self):
        wrapper = self.root / 'synthetic-wrapper'
        nested = SyntheticGit(wrapper / '.git')
        sha = nested.commit({'a': ('100644', b'synthetic')})
        child = wrapper / 'not-a-repository'; child.mkdir()
        alias = self.root / 'synthetic-alias'
        try:
            alias.symlink_to(child, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('host cannot create synthetic directory symlinks')
        with self.assertRaises(BlockedError): GitSource(alias).read_blob(sha, 'a')

    def test_gitfile_indirection_is_unsupported_and_blocked(self):
        wrapper = self.root / 'synthetic-gitfile-wrapper'; wrapper.mkdir()
        (wrapper / '.git').write_text('gitdir: ' + str(self.repo.path) + '\n', encoding='utf-8')
        with patch('ci_contract.gitsource.subprocess.run') as run:
            with self.assertRaises(BlockedError) as raised:
                GitSource(wrapper).read_blob(self.base, 'src/a.txt')
            self.assertEqual(raised.exception.reason_code, 'repository-unavailable')
            run.assert_not_called()

    def test_root_fake_objects_cannot_override_dotgit_metadata(self):
        wrapper = self.root / 'synthetic-wrapper'
        nested = SyntheticGit(wrapper / '.git')
        trusted = nested.commit({'.ci/manifest.json': ('100644', b'trusted')})
        forged = nested.commit({'.ci/manifest.json': ('100644', b'untrusted')})
        trusted_tree = nested.run('rev-parse', '--verify', trusted + '^{tree}').strip().decode('ascii')
        forged_tree = nested.run('rev-parse', '--verify', forged + '^{tree}').strip().decode('ascii')
        forged_bytes = nested.run('cat-file', 'tree', forged_tree)
        (wrapper / 'HEAD').write_bytes(b'ref: refs/heads/synthetic\n')
        (wrapper / 'refs' / 'heads').mkdir(parents=True)
        (wrapper / 'refs' / 'heads' / 'synthetic').write_bytes((trusted + '\n').encode('ascii'))
        info = wrapper / 'objects' / 'info'
        info.mkdir(parents=True)
        (info / 'alternates').write_bytes(b'../.git/objects\n')
        fake_object = wrapper / 'objects' / trusted_tree[:2] / trusted_tree[2:]
        fake_object.parent.mkdir()
        fake_object.write_bytes(zlib.compress(b'tree ' + str(len(forged_bytes)).encode('ascii')
                                             + b'\0' + forged_bytes))
        reader = GitSource(wrapper)
        self.assertEqual(reader.read_blob(trusted, '.ci/manifest.json', 'base'), b'trusted')
        self.assertEqual(Path(reader._git_dir), nested.path)

    def test_raw_blob_oid_is_verified_on_single_and_batch_reads(self):
        oid = self.reader.entries(self.base)['src/a.txt'][1]
        object_path = self.repo.path / 'objects' / oid[:2] / oid[2:]
        object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        object_path.write_bytes(zlib.compress(b'blob 7\0attack\n'))
        for read in (lambda: self.reader.read_blob(self.base, 'src/a.txt'),
                     lambda: self.reader.source(self.base, self.base)):
            with self.subTest(read=read), self.assertRaises(BlockedError) as raised:
                read()
            self.assertEqual(raised.exception.reason_code, 'source-input-unavailable')

    def test_missing_repository_and_git_have_distinct_reasons(self):
        for location in (self.root / 'absent', self.root):
            with self.subTest(location=location.name), self.assertRaises(BlockedError) as raised:
                GitSource(location).verify_commit(self.base, 'base')
            self.assertEqual(raised.exception.reason_code, 'repository-unavailable')
        with patch.dict(os.environ, {'PATH': ''}):
            with self.assertRaises(BlockedError) as raised:
                GitSource(self.repo.path).verify_commit(self.base, 'target')
            self.assertEqual(raised.exception.reason_code, 'git-unavailable')

    def test_missing_commits_keep_entries_and_blob_caller_side(self):
        for side in ('base', 'target', 'projection-anchor'):
            for read in (lambda: self.reader.entries('0' * 40, side),
                         lambda: self.reader.read_blob('0' * 40, 'src/a.txt', side)):
                with self.subTest(side=side), self.assertRaises(BlockedError) as raised:
                    read()
                self.assertEqual(raised.exception.reason_code, side + '-not-recoverable')

    def test_missing_tree_keeps_entries_caller_side(self):
        tree = self.repo.run('rev-parse', '--verify', self.base + '^{tree}').strip().decode('ascii')
        object_path = self.repo.path / 'objects' / tree[:2] / tree[2:]
        object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        object_path.unlink()
        for side in ('base', 'target', 'projection-anchor'):
            with self.subTest(side=side), self.assertRaises(BlockedError) as raised:
                GitSource(self.repo.path).entries(self.base, side)
            self.assertEqual(raised.exception.reason_code, side + '-not-recoverable')

    def test_projection_anchor_requires_raw_commit_ancestry(self):
        middle = self.repo.commit(DETERMINISTIC_FILES, parents=(self.base,), message='middle')
        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(middle,), message='tip')
        unrelated = self.repo.commit(DETERMINISTIC_FILES, message='unrelated root')
        self.reader.require_ancestor(self.base, tip)
        self.reader.require_ancestor(tip, tip)
        with self.assertRaises(BlockedError) as raised:
            self.reader.require_ancestor(unrelated, tip)
        self.assertEqual(raised.exception.reason_code, 'projection-anchor-not-ancestor')
        with self.assertRaises(BlockedError) as raised:
            self.reader.require_ancestor('0' * 40, tip)
        self.assertEqual(raised.exception.reason_code, 'projection-anchor-not-recoverable')

    def test_missing_projection_ancestry_blocks_without_history_inference(self):
        middle = self.repo.commit(DETERMINISTIC_FILES, parents=(self.base,), message='middle')
        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(middle,), message='tip')
        object_path = self.repo.path / 'objects' / middle[:2] / middle[2:]
        object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        object_path.unlink()
        with self.assertRaises(BlockedError) as raised:
            self.reader.require_ancestor(self.base, tip)
        self.assertEqual(raised.exception.reason_code, 'projection-ancestry-unavailable')

    def test_raw_ancestry_ignores_graft_and_shallow_files(self):
        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(self.base,), message='tip')
        unrelated = self.repo.commit(DETERMINISTIC_FILES, message='unrelated root')
        (self.repo.path / 'info').mkdir()
        (self.repo.path / 'info' / 'grafts').write_bytes((tip + ' ' + unrelated + '\n').encode('ascii'))
        (self.repo.path / 'shallow').write_bytes((tip + '\n').encode('ascii'))
        self.reader.require_ancestor(self.base, tip)
        with self.assertRaises(BlockedError) as raised:
            self.reader.require_ancestor(unrelated, tip)
        self.assertEqual(raised.exception.reason_code, 'projection-anchor-not-ancestor')

    def test_ancestry_uses_one_live_batch_for_60_generations(self):
        tree = self.repo.run('rev-parse', '--verify', self.base + '^{tree}').strip().decode('ascii')
        tip = self.base
        for _ in range(60):
            tip = self.repo.run('commit-tree', tree, '-p', tip, input=b'ancestor\n').strip().decode('ascii')
        real_run, real_popen = subprocess.run, subprocess.Popen
        calls, live_batches = [], []
        inside_run = False

        def record_run(command, **kwargs):
            nonlocal inside_run
            calls.append(command)
            inside_run = True
            try:
                return real_run(command, **kwargs)
            finally:
                inside_run = False

        def record_popen(command, **kwargs):
            if not inside_run:
                live_batches.append((command, kwargs))
            return real_popen(command, **kwargs)

        with patch('ci_contract.gitsource.subprocess.run', side_effect=record_run), \
             patch('ci_contract.gitsource.subprocess.Popen', side_effect=record_popen):
            self.reader.require_ancestor(self.base, tip)
        self.assertEqual(len(calls), 3)  # exact-location probe and two type checks
        self.assertEqual(len(live_batches), 1)
        command, kwargs = live_batches[0]
        self.assertEqual(command[-2:], ['cat-file', '--batch'])
        self.assertTrue(os.path.isabs(command[0]))
        self.assertIs(kwargs['shell'], False)
        self.assertNotIn('text', kwargs)
        self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'], '')
        self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
        self.assertEqual(kwargs['env']['GIT_NO_REPLACE_OBJECTS'], '1')

    def test_ancestry_depth_boundary_is_inclusive_and_bounded(self):
        tree = self.repo.run('rev-parse', '--verify', self.base + '^{tree}').strip().decode('ascii')
        tip = self.base
        for _ in range(_MAX_ANCESTRY_DEPTH):
            tip = self.repo.run('commit-tree', tree, '-p', tip, input=b'ancestor\n').strip().decode('ascii')
        self.reader.require_ancestor(self.base, tip)
        too_deep = self.repo.run('commit-tree', tree, '-p', tip, input=b'ancestor\n').strip().decode('ascii')
        with self.assertRaises(BlockedError) as raised:
            self.reader.require_ancestor(self.base, too_deep)
        self.assertEqual(raised.exception.reason_code, 'projection-ancestry-limit-exceeded')

    def test_ancestry_total_commit_bound_is_enforced(self):
        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(self.base,), message='tip')
        with patch('ci_contract.gitsource._MAX_ANCESTRY_COMMITS', 1):
            with self.assertRaises(BlockedError) as raised:
                self.reader.require_ancestor(self.base, tip)
        self.assertEqual(raised.exception.reason_code, 'projection-ancestry-limit-exceeded')

    def test_ancestry_discovery_bound_rejects_wide_commit_before_enqueuing(self):
        tree = self.repo.run('rev-parse', '--verify', self.base + '^{tree}').strip()

        def wide_commit(parent_count):
            parents = [self.base, *(f'{i:040x}' for i in range(1, parent_count))]
            data = (b'tree ' + tree + b'\n' +
                    b''.join(b'parent ' + parent.encode('ascii') + b'\n' for parent in parents) +
                    b'author Synthetic Author <synthetic@example.invalid> 946684800 +0000\n'
                    b'committer Synthetic Author <synthetic@example.invalid> 946684800 +0000\n\n'
                    b'wide synthetic ancestry\n')
            self.assertLess(len(data), _MAX_ANCESTRY_COMMIT_BYTES)
            return self.repo.run('hash-object', '-w', '-t', 'commit', '--stdin',
                                 input=data).strip().decode('ascii')

        # Base counts as one discovered commit; the anchor is the first parent.
        boundary = wide_commit(_MAX_ANCESTRY_DISCOVERED - 1)
        self.reader.require_ancestor(self.base, boundary)
        too_wide = wide_commit(_MAX_ANCESTRY_DISCOVERED)
        reads = []
        actual_batch = self.reader._commit_batch

        @contextmanager
        def record_batch():
            with actual_batch() as read:
                def record(oid):
                    reads.append(oid)
                    return read(oid)
                yield record

        with patch.object(self.reader, '_commit_batch', side_effect=record_batch):
            with self.assertRaises(BlockedError) as raised:
                self.reader.require_ancestor(self.base, too_wide)
        self.assertEqual(raised.exception.reason_code, 'projection-ancestry-limit-exceeded')
        self.assertEqual(reads, [too_wide])
        # Negative control: weakening only the discovery bound admits the same
        # object after two reads; depth, payload and read limits cannot catch it.
        with patch('ci_contract.gitsource._MAX_ANCESTRY_DISCOVERED', _MAX_ANCESTRY_DISCOVERED + 1):
            self.reader.require_ancestor(self.base, too_wide)

    def test_ancestry_merge_can_reach_anchor_on_another_parent(self):
        unrelated = self.repo.commit(DETERMINISTIC_FILES, message='unrelated root')
        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(unrelated, self.base), message='merge')
        self.reader.require_ancestor(self.base, tip)

    def test_ancestry_commit_oid_is_verified_including_anchor(self):
        # Real git must end on its own once the pipes close. A kill would end
        # only Git for Windows' launcher and leave git.exe holding the files.
        kills = []

        class KillRecordingPopen(subprocess.Popen):
            def kill(self):
                kills.append(self.args)
                super().kill()

        tip = self.repo.commit(DETERMINISTIC_FILES, parents=(self.base,), message='tip')
        for oid in (tip, self.base):
            object_path = self.repo.path / 'objects' / oid[:2] / oid[2:]
            original = object_path.read_bytes()
            payload = zlib.decompress(original).replace(b'synthetic', b'SYNTHETIC')
            object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
            object_path.write_bytes(zlib.compress(payload))
            with self.subTest(oid=oid), self.assertRaises(BlockedError) as raised, \
                 patch('ci_contract.gitsource.subprocess.Popen', KillRecordingPopen):
                self.reader.require_ancestor(self.base, tip)
            self.assertEqual(raised.exception.reason_code, 'projection-ancestry-unavailable')
            object_path.write_bytes(original)
        self.assertEqual(kills, [])

    def test_ancestry_batch_malformed_protocol_is_blocked_and_closed(self):
        self.reader.verify_commit(self.base)
        prefix = self.base.encode('ascii')
        malformed = (b'', b'x' * 256 + b'\n', prefix + b' missing\n',
                     prefix + b' commit invalid\n', prefix + b' commit -1\n',
                     prefix + b' commit 01\n', prefix + b' blob 0\n\n',
                     b'0' * 40 + b' commit 0\n\n', prefix + b' commit 4\nabc',
                     prefix + b' commit 3\nabcX')
        cases = ((r, h, e) for r in malformed for h in (False, True) for e in (False, True))
        for response, hangs, exited_stdin in cases:
            process = BatchProcessStub(response, hangs=hangs, exited_stdin=exited_stdin)
            with self.subTest(response=response, hangs=hangs, exited_stdin=exited_stdin), \
                 patch('ci_contract.gitsource.subprocess.Popen', return_value=process):
                with self.assertRaises(BlockedError) as raised:
                    with self.reader._commit_batch() as read:
                        read(self.base)
                self.assertEqual(raised.exception.reason_code, 'projection-ancestry-unavailable')
                process.assert_closed_then_ended(self)

    def test_ancestry_batch_oversized_payload_is_blocked_before_read_and_closed(self):
        self.reader.verify_commit(self.base)
        sizes = (str(_MAX_ANCESTRY_COMMIT_BYTES + 1).encode('ascii'), b'9' * 100)
        for size_text, hangs in ((s, h) for s in sizes for h in (False, True)):
            process = BatchProcessStub(self.base.encode('ascii') + b' commit ' + size_text + b'\n',
                                       hangs=hangs)
            with self.subTest(size=size_text, hangs=hangs), \
                 patch('ci_contract.gitsource.subprocess.Popen', return_value=process), \
                 patch.object(process.stdout, 'read', side_effect=AssertionError('body must not be read')):
                with self.assertRaises(BlockedError) as raised:
                    with self.reader._commit_batch() as read:
                        read(self.base)
                self.assertEqual(raised.exception.reason_code, 'projection-ancestry-limit-exceeded')
                process.assert_closed_then_ended(self)

    def test_ancestry_batch_request_to_exited_git_is_blocked_and_closed(self):
        self.reader.verify_commit(self.base)
        for hangs in (False, True):
            process = BatchProcessStub(b'', hangs=hangs, exited_stdin=True, fail_flush=True)
            with self.subTest(hangs=hangs), \
                 patch('ci_contract.gitsource.subprocess.Popen', return_value=process):
                with self.assertRaises(BlockedError) as raised:
                    with self.reader._commit_batch() as read:
                        read(self.base)
                self.assertEqual(raised.exception.reason_code, 'projection-ancestry-unavailable')
                process.assert_closed_then_ended(self)

    def test_ancestry_batch_size_boundary_and_process_exit_are_checked(self):
        self.reader.verify_commit(self.base)
        payload = b'a' * _MAX_ANCESTRY_COMMIT_BYTES
        size = str(len(payload)).encode('ascii')
        oid = hashlib.sha1(b'commit ' + size + b'\0' + payload).hexdigest()
        response = oid.encode('ascii') + b' commit ' + size + b'\n' + payload + b'\n'
        for exit_status in (0, 1):
            process = BatchProcessStub(response, exit_status)
            with self.subTest(exit_status=exit_status), \
                 patch('ci_contract.gitsource.subprocess.Popen', return_value=process):
                if exit_status:
                    with self.assertRaises(BlockedError) as raised:
                        with self.reader._commit_batch() as read:
                            self.assertEqual(read(oid), payload)
                    self.assertEqual(raised.exception.reason_code, 'projection-ancestry-unavailable')
                else:
                    with self.reader._commit_batch() as read:
                        self.assertEqual(read(oid), payload)
                self.assertFalse(process.killed)
                self.assertTrue(process.stdin.closed)
                self.assertTrue(process.stdout.closed)
                self.assertGreaterEqual(process.waits, 1)

    def test_source_preserves_explicit_second_commit_side(self):
        for side in ('base', 'target', 'projection-anchor'):
            with self.subTest(side=side), self.assertRaises(BlockedError) as raised:
                self.reader.source(self.base, '0' * 40, side=side)
            self.assertEqual(raised.exception.reason_code, side + '-not-recoverable')

    def test_source_preserves_explicit_side_for_missing_tree(self):
        tree = self.repo.run('rev-parse', '--verify', self.base + '^{tree}').strip().decode('ascii')
        object_path = self.repo.path / 'objects' / tree[:2] / tree[2:]
        object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        object_path.unlink()
        for side in ('base', 'target', 'projection-anchor'):
            with self.subTest(side=side), self.assertRaises(BlockedError) as raised:
                GitSource(self.repo.path).source(self.base, self.base, side=side)
            self.assertEqual(raised.exception.reason_code, side + '-not-recoverable')

    def test_branch_short_sha_uppercase_and_revision_syntax_are_invalid(self):
        values = ('HEAD', 'main', 'refs/heads/main', self.base[:12], self.base.upper(),
                  self.base + '\n', self.base + ' ', self.base + '^{commit}',
                  '0' * 64, '', '--help', None, 123)
        with patch('ci_contract.gitsource.subprocess.run') as run:
            for value in values:
                with self.subTest(value=value), self.assertRaises(InputError):
                    self.reader.verify_commit(value)
            run.assert_not_called()

    def test_missing_base_is_blocked_without_inference(self):
        with self.assertRaises(BlockedError) as raised:
            self.reader.source('0' * 40, self.base)
        self.assertEqual(raised.exception.reason_code, 'base-not-recoverable')

    def test_missing_target_is_blocked(self):
        with self.assertRaises(BlockedError) as raised:
            self.reader.source(self.base, '0' * 40)
        self.assertEqual(raised.exception.reason_code, 'target-not-recoverable')

    def test_non_commit_object_and_annotated_tag_oid_are_invalid(self):
        blob = self.repo.run('hash-object', '-w', '--stdin', input=b'not a commit').strip().decode('ascii')
        tag_data = (f'object {self.base}\ntype commit\ntag synthetic\n'
                    'tagger Synthetic Author <synthetic@example.invalid> 946684800 +0000\n\nsynthetic tag\n').encode('ascii')
        tag = self.repo.run('hash-object', '-w', '-t', 'tag', '--stdin', input=tag_data).strip().decode('ascii')
        for oid in (blob, tag):
            with self.subTest(oid=oid), self.assertRaises(InputError):
                self.reader.verify_commit(oid)

    def test_blob_bytes_not_worktree_or_filter_output(self):
        (self.repo.path / 'src').mkdir()
        (self.repo.path / 'src' / 'a.txt').write_bytes(b'decoy bytes')
        self.assertEqual(self.reader.read_blob(self.base, 'src/a.txt'), b'hello\r\n')
        entry = next(entry for entry in self.reader.source(self.base, self.base)['inputs'] if entry['kind'] == 'file')
        self.assertEqual(entry['bytesSha256'], hashlib.sha256(b'hello\r\n').hexdigest())
        self.assertNotEqual(entry['bytesSha256'], self.reader.entries(self.base)['src/a.txt'][1])
        self.assertEqual(entry['size'], 7)

    def test_blob_newlines_and_binary_bytes_are_exact(self):
        data = bytes(range(256)) + b'\r\n\n\x00\xff'
        target = self.repo.commit({'binary.dat': ('100644', data)})
        self.assertEqual(self.reader.read_blob(target, 'binary.dat'), data)
        self.assertEqual(self.reader.source(self.base, target)['inputs'][0]['bytesSha256'], hashing.raw_hash(data))

    def test_missing_blob_path_is_blocked(self):
        with self.assertRaises(BlockedError) as raised:
            self.reader.read_blob(self.base, 'not-present')
        self.assertEqual(raised.exception.reason_code, 'source-input-unavailable')

    def test_source_wrapper_matches_schema_and_pinned_domain(self):
        source = self.reader.source(self.base, self.base, {'src/a.txt': 'fixture'})
        self.assertEqual(source['comparison'], 'head')
        wrapper = hashing.inventory_from_source(source)
        schema.validate(wrapper)
        document = schema.load_schema()
        validator = schema.make_validator({'$schema': document['$schema'], '$defs': document['$defs'], '$ref': '#/$defs/source'})
        self.assertTrue(validator.is_valid(source))
        self.assertEqual(source['digest'], hashing.domain_hash('inventory', wrapper))
        self.assertEqual(source['inputs'][0], {'path': 'src', 'kind': 'directory', 'mode': '040755', 'size': 0, 'bytesSha256': None, 'role': 'source'})
        self.assertEqual(source['inputs'][1]['role'], 'fixture')

    def test_all_nested_parent_directories_are_included(self):
        target = self.repo.commit({'one/two/three.txt': ('100644', b'content')})
        inputs = self.reader.source(self.base, target)['inputs']
        self.assertEqual([entry['path'] for entry in inputs], ['one', 'one/two', 'one/two/three.txt'])
        self.assertEqual([entry['mode'] for entry in inputs], ['040755', '040755', '100644'])

    def test_explicit_empty_subtree_directory_is_in_inventory(self):
        target = self.repo.commit({'empty': ('040000', b'')})
        self.assertEqual(self.reader.entries(target), {})
        inputs = self.reader.source(self.base, target)['inputs']
        self.assertEqual(inputs, [{'path': 'empty', 'kind': 'directory', 'mode': '040755', 'size': 0, 'bytesSha256': None, 'role': 'source'}])

    def test_empty_directory_changes_digest_without_file_change_record(self):
        target = self.repo.commit(dict(DETERMINISTIC_FILES, empty=('040000', b'')), parents=(self.base,))
        self.assertEqual(self.reader.changes(self.base, target), [])
        self.assertNotEqual(self.reader.source(self.base, self.base)['digest'],
                            self.reader.source(self.base, target)['digest'])

    def test_empty_root_tree_fails_inventory_minimum(self):
        target = self.repo.commit({})
        with self.assertRaises(InputError):
            self.reader.source(self.base, target)

    def test_mode_only_change_changes_digest_and_is_modify(self):
        target = self.repo.commit({'src/a.txt': ('100755', b'hello\r\n')}, parents=(self.base,))
        before = self.reader.source(self.base, self.base)
        after = self.reader.source(self.base, target)
        self.assertEqual(before['inputs'][1]['bytesSha256'], after['inputs'][1]['bytesSha256'])
        self.assertNotEqual(before['digest'], after['digest'])
        self.assertEqual(self.reader.changes(self.base, target), [{'path': 'src/a.txt', 'status': 'modify'}])
        # Negative control: dropping mode would hide this mutation.
        without_mode = lambda entries: [{key: value for key, value in entry.items() if key != 'mode'} for entry in entries]
        self.assertEqual(without_mode(before['inputs']), without_mode(after['inputs']))

    def test_rename_is_delete_and_add(self):
        target = self.repo.commit({'new/a.txt': ('100644', b'hello\r\n')}, parents=(self.base,))
        self.assertEqual(self.reader.changes(self.base, target), [
            {'path': 'new/a.txt', 'status': 'add'}, {'path': 'src/a.txt', 'status': 'delete'}])

    def test_case_only_rename_has_no_within_snapshot_collision(self):
        base = self.repo.commit({'A.txt': ('100644', b'same')})
        target = self.repo.commit({'a.txt': ('100644', b'same')}, parents=(base,))
        self.assertEqual(self.reader.changes(base, target), [
            {'path': 'A.txt', 'status': 'delete'}, {'path': 'a.txt', 'status': 'add'}])

    def test_content_modify_add_delete_and_unchanged(self):
        base = self.repo.commit({'edit': ('100644', b'old'), 'remove': ('100644', b'old'), 'same': ('100644', b'same')})
        target = self.repo.commit({'edit': ('100644', b'new'), 'add': ('100644', b'new'), 'same': ('100644', b'same')}, parents=(base,))
        self.assertEqual(self.reader.changes(base, target), [
            {'path': 'add', 'status': 'add'}, {'path': 'edit', 'status': 'modify'}, {'path': 'remove', 'status': 'delete'}])
        self.assertEqual(self.reader.changes(target, target), [])

    def test_symlink_and_submodule_are_rejected(self):
        for mode, data in (('120000', b'outside'), ('160000', self.base.encode('ascii'))):
            with self.subTest(mode=mode):
                target = self.repo.commit({'link': (mode, data)})
                with self.assertRaises(InputError):
                    self.reader.source(self.base, target)

    def test_lfs_pointer_is_rejected_without_filter_or_fetch(self):
        for url in (b'https://git-lfs.github.com/spec/v1', b'https://hawser.github.com/spec/v1'):
            pointer = b'version ' + url + b'\noid sha256:' + b'0' * 64 + b'\nsize 42\n'
            with self.subTest(url=url):
                target = self.repo.commit({'asset': ('100644', pointer)})
                with self.assertRaises(InputError):
                    self.reader.source(self.base, target)

    def test_non_utf8_and_non_nfc_git_paths_are_rejected(self):
        for path in (b'bad-\xff', 'e\u0301.txt'):
            with self.subTest(path=path):
                target = self.repo.commit({path: ('100644', b'content')})
                with self.assertRaises(InputError):
                    self.reader.source(self.base, target)

    def test_casefold_collisions_include_parent_directories(self):
        for paths in (('A.txt', 'a.txt'), ('Straße.txt', 'STRASSE.txt'), ('Dir/a', 'dir/b')):
            with self.subTest(paths=paths):
                target = self.repo.commit({path: ('100644', b'content') for path in paths})
                with self.assertRaises(InputError):
                    self.reader.source(self.base, target)

    def test_invalid_changed_base_paths_cannot_hide_in_deletion(self):
        base = self.repo.commit({'bad:name': ('100644', b'content')})
        with self.assertRaises(InputError):
            self.reader.changes(base, self.base)

    def test_replacement_refs_cannot_change_source_objects(self):
        replaced = self.repo.commit({'attacker': ('100644', b'wrong')})
        refs = self.repo.path / 'refs' / 'replace'
        refs.mkdir()
        (refs / self.base).write_bytes((replaced + '\n').encode('ascii'))
        self.assertEqual(self.reader.read_blob(self.base, 'src/a.txt'), b'hello\r\n')
        self.assertEqual([entry['path'] for entry in self.reader.source(self.base, self.base)['inputs']], ['src', 'src/a.txt'])

    def test_hostile_git_environment_cannot_redirect_trace_or_config(self):
        trace = self.root / 'trace.txt'
        hostile = {'GIT_DIR': str(self.root / 'absent'), 'GIT_WORK_TREE': str(self.root),
                   'GIT_OBJECT_DIRECTORY': str(self.root / 'absent'), 'GIT_INDEX_FILE': str(trace),
                   'GIT_ALTERNATE_OBJECT_DIRECTORIES': str(self.root / 'absent'),
                   'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'core.repositoryformatversion',
                   'GIT_CONFIG_VALUE_0': '999', 'GIT_CONFIG_PARAMETERS': 'malformed',
                   'GIT_TRACE': str(trace), 'GIT_TRACE2_EVENT': str(trace),
                   'GIT_EXEC_PATH': str(self.root / 'absent'), 'GIT_REPLACE_REF_BASE': 'refs/hostile/',
                   'GIT_NO_LAZY_FETCH': '0', 'GIT_ALLOW_PROTOCOL': 'file:http:https:ext'}
        with patch.dict(os.environ, hostile):
            self.assertEqual(GitSource(self.repo.path).read_blob(self.base, 'src/a.txt'), b'hello\r\n')
        self.assertFalse(trace.exists())

    def test_global_and_local_settings_cannot_change_output(self):
        target = self.repo.commit({'new': ('100644', b'hello\r\n')}, parents=(self.base,))
        expected_source = self.reader.source(self.base, target)
        expected_changes = self.reader.changes(self.base, target)
        fake_global = self.root / 'hostile-global'
        fake_global.write_text('[core]\nrepositoryformatversion = 999\n', encoding='utf-8')
        with (self.repo.path / 'config').open('ab') as stream:
            stream.write(b'\n[diff]\nrenames = copies\nrelative = true\norderFile = does-not-exist\nexternal = synthetic-never-run\n'
                         b'[core]\nquotePath = true\nfsmonitor = synthetic-never-run\nattributesFile = does-not-exist\n'
                         b'[filter "lfs"]\nprocess = synthetic-never-run\nrequired = true\n'
                         b'[alias]\nls-tree = !synthetic-never-run\n')
        with patch.dict(os.environ, {'GIT_CONFIG_GLOBAL': str(fake_global), 'GIT_EXTERNAL_DIFF': 'synthetic-never-run'}):
            reader = GitSource(self.repo.path)
            self.assertEqual(reader.source(self.base, target), expected_source)
            self.assertEqual(reader.changes(self.base, target), expected_changes)

    def test_missing_promisor_blob_is_blocked_with_no_lazy_fetch(self):
        oid = self.reader.entries(self.base)['src/a.txt'][1]
        object_path = self.repo.path / 'objects' / oid[:2] / oid[2:]
        object_path.chmod(stat.S_IWRITE | stat.S_IREAD)
        object_path.unlink()
        with (self.repo.path / 'config').open('ab') as stream:
            stream.write(b'\n[extensions]\npartialClone = synthetic\n[remote "synthetic"]\npromisor = true\nurl = ext::synthetic-never-run\n')
        with self.assertRaises(BlockedError) as raised:
            self.reader.read_blob(self.base, 'src/a.txt')
        self.assertEqual(raised.exception.reason_code, 'source-input-unavailable')

    def test_reader_changes_no_repository_bytes(self):
        target = self.repo.commit({'new': ('100755', b'hello\r\n')}, parents=(self.base,))
        snapshot = lambda: {str(path.relative_to(self.repo.path)): path.read_bytes() for path in self.repo.path.rglob('*') if path.is_file()}
        before = snapshot()
        self.reader.source(self.base, target)
        self.reader.changes(self.base, target)
        self.reader.read_blob(self.base, 'src/a.txt')
        self.assertEqual(snapshot(), before)

    def test_only_allowlisted_plumbing_with_binary_io_and_no_shell(self):
        real_run = subprocess.run
        calls = []

        def recording_run(command, **kwargs):
            calls.append((command, kwargs))
            return real_run(command, **kwargs)

        with patch('ci_contract.gitsource.subprocess.run', side_effect=recording_run):
            self.reader.source(self.base, self.base)
            self.reader.changes(self.base, self.base)
        for command, kwargs in calls:
            self.assertTrue(os.path.isabs(command[0]))
            self.assertNotEqual(command[0], 'git')
            options = command[2:]
            while options[0] == '-c':
                options = options[2:]
            self.assertTrue(options[0].startswith('--git-dir='))
            options = options[1:]
            self.assertIn(options[0], ('rev-parse', 'cat-file', 'ls-tree', 'diff-tree'))
            self.assertIs(kwargs['shell'], False)
            self.assertNotIn('text', kwargs)
            self.assertEqual(kwargs['env']['GIT_ALLOW_PROTOCOL'], '')
            self.assertEqual(kwargs['env']['GIT_NO_LAZY_FETCH'], '1')
            self.assertEqual(kwargs['env']['GIT_NO_REPLACE_OBJECTS'], '1')
        with self.assertRaises(InputError):
            self.reader._run(['fetch', 'origin'])

    def test_300_files_use_one_blob_batch_and_constant_process_count(self):
        target = self.repo.commit({f'data/file-{i:03d}': ('100644', f'payload-{i}'.encode('ascii'))
                                   for i in range(300)})
        calls = []
        real_run = subprocess.run

        def record(command, **kwargs):
            calls.append((command, kwargs))
            return real_run(command, **kwargs)

        with patch('ci_contract.gitsource.subprocess.run', side_effect=record):
            source = GitSource(self.repo.path).source(target, target)
        self.assertEqual(len(source['inputs']), 301)
        blob_batches = [(command, kwargs) for command, kwargs in calls
                        if command[-2:] == ['cat-file', '--batch'] and kwargs['input']]
        self.assertEqual(len(blob_batches), 1)
        self.assertEqual(len(blob_batches[0][1]['input'].splitlines()), 300)
        self.assertEqual(len(calls), 5)  # exact-location probe, type, tree, blobs, tree ID

    def test_inventory_entry_bound_counts_directories_before_blob_read(self):
        # One raw flat tree is faster than 10,000 redundant hash-object writes.
        oid = self.repo.run('hash-object', '-w', '--stdin', input=b'payload').strip()
        records = b''.join(b'100644 blob ' + oid + b'\tfile-' + str(i).encode('ascii') + b'\0'
                           for i in range(10000))
        tree = self.repo.run('mktree', '-z', '--missing', input=records).strip()
        root = self.repo.run('mktree', '-z', '--missing',
                             input=b'040000 tree ' + tree + b'\tdirectory\0').strip().decode('ascii')
        target = self.repo.run('commit-tree', root, input=b'entry bound\n').strip().decode('ascii')
        with patch.object(self.reader, '_objects') as blobs:
            with self.assertRaises(InputError):
                self.reader.source(self.base, target)
            blobs.assert_not_called()

    def test_paths_and_source_roles_retain_directories(self):
        target = self.repo.commit({'empty': ('040000', b''), 'data/file': ('100644', b'payload')})
        self.assertEqual(self.reader.paths(target), frozenset(('empty', 'data', 'data/file')))
        source = self.reader.source(self.base, target, {'empty': 'fixture', 'data': 'generator'})
        self.assertEqual({entry['path']: entry['role'] for entry in source['inputs']},
                         {'empty': 'fixture', 'data': 'generator', 'data/file': 'source'})

    def test_read_blob_does_not_copy_cached_entry_mapping(self):
        self.reader.entries(self.base)
        with patch.object(self.reader, 'entries', side_effect=AssertionError('public mapping copied')):
            self.assertEqual(self.reader.read_blob(self.base, 'src/a.txt'), b'hello\r\n')

    def test_git_metadata_aliases_in_tree_are_rejected(self):
        for name in ('.git', '.GIT', 'git~1', 'GIT~1', 'nested/.gIt/file', 'nested/GIT~1/file',
                     '.g\u200cit', '\ufeff.git', 'nested/.g\u202eit/file', '.git\u206f'):
            with self.subTest(name=name):
                target = self.repo.commit({name: ('100644', b'payload')})
                with self.assertRaises(InputError):
                    self.reader.source(self.base, target)

    def test_entries_returns_copy_of_cache(self):
        entries = self.reader.entries(self.base)
        entries.clear()
        self.assertIn('src/a.txt', self.reader.entries(self.base))


class GitExecutableResolutionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cwd = self.root / 'working'
        self.repo = self.root / 'repository'
        self.cwd.mkdir()
        self.repo.mkdir()
        self.executable = 'git.exe' if os.name == 'nt' else 'git'
        self.windows_identities = {}

    def executable_in(self, directory):
        directory.mkdir(parents=True, exist_ok=True)
        candidate = directory / self.executable
        candidate.write_bytes(b'synthetic executable marker; never run')
        candidate.chmod(stat.S_IREAD | stat.S_IWRITE | stat.S_IEXEC)
        return candidate

    def windows_stat(self, value):
        """Give each normalized synthetic Windows directory a stable identity."""
        value = ntpath.normcase(ntpath.abspath(value))
        inode = self.windows_identities.setdefault(value, len(self.windows_identities) + 1)
        return SimpleNamespace(st_dev=1, st_ino=inode)

    def test_absolute_cwd_descendants_are_eligible_but_exact_cwd_and_repo_are_not(self):
        cwd_executable = self.executable_in(self.cwd)
        cwd_child = self.executable_in(self.cwd / 'bin')
        repo_executable = self.executable_in(self.repo)
        repo_child = self.executable_in(self.repo / 'tools')
        allowed = self.executable_in(self.root / 'trusted-bin')
        path = os.pathsep.join(('', '.', 'relative', str(cwd_executable.parent),
                                str(cwd_child.parent), str(repo_executable.parent),
                                str(repo_child.parent), str(allowed.parent)))
        self.assertEqual(_resolve_git(self.repo, path=path, cwd=self.cwd), str(cwd_child.resolve()))
        path = os.pathsep.join((str(cwd_executable.parent), str(repo_executable.parent),
                                str(repo_child.parent), str(allowed.parent)))
        self.assertEqual(_resolve_git(self.repo, path=path, cwd=self.cwd), str(allowed.resolve()))
        with self.assertRaises(BlockedError) as raised:
            _resolve_git(self.repo, path=os.pathsep.join(('', '.', str(self.repo))), cwd=self.cwd)
        self.assertEqual(raised.exception.reason_code, 'git-unavailable')

    def test_drive_root_cwd_does_not_exclude_absolute_installation(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        self.assertEqual(_resolve_git(self.repo, path=str(allowed.parent), cwd=self.root.anchor),
                         str(allowed.resolve()))

    def test_quoted_path_entries_are_skipped_without_stripping_quotes(self):
        quoted = self.executable_in(self.root / 'quoted-bin')
        allowed = self.executable_in(self.root / 'trusted-bin')
        for entry in ('"' + str(quoted.parent) + '"', '"' + str(quoted.parent),
                      str(quoted.parent) + '"'):
            with self.subTest(entry=entry):
                path = os.pathsep.join((entry, str(allowed.parent)))
                self.assertEqual(_resolve_git(self.repo, path=path, cwd=self.cwd), str(allowed.resolve()))

    def test_windows_device_prefixes_and_quotes_are_skipped_under_emulation(self):
        considered = []
        trusted = r'C:\Program Files\Git\cmd\git.exe'

        def isfile(value):
            considered.append(value)
            return True

        windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
            ('abspath', 'realpath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
            isfile=isfile)
        windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
            environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
            stat=self.windows_stat)
        prefixes = ('\\\\?\\', '\\\\.\\', '//?/', '//./', '\\\\?/', '\\\\./')
        unsafe = [prefix + r'C:\working' for prefix in prefixes]
        unsafe += [prefix + r'C:\repository\tools' for prefix in prefixes]
        unsafe += ['"' + r'C:\working' + '"', '"' + r'C:\repository\tools' + '"']
        with patch('ci_contract.gitsource.os', windows_os):
            for entry in unsafe:
                with self.subTest(entry=entry):
                    result = _resolve_git(r'C:\repository', path=entry + ';' + ntpath.dirname(trusted),
                                          cwd=r'C:\working')
                    self.assertEqual(ntpath.normcase(result), ntpath.normcase(trusted))
        self.assertEqual([ntpath.normcase(value) for value in considered],
                         [ntpath.normcase(trusted)] * len(unsafe))

    def test_windows_drive_root_cwd_and_repo_subtree_under_emulation(self):
        windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
            ('abspath', 'realpath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
            isfile=lambda value: True)
        windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
            environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
            stat=self.windows_stat)
        with patch('ci_contract.gitsource.os', windows_os):
            result = _resolve_git(r'C:\repository', path=r'C:\;C:\repository\bin;C:\Git\bin', cwd='C:\\')
            self.assertEqual(ntpath.normcase(result), ntpath.normcase(r'C:\Git\bin\git.exe'))

    def assert_unc_rejected_before_realpath(self):
        resolved = []
        trusted = r'C:\trusted-bin\git.exe'

        def realpath(value):
            resolved.append(value)
            return ntpath.abspath(value)

        windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
            ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
            realpath=realpath, isfile=lambda value: True)
        windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
            environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
            stat=self.windows_stat)
        entries = ('\\\\host\\share', '//host/share', '\\/host/share', '/\\host\\share')
        with patch('ci_contract.gitsource.os', windows_os):
            for entry in entries:
                resolved.clear()
                result = _resolve_git(r'C:\repository',
                                      path=entry + ';' + ntpath.dirname(trusted),
                                      cwd=r'C:\working')
                self.assertEqual(ntpath.normcase(result), ntpath.normcase(trusted))
                self.assertFalse(any(value.replace('/', '\\').startswith('\\\\')
                                     for value in resolved),
                                 'UNC entries must not reach realpath')

    def test_f1_all_unc_spellings_rejected_before_realpath(self):
        self.assert_unc_rejected_before_realpath()

    def test_f1_two_spelling_guard_mutant_is_detected(self):
        with patch('ci_contract.gitsource._windows_unc_path',
                   side_effect=lambda path: path.startswith(('\\\\', '//'))):
            with self.assertRaises(AssertionError):
                self.assert_unc_rejected_before_realpath()


    def test_windows_unc_path_entries_are_skipped_under_emulation(self):
        considered = []
        trusted = r'C:\trusted-bin\git.exe'

        def isfile(value):
            considered.append(ntpath.normcase(value))
            return True

        windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
            ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
            realpath=ntpath.abspath, isfile=isfile)
        windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
            environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
            stat=self.windows_stat)
        entries = (r'\\localhost\C$\working', '//localhost/C$/working',
                   r'\\localhost\C$\repository\tools', '//localhost/C$/repository/tools',
                   r'\\server\share\bin', '//server/share/bin')
        with patch('ci_contract.gitsource.os', windows_os):
            for entry in entries:
                with self.subTest(entry=entry):
                    result = _resolve_git(r'C:\repository',
                                          path=entry + ';' + ntpath.dirname(trusted),
                                          cwd=r'C:\working')
                    self.assertEqual(ntpath.normcase(result), ntpath.normcase(trusted))
        self.assertEqual(considered, [ntpath.normcase(trusted)] * len(entries))

    def test_windows_resolved_unc_aliases_are_also_skipped(self):
        alias = r'C:\alias'
        trusted = r'C:\trusted-bin'
        for unc in (r'\\localhost\C$\working', '//server/share/bin'):
            for candidate_alias in (False, True):
                def resolve(value):
                    trigger = ntpath.join(alias, 'git.exe') if candidate_alias else alias
                    if ntpath.normcase(value) == ntpath.normcase(trigger):
                        return unc + ('/git.exe' if candidate_alias else '')
                    return ntpath.abspath(value)

                windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
                    ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
                    realpath=resolve, isfile=lambda value: True)
                windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
                    environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
                    stat=self.windows_stat)
                with self.subTest(unc=unc, candidate_alias=candidate_alias), \
                     patch('ci_contract.gitsource.os', windows_os):
                    result = _resolve_git(r'C:\repository', path=alias + ';' + trusted,
                                          cwd=r'C:\working')
                    self.assertEqual(ntpath.normcase(result),
                                     ntpath.normcase(ntpath.join(trusted, 'git.exe')))

    def test_windows_filesystem_aliases_exclude_cwd_repo_and_repo_descendants(self):
        aliases = {'s:\\': r'c:\working', 'r:\\': r'c:\repository'}

        def filesystem_stat(value):
            value = ntpath.normcase(ntpath.abspath(value))
            return self.windows_stat(aliases.get(value, value))

        windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
            ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
            realpath=ntpath.abspath, isfile=lambda value: True)
        windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
            environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
            stat=filesystem_stat)
        with patch('ci_contract.gitsource.os', windows_os):
            for entry in ('S:\\', 'R:\\', r'R:\tools'):
                with self.subTest(entry=entry):
                    result = _resolve_git(r'C:\repository',
                                          path=entry + r';C:\trusted-bin', cwd=r'C:\working')
                    self.assertEqual(ntpath.normcase(result), r'c:\trusted-bin\git.exe')
            # CWD descendants retain their existing eligibility.
            result = _resolve_git(r'C:\repository', path=r'S:\tools', cwd=r'C:\working')
            self.assertEqual(ntpath.normcase(result), r's:\tools\git.exe')

    def test_filesystem_identity_includes_device_as_well_as_inode(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        real_stat = os.stat
        cwd_stat = real_stat(self.cwd)

        def filesystem_stat(value, *args, **kwargs):
            if os.path.normcase(os.fspath(value)) == os.path.normcase(str(allowed.parent)):
                return SimpleNamespace(st_dev=cwd_stat.st_dev + 1, st_ino=cwd_stat.st_ino)
            return real_stat(value, *args, **kwargs)

        with patch('ci_contract.gitsource.os.stat', side_effect=filesystem_stat):
            result = _resolve_git(self.repo, path=str(allowed.parent), cwd=self.cwd)
        self.assertEqual(os.path.normcase(result), os.path.normcase(str(allowed.resolve())))

    def test_unstatable_path_entries_are_skipped(self):
        unsafe = self.executable_in(self.root / 'unstatable-bin')
        allowed = self.executable_in(self.root / 'trusted-bin')
        real_stat = os.stat

        def filesystem_stat(value, *args, **kwargs):
            if os.path.normcase(os.fspath(value)) == os.path.normcase(str(unsafe.parent)):
                raise PermissionError('synthetic directory stat denial')
            return real_stat(value, *args, **kwargs)

        with patch('ci_contract.gitsource.os.stat', side_effect=filesystem_stat):
            result = _resolve_git(self.repo,
                                  path=os.pathsep.join((str(unsafe.parent), str(allowed.parent))),
                                  cwd=self.cwd)
        self.assertEqual(os.path.normcase(result), os.path.normcase(str(allowed.resolve())))

    def test_unstatable_path_ancestors_are_skipped(self):
        unsafe = self.executable_in(self.root / 'unstatable-parent' / 'bin')
        allowed = self.executable_in(self.root / 'trusted-bin')
        real_stat = os.stat

        def filesystem_stat(value, *args, **kwargs):
            if os.path.normcase(os.fspath(value)) == os.path.normcase(str(unsafe.parent.parent)):
                raise PermissionError('synthetic ancestor stat denial')
            return real_stat(value, *args, **kwargs)

        with patch('ci_contract.gitsource.os.stat', side_effect=filesystem_stat):
            result = _resolve_git(self.repo,
                                  path=os.pathsep.join((str(unsafe.parent), str(allowed.parent))),
                                  cwd=self.cwd)
        self.assertEqual(os.path.normcase(result), os.path.normcase(str(allowed.resolve())))

    def test_unstatable_cwd_or_repository_identity_blocks_resolution(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        real_stat = os.stat
        for unavailable in (self.cwd, self.repo):
            def filesystem_stat(value, *args, **kwargs):
                if os.path.normcase(os.fspath(value)) == os.path.normcase(str(unavailable)):
                    raise PermissionError('synthetic root stat denial')
                return real_stat(value, *args, **kwargs)

            with self.subTest(root=unavailable.name), \
                 patch('ci_contract.gitsource.os.stat', side_effect=filesystem_stat):
                with self.assertRaises(BlockedError) as raised:
                    _resolve_git(self.repo, path=str(allowed.parent), cwd=self.cwd)
                self.assertEqual(raised.exception.reason_code, 'git-unavailable')

    def test_native_symlink_identity_excludes_cwd_repo_and_repo_descendants(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        for index, (target, child) in enumerate(((self.cwd, ''), (self.repo, ''),
                                                (self.repo, 'tools'))):
            self.executable_in(target / child)
            alias = self.root / ('alias-' + str(index))
            try:
                alias.symlink_to(target, target_is_directory=True)
            except (OSError, NotImplementedError) as error:
                self.skipTest('host cannot create synthetic directory symlinks: ' +
                              type(error).__name__)
            with self.subTest(target=target.name, child=child):
                # Preserve the alias spelling to prove the stat exclusion,
                # rather than letting realpath's string comparison protect it.
                with patch('ci_contract.gitsource.os.path.realpath', side_effect=os.path.abspath):
                    result = _resolve_git(self.repo,
                                          path=os.pathsep.join((str(alias / child), str(allowed.parent))),
                                          cwd=self.cwd)
                self.assertEqual(os.path.normcase(result),
                                 os.path.normcase(str(allowed.resolve())))

    @unittest.skipUnless(os.name == 'nt', 'native directory junctions require Windows')
    def test_native_windows_junction_identity_excludes_cwd(self):
        command = os.environ.get('COMSPEC')
        if not command or not os.path.isabs(command) or not os.path.isfile(command):
            self.skipTest('host has no absolute COMSPEC for synthetic junction creation')
        self.executable_in(self.cwd)
        allowed = self.executable_in(self.root / 'trusted-bin')
        alias = self.root / 'junction'
        try:
            result = subprocess.run([command, '/d', '/c', 'mklink', '/J', str(alias), str(self.cwd)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                    shell=False, check=False)
        except OSError as error:
            self.skipTest('host cannot create synthetic directory junctions: ' +
                          type(error).__name__)
        if result.returncode:
            self.skipTest('host cannot create synthetic directory junctions: mklink exit ' +
                          str(result.returncode))
        self.addCleanup(alias.rmdir)
        with patch('ci_contract.gitsource.os.path.realpath', side_effect=os.path.abspath):
            result = _resolve_git(self.repo,
                                  path=os.pathsep.join((str(alias), str(allowed.parent))),
                                  cwd=self.cwd)
        self.assertEqual(os.path.normcase(result), os.path.normcase(str(allowed.resolve())))

    def test_windows_resolved_device_aliases_are_also_skipped(self):
        trusted = r'C:\Git\bin'
        alias = r'C:\alias'
        for prefix in ('\\\\?\\', '\\\\.\\'):
            for candidate_alias in (False, True):
                def resolve(value):
                    trigger = ntpath.join(alias, 'git.exe') if candidate_alias else alias
                    if ntpath.normcase(value) == ntpath.normcase(trigger):
                        return prefix + r'C:\repository\bin' + ('\\git.exe' if candidate_alias else '')
                    return ntpath.abspath(value)

                windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
                    ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
                    realpath=resolve, isfile=lambda value: True)
                windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
                    environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
                    stat=self.windows_stat)
                with self.subTest(prefix=prefix, candidate_alias=candidate_alias), \
                     patch('ci_contract.gitsource.os', windows_os):
                    result = _resolve_git(r'C:\repository', path=alias + ';' + trusted, cwd=r'C:\working')
                    self.assertEqual(result, r'c:\git\bin\git.exe')

    def test_windows_prefixed_root_identities_block_resolution(self):
        # Raw and resolved repository/CWD identities must be rejected before
        # candidate lookup; an unprefixed spelling cannot bypass exclusion.
        for prefix in ('\\\\?\\', '\\\\.\\', '//?/', '//./'):
            for root_kind in ('repository', 'cwd'):
                for resolved_alias in (False, True):
                    unsafe = r'C:\RePoSiToRy' if root_kind == 'repository' else r'C:\WoRkInG'
                    root = r'C:\Alias' if resolved_alias else prefix + unsafe
                    repo = root if root_kind == 'repository' else r'D:\Repository'
                    cwd = root if root_kind == 'cwd' else r'D:\Working'
                    path = r'c:\repository\bin' if root_kind == 'repository' else r'c:\working'

                    def resolve(value):
                        if resolved_alias and ntpath.normcase(value) == ntpath.normcase(root):
                            return prefix + unsafe
                        return ntpath.abspath(value)

                    def forbidden_lookup(value):
                        raise AssertionError('unsafe root must block before candidate lookup')

                    windows_path = SimpleNamespace(**{name: getattr(ntpath, name) for name in
                        ('abspath', 'normcase', 'isabs', 'commonpath', 'join', 'dirname')},
                        realpath=resolve, isfile=forbidden_lookup)
                    windows_os = SimpleNamespace(path=windows_path, pathsep=';', name='nt',
                        environ={}, X_OK=os.X_OK, access=lambda *args: True, fspath=os.fspath,
                        stat=self.windows_stat)
                    with self.subTest(prefix=prefix, root=root_kind, resolved=resolved_alias), \
                         patch('ci_contract.gitsource.os', windows_os):
                        with self.assertRaises(BlockedError) as raised:
                            _resolve_git(repo, path=path, cwd=cwd)
                        self.assertEqual(raised.exception.reason_code, 'git-unavailable')

    def test_repository_path_entry_cannot_escape_through_symlink(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        alias = self.repo / 'tools'
        try:
            alias.symlink_to(allowed.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('host cannot create synthetic directory symlinks')
        with self.assertRaises(BlockedError):
            _resolve_git(self.repo, path=str(alias), cwd=self.cwd)

    def test_symlink_executable_cannot_resolve_back_into_repository(self):
        unsafe = self.executable_in(self.repo / 'tools')
        alias_dir = self.root / 'alias-bin'; alias_dir.mkdir()
        try:
            (alias_dir / self.executable).symlink_to(unsafe)
        except (OSError, NotImplementedError):
            self.skipTest('host cannot create synthetic executable symlinks')
        with self.assertRaises(BlockedError):
            _resolve_git(self.repo, path=str(alias_dir), cwd=self.cwd)

    def test_symlink_directory_cannot_resolve_back_into_working_directory(self):
        unsafe = self.executable_in(self.cwd)
        alias = self.root / 'alias-bin'
        try:
            alias.symlink_to(unsafe.parent, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest('host cannot create synthetic directory symlinks')
        with self.assertRaises(BlockedError):
            _resolve_git(self.repo, path=str(alias), cwd=self.cwd)

    def test_symlink_executable_cannot_resolve_into_exact_working_directory(self):
        unsafe = self.executable_in(self.cwd)
        alias_dir = self.root / 'alias-bin'; alias_dir.mkdir()
        try:
            (alias_dir / self.executable).symlink_to(unsafe)
        except (OSError, NotImplementedError):
            self.skipTest('host cannot create synthetic executable symlinks')
        with self.assertRaises(BlockedError):
            _resolve_git(self.repo, path=str(alias_dir), cwd=self.cwd)

    def test_synthetic_helper_uses_shared_safe_absolute_resolver(self):
        allowed = self.executable_in(self.root / 'trusted-bin')
        self.executable_in(self.cwd)
        self.executable_in(self.repo / 'synthetic.git')
        path = os.pathsep.join((str(self.cwd), str(self.repo / 'synthetic.git'), str(allowed.parent)))
        with patch.dict(os.environ, {'PATH': path}), \
             patch('ci_contract.gitsource.os.getcwd', return_value=str(self.cwd)), \
             patch('synthetic_git._resolve_git', wraps=_resolve_git) as resolve, \
             patch('synthetic_git.subprocess.run', return_value=SimpleNamespace(stdout=b'')) as run:
            repo = SyntheticGit(self.repo / 'synthetic.git')
            repo.run('hash-object', '--stdin', input=b'synthetic')
        resolve.assert_called_once_with(self.repo / 'synthetic.git')
        for call in run.call_args_list:
            self.assertEqual(call.args[0][0], str(allowed.resolve()))
            self.assertIs(call.kwargs['shell'], False)


class InventoryTests(unittest.TestCase):
    def test_hfs_ignored_characters_cannot_disguise_git_metadata(self):
        ignored = [chr(value) for value in (*range(0x200c, 0x2010), *range(0x202a, 0x202f),
                                            *range(0x206a, 0x2070), 0xfeff)]
        for char in ignored:
            for position in range(5):
                alias = '.gIt'[:position] + char + '.gIt'[position:]
                for path in (alias, 'nested/' + alias + '/file'):
                    with self.subTest(char=hex(ord(char)), path=repr(path)), self.assertRaises(InputError):
                        inventory.validate_path(path)
        for valid in ('.g\u200bit', '\u2060.git', '.g\u200citignore', 'normal\ufeff.txt'):
            with self.subTest(valid=repr(valid)):
                self.assertEqual(inventory.validate_path(valid), valid)

    def test_invalid_portable_paths_are_rejected(self):
        paths = ('.git', '.GIT', 'git~1', 'GIT~1', 'nested/.git/file', '', '.', '..', '/absolute', '../outside', 'a/../b', 'a/./b', 'a//b', 'a/',
                 'a\x00b', 'a\nb', 'a\tb', 'a\x7fb', 'a\x85b', 'C:/a', 'a:b', 'a\\b',
                 'a.', 'a ', 'dir./a', 'con', 'NUL.txt', 'COM1.dat', 'lpt9', 'COM¹.txt',
                 'CONOUT$', 'a?b', 'a*b', 'a|b', 'a<b', 'a>b', 'a"b', 'e\u0301',
                 '\ud800', 'a' * 513, b'\xff')
        for path in paths:
            with self.subTest(path=repr(path)), self.assertRaises(InputError):
                inventory.validate_path(path)

    def test_valid_unicode_and_filename_whitespace_are_preserved(self):
        for path in ('src/é.py', '資料/文.txt', 'src/a b.txt', 'nulled.txt', 'COM10.txt', 'a/ b', 'a/💡'):
            with self.subTest(path=path):
                self.assertEqual(inventory.validate_path(path), path)
                self.assertEqual(inventory.validate_path(path.encode('utf-8')), path)

    def test_entries_are_sorted_by_codepoint_without_mutating_input(self):
        files = {'z': ('100755', b'z'), 'a/f': ('100644', b'f')}
        original = copy.deepcopy(files)
        result = inventory.build_inventory(files)
        self.assertEqual([entry['path'] for entry in result['entries']], ['a', 'a/f', 'z'])
        self.assertEqual(files, original)

    def test_duplicate_and_casefold_aliases_are_rejected(self):
        base = inventory.build_inventory({'a': ('100644', b'a')})['entries'][0]
        with self.assertRaises(InputError):
            inventory.normalize_inventory([base, copy.deepcopy(base)])
        for files in ({'A': ('100644', b'a'), 'a': ('100644', b'b')},
                      {'Dir/a': ('100644', b'a'), 'dir/b': ('100644', b'b')}):
            with self.assertRaises(InputError):
                inventory.build_inventory(files)

    def test_file_directory_aliases_are_rejected_in_either_input_order(self):
        for files in ({'a': ('100644', b'a'), 'a/b': ('100644', b'b')},
                      {'a/b': ('100644', b'b'), 'a': ('100644', b'a')}):
            with self.assertRaises(InputError):
                inventory.build_inventory(files)

    def test_missing_parents_and_invalid_directory_semantics_are_rejected(self):
        entries = inventory.build_inventory({'dir/file': ('100644', b'f')})['entries']
        with self.assertRaises(InputError):
            inventory.normalize_inventory(entries[1:])
        for field, value in (('mode', '040000'), ('size', 1), ('bytesSha256', '0' * 64)):
            changed = copy.deepcopy(entries)
            changed[0][field] = value
            with self.subTest(field=field), self.assertRaises(InputError):
                inventory.normalize_inventory(changed)

    def test_roles_are_explicit_valid_and_known_paths_only(self):
        for roles in ({'unknown': 'fixture'}, {'file': 'unknown'}, {'file': []}, {'file': None}):
            with self.subTest(roles=roles), self.assertRaises(InputError):
                inventory.build_inventory({'file': ('100644', b'f')}, roles)

    def test_inventory_field_types_and_unknown_fields_are_rejected(self):
        entry = inventory.build_inventory({'file': ('100644', b'f')})['entries'][0]
        for key, value in (('extra', 1), ('mode', '120000'), ('size', True), ('size', -1),
                           ('bytesSha256', 'A' * 64), ('bytesSha256', None), ('kind', 'other')):
            changed = dict(entry, **{key: value})
            with self.subTest(key=key, value=value), self.assertRaises(InputError):
                inventory.normalize_inventory([changed])

    def test_source_digest_ignores_input_order_but_commits_roles_and_modes(self):
        before = inventory.build_inventory({'b': ('100644', b'x'), 'a': ('100644', b'y')})
        reordered = dict(before, entries=list(reversed(before['entries'])))
        self.assertEqual(inventory.source_digest(before), inventory.source_digest(reordered))
        changed = copy.deepcopy(before)
        changed['entries'][0]['role'] = 'fixture'
        self.assertNotEqual(inventory.source_digest(before), inventory.source_digest(changed))
        self.assertNotEqual(inventory.source_digest(before), hashing.raw_hash(cjson.dumps(before)))


if __name__ == '__main__':
    unittest.main()
