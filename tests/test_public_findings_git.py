"""Findings F4 and F7 of the independent review of the public copy (4de838a).

F4: a `.git` that is a symbolic link (or junction) is refused, not followed.
F7: every Git call is bounded in time; an expired call is the fixed refusal
git-timeout (blocked, 4). The fake Git is a Python child process that sleeps,
placed behind the module's own command builder; the time limits are patched
short. All data is synthetic.
"""
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from ci_contract import gitsource
from ci_contract.errors import BlockedError
from ci_contract.gitsource import GitSource
from synthetic_git import SyntheticGit

SLEEP = 30  # seconds the fake Git sleeps; the patched limits are far shorter
SHORT = 0.5


def fake_git(script):
    return patch.object(GitSource, '_command', return_value=[sys.executable, '-c', script])


def short_limits(exit_seconds=None):
    patches = [patch.object(gitsource, '_GIT_TIMEOUT_SECONDS', SHORT, create=True)]
    if exit_seconds is not None:
        patches.append(patch.object(gitsource, '_BATCH_EXIT_SECONDS', exit_seconds))
    return patches


class DotGitLinkIsRefused(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-dotgit-link-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.real = SyntheticGit(self.root / 'elsewhere.git')
        self.sha = self.real.commit({'a': ('100644', b'synthetic')})
        self.wrapper = self.root / 'wrapper'
        self.wrapper.mkdir()

    def symlink(self):
        link = self.wrapper / '.git'
        try:
            os.symlink(self.real.path, link, target_is_directory=True)
        except (OSError, NotImplementedError):
            return False
        self.addCleanup(lambda: os.path.islink(link) and (os.unlink(link) if os.name != 'nt' else os.rmdir(link)))
        return True

    def junction(self):
        command = os.environ.get('COMSPEC')
        if os.name != 'nt' or not command or not os.path.isabs(command) or not os.path.isfile(command):
            return False
        link = self.wrapper / '.git'
        try:
            result = subprocess.run([command, '/d', '/c', 'mklink', '/J', str(link), str(self.real.path)],
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, check=False)
        except OSError:
            return False
        if result.returncode:
            return False
        self.addCleanup(lambda: os.path.isjunction(link) and os.rmdir(link))
        return True

    def assert_refused(self):
        reader = GitSource(self.wrapper)
        with self.assertRaises(BlockedError) as raised:
            reader.read_blob(self.sha, 'a')
        self.assertEqual(raised.exception.reason_code, 'repository-unavailable')
        with patch('ci_contract.gitsource.subprocess.run') as run, \
             patch('ci_contract.gitsource.subprocess.Popen') as popen:
            with self.assertRaises(BlockedError) as raised:
                GitSource(self.wrapper).read_blob(self.sha, 'a')
            self.assertEqual(raised.exception.reason_code, 'repository-unavailable')
            run.assert_not_called()
            popen.assert_not_called()

    def test_control_the_same_repository_as_a_real_dotgit_directory_is_read(self):
        nested = SyntheticGit(self.wrapper / '.git')
        sha = nested.commit({'a': ('100644', b'synthetic')})
        self.assertEqual(GitSource(self.wrapper).read_blob(sha, 'a'), b'synthetic')

    def test_dotgit_symbolic_link_to_a_repository_is_refused(self):
        if not self.symlink():
            self.skipTest('host cannot create synthetic directory symlinks')
        self.assert_refused()

    def test_dotgit_junction_to_a_repository_is_refused(self):
        if not self.junction():
            self.skipTest('host cannot create synthetic directory junctions (Windows only)')
        self.assert_refused()


class GitCallsAreBounded(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='synthetic-git-timeout-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for item in short_limits(exit_seconds=SHORT):
            item.start()
            self.addCleanup(item.stop)

    def reader(self):
        # Pre-resolved: the fake command replaces the whole Git command line, so
        # the (real) location probe in _prepare must not run.
        reader = GitSource(self.root)
        reader._git_dir = str(self.root)
        reader._git_executable = sys.executable
        return reader

    def open_and_leave_batch(self):
        with self.reader()._commit_batch():
            pass

    def elapsed(self, action):
        started = time.monotonic()
        try:
            action()
        finally:
            self.elapsed_seconds = time.monotonic() - started

    def test_a_git_call_that_does_not_answer_is_the_fixed_refusal(self):
        with fake_git('import time; time.sleep(%d)' % SLEEP):
            with self.assertRaises(BlockedError) as raised:
                self.elapsed(lambda: self.reader().verify_commit('a' * 40))
        self.assertEqual(raised.exception.reason_code, 'git-timeout')
        self.assertLess(self.elapsed_seconds, SLEEP / 2)

    def test_every_run_call_of_a_real_repository_carries_the_limit(self):
        repo = SyntheticGit(self.root / 'repo.git')
        base = repo.commit({'src/a.txt': ('100644', b'hello\r\n')})
        target = repo.commit({'src/a.txt': ('100644', b'changed\r\n')}, parents=(base,))
        calls = []
        real_run = subprocess.run

        def record(command, **kwargs):
            calls.append(kwargs)
            return real_run(command, **kwargs)

        reader = GitSource(repo.path)
        with patch('ci_contract.gitsource.subprocess.run', side_effect=record):
            reader.verify_commit(base)
            reader.changes(base, target)
            reader.source(base, target)
            self.assertEqual(reader.read_blob(target, 'src/a.txt'), b'changed\r\n')
        self.assertGreaterEqual(len(calls), 5)
        for kwargs in calls:
            self.assertEqual(kwargs.get('timeout'), gitsource._GIT_TIMEOUT_SECONDS)

    def test_the_live_batch_request_that_is_not_answered_is_the_fixed_refusal(self):
        script = 'import sys, time; sys.stdin.readline(); time.sleep(%d)' % SLEEP
        with fake_git(script):
            with self.assertRaises(BlockedError) as raised:
                with self.reader()._commit_batch() as read:
                    self.elapsed(lambda: read('a' * 40))
        self.assertEqual(raised.exception.reason_code, 'git-timeout')
        self.assertLess(self.elapsed_seconds, SLEEP / 2)

    def test_the_live_batch_that_does_not_exit_after_its_input_closed_is_refused(self):
        script = 'import sys, time; sys.stdin.read(); time.sleep(%d)' % SLEEP
        with fake_git(script):
            with self.assertRaises(BlockedError) as raised:
                self.elapsed(self.open_and_leave_batch)
        self.assertEqual(raised.exception.reason_code, 'git-timeout')
        self.assertLess(self.elapsed_seconds, SLEEP / 2)


if __name__ == '__main__':
    unittest.main()
