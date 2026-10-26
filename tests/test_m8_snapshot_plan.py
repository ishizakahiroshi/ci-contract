"""M8 C2: snapshot plans read the target side from a directory. Synthetic repositories only."""
import os
import tempfile
import unittest
from pathlib import Path
from ci_contract.errors import BlockedError, InputError
from ci_contract.plan import build_plan
from ci_contract.schema import validate
from test_plan import synthetic_history


def write_tree(directory, files):
    for path, (_, data) in files.items():
        target = directory.joinpath(*path.split('/'))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)


class SnapshotCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-snapshot-')
        cls.root = Path(cls.temp.name)
        (cls.git, _, cls.base, cls.target, _, _, cls.base_files, cls.target_files) = synthetic_history(
            cls.root / 'synthetic.git')
        cls.commit_plan = build_plan(cls.git.path, 'synthetic', cls.base, cls.target)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def work(self, name, files):
        directory = self.root / name
        directory.mkdir()
        write_tree(directory, files)
        return directory

    def snapshot(self, directory, include=()):
        return build_plan(self.git.path, 'synthetic', self.base, None, snapshot_dir=str(directory), include=include)


class SnapshotPlanTests(SnapshotCase):
    def test_a_snapshot_of_the_target_files_has_the_commit_plans_inputs_and_no_commit(self):
        plan = self.snapshot(self.work('same-as-target', self.target_files))
        validate(plan)
        source = plan['source']
        self.assertEqual((source['mode'], source['comparison'], source['targetCommit'], source['tree']),
                         ('snapshot', 'snapshot', None, None))
        self.assertEqual(source['baseCommit'], self.base)
        # The same bytes give the same input digest and the same selection as the commit plan.
        self.assertEqual(source['digest'], self.commit_plan['source']['digest'])
        self.assertEqual(source['inputs'], self.commit_plan['source']['inputs'])
        self.assertEqual(plan['selectionEvidence']['selectedInstanceIds'],
                         self.commit_plan['selectionEvidence']['selectedInstanceIds'])
        self.assertEqual(plan['selectionRequest']['comparison'], 'snapshot')

    def test_deletions_additions_and_untracked_files(self):
        files = dict(self.target_files)
        del files['docs/readme.md']
        directory = self.work('changed', files)
        (directory / 'notes.txt').write_bytes(b'synthetic untracked\n')
        plain = self.snapshot(directory)
        paths = {entry['path'] for entry in plain['source']['inputs']}
        self.assertNotIn('docs/readme.md', paths)
        self.assertNotIn('notes.txt', paths)  # never picked up without an explicit include
        changes = {(c['status'], c['oldPath'], c['newPath']) for c in plain['selectionEvidence']['changes']}
        self.assertIn(('deleted', 'docs/readme.md', None), changes)
        self.assertIn(('modified', 'src/main.txt', 'src/main.txt'), changes)
        with self.assertRaises(BlockedError) as undeclared:
            self.snapshot(directory, include=['notes.txt'])
        # The base manifest does not declare notes.txt: the same refusal as a commit adding it.
        added = dict(files, **{'notes.txt': ('100644', b'synthetic untracked\n')})
        commit = self.git.commit(added, parents=(self.base,), message='synthetic added untracked')
        with self.assertRaises(BlockedError) as committed:
            build_plan(self.git.path, 'synthetic', self.base, commit)
        self.assertEqual(undeclared.exception.reason_code, committed.exception.reason_code)

    def test_refusals(self):
        directory = self.work('refusals', self.target_files)
        with self.assertRaises(InputError):
            build_plan(self.git.path, 'synthetic', self.base, self.target, snapshot_dir=str(directory))
        with self.assertRaises(InputError):
            self.snapshot(Path('relative-snapshot'))
        with self.assertRaises(BlockedError) as missing:
            self.snapshot(directory, include=['absent.txt'])
        self.assertEqual(missing.exception.reason_code, 'snapshot-input-missing')
        with self.assertRaises(InputError):
            self.snapshot(directory, include=['src/main.txt'])  # already a base path
        linked = self.work('hardlinked', self.target_files)
        os.link(linked / 'src' / 'main.txt', self.root / 'outside-link.txt')
        with self.assertRaises(BlockedError) as hardlink:
            self.snapshot(linked)
        self.assertEqual(hardlink.exception.reason_code, 'snapshot-unsupported-entry')


class MaterializeTests(SnapshotCase):
    def test_a_commit_source_is_written_with_the_plans_digest(self):
        from ci_contract.snapshot import digest_after, materialize
        copy = self.root / 'commit-copy'
        digest = materialize(self.commit_plan['source'], str(copy), repo_path=str(self.git.path))
        self.assertEqual(digest, self.commit_plan['source']['digest'])
        self.assertEqual((copy / 'src' / 'main.txt').read_bytes(), b'synthetic target\n')
        self.assertEqual(digest_after(self.commit_plan['source'], str(copy)), digest)

    def test_a_snapshot_source_is_written_and_a_later_change_is_stale(self):
        from ci_contract.request import StaleError
        from ci_contract.snapshot import digest_after, materialize
        directory = self.work('materialize', self.target_files)
        plan = self.snapshot(directory)
        copy = self.root / 'snapshot-copy'
        self.assertEqual(materialize(plan['source'], str(copy), snapshot_dir=str(directory)), plan['source']['digest'])
        # c12: an input that changes after planning is stale (5), and nothing is written.
        (directory / 'src' / 'main.txt').write_bytes(b'synthetic changed after planning\n')
        with self.assertRaises(StaleError) as changed:
            materialize(plan['source'], str(self.root / 'snapshot-copy-2'), snapshot_dir=str(directory))
        self.assertEqual(changed.exception.reason_code, 'source-changed')
        self.assertFalse((self.root / 'snapshot-copy-2').exists())
        # A check that rewrites a declared input changes the digest after the run; outputs do not.
        (copy / 'build-output.txt').write_bytes(b'synthetic output\n')
        self.assertEqual(digest_after(plan['source'], str(copy)), plan['source']['digest'])
        (copy / 'docs' / 'readme.md').write_bytes(b'synthetic rewritten\n')
        self.assertNotEqual(digest_after(plan['source'], str(copy)), plan['source']['digest'])
        with self.assertRaises(InputError):
            materialize(plan['source'], str(copy), snapshot_dir=str(directory))  # existing folder

    def test_the_cli_writes_a_snapshot_plan(self):
        import subprocess
        import sys
        from ci_contract import cjson
        directory = self.work('cli', self.target_files)
        out = self.root / 'cli-plan.json'
        env = {**os.environ, 'PYTHONPATH': str(Path(__file__).resolve().parents[1] / 'src')}
        common = [sys.executable, '-m', 'ci_contract', 'plan', '--repo', 'synthetic', '--repo-path', str(self.git.path),
                  '--base', self.base, '--profile', 'change']
        result = subprocess.run(common + ['--snapshot', str(directory), '--out', str(out)],
                                env=env, capture_output=True, check=False)
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(cjson.loads(out.read_bytes())['source']['mode'], 'snapshot')
        refused = self.root / 'cli-refused.json'
        for extra in (['--target', self.target, '--snapshot', str(directory)], [],
                      ['--target', self.target, '--include', 'notes.txt']):
            result = subprocess.run(common + extra + ['--out', str(refused)], env=env, capture_output=True, check=False)
            self.assertEqual(result.returncode, 3)
            self.assertFalse(refused.exists())


if __name__ == '__main__':
    unittest.main()
