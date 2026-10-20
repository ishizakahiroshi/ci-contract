"""Success-only output ownership under failing binary stdout receipts."""
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from ci_contract import cli
from ci_contract.plan import build_plan
from test_plan import synthetic_history


class OutputReceiptTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-output-')
        cls.root = Path(cls.temp.name)
        history = synthetic_history(cls.root / 'synthetic.git')
        git, _, base, target, *_ = history
        cls.plan = build_plan(git.path, 'synthetic', base, target)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def invoke(self, path, failure):
        class FaultyReceipt:
            def write(self, data):
                if failure == 'write':
                    raise OSError('synthetic write failure')
                return 1 if failure == 'short' else len(data)

            def flush(self):
                if failure == 'flush':
                    raise OSError('synthetic flush failure')
        error = io.BytesIO()
        args = ['plan', '--repo', 'synthetic', '--repo-path', 'synthetic.git',
                '--base', 'a' * 40, '--target', 'b' * 40,
                '--profile', 'change', '--out', str(path)]
        with patch('ci_contract.plan.build_plan', return_value=self.plan), \
                patch('sys.stdout', SimpleNamespace(buffer=FaultyReceipt())), \
                patch('sys.stderr', SimpleNamespace(buffer=error)):
            result = cli.main(args)
        return result, error.getvalue()

    def test_stdout_write_short_and_flush_failures_remove_owned_output(self):
        for failure in ('write', 'short', 'flush'):
            with self.subTest(failure=failure):
                path = self.root / (failure + '.json')
                self.assertEqual(self.invoke(path, failure), (9, b'ci-contract: internal error\n'))
                self.assertFalse(path.exists())

    def test_stdout_failure_does_not_delete_preexisting_output(self):
        path = self.root / 'preexisting.json'
        path.write_bytes(b'synthetic preexisting')
        self.assertEqual(self.invoke(path, 'write'), (3, b'ci-contract: invalid input\n'))
        self.assertEqual(path.read_bytes(), b'synthetic preexisting')
