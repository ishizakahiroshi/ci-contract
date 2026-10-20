"""Three-document verify CLI contract using synthetic inputs only."""
import copy
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from ci_contract import cjson, cli
from synthetic_verify import documents, acceptance_documents, MODELS


class BinaryStream:
    def __init__(self):
        self.buffer = io.BytesIO()

    def write(self, text):
        raise AssertionError('CLI status must use binary output')


class VerifyCliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.paths = [self.root / (name + '-synthetic-private-value.json')
                      for name in ('plan', 'execution', 'result')]
        self.values = documents()[:3]
        self.write_documents(self.values)

    def write_documents(self, values):
        for path, value in zip(self.paths, values):
            path.write_bytes(cjson.dumps(value))

    def arguments(self):
        return ['verify', '--plan', str(self.paths[0]), '--execution', str(self.paths[1]),
                '--result', str(self.paths[2])]

    def run_cli(self, arguments=None):
        out, err = BinaryStream(), BinaryStream()
        with patch.object(sys, 'stdout', out), patch.object(sys, 'stderr', err):
            code = cli.main(self.arguments() if arguments is None else arguments)
        return code, out.buffer.getvalue(), err.buffer.getvalue()

    def assert_invalid(self):
        self.assertEqual(self.run_cli(), (3, b'invalid-input\n', b'ci-contract: invalid input\n'))

    def test_valid_documents_without_backing_are_blocked(self):
        self.assertEqual(self.run_cli(), (4, b'blocked\n', b'ci-contract: verification not accepted\n'))

    def test_success_examples_without_backing_cannot_be_accepted(self):
        for identifier in ('r13', 'r14'):
            case = next(case for case in MODELS['cases'] if case['id'] == identifier)
            with self.subTest(case=identifier):
                self.write_documents(acceptance_documents(case)[:3])
                self.assertEqual(self.run_cli(), (4, b'blocked\n', b'ci-contract: verification not accepted\n'))

    def test_schema_error_in_each_document_precedes_blocked(self):
        for index in range(3):
            with self.subTest(document=index):
                values = copy.deepcopy(self.values)
                values[index]['unexpected'] = 'synthetic-private-value'
                self.write_documents(values)
                self.assert_invalid()

    def test_strict_json_errors_in_each_document(self):
        malformed = (b'{"kind":"plan","kind":"plan"}', b'{"value":NaN}',
                     b'{"value":Infinity}', b'\xff', b'{} trailing')
        for index in range(3):
            for data in malformed:
                with self.subTest(document=index, data=data):
                    self.write_documents(self.values)
                    self.paths[index].write_bytes(data)
                    self.assert_invalid()

    def test_lf_identifier_and_hash_lexical_errors(self):
        for index, key in ((1, 'executionId'), (2, 'executionId'), (2, 'planSha256')):
            with self.subTest(document=index, field=key):
                values = copy.deepcopy(self.values)
                values[index][key] += '\n'
                self.write_documents(values)
                self.assert_invalid()
        values = copy.deepcopy(self.values)
        values[0]['source']['targetCommit'] += '\n'
        self.write_documents(values)
        self.assert_invalid()

    def test_missing_files_have_fixed_diagnostic_without_path(self):
        for index in range(3):
            with self.subTest(document=index):
                self.write_documents(self.values)
                self.paths[index].unlink()
                self.assert_invalid()

    def test_unreadable_file_has_fixed_diagnostic_without_exception_value(self):
        with patch.object(Path, 'read_bytes', side_effect=PermissionError('synthetic-private-value')):
            self.assert_invalid()

    def test_input_bytes_and_directory_contents_are_unchanged(self):
        before = {p.name: p.read_bytes() for p in self.root.iterdir()}
        self.run_cli()
        self.assertEqual({p.name: p.read_bytes() for p in self.root.iterdir()}, before)

    def test_repeated_output_is_identical_single_binary_lf_line(self):
        first = self.run_cli()
        self.assertEqual(self.run_cli(), first)
        self.assertEqual(first[1], b'blocked\n')
        self.assertNotIn(b'\r', first[1])
        self.assertEqual(first[1].count(b'\n'), 1)

    def test_ledger_option_is_not_supported(self):
        self.assertEqual(self.run_cli(self.arguments() + ['--ledger', 'synthetic-private-value']),
                         (3, b'invalid-input\n', b'ci-contract: invalid input\n'))

    def test_missing_required_option_is_invalid_and_safe(self):
        self.assertEqual(self.run_cli(['verify', '--plan', 'synthetic-private-value']),
                         (3, b'invalid-input\n', b'ci-contract: invalid input\n'))

    def test_internal_exception_has_error_status_without_leaking_value(self):
        with patch('ci_contract.verify.verify', side_effect=RuntimeError('synthetic-private-value')):
            self.assertEqual(self.run_cli(), (9, b'error\n', b'ci-contract: internal error\n'))

    def test_module_entrypoint_uses_process_exit_and_binary_lf(self):
        env = os.environ.copy()
        env['PYTHONPATH'] = str(Path(__file__).resolve().parents[1] / 'src')
        completed = subprocess.run([sys.executable, '-m', 'ci_contract'] + self.arguments(),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, check=False)
        self.assertEqual((completed.returncode, completed.stdout, completed.stderr),
                         (4, b'blocked\n', b'ci-contract: verification not accepted\n'))


if __name__ == '__main__':
    unittest.main()


class HelpExitTests(unittest.TestCase):
    def test_verify_help_is_not_acceptance(self):
        for option in ('-h', '--help'):
            with self.subTest(option=option):
                out, err = io.TextIOWrapper(io.BytesIO()), io.TextIOWrapper(io.BytesIO())
                with patch.object(sys,'stdout',out), patch.object(sys,'stderr',err):
                    result = cli.main(['verify',option])
                self.assertEqual(result,3)
                self.assertEqual(out.buffer.getvalue(),b'invalid-input\n')
                self.assertEqual(err.buffer.getvalue(),b'ci-contract: invalid input\n')


class CorrectiveCliMutants(unittest.TestCase):
    def test_help_zero_exit_fault_is_detected(self):
        import inspect, types
        source=inspect.getsource(cli).replace("commands.add_parser('verify', add_help=False)","commands.add_parser('verify')")
        faulty=types.ModuleType('ci_contract.synthetic_help_fault');faulty.__package__='ci_contract'
        exec(compile(source,'<synthetic-help-fault>','exec'),faulty.__dict__)
        for option in ('-h','--help'):
            out,err=io.StringIO(),io.StringIO()
            with patch.object(sys,'stdout',out),patch.object(sys,'stderr',err),self.assertRaises(SystemExit) as caught:
                faulty.main(['verify',option])
            self.assertEqual(caught.exception.code,0)
            self.assertNotEqual(caught.exception.code,3)

    def test_wrong_internal_error_diagnostic_fault_is_detected(self):
        import inspect, types
        source=inspect.getsource(cli).replace("b'ci-contract: internal error\\n' if verdict['exitCode'] == INTERNAL_ERROR", "b'ci-contract: verification not accepted\\n' if verdict['exitCode'] == INTERNAL_ERROR")
        self.assertNotEqual(source,inspect.getsource(cli))
        faulty=types.ModuleType('ci_contract.synthetic_error_fault');faulty.__package__='ci_contract'
        exec(compile(source,'<synthetic-error-fault>','exec'),faulty.__dict__)
        out,err=BinaryStream(),BinaryStream()
        with patch.object(sys,'stdout',out),patch.object(sys,'stderr',err),patch('ci_contract.cli.Path.read_bytes',side_effect=RuntimeError('synthetic')):
            code=faulty.main(['verify','--plan','p','--execution','e','--result','r'])
        self.assertEqual(code,9)
        self.assertEqual(err.buffer.getvalue(),b'ci-contract: verification not accepted\n')
        self.assertNotEqual(err.buffer.getvalue(),b'ci-contract: internal error\n')
