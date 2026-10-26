"""Strict metadata decoding and fixture-owned coverage expectations."""
import ast
import copy
from pathlib import Path
import unittest
from ci_contract import cjson

ROOT = Path(__file__).resolve().parent
STAGES = {'verifyCore': 'verify-cases.json', 'requestCore': 'request-cases.json',
          'claimCore': 'claim-cases.json'}
STRICT_READERS = ('test_contract_bytes.py', 'test_plan.py', 'test_plan_round2.py',
                  'test_publication_corrections.py', 'test_verify_corrections.py',
                  'publication_source.py', 'test_correction_metadata.py')


def assert_expected_codes(test, coverage, fixtures):
    for stage, fixture in fixtures.items():
        expected = {case['id']: case['expected']['exitCode'] for case in fixture['cases']}
        rows = coverage[stage]['cases']
        test.assertEqual({row['id'] for row in rows}, set(expected))
        test.assertEqual(len(rows), len(expected))
        for row in rows:
            # Non-terminal observations (coalesced and similar) have a null code.
            code = expected[row['id']]
            test.assertIs(type(row['expectedExitCode']), int if code is not None else type(None))
            test.assertEqual(row['expectedExitCode'], code)


def assert_strict_readers(test, source):
    for node in ast.walk(ast.parse(source)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'json'):
            test.assertNotEqual(node.func.attr, 'loads')


class CoverageExpectationTests(unittest.TestCase):
    def documents(self):
        coverage = cjson.loads((ROOT / 'acceptance-coverage.json').read_bytes())
        fixtures = {stage: cjson.loads((ROOT / 'fixtures' / name).read_bytes())
                    for stage, name in STAGES.items()}
        return coverage, fixtures

    def test_each_expected_code_matches_its_fixed_fixture(self):
        assert_expected_codes(self, *self.documents())

    def test_each_changed_expected_code_is_detected(self):
        coverage, fixtures = self.documents()
        for stage in STAGES:
            for index, row in enumerate(coverage[stage]['cases']):
                with self.subTest(stage=stage, case=row['id']):
                    changed = copy.deepcopy(coverage)
                    code = row['expectedExitCode']
                    changed[stage]['cases'][index]['expectedExitCode'] = 0 if code is None else (code + 1) % 10
                    with self.assertRaises(AssertionError):
                        assert_expected_codes(self, changed, fixtures)

    def test_boolean_is_not_an_integer_exit_code(self):
        coverage, fixtures = self.documents()
        for stage in STAGES:
            row = next(row for row in coverage[stage]['cases'] if row['expectedExitCode'] == 0)
            row['expectedExitCode'] = False
            with self.assertRaises(AssertionError):
                assert_expected_codes(self, coverage, fixtures)

    def test_null_and_integer_codes_are_not_interchangeable(self):
        coverage, fixtures = self.documents()
        rows = coverage['claimCore']['cases']
        for index, row in enumerate(rows):
            with self.subTest(case=row['id']):
                changed = copy.deepcopy(coverage)
                changed['claimCore']['cases'][index]['expectedExitCode'] = (
                    False if row['expectedExitCode'] is None else None)
                with self.assertRaises(AssertionError):
                    assert_expected_codes(self, changed, fixtures)

    def test_metadata_readers_are_strict(self):
        for name in STRICT_READERS:
            with self.subTest(file=name):
                assert_strict_readers(self, (ROOT / name).read_text(encoding='utf-8'))

    def test_each_restored_permissive_reader_is_detected(self):
        for name in STRICT_READERS:
            source = (ROOT / name).read_text(encoding='utf-8')
            offsets = [node.func.value for node in ast.walk(ast.parse(source))
                       if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                       and node.func.attr == 'loads' and isinstance(node.func.value, ast.Name)
                       and node.func.value.id == 'cjson']
            self.assertTrue(offsets)
            for node in offsets:
                with self.subTest(file=name, line=node.lineno):
                    lines = source.splitlines(keepends=True)
                    line = lines[node.lineno - 1]
                    lines[node.lineno - 1] = line[:node.col_offset] + 'json' + line[node.col_offset + 5:]
                    with self.assertRaises(AssertionError):
                        assert_strict_readers(self, ''.join(lines))
