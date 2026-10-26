"""Finding F5 of the independent review of the public copy (4de838a).

The nesting limit of documents is an explicit constant, cjson.MAX_DEPTH, decided
before any recursion; it does not depend on the interpreter's recursion limit.
Tests at the limit and one past it, for the serializer, the parser, the array
normalizer and the CLI. All data is synthetic.
"""
import io
import sys
import unittest
from importlib.resources import files
from unittest.mock import patch

from ci_contract import cjson, cli
from ci_contract.arrays import normalize
from ci_contract.errors import InputError
from synthetic_verify import documents

LIMIT = getattr(cjson, 'MAX_DEPTH', 64)  # 64: the documented limit (absent before the fix)


def nested(levels, kind='list'):
    value = 1
    for _ in range(levels):
        value = [value] if kind == 'list' else {'k': value}
    return value


def text(levels, kind='list'):
    opening, closing = ('[', ']') if kind == 'list' else ('{"k":', '}')
    return opening * levels + '1' + closing * levels


def depth_of(value):
    """Nesting of arrays/objects, computed without recursion."""
    deepest, pending = 0, [(value, 0)]
    while pending:
        item, level = pending.pop()
        if isinstance(item, (list, dict)):
            level += 1
            deepest = max(deepest, level)
            pending.extend((child, level) for child in (item.values() if isinstance(item, dict) else item))
    return deepest


class NestingLimit(unittest.TestCase):
    def test_the_limit_is_documented_and_covers_every_document_the_package_reads(self):
        self.assertEqual(LIMIT, 64)
        schema = cjson.loads(files('ci_contract').joinpath('data/contract-v1.schema.json').read_bytes())
        self.assertEqual(depth_of(schema), 13)
        deepest_contract = max(depth_of(document) for document in documents())
        self.assertEqual(deepest_contract, 7)  # the result with its embedded proofs
        self.assertGreaterEqual(LIMIT, 4 * depth_of(schema))
        self.assertIn('MAX_DEPTH', cjson.dumps.__doc__)
        self.assertIn('MAX_DEPTH', cjson.loads.__doc__)

    def test_dumps_accepts_the_limit_and_refuses_one_more(self):
        for kind in ('list', 'dict'):
            with self.subTest(kind=kind):
                self.assertEqual(cjson.dumps(nested(LIMIT, kind)), text(LIMIT, kind).encode())
                with self.assertRaises(InputError):
                    cjson.dumps(nested(LIMIT + 1, kind))

    def test_loads_accepts_the_limit_and_refuses_one_more(self):
        for kind in ('list', 'dict'):
            with self.subTest(kind=kind):
                self.assertEqual(cjson.loads(text(LIMIT, kind)), nested(LIMIT, kind))
                self.assertEqual(cjson.loads(text(LIMIT, kind).encode()), nested(LIMIT, kind))
                with self.assertRaises(InputError):
                    cjson.loads(text(LIMIT + 1, kind))
                with self.assertRaises(InputError):
                    cjson.loads(text(LIMIT + 1, kind).encode())

    def test_brackets_inside_strings_do_not_count(self):
        # The outer object is level 1, so "b" may nest LIMIT - 1 more levels.
        value = cjson.loads('{"a":"' + '[' * 500 + '\\"' + '{' * 500 + '","b":' + text(LIMIT - 1) + '}')
        self.assertEqual(value['b'], nested(LIMIT - 1))
        with self.assertRaises(InputError):
            cjson.loads('{"a":"' + '[' * 500 + '\\"' + '{' * 500 + '","b":' + text(LIMIT) + '}')

    def test_siblings_do_not_add_up(self):
        wide = '[' + ','.join(text(LIMIT - 1) for _ in range(50)) + ']'
        self.assertEqual(depth_of(cjson.loads(wide)), LIMIT)

    def test_the_verdict_does_not_depend_on_the_recursion_limit(self):
        previous = sys.getrecursionlimit()
        sys.setrecursionlimit(20000)
        try:
            with self.assertRaises(InputError):
                cjson.dumps(nested(200))
            with self.assertRaises(InputError):
                cjson.loads(text(200))
            with self.assertRaises(InputError):
                normalize(nested(200))
            self.assertEqual(depth_of(cjson.loads(text(LIMIT))), LIMIT)
        finally:
            sys.setrecursionlimit(previous)

    def test_a_very_deep_text_is_refused_without_parsing_it(self):
        with patch('ci_contract.cjson.json.loads', side_effect=AssertionError('parser reached')):
            with self.assertRaises(InputError):
                cjson.loads('[' * 200000)

    def test_normalize_accepts_the_limit_and_refuses_one_more(self):
        self.assertEqual(normalize(nested(LIMIT)), nested(LIMIT))
        with self.assertRaises(InputError):
            normalize(nested(LIMIT + 1))
        document = {'kind': 'plan', 'x': nested(LIMIT - 1)}
        self.assertEqual(normalize(document), document)
        document['x'] = nested(LIMIT)
        with self.assertRaises(InputError):
            normalize(document)

    def test_cli_refuses_deep_input_as_invalid_input(self):
        for command in (['canon', '-'], ['hash', '--canonical', '-']):
            for levels in (LIMIT, LIMIT + 1, 200):
                with self.subTest(command=command[0], levels=levels):
                    stdin = io.TextIOWrapper(io.BytesIO(text(levels).encode()), encoding='utf-8')
                    out, err = io.BytesIO(), io.BytesIO()
                    stdout = io.TextIOWrapper(out, encoding='utf-8')
                    stderr = io.TextIOWrapper(err, encoding='utf-8')
                    with patch('sys.stdin', stdin), patch('sys.stdout', stdout), patch('sys.stderr', stderr):
                        code = cli.main(command)
                        stdout.flush(), stderr.flush()
                    if levels > LIMIT:
                        self.assertEqual((code, out.getvalue(), err.getvalue()),
                                         (3, b'', b'ci-contract: invalid input\n'))
                    else:
                        self.assertEqual((code, err.getvalue()), (0, b''))


if __name__ == '__main__':
    unittest.main()
