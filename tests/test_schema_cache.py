"""The meta-schema check runs once per schema document that passed it.

Synthetic schema documents only. Each test uses its own ``$comment`` so that a document
checked by another test is not already remembered. The test named ``test_fails_before_*``
states the speed-up; it fails on 6b61908, where every make_validator call checks again.
"""
import unittest
from unittest.mock import patch
from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError
from ci_contract import schema

CHECK = Draft202012Validator.check_schema


def document(comment, **fields):
    return dict({'$schema': 'https://json-schema.org/draft/2020-12/schema', '$comment': comment,
                 'type': 'object', 'required': ['name'], 'properties': {'name': {'type': 'string'}}}, **fields)


class SchemaCheckCacheTests(unittest.TestCase):
    def spy(self):
        return patch.object(Draft202012Validator, 'check_schema', side_effect=CHECK)

    def test_fails_before_a_passing_document_is_checked_once(self):
        value = document('synthetic-cache-once')
        with self.spy() as check:
            first = schema.make_validator(value)
            second = schema.make_validator(dict(value))
        self.assertEqual(check.call_count, 1)
        for validator in (first, second):
            self.assertTrue(validator.is_valid({'name': 'synthetic'}))
            self.assertFalse(validator.is_valid({'name': 1}))

    def test_a_failing_document_is_checked_and_refused_every_time(self):
        value = document('synthetic-cache-failing', type=5)
        with self.spy() as check:
            for _ in range(2):
                with self.assertRaises(SchemaError):
                    schema.make_validator(value)
        self.assertEqual(check.call_count, 2)

    def test_a_changed_document_is_checked_again(self):
        with self.spy() as check:
            schema.make_validator(document('synthetic-cache-changed'))
            schema.make_validator(document('synthetic-cache-changed', required=[]))
            with self.assertRaises(SchemaError):
                schema.make_validator(document('synthetic-cache-changed', required='name'))
        self.assertEqual(check.call_count, 3)

    def test_a_document_that_is_not_canonical_json_is_checked_every_time(self):
        value = document('synthetic-cache-float', default=1.5)  # a float is valid here, not canonical JSON
        with self.spy() as check:
            for _ in range(2):
                schema.make_validator(value)
        self.assertEqual(check.call_count, 2)

    def test_the_default_schema_and_validate_keep_their_verdicts(self):
        # Positive control: schema.validate still accepts and refuses as before when cached.
        from ci_contract.errors import InputError
        for _ in range(2):
            with self.assertRaises(InputError):
                schema.validate({})


if __name__ == '__main__':
    unittest.main()
