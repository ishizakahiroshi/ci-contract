"""Offline Draft 2020-12 structure checking, not semantic acceptance."""
from importlib.resources import files
from datetime import datetime
import re
from .cjson import loads, dumps
from .errors import InputError, DependencyError


def load_schema():
    return loads(files('ci_contract').joinpath('data/contract-v1.schema.json').read_bytes())


def make_validator(schema=None):
    try:
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry
        from referencing.exceptions import NoSuchResource
    except ImportError:
        raise DependencyError("optional schema dependency unavailable") from None
    document = load_schema() if schema is None else schema

    def no_retrieval(uri):
        raise NoSuchResource(ref=uri)

    # Registry has no remote retrieval path. Even malicious external references
    # cannot trigger file or network access. Local fragment refs still resolve.
    Draft202012Validator.check_schema(document)
    checker = FormatChecker()

    # jsonschema's optional date-time checker may be absent without format
    # extras. Supply a strict stdlib implementation rather than silently skip.
    @checker.checks('date-time', raises=(ValueError, OverflowError))
    def date_time(value):
        if not isinstance(value, str):
            return True
        if re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}[Tt][0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]+)?(?:[Zz]|[+-][0-9]{2}:[0-9]{2})', value) is None:
            return False
        if value[-1] not in 'Zz' and (int(value[-5:-3]) > 23 or int(value[-2:]) > 59):
            return False
        datetime.fromisoformat(value.upper().replace('Z', '+00:00'))
        return True

    return Draft202012Validator(document, format_checker=checker,
                               registry=Registry(retrieve=no_retrieval))


def validate(value):
    dumps(value)
    validator = make_validator()
    if next(validator.iter_errors(value), None) is not None:
        # Do not expose jsonschema's instance-containing diagnostics.
        raise InputError("schema structure mismatch")
