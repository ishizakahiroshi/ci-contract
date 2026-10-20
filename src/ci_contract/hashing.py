"""Raw and domain SHA256 with explicit, pinned projections."""
import hashlib
import json
from importlib.resources import files
from . import cjson
from .arrays import normalize
from .errors import InputError

PROJECTIONS = json.loads(files('ci_contract').joinpath('data/domain-hash-projections.json').read_bytes())
_ENTRIES = {entry['kind']: entry for entry in PROJECTIONS['entries']}
DOMAIN_KINDS = tuple(_ENTRIES)


def raw_hash(data):
    """Hash exact bytes without parsing or line-ending conversion."""
    if type(data) is not bytes:
        raise InputError("raw hash requires bytes")
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value, document_kind=None):
    return raw_hash(cjson.dumps(normalize(value, document_kind)))


def domain_digest(kind, canonical_bytes):
    """Low-level formula for already canonical bytes; no projection or normalization.

    This primitive supports the deliberately partial golden objects. Call
    domain_hash for the closed, kind-specific projection of a document.
    """
    if kind not in _ENTRIES or type(canonical_bytes) is not bytes:
        raise InputError("unsupported domain or byte input")
    if cjson.dumps(cjson.loads(canonical_bytes)) != canonical_bytes:
        raise InputError("expected canonical JSON bytes")
    return raw_hash(('ci-contract/v1:' + kind).encode('ascii') + b'\n' + canonical_bytes)


def _closed(value, rule):
    if type(value) is not dict:
        raise InputError("projection requires an object")
    allowed = set(rule['keys']) | set(rule['exclude'])
    if set(value) - allowed:
        raise InputError("unknown projection field")
    return {key: value[key] for key in rule['keys'] if key in value}


def project(kind, value):
    """Project explicit domain input. Missing fields are left to schema validation.

    request-binding takes the binding itself, inventory takes the inventory
    wrapper, journal-record takes its closed header with payloadProjection.
    Only named exclusions are removed; unrelated nested hashes remain committed.
    """
    if kind not in _ENTRIES:
        raise InputError("unsupported domain")
    cjson.dumps(value)
    rule = _ENTRIES[kind]
    result = _closed(value, rule)
    if kind == 'inventory':
        for key, constant in rule['constants'].items():
            if key not in result or type(result[key]) is not type(constant) or result[key] != constant:
                raise InputError("invalid inventory wrapper")
        if 'entries' not in result or type(result['entries']) is not list:
            raise InputError("invalid inventory entries")
    if kind == 'journal-record':
        payload_kind = result.get('payloadKind')
        if payload_kind not in rule['payloads'] or 'payloadProjection' not in result:
            raise InputError("invalid journal payload kind")
        payload = _closed(result['payloadProjection'], rule['payloads'][payload_kind])
        # Payload result arrays retain their own document context, not a made-up
        # journal path. Other pinned payload kinds have no registered arrays.
        result['payloadProjection'] = normalize(payload, 'result' if payload_kind == 'result' else payload_kind)
    context = 'source-inventory' if kind == 'inventory' else kind
    return normalize(result, context)


def domain_hash(kind, value):
    return domain_digest(kind, cjson.dumps(project(kind, value)))


def inventory_from_source(source):
    """Build the specified inventory wrapper, without reading actual source files."""
    if type(source) is not dict or type(source.get('inputs')) is not list:
        raise InputError("source inputs required")
    wrapper = dict(_ENTRIES['inventory']['constants'], entries=source['inputs'])
    return project('inventory', wrapper)
