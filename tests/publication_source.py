"""Optional comparison with privately held, read-only original source files."""
import hashlib
from ci_contract import cjson
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
INPUT = ROOT.parents[2] / 'input'


def transformed_source(test, name, expected_sha256):
    source = INPUT / name
    publication = INPUT / 'publication-map.json'
    if not source.is_file() or not publication.is_file():
        test.skipTest('read-only original source and publication map are not both present')
    data = source.read_bytes()
    test.assertEqual(hashlib.sha256(data).hexdigest(), expected_sha256)
    text = data.decode('utf-8')
    for replacement in cjson.loads(publication.read_bytes())['replacements']:
        text = text.replace(replacement['from'], replacement['to'])
    return text.encode('utf-8')
