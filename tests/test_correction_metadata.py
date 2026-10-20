"""Reproduce synthetic placeholder labels and keep stage claims bounded."""
import hashlib
import copy
import json
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class CorrectionMetadataTests(unittest.TestCase):
    def test_all_synthetic_labels_reproduce_pinned_fixture_values(self):
        sources = json.loads((ROOT / 'src/ci_contract/data/SOURCES.json').read_bytes())
        labels = sources['syntheticHashLabels']['labels']
        self.assertEqual(len(labels), 31)
        self.assertEqual(len({r['label'] for r in labels}), len(labels))
        for row in labels:
            with self.subTest(label=row['label']):
                self.assertEqual(row['utf8Bytes'], 'synthetic-only:' + row['label'])
                self.assertEqual(hashlib.sha256(row['utf8Bytes'].encode('utf-8')).hexdigest(), row['sha256'])
                self.assertTrue(row['occurrences'])
                for reference in row['occurrences']:
                    value = json.loads((ROOT / reference['path']).read_bytes())
                    for token in reference['jsonPointer'].split('/')[1:]:
                        token = token.replace('~1', '/').replace('~0', '~')
                        value = value[int(token)] if isinstance(value, list) else value[token]
                    self.assertEqual(value, row['sha256'])

    def test_stage_observations_do_not_claim_selected_set_equality(self):
        coverage = json.loads((ROOT / 'tests/acceptance-coverage.json').read_bytes())
        for case in coverage['planCore']['cases']:
            self.assertEqual(case['status'], 'stage-observation-passed')
            self.assertFalse(case['selectedSetCompared'])
            self.assertEqual(case['negativeControlStatus'], 'implementation-monkeypatch-fault-detected')
        r05 = next(c for c in coverage['planCore']['cases'] if c['id'] == 'r05')
        self.assertEqual(r05['syntheticPlanSelectedCount'], 5)
        self.assertEqual(coverage['planCore']['fullAcceptanceCasesPassed'], 0)

    def test_new_quality_mapping_cannot_introduce_an_exception(self):
        from ci_contract.errors import BlockedError
        from ci_contract.plan import _quality_not_reduced
        base = json.loads((ROOT / 'tests/fixtures/synthetic-quality-projection.json').read_bytes())
        target = copy.deepcopy(base)
        target['requirements'][0]['externalReferences'].append('SYNTHETIC-new-waived-reference')
        mapping = copy.deepcopy(target['mappings'][0])
        mapping.update(externalReference='SYNTHETIC-new-waived-reference',
                       exceptionIds=['synthetic-unsupported-waiver'])
        target['mappings'].append(mapping)
        with self.assertRaisesRegex(BlockedError, 'quality-obligations-reduced'):
            _quality_not_reduced(base, target)
