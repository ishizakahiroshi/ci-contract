"""Carry-over regression tests with actual source-code fault controls."""
import copy
import inspect
from pathlib import Path
import tempfile
import types
import unittest

from ci_contract import cjson, plan, schema, selection
from ci_contract.errors import BlockedError, InputError
from test_plan import canonical, fixture, synthetic_history
from test_selection import simple_input


def mutant_source(before, after):
    """Compile a changed production module in memory, never edit its file."""
    source = inspect.getsource(plan)
    if source.count(before) != 1:
        raise AssertionError('fault location changed')
    module = types.ModuleType('ci_contract.plan_fault')
    module.__package__ = 'ci_contract'
    exec(compile(source.replace(before, after), '<synthetic-plan-fault>', 'exec'), module.__dict__)
    return module.build_plan


class CarryoverPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='ci-contract-carryover-')
        cls.git, cls.anchor, cls.base, cls.target, _, cls.manifest, cls.base_files, cls.target_files = (
            synthetic_history(Path(cls.temp.name) / 'synthetic.git'))

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def assert_undeclared_base(self, builder):
        files = copy.deepcopy(self.base_files)
        files['unknown/unchanged.txt'] = ('100644', b'synthetic undeclared base input')
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic undeclared base')
        files['src/main.txt'] = ('100644', b'synthetic changed source')
        target = self.git.commit(files, parents=(base,), message='synthetic declared change')
        with self.assertRaisesRegex(BlockedError, '^undeclared-source-input$'):
            builder(self.git.path, 'synthetic', base, target)

    def test_k4_undeclared_source_input_on_trusted_base(self):
        self.assert_undeclared_base(plan.build_plan)

    def test_k4_removing_raise_is_detected(self):
        builder = mutant_source("        raise BlockedError('undeclared-source-input')",
                                '        pass  # synthetic removed rejection')
        with self.assertRaises(AssertionError):
            self.assert_undeclared_base(builder)

    def assert_base_only_undeclared(self, builder):
        files = copy.deepcopy(self.base_files)
        files['unknown/unchanged.txt'] = ('100644', b'synthetic base-only unruled input')
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic unruled base')
        target_manifest = copy.deepcopy(self.manifest)
        rule = copy.deepcopy(next(rule for rule in target_manifest['selectionModel']['inputRules']
                                  if rule['path'] == 'src/main.txt'))
        rule.update(id='synthetic-added-rule', path='unknown/unchanged.txt')
        target_manifest['selectionModel']['inputRules'].append(rule)
        files[plan.MANIFEST] = ('100644', canonical(target_manifest))
        target = self.git.commit(files, parents=(base,), message='synthetic target adds rule only')
        with self.assertRaisesRegex(BlockedError, '^undeclared-source-input$'):
            builder(self.git.path, 'synthetic', base, target)

    def test_f3_target_rule_cannot_cover_unruled_base(self):
        self.assert_base_only_undeclared(plan.build_plan)

    def test_f3_removing_base_condition_is_detected(self):
        before = "or any(entry['kind'] == 'file' and entry['path'] not in base_roles for entry in base_source['inputs'])"
        builder = mutant_source(before, 'or False')
        with self.assertRaises(AssertionError):
            self.assert_base_only_undeclared(builder)

    def assert_standalone_before_unknown(self, builder, product='general'):
        files = copy.deepcopy(self.base_files)
        manifest = copy.deepcopy(self.manifest)
        manifest['repository'].update(group='standalone', product=product)
        if product == 'github-only':
            manifest['repository'].update(localAllowed=False, defaultTarget='github')
        files[plan.MANIFEST] = ('100644', canonical(manifest))
        base = self.git.commit(files, parents=(self.anchor,), message='synthetic unsupported group')
        files['unknown/new.txt'] = ('100644', b'synthetic unknown path')
        target = self.git.commit(files, parents=(base,), message='synthetic unknown addition')
        with self.assertRaisesRegex(BlockedError, '^unsupported-repository-group$'):
            builder(self.git.path, 'synthetic', base, target)

    def test_k5_group_rejection_precedes_unknown_path(self):
        self.assert_standalone_before_unknown(plan.build_plan)

    def test_k5_product_cannot_override_unsupported_group(self):
        self.assert_standalone_before_unknown(plan.build_plan, 'github-only')

    def test_k5_restoring_late_group_check_is_detected(self):
        block = ("    if manifest['repository']['group'] == 'standalone':\n"
                 "        raise BlockedError('unsupported-repository-group')\n")
        source = inspect.getsource(plan)
        self.assertEqual(source.count(block), 1)
        source = source.replace(block, '')
        marker = "    selected = select({'model': target_compact"
        self.assertEqual(source.count(marker), 1)
        source = source.replace(marker, block + marker)
        module = types.ModuleType('ci_contract.plan_fault')
        module.__package__ = 'ci_contract'
        exec(compile(source, '<synthetic-order-fault>', 'exec'), module.__dict__)
        with self.assertRaises(AssertionError):
            self.assert_standalone_before_unknown(module.build_plan)


class GeneralScopeTests(unittest.TestCase):
    def test_excluded_scope_cannot_be_relabelled_by_alias_or_approval(self):
        for requested, aliases in [('public-copy', {'public-copy': 'public'}),
                                   ('missing', {}), ('excluded-copy', {'excluded-copy': 'excluded'})]:
            with self.subTest(requested=requested):
                value = simple_input()
                value['scope'] = {'repositoryGroup': 'excluded', 'requestedAlias': requested,
                                  'aliases': aliases}
                value['repoFullProfileApproved'] = True
                result = selection.select(value)
                self.assertEqual((result['exitCode'], result['reasonCode']), (4, 'excluded-scope'))
                self.assertEqual(result['selectedInstanceIds'], [])

    def assert_requested_alias_shape(self, selector):
        for group in ('excluded', 'public'):
            for requested in (5, ''):
                value = simple_input()
                value['scope'] = {'repositoryGroup': group, 'requestedAlias': requested}
                result = selector(value)
                self.assertEqual((result['status'], result['exitCode']), ('invalid-input', 3))

    def test_g1_requested_alias_shape_precedes_scope_rejection(self):
        self.assert_requested_alias_shape(selection.select)

    def test_g1_early_rejection_mutant_is_detected(self):
        source = inspect.getsource(selection)
        block = "    if group == 'excluded':\n        return _result('blocked', 4, 'excluded-scope')\n"
        self.assertEqual(source.count(block), 1)
        source = source.replace(block, '').replace("    requested = scope.get('requestedAlias')", block + "    requested = scope.get('requestedAlias')")
        module = types.ModuleType('ci_contract.selection_fault')
        module.__package__ = 'ci_contract'
        exec(compile(source, '<synthetic-scope-fault>', 'exec'), module.__dict__)
        with self.assertRaises(AssertionError):
            self.assert_requested_alias_shape(module.select)

    def test_github_only_product_requires_github_and_disallows_local(self):
        value = fixture('synthetic-manifest-template.json')
        value['repository'].update(product='github-only', localAllowed=False, defaultTarget='github')
        schema.validate(value)
        for field, bad in [('localAllowed', True), ('defaultTarget', 'local')]:
            with self.subTest(field=field):
                changed = copy.deepcopy(value)
                changed['repository'][field] = bad
                with self.assertRaises(InputError):
                    schema.validate(changed)


class FullProfileSchemaBoundaryTests(unittest.TestCase):
    """The fixed schema cannot express the requested full declaration."""
    def test_typed_selection_model_rejects_full_profile_extension(self):
        value = fixture('synthetic-manifest-template.json')
        value['selectionModel']['profileInstanceIds'] = {'full': []}
        with self.assertRaises(InputError):
            schema.validate(value)

    def test_full_is_not_a_typed_profile(self):
        value = fixture('synthetic-manifest-template.json')
        value['selectionModel']['checkMappings'][0]['condition']['profiles'] = ['full']
        with self.assertRaises(InputError):
            schema.validate(value)


if __name__ == '__main__':
    unittest.main()
