"""Target-only declarations defer without becoming executable selection inputs."""
import copy
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from ci_contract import cjson, cli, request
from ci_contract.errors import BlockedError
from ci_contract.hashing import domain_hash
from ci_contract.plan import build_plan, plan_bytes, MANIFEST
from synthetic_request import fixed_model
from test_plan import synthetic_history, canonical
from test_request import mutant


class Stream:
    def __init__(self):
        self.buffer=io.BytesIO()


class TargetDeferredGitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='synthetic-deferred-')
        cls.directory=Path(cls.temp.name)
        cls.git,_,cls.base,_,_,manifest,_,target_files=synthetic_history(cls.directory/'objects')
        incoming=copy.deepcopy(manifest)
        added=copy.deepcopy(incoming['checks'][0])
        added.update(id='synthetic-target-only',argv=['synthetic-target-only'],always=False,alwaysScope=None)
        incoming['checks'].append(added)
        # Deliberately no checkMapping or quality mapping for this untrusted,
        # non-guard target-only declaration. Base controls remain untouched.
        target_files=copy.deepcopy(target_files)
        target_files[MANIFEST]=('100644',canonical(incoming))
        cls.target=cls.git.commit(target_files,parents=(cls.base,),message='synthetic deferred target')
        cls.reference=build_plan(cls.git.path,'synthetic',cls.base,cls.target)
        cls.selection=copy.deepcopy(cls.reference['selectionRequest'])
        cls.fixed=request.fixed_inputs_from_git(cls.git.path,'synthetic',cls.base,cls.target)

    @classmethod
    def tearDownClass(cls):
        cls.temp.cleanup()

    def test_changed_cli_and_core_match_base_bytes_and_full_defers(self):
        changed=request.build_selection_plan(self.selection,'change',**copy.deepcopy(self.fixed))
        self.assertEqual(plan_bytes(changed),plan_bytes(self.reference))
        self.assertIn('target-only-check:synthetic-target-only',changed['omissionReasons'])
        common=['plan','--repo','synthetic','--repo-path',str(self.git.path),
                '--target',self.target,'--profile','change']
        outputs={}
        for mode in ('base','changed','full'):
            with self.subTest(mode=mode):
                output=self.directory/('synthetic-'+mode+'-plan.json')
                if mode=='base':
                    args=common+['--base',self.base]
                else:
                    selection=copy.deepcopy(self.selection);selection['mode']=mode
                    path=self.directory/('synthetic-'+mode+'-selection.json')
                    path.write_bytes(cjson.dumps(selection))
                    args=common+['--selection',str(path)]
                with patch('sys.stdout',Stream()) as stdout,patch('sys.stderr',Stream()) as stderr:
                    self.assertEqual(cli.main(args+['--out',str(output)]),0)
                    self.assertEqual(stderr.buffer.getvalue(),b'')
                    document=cjson.loads(output.read_bytes())
                    self.assertEqual(stdout.buffer.getvalue(),(domain_hash('plan',document)+'\n').encode())
                outputs[mode]=output.read_bytes()
                self.assertIn('target-only-check:synthetic-target-only',document['omissionReasons'])
                self.assertNotIn('synthetic-target-only',{c['logicalCheckId'] for c in document['checks']})
        self.assertEqual(outputs['base'],outputs['changed'])
        self.assertEqual(outputs['changed'],plan_bytes(self.reference))
        full_selection=copy.deepcopy(self.selection);full_selection['mode']='full'
        full=request.build_selection_plan(full_selection,'change',**copy.deepcopy(self.fixed))
        self.assertEqual(outputs['full'],plan_bytes(full))

    def test_restoring_raw_target_compile_breaks_changed_and_full(self):
        broken=mutant('    requested_instances = []',
                      '    _compile(target_manifest, compile_profile)\n    requested_instances = []')
        for mode in ('changed','full'):
            with self.subTest(mode=mode):
                selection=copy.deepcopy(self.selection);selection['mode']=mode
                actual=request.build_selection_plan(selection,'change',**copy.deepcopy(self.fixed))
                self.assertIn('target-only-check:synthetic-target-only',actual['omissionReasons'])
                with self.assertRaisesRegex(BlockedError,'unmapped-check-variant'):
                    broken.build_selection_plan(selection,'change',**copy.deepcopy(self.fixed))


class TargetQualityDeferredTests(unittest.TestCase):
    def test_unknown_requirement_of_target_only_guard_defers_in_all_modes(self):
        selection,fixed=fixed_model()
        extra=copy.deepcopy(fixed['target_manifest']['checks'][0])
        extra.update(id='synthetic-target-only-guard',argv=['synthetic-target-guard'],
                     requirementIds=['synthetic-unknown'],always=True,
                     alwaysScope={'scope':'repo','componentIds':[],'profiles':['change']})
        fixed['target_manifest']['checks'].append(extra)
        broken=mutant('    _quality_not_reduced(projection, target_projection)',
                      "    _quality_not_reduced(projection, target_projection)\n    if selection['mode'] == 'full':\n        _quality(target_manifest, target_projection)")
        for mode in ('changed','explicit','full'):
            with self.subTest(mode=mode):
                selected=copy.deepcopy(selection);selected['mode']=mode
                if mode=='explicit':selected['requestedCheckIds']=['auth.unit']
                plan=request.build_selection_plan(selected,'change',**copy.deepcopy(fixed))
                self.assertIn('target-only-check:synthetic-target-only-guard',plan['omissionReasons'])
                self.assertNotIn('synthetic-unknown',plan['requirements'])
                self.assertNotIn('synthetic-target-only-guard',{c['logicalCheckId'] for c in plan['checks']})
                if mode=='full':
                    with self.assertRaisesRegex(BlockedError,'quality-check-unmapped'):
                        broken.build_selection_plan(selected,'change',**copy.deepcopy(fixed))
                else:
                    self.assertEqual(plan_bytes(broken.build_selection_plan(selected,'change',**copy.deepcopy(fixed))),plan_bytes(plan))
