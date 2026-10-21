"""Trust anchors are checked independently of requested pins."""
import copy
import unittest
from unittest.mock import patch
from ci_contract import request, plan as planner
from ci_contract.errors import InputError
import test_request
from test_request import mutant

class AnchorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_request.RequestTests.setUpClass();cls.fixture=test_request.RequestTests
    @classmethod
    def tearDownClass(cls):test_request.RequestTests.tearDownClass()
    def invoke(self,module):
        f=self.fixture
        return module.fixed_inputs_from_git(f.git.path,'synthetic',f.base,f.target)
    def test_repository_identity(self):
        original=planner._document
        def document(git,commit,path,kind,**kw):
            doc,data=original(git,commit,path,kind,**kw)
            if commit==self.fixture.base and kind=='manifest':doc['repository']['id']='synthetic-other'
            return doc,data
        broken=mutant("if manifest['repository']['id'] != repository_id:","if False:")
        with patch.object(planner,'_document',side_effect=document):
            with self.assertRaises(InputError):self.invoke(request)
            self.assertIn('source',self.invoke(broken))
    def test_anchor_repository_and_path(self):
        original=planner._document
        for field,value,before in [('repositoryId','synthetic-other',"anchor['repositoryId'] != repository_id"),('path','other.json',"anchor['path'] != PROJECTION")]:
            def document(git,commit,path,kind,**kw):
                doc,data=original(git,commit,path,kind,**kw)
                if commit==self.fixture.base and kind=='manifest':doc['qualityProjectionRef'][field]=value
                return doc,data
            broken=mutant(before,'False')
            with self.subTest(field=field),patch.object(planner,'_document',side_effect=document):
                with self.assertRaises(InputError):self.invoke(request)
                self.assertIn('source',self.invoke(broken))
    def test_anchor_bytes(self):
        from ci_contract.gitsource import GitSource
        original=GitSource.read_blob
        def read(git,commit,path,**kw):
            data=original(git,commit,path,**kw)
            return data+b' ' if kw.get('side')=='projection-anchor' else data
        broken=mutant('if anchored_bytes != projection_bytes:','if False:')
        with patch.object(GitSource,'read_blob',read):
            with self.assertRaises(request.StaleError):self.invoke(request)
            self.assertIn('source',self.invoke(broken))
