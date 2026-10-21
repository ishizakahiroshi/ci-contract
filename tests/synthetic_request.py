"""Synthetic fixed controls for exercising the real request planner."""
import copy
from pathlib import Path
from ci_contract import cjson
from ci_contract.arrays import normalize
from ci_contract.hashing import raw_hash
from ci_contract.plan import variant_id
from ci_contract.request import build_selection_plan, PIN_PATHS
from synthetic_verify import make_plan

ROOT=Path(__file__).resolve().parent


def fixed_model():
    model=make_plan()
    manifest=cjson.loads((ROOT/'fixtures/synthetic-manifest-template.json').read_bytes())
    lock=cjson.loads((ROOT/'fixtures/synthetic-engine-lock.json').read_bytes())
    policy=cjson.loads((ROOT/'fixtures/synthetic-policy.json').read_bytes())
    checks={}
    for instance in model['checks']:
        logical=instance['logicalCheckId']
        if logical not in checks:
            check=copy.deepcopy(instance);check['id']=logical
            check.pop('logicalCheckId');check.pop('variant');check['variants']=[]
            check['alwaysScope']={'scope':'repo','componentIds':[],'profiles':['change','case']} if check['always'] else None
            checks[logical]=check
        checks[logical]['variants'].append(instance['variant'])
    manifest['checks']=list(checks.values())
    req=copy.deepcopy(manifest['requirements'][0]);req.update(id='synthetic.requirement',checkIds=sorted(checks),externalReferences=['synthetic.quality'])
    manifest['requirements']=[req]
    variants=sorted({variant_id(v) for c in checks.values() for v in c['variants']})
    condition={'profiles':['change','case'],'variantIds':variants}
    graph=manifest['selectionModel'];graph['components']=[{'id':'synthetic-component','broadLogicalCheckIds':sorted(checks)}]
    graph['inputRules']=[{'id':'synthetic-input-'+str(i),'path':entry['path'],'role':entry['role'],
                         'componentIds':['synthetic-component'],'sides':'base-and-target','condition':copy.deepcopy(condition)}
                        for i,entry in enumerate(model['source']['inputs']) if entry['kind']=='file']
    for check in manifest['checks']:check['inputRuleIds']=[rule['id'] for rule in graph['inputRules']]
    graph['impactEdges']=[]
    graph['checkMappings']=[{'componentIds':['synthetic-component'],'logicalCheckIds':sorted(checks),'condition':condition}]
    graph['completeness']['scopeComponentIds']=['synthetic-component']
    projection=cjson.loads((ROOT/'fixtures/synthetic-quality-projection.json').read_bytes())
    mapping=copy.deepcopy(projection['mappings'][0])
    mapping.update(externalReference='synthetic.quality',requirementId='synthetic.requirement',logicalCheckIds=sorted(checks),exceptionIds=[])
    projection.update(requirements=copy.deepcopy(manifest['requirements']),mappings=[mapping],exceptionIds=[])
    pbytes=cjson.dumps(normalize(projection))
    manifest['qualityProjectionRef'].update(commit='a'*40,sha256=raw_hash(pbytes))
    controls={}
    for key,document in [('policy',policy),('qualityProjection',projection),('engineLock',lock)]:
        data=cjson.dumps(normalize(document))
        controls[key]={'ref':{'repositoryId':'synthetic','commit':'a'*40 if key=='qualityProjection' else 'b'*40,
                             'path':PIN_PATHS[key],'sha256':raw_hash(data)},'bytes':data}
    manifest['policySha256']=controls['policy']['ref']['sha256']
    data=cjson.dumps(normalize(manifest))
    controls['manifest']={'ref':{'repositoryId':'synthetic','commit':'b'*40,'path':PIN_PATHS['manifest'],'sha256':raw_hash(data)},'bytes':data}
    selection={'version':'1','repositoryId':'synthetic','baseCommit':'b'*40,'comparison':'head','mode':'changed',
               'requestedCheckIds':[],'cases':[],'expectedPins':{key:copy.deepcopy(item['ref']) for key,item in controls.items()}}
    inputs={'trusted_inputs':controls,'source':copy.deepcopy(model['source']),'base_source':copy.deepcopy(model['source']),
            'target_manifest':manifest,'target_projection':projection,'changes':[{'status':'modify','path':'src/auth.ts'}]}
    return selection,inputs


def rebuilt_model():
    selection,inputs=fixed_model()
    return build_selection_plan(selection,'change',**inputs)
