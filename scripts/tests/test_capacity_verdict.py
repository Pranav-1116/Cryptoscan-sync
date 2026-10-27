import importlib.util
from pathlib import Path
import pytest

path=Path(__file__).resolve().parents[1]/'load_test.py'
spec=importlib.util.spec_from_file_location('capacity_harness',path)
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


@pytest.mark.parametrize('status', [429,401,403,404,500,0])
def test_no_successful_operations_is_not_capacity(status):
    result=module.Result()
    for _ in range(10):result.record(0.001,status)
    report=module.summarize(result,wall=1.0,max_error_rate=.01,max_throttle_rate=.01)
    assert report['capacity_verdict']=='FAIL'
    assert report['successful_operations']==0
    assert report['successful_throughput_rps']==0


def test_latency_and_throughput_use_successes_only():
    result=module.Result();result.record(.01,200);result.record(10,500);result.record(.001,429)
    report=module.summarize(result,wall=2,max_error_rate=.01,max_throttle_rate=.01)
    assert report['capacity_verdict']=='FAIL'
    assert report['successful_operations']==1 and report['successful_throughput_rps']==.5
    assert report['latency_ms']['p95']==10 and report['latency_ms']['p99']==10


def test_unmeasured_has_null_latency_and_fails():
    report=module.summarize(module.Result(),wall=1,max_error_rate=.01,max_throttle_rate=.01)
    assert report['capacity_verdict']=='FAIL'
    assert report['latency_ms']['p95'] is None


def test_success_is_scoped_engineering_evidence_not_bank_approval():
    result=module.Result()
    for _ in range(10):result.record(.02,200)
    report=module.summarize(result,wall=2,max_error_rate=.01,max_throttle_rate=.01)
    assert report['capacity_verdict']=='PASS'
    assert report['bank_approved'] is False
    assert report['successful_throughput_rps']==5


def test_main_does_not_exit_success_when_every_request_is_throttled(monkeypatch,capsys):
    monkeypatch.setattr(module.sys,'argv',['load_test.py','--username','synthetic','--password','synthetic-only',
        '--users','1','--duration','.01','--identity','shared-session'])
    monkeypatch.setattr(module,'login',lambda *a:'synthetic-token')
    monkeypatch.setattr(module,'worker',lambda call,result,*args:result.record(.001,429))
    assert module.main()==1


def test_revocation_continues_after_network_failure(monkeypatch):
    calls=[]
    def response(base,path,*args):
        calls.append(path)
        if path.endswith('/one'):raise OSError('synthetic offline')
        return 204,{}
    monkeypatch.setattr(module,'_json',response)
    assert module.revoke_vu_keys('http://synthetic','synthetic',[('one','key'),('two','key')]) is False
    assert len(calls)==2


@pytest.mark.parametrize('mode',['cleanup_failure','worker_crash'])
def test_cleanup_or_worker_failure_cannot_report_capacity_pass(monkeypatch,capsys,mode):
    monkeypatch.setattr(module.sys,'argv',['load_test.py','--username','synthetic','--password','synthetic-only','--users','1','--duration','.01'])
    monkeypatch.setattr(module,'login',lambda *a:'synthetic')
    monkeypatch.setattr(module,'create_vu_keys',lambda *a:[('synthetic-id','synthetic-key')])
    monkeypatch.setattr(module,'revoke_vu_keys',lambda *a:mode!='cleanup_failure')
    def work(call,result,*args):
        result.record(.01,200)
        if mode=='worker_crash':raise ValueError('synthetic error')
    monkeypatch.setattr(module,'worker',work)
    assert module.main()==1


@pytest.mark.parametrize('metrics',[
    {'error_rate':0,'throttled_429':10,'requests':10},
    {'capacity_verdict':'PASS','successful_operations':0,'error_rate':0,'throttle_rate':0,'temporary_keys_revoked':True},
    {'capacity_verdict':'PASS','successful_operations':10,'error_rate':0,'throttle_rate':0,'temporary_keys_revoked':False},
    {'capacity_verdict':'PASS','successful_operations':10,'error_rate':.5,'throttle_rate':0,'temporary_keys_revoked':True},
])
def test_parent_rejects_old_or_unqualified_harness_metrics(monkeypatch,metrics):
    import json, subprocess
    import production_evidence as parent
    def run(cmd,**kwargs):
        assert '--password' not in cmd and 'synthetic-secret' not in cmd
        assert kwargs['env']['CRYPTOSCAN_LOAD_PASSWORD']=='synthetic-secret'
        return subprocess.CompletedProcess(cmd,0,json.dumps(metrics),'')
    monkeypatch.setattr(parent.subprocess,'run',run)
    assert parent.run_load('http://synthetic',1,.01,'synthetic','synthetic-secret').status=='FAIL'


def test_partial_key_creation_failure_retains_known_ids_for_cleanup(monkeypatch):
    calls=[]
    def response(*args):
        calls.append(True)
        if len(calls)==1:return 201,{'id':'synthetic','raw_key':'synthetic-key'}
        raise OSError('synthetic outage')
    monkeypatch.setattr(module,'_json',response)
    assert module.create_vu_keys('http://synthetic','synthetic',2)==[('synthetic','synthetic-key')]
