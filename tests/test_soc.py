from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
import pytest
from fastapi.testclient import TestClient
from app.main import create_app, run_simulation
from app.engine import detect
from app.simulations import generate

@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('AI_PROVIDER', 'offline')
    with TestClient(create_app(tmp_path/'test.db', seed=False)) as c:
        yield c

@pytest.mark.parametrize('scenario,rule', [('password-guessing','AUTH-001'),('encoded-powershell','EXEC-002'),('cloud-exfiltration','EXFIL-003')])
def test_positive_detections(scenario, rule):
    result = detect(generate(scenario))
    assert len(result) == 1 and result[0][0]['id'] == rule

def test_negative_controls():
    assert detect(generate('benign-activity')) == []
    assert detect(generate('password-guessing')[:4]) == []
    events = generate('encoded-powershell')
    events[0]['data']['command_line'] = 'powershell.exe Get-Date'
    assert detect(events) == []
    events = generate('cloud-exfiltration')
    events[0]['data']['bytes_sent'] = 100*1024*1024-1
    assert detect(events) == []

def test_auth_window_and_entity_isolation():
    events = generate('password-guessing')[:5]
    start = datetime.fromisoformat(events[0]['timestamp'])
    for n, event in enumerate(events):
        event['timestamp'] = (start+timedelta(seconds=n*76)).isoformat()
    assert detect(events) == []
    events = generate('password-guessing')[:5]
    events[-1]['user'] = 'someone.else'
    assert detect(events) == []
    events = generate('password-guessing')[:5]
    events[-1]['data']['source_ip'] = '192.0.2.99'
    assert detect(events) == []

def test_auth_exact_boundary_and_order():
    events = generate('password-guessing')[:5]
    start = datetime.fromisoformat(events[0]['timestamp'])
    for n, event in enumerate(events):
        event['timestamp'] = (start+timedelta(seconds=n*75)).isoformat()
    assert len(detect(list(reversed(events)))) == 1

def test_network_boundary_and_category():
    events = generate('cloud-exfiltration')
    events[0]['data']['bytes_sent'] = 100*1024*1024
    assert len(detect(events)) == 1
    events[0]['data']['destination_category'] = 'internal'
    assert detect(events) == []

def test_end_to_end(client):
    assert client.get('/api/health').json()['status'] == 'ok'
    result = client.post('/api/simulations', json={'scenario':'password-guessing'})
    assert result.status_code == 201
    iid = result.json()['incident_ids'][0]
    incident = client.get(f'/api/incidents/{iid}').json()
    assert len(incident['evidence']) == 5
    assert incident['rule']['technique'] == 'T1110.001'
    updated = client.patch(f'/api/incidents/{iid}',json={'status':'investigating','note':'Checking the owner'}).json()
    assert updated['audit'][-1]['note'] == 'Checking the owner'
    answer = client.post(f'/api/incidents/{iid}/investigate',json={'question':'What next?'}).json()
    assert answer['provider'] == 'offline'
    assert answer['evidence_ids'] == [e['id'] for e in incident['evidence']]
    client.patch(f'/api/incidents/{iid}',json={'status':'resolved','note':'Confirmed synthetic'})
    assert client.get('/api/overview').json()['counts']['resolved'] == 1

@pytest.mark.parametrize('payload',[{'scenario':'execute-shell'},{'scenario':''},{}])
def test_invalid_simulation(client,payload):
    assert client.post('/api/simulations',json=payload).status_code == 422

def test_request_boundaries(client):
    assert client.post('/api/simulations',json={'scenario':'benign-activity'},headers={'origin':'https://attacker.example'}).status_code == 403
    assert client.get('/api/health',headers={'host':'attacker.example'}).status_code == 400
    assert client.get('/api/incidents/missing').status_code == 404
    iid = client.post('/api/simulations',json={'scenario':'encoded-powershell'}).json()['incident_ids'][0]
    assert client.patch(f'/api/incidents/{iid}',json={'status':'deleted'}).status_code == 422
    assert client.post(f'/api/incidents/{iid}/investigate',json={'question':''}).status_code == 422
    assert client.post(f'/api/incidents/{iid}/investigate',json={'question':'x'*2001}).status_code == 422

def test_seed_once_and_persistence(tmp_path):
    path = tmp_path/'persist.db'
    with TestClient(create_app(path)) as c:
        overview = c.get('/api/overview').json()
        assert overview['events'] == 10 and overview['total_incidents'] == 3
        iid = overview['incidents'][0]['id']
        c.patch(f'/api/incidents/{iid}',json={'status':'resolved','note':'Persist me'})
    with TestClient(create_app(path)) as c:
        assert c.get('/api/overview').json()['total_incidents'] == 3
        assert c.get(f'/api/incidents/{iid}').json()['status'] == 'resolved'

def test_concurrent_simulations(tmp_path):
    path=tmp_path/'concurrent.db'
    with TestClient(create_app(path,seed=False)) as c:
        with ThreadPoolExecutor(max_workers=4) as pool:
            results=list(pool.map(lambda _:run_simulation(str(path),'cloud-exfiltration'),range(8)))
        assert len({r['run_id'] for r in results}) == 8
        assert c.get('/api/overview').json()['total_incidents'] == 8

def test_static_and_security_headers(client):
    assert client.get('/').status_code == 200
    assert client.get('/static/app.js').status_code == 200
    assert "frame-ancestors 'none'" in client.get('/').headers['content-security-policy']
    assert client.get('/.env').status_code == 404

def test_ai_failure_is_sanitized(client, monkeypatch):
    async def fail(*args):
        raise RuntimeError('sensitive internal detail')
    monkeypatch.setattr('app.main.investigate', fail)
    iid=client.post('/api/simulations',json={'scenario':'encoded-powershell'}).json()['incident_ids'][0]
    response=client.post(f'/api/incidents/{iid}/investigate',json={'question':'Explain'})
    assert response.status_code == 503
    assert 'sensitive' not in response.text
