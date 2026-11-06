#!/usr/bin/env bash
# Run ONLY in a disposable copy on an approved Linux lab. Never production.
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=smart-dns-issue1
export LOCAL_UID=$(id -u) LOCAL_GID=$(id -g)
test ! -e .local/lab-started || { echo 'Inspect earlier experiment before retry'; exit 1; }
mkdir -p .local
docker ps -aq --no-trunc | sort > .local/baseline.ids
if docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" | grep -q .; then
  echo 'Existing task project: stop and inspect, no blind reuse'; exit 1
fi
if ss -lntH '( sport = :18443 or sport = :18444 )' | grep -q .; then
  echo 'Lab ports occupied; refusing to disturb their owner'; exit 1
fi
python3 - <<'PY'
import json, pathlib, secrets, socket
from tools.render import catalog_rules, public_v4
p=pathlib.Path('.local')
registry_path=pathlib.Path('rules/registry.json')
registry=json.loads(registry_path.read_text()) if registry_path.exists() else None
rules=catalog_rules(json.loads(pathlib.Path('rules/pilot.json').read_text()), registry)
assert not rules.get('domain_suffixes'), 'fixed-origin lab requires separate suffix acceptance'
origins={}
for host in rules['domains']:
    addresses=sorted({row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)})
    for address in addresses: public_v4(address)
    origins[host]=addresses[0]
settings={'doh_host':'dns.example.net','relay_ipv4':'192.0.2.10','client_ids':[secrets.token_hex(24)],'own_zones':['example.net'],'upstream_dns':['https://dns.quad9.net/dns-query'],'bootstrap_dns':['9.9.9.9'],'admin_username':'lab-admin','admin_password_hash':'$2b$10$kkngSiVN5gx/I5BfjB/TGOJmh1hd1rHbjZlw8R0EbBXsUnS721f56'}
(p/'settings.json').write_text(json.dumps(settings))
(p/'origins.json').write_text(json.dumps(origins))
(p/'admin-password').write_text('lab-only-change-me') # Disposable fixture only.
PY
python3 tools/render.py --settings .local/settings.json --origins .local/origins.json
compose=(docker compose -f generated/compose.lab.json)
cleanup() {
  result=$?
  trap - EXIT INT TERM
  "${compose[@]}" logs --no-color > .local/compose.log 2>&1 || true
  "${compose[@]}" down --volumes --remove-orphans > .local/cleanup.log 2>&1 || result=1
  docker ps -aq --no-trunc | sort > .local/final.ids
  if ! cmp -s .local/baseline.ids .local/final.ids; then
    echo 'Container identity mismatch: inspect baseline/final'; result=1
  fi
  if docker network ls --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" -q | grep -q .; then
    echo 'Owned network remains'; result=1
  fi
  echo "cleanup-result=$result"
  exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
touch .local/lab-started
"${compose[@]}" config -q
timeout 240 "${compose[@]}" pull --quiet
"${compose[@]}" run --rm --no-deps relay haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg
"${compose[@]}" up -d
for attempt in $(seq 1 60); do
  if curl --silent --insecure --max-time 2 https://127.0.0.1:18443/ -o /dev/null; then break; fi
  sleep 1
done
# Docker provider events need readiness by actual application response.
python3 - <<'PY'
import json,time,urllib.request,ssl
settings=json.load(open('.local/settings.json'))
for i in range(60):
    try:
        r=urllib.request.urlopen(urllib.request.Request('https://127.0.0.1:18443/',headers={'Host':'existing.example.net'}),context=ssl._create_unverified_context(),timeout=2)
        if r.status==200: break
    except Exception: pass
    time.sleep(1)
else: raise SystemExit('HTTP router readiness timeout')
PY
dns_ip=$(docker inspect "$("${compose[@]}" ps -q dns)" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
management_base="http://$dns_ip:3000"
gateway=$(docker network inspect "${COMPOSE_PROJECT_NAME}_dns" --format '{{(index .IPAM.Config 0).Gateway}}')
timeout 120 python3 tools/probe.py --settings .local/settings.json --management-base "$management_base" --admin-password-file .local/admin-password --check-revocation > .local/probe.json
cat .local/probe.json
review_args=()
if [ "${1:-}" = "--observe-review" ]; then review_args=(--observe); fi
timeout 120 python3 tools/probe_review.py --settings .local/settings.json --edge-container "$("${compose[@]}" ps -q edge)" "${review_args[@]}" > .local/review-probe.json
cat .local/review-probe.json
timeout 60 python3 tools/probe_limits.py --settings .local/settings.json --management-base "$management_base" --admin-password-file .local/admin-password --fixture-bind "$gateway" > .local/limits.json
cat .local/limits.json

# Read native effective policy and probe direct peer/host paths; no passwords or
# ClientIDs in docker command arguments. Basic credentials stay in HTTP memory.
export LAB_DNS_IP="$dns_ip" LAB_EDGE_ID="$("${compose[@]}" ps -q edge)"
python3 - <<'PY'
import base64,json,os,pathlib,re,socket,struct,subprocess,sys
sys.path.insert(0,'tools')
from probe import management_request,question
from render import catalog_rules
p=pathlib.Path('.local'); s=json.loads((p/'settings.json').read_text()); password=(p/'admin-password').read_text()
registry_path=pathlib.Path('rules/registry.json')
registry=json.loads(registry_path.read_text()) if registry_path.exists() else None
rules=catalog_rules(json.loads(pathlib.Path('rules/pilot.json').read_text()), registry)
status,body=management_request('http://'+os.environ['LAB_DNS_IP']+':3000','/control/filtering/status',s['admin_username'],password)
assert status==200
effective=json.loads(body)['user_rules']
dns_hosts={line.split('|')[1] for line in effective}
service='smart-dns-issue1-relay-1'
labels=json.loads(subprocess.check_output(['docker','inspect',service]))[0]['Config']['Labels']
tcp_hosts=set(re.findall(r'HostSNI\(`([^`]+)`\)',labels['traefik.tcp.routers.sd-relay.rule']))
hap_hosts=set(re.findall(r'^  acl policy_allowed req\.ssl_sni,lower -m str (\S+)$',pathlib.Path('generated/haproxy.cfg').read_text(),re.M))
assert dns_hosts==tcp_hosts==hap_hosts==set(rules['domains'])
edge=os.environ['LAB_EDGE_ID']
response=subprocess.run(['docker','exec',edge,'wget','-S','-O','-','http://dns:3000/control/status'],capture_output=True)
assert response.returncode!=0 and b'401' in response.stderr, 'peer management was not rejected'
query=base64.urlsafe_b64encode(question('chatgpt.com')).rstrip(b'=').decode()
wire=subprocess.check_output(['docker','exec',edge,'wget','-q','-O','-','http://dns:3000/dns-query?dns='+query])
assert len(wire)>=12 and wire[3]&15==5 and wire[6:8]==b'\0\0'
address=(os.environ['LAB_DNS_IP'],5353)
with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
    udp.settimeout(.5); udp.sendto(question('chatgpt.com'),address)
    try:
        wire=udp.recv(4096)
        assert len(wire)>=12 and wire[3]&15==5 and wire[6:8]==b'\0\0'
    except (socket.timeout,ConnectionResetError): pass
with socket.create_connection(address,timeout=2) as tcp:
    tcp.settimeout(.5); wire=question('chatgpt.com'); tcp.sendall(struct.pack('!H',len(wire))+wire)
    try:
        wire=tcp.recv(4096)
        assert not wire or (len(wire)>=14 and wire[5]&15==5 and wire[8:10]==b'\0\0')
    except (socket.timeout,ConnectionResetError): pass
result={'check':'effective-three-host-sets-and-direct-peer-admission','status':'PASS','effective_hosts':sorted(dns_hosts),'peer_management':'401','peer_anonymous_GET':'REFUSED','direct_plain_DNS':'no-useful-answer'}
(p/'peer-probe.json').write_text(json.dumps(result,indent=2))
print(json.dumps(result))
PY

# Fault-inject ONLY the disposable relay. Keep edge and unrelated HTTP fixture
# running; restore the accepted configuration after the native startup failure.
python3 tools/render.py --settings .local/settings.json --origins .local/origins.json --out .local/rejected-candidate
printf '\nnot_a_haproxy_directive\n' >> .local/rejected-candidate/haproxy.cfg
candidate=(docker compose -f .local/rejected-candidate/compose.lab.json)
docker inspect "$("${compose[@]}" ps -q edge)" "$("${compose[@]}" ps -q existing-site)" --format '{{.Id}} {{.State.StartedAt}}' > .local/unchanged-before.txt
"${compose[@]}" stop dns relay
"${candidate[@]}" up -d --no-deps relay
bad_id=$("${candidate[@]}" ps -aq relay)
for attempt in $(seq 1 30); do
  state=$(docker inspect "$bad_id" --format '{{.State.Status}}')
  if [ "$state" = exited ]; then break; fi
  sleep .2
done
test "$state" = exited
test "$(docker inspect "$bad_id" --format '{{.State.ExitCode}}')" != 0
docker inspect "$bad_id" --format '{{.State.ExitCode}}' > .local/rejected-relay.exit-code
docker logs "$bad_id" > .local/rejected-relay.log 2>&1
curl --silent --insecure --fail -H 'Host: existing.example.net' https://127.0.0.1:18443/ > /dev/null
"${compose[@]}" up -d --no-deps relay dns
# Wait for actual authenticated DNS behavior, not just a container-running flag.
python3 - <<'PY'
import json,sys,time
sys.path.insert(0,'tools')
from probe import doh,question
s=json.load(open('.local/settings.json'))
for i in range(60):
    try:
        code,body=doh('https://127.0.0.1:18443/dns-query/'+s['client_ids'][0],s['doh_host'],question('chatgpt.com'))
        if code==200 and len(body)>=12 and body[3]&15==0: break
    except OSError: pass
    time.sleep(.1)
else: raise SystemExit('rollback DNS readiness timeout')
PY
dns_ip=$(docker inspect "$("${compose[@]}" ps -q dns)" --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}')
timeout 120 python3 tools/probe.py --settings .local/settings.json --management-base "http://$dns_ip:3000" --admin-password-file .local/admin-password > .local/rollback-probe.json
docker inspect "$("${compose[@]}" ps -q edge)" "$("${compose[@]}" ps -q existing-site)" --format '{{.Id}} {{.State.StartedAt}}' > .local/unchanged-after.txt
cmp .local/unchanged-before.txt .local/unchanged-after.txt
python3 - <<'PY'
import json,pathlib
p=pathlib.Path('.local')
result={'check':'failed-native-candidate-and-restoration','status':'PASS','rejected_exit_code':int((p/'rejected-relay.exit-code').read_text()),'edge_and_neighbor_identity_unchanged':(p/'unchanged-before.txt').read_bytes()==(p/'unchanged-after.txt').read_bytes(),'restored_probe_count':len(json.loads((p/'rollback-probe.json').read_text()))}
(p/'rollback.json').write_text(json.dumps(result,indent=2))
PY
echo 'PASS: failed candidate restored; edge and unrelated HTTP container unchanged'
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}} {{.NetIO}}' $("${compose[@]}" ps -q) > .local/stats.txt
"${compose[@]}" ps -q > .local/running.ids
python3 - <<'PY'
import json,pathlib,subprocess
lock=json.load(open('config/images.lock.json')); mapping={'dns':'agh','relay':'relay','edge':'edge','existing-site':'fixture'}
containers=json.loads(subprocess.check_output(['docker','inspect',*pathlib.Path('.local/running.ids').read_text().split()]))
receipt=[]
for c in containers:
    service=c['Config']['Labels']['com.docker.compose.service']; expected=lock[mapping[service]]
    image=json.loads(subprocess.check_output(['docker','image','inspect',expected]))[0]
    assert c['Image']==image['Id'] and c['State']['Running']
    receipt.append({'service':service,'locked_ref':expected,'running_image_id':c['Image'],'repo_digests':image['RepoDigests']})
pathlib.Path('.local/image-digests.json').write_text(json.dumps(receipt,indent=2))
PY
