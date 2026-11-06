#!/usr/bin/env bash
# Run ONLY in a disposable copy on an approved Linux lab. Never production.
set -euo pipefail
cd "$(dirname "$0")/.."
export COMPOSE_PROJECT_NAME=smart-dns-issue1
export LOCAL_UID=$(id -u) LOCAL_GID=$(id -g)
test ! -e .local/lab-started || { echo 'Inspect earlier experiment before retry'; exit 1; }
mkdir -p .local
docker ps -aq --no-trunc | sort > .local/baseline.ids
if docker ps -aq --filter "label=com.docker.compose.project=$COMPOSE_PROJECT_NAME" | grep -q .; then
  echo 'Existing task project: stop and inspect, no blind reuse'; exit 1
fi
python3 - <<'PY'
import json, pathlib, secrets, socket
from tools.render import public_v4
p=pathlib.Path('.local')
rules=json.loads(pathlib.Path('rules/pilot.json').read_text())
origins={}
for host in rules['domains']:
    addresses=sorted({row[4][0] for row in socket.getaddrinfo(host,443,socket.AF_INET,socket.SOCK_STREAM)})
    for address in addresses: public_v4(address)
    origins[host]=addresses[0]
settings={'doh_host':'dns.example.net','relay_ipv4':'192.0.2.10','client_ids':[secrets.token_hex(24)],'own_zones':['example.net'],'upstream_dns':['https://dns.quad9.net/dns-query'],'bootstrap_dns':['9.9.9.9']}
(p/'settings.json').write_text(json.dumps(settings))
(p/'origins.json').write_text(json.dumps(origins))
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
timeout 120 python3 tools/probe.py --settings .local/settings.json > .local/probe.json
cat .local/probe.json
docker stats --no-stream --format '{{.Name}} {{.MemUsage}} {{.CPUPerc}} {{.NetIO}}' $("${compose[@]}" ps -q) > .local/stats.txt
for image in adguard/adguardhome:v0.107.80 haproxy:3.2.26-alpine traefik:v3.6.25 traefik/whoami:v1.11.0; do
  docker image inspect "$image" --format '{{json .RepoDigests}}'
done > .local/image-digests.jsonl
