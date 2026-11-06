"""Small representation adapter: one reviewed exact-host set -> three configs.

No fetch, DNS resolution, remote writes, or deployment. Runtime origins and
client credentials are explicit local inputs. Generated JSON is valid YAML.
"""
import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
IMAGES = json.loads((ROOT / "config/images.lock.json").read_text(encoding="utf-8"))


def hostname(value):
    if not isinstance(value, str) or len(value) > 253 or value != value.lower():
        raise ValueError("domain must be lowercase ASCII, <=253 characters")
    labels = value.split(".")
    if len(labels) < 2 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
        raise ValueError("invalid exact domain")
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return value
    raise ValueError("IP literal is not a domain")


def public_v4(value):
    ip = ipaddress.ip_address(value)
    if ip.version != 4 or not ip.is_global or ip.is_multicast or value != str(ip):
        raise ValueError("origin must be a canonical public unicast IPv4")
    return value


def compile_config(rules, settings, origins):
    domains = rules["domains"]
    if not domains or len(domains) > 20 or domains != sorted(set(domains)):
        raise ValueError("pilot requires 1..20 unique sorted exact domains")
    own = [hostname(z) for z in settings["own_zones"]]
    doh_host = hostname(settings["doh_host"])
    blocked = rules["excluded_zones"] + own + [doh_host]
    for d in domains:
        hostname(d)
        if any(d == zone or d.endswith("." + zone) for zone in blocked):
            raise ValueError("excluded or own domain")
    if set(origins) != set(domains):
        raise ValueError("origins must exactly cover the reviewed host set")
    relay_ip = str(ipaddress.IPv4Address(settings["relay_ipv4"]))
    origins = {d: public_v4(origins[d]) for d in domains}
    forbidden_ips = {relay_ip, "168.63.129.16"} | set(settings.get("own_public_ipv4", []))
    if any(ip in forbidden_ips for ip in origins.values()):
        raise ValueError("origin points to own ingress or provider infrastructure")
    ids = settings["client_ids"]
    if not ids or len(ids) != len(set(ids)) or any(not re.fullmatch(r"[0-9a-f]{32,64}", x) for x in ids):
        raise ValueError("use unique random 128..256-bit lowercase hexadecimal ClientIDs")
    fingerprint = hashlib.sha256(json.dumps({"rules": rules, "origins": origins}, sort_keys=True).encode()).hexdigest()
    user_rules = []
    for d in domains:
        user_rules += [f"|{d}|$dnstype=A,dnsrewrite=NOERROR;A;{relay_ip}",
                       f"|{d}|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;"]
    agh = {
        "http": {"address": "0.0.0.0:3000", "doh": {"insecure_enabled": True}},
        "users": [], "dns": {"bind_hosts": ["0.0.0.0"], "port": 5353,
          "serve_plain_dns": True, "allowed_clients": ids, "disallowed_clients": [],
          "upstream_dns": settings["upstream_dns"], "bootstrap_dns": settings["bootstrap_dns"],
          "ratelimit": 20, "cache_enabled": False, "fallback_dns": [], "use_private_ptr_resolvers": False,
          "hostsfile_enabled": False, "handle_ddr": False},
        "tls": {"enabled": False, "port_https": 0, "port_dns_over_tls": 0, "port_dns_over_quic": 0},
        "filters": [], "whitelist_filters": [], "user_rules": user_rules,
        "clients": {"runtime_sources": {"whois": False, "rdns": False, "arp": False, "dhcp": False, "hosts": False}},
        "querylog": {"enabled": False}, "statistics": {"enabled": False}, "schema_version": 34}
    hap = [f"# rule snapshot {fingerprint}", "global", "  log stdout format raw local0", "  maxconn 256", "defaults", "  mode tcp", "  log global", "  option tcplog", "  timeout connect 5s", "  timeout client 60s", "  timeout server 60s", "frontend tls_relay", "  bind :8443", "  tcp-request inspect-delay 5s"]
    for i, d in enumerate(domains):
        hap += [f"  acl host_{i} req.ssl_sni,lower -m str {d}"]
    hap += ["  tcp-request content reject if { req.ssl_hello_type 1 } !" + " !".join(f"host_{i}" for i in range(len(domains))),
            "  tcp-request content accept if { req.ssl_hello_type 1 }"]
    for i, d in enumerate(domains):
        hap += [f"  use_backend origin_{i} if host_{i}"]
    hap += ["  default_backend denied", "backend denied", "  tcp-request content reject"]
    for i, d in enumerate(domains):
        hap += [f"backend origin_{i}", f"  # {d}; no runtime resolver, no dynamic destination", f"  server fixed {origins[d]}:443"]
    # Compose consumes $$ as a literal $, preserving the regex end anchor in labels.
    labels_dns = {"traefik.enable": "true", "traefik.http.routers.sd-doh.rule": f"Host(`{doh_host}`) && (Path(`/dns-query`) || PathRegexp(`^/dns-query/[0-9a-f]{{32,64}}$$`))", "traefik.http.routers.sd-doh.entrypoints": "websecure", "traefik.http.routers.sd-doh.tls": "true", "traefik.http.services.sd-doh.loadbalancer.server.port": "3000"}
    labels_relay = {"traefik.enable": "true", "traefik.tcp.routers.sd-relay.rule": " || ".join(f"HostSNI(`{d}`)" for d in domains), "traefik.tcp.routers.sd-relay.entrypoints": "websecure", "traefik.tcp.routers.sd-relay.tls.passthrough": "true", "traefik.tcp.services.sd-relay.loadbalancer.server.port": "8443"}
    bounded = {"restart": "no", "mem_limit": "128m", "cpus": 0.5, "pids_limit": 100, "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}}, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    services = {
        "dns": {**bounded, "image": IMAGES["agh"], "user": "${LOCAL_UID:-1000}:${LOCAL_GID:-1000}", "cap_add": ["NET_BIND_SERVICE"], "volumes": ["./agh-conf:/opt/adguardhome/conf"], "tmpfs": ["/opt/adguardhome/work:uid=${LOCAL_UID:-1000},gid=${LOCAL_GID:-1000}"], "labels": labels_dns},
        "relay": {**bounded, "image": IMAGES["relay"], "read_only": True, "ports": ["127.0.0.1:18444:8443"], "volumes": ["./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"], "labels": labels_relay},
        "edge": {**bounded, "image": IMAGES["edge"], "ports": ["127.0.0.1:18443:8443"], "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"],
          "command": ["--entrypoints.websecure.address=:8443", "--providers.docker=true", "--providers.docker.exposedbydefault=false", "--providers.docker.constraints=Label(`smart-dns.lab`,`true`)", "--api.dashboard=false", "--accesslog=true", "--accesslog.format=json", "--accesslog.fields.defaultmode=drop", "--accesslog.fields.names.RouterName=keep", "--accesslog.fields.names.ServiceName=keep", "--accesslog.fields.names.DownstreamStatus=keep", "--accesslog.fields.headers.defaultmode=drop", "--accesslog.fields.headers.names.X-Lab-Case=keep"]},
        "existing-site": {**bounded, "image": IMAGES["fixture"], "labels": {"traefik.enable": "true", "traefik.http.routers.existing.rule": "Host(`existing.example.net`)", "traefik.http.routers.existing.entrypoints": "websecure", "traefik.http.routers.existing.tls": "true", "traefik.http.services.existing.loadbalancer.server.port": "80"}}
    }
    for service in services.values():
        service.setdefault("labels", {})["smart-dns.lab"] = "true"
    return {"agh-conf/AdGuardHome.yaml": agh, "haproxy.cfg": "\n".join(hap) + "\n", "compose.lab.json": {"services": services}, "snapshot.json": {"sha256": fingerprint, "domains": domains, "origins": origins, "images": IMAGES}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=ROOT / "rules/pilot.json")
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--origins", type=Path, required=True)
    parser.add_argument("--out", type=Path, default=ROOT / "generated")
    args = parser.parse_args()
    artifacts = compile_config(*(json.loads(p.read_text(encoding="utf-8")) for p in (args.rules, args.settings, args.origins)))
    args.out.mkdir(parents=True, exist_ok=True)
    for name, data in artifacts.items():
        (args.out / name).parent.mkdir(parents=True, exist_ok=True)
        (args.out / name).write_text(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print("Rendered", len(artifacts), "artifacts; no services started")


if __name__ == "__main__":
    main()
