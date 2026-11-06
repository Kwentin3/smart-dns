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
import tempfile

ROOT = Path(__file__).resolve().parents[1]
IMAGES = json.loads((ROOT / "config/images.lock.json").read_text(encoding="utf-8"))
DENIED_ORIGIN_V4 = (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8",
    "169.254.0.0/16", "172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24",
    "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15", "198.51.100.0/24",
    "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4", "168.63.129.16/32",
)


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


def approved_rules(catalog):
    """One service-policy owner. Project desired exact hosts; never claim applied."""
    if catalog.get("domain_policy") != "exact":
        raise ValueError("only explicitly approved exact domains are supported")
    services = catalog["services"]
    if not isinstance(services, list) or not services:
        raise ValueError("catalog requires at least one visible service")
    seen, all_domains, active, states = set(), set(), set(), []
    for service in services:
        service_id = service["id"]
        if not isinstance(service_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", service_id) or service_id in seen:
            raise ValueError("service IDs must be unique simple lowercase names")
        seen.add(service_id)
        if type(service["enabled"]) is not bool or not isinstance(service["name"], str) or not service["name"].strip():
            raise ValueError("service requires a name and an explicit boolean enabled flag")
        if not isinstance(service["reason"], str) or not service["reason"].strip():
            raise ValueError("service state requires an explanation")
        domains = service["domains"]
        if not isinstance(domains, list) or domains != sorted(set(domains)):
            raise ValueError("service domains must be a unique sorted list")
        if service["enabled"] and not domains:
            raise ValueError("an enabled service requires at least one approved domain")
        for domain in domains:
            hostname(domain)
        all_domains.update(domains)
        if service["enabled"]:
            active.update(domains)
        states.append({"id": service_id, "name": service["name"], "enabled": service["enabled"], "reason": service["reason"], "domains": domains, "discovery_source": service.get("source"), "source_path": service.get("source_path")})
    excluded = catalog["excluded_domains"]
    if not isinstance(excluded, dict) or not set(excluded) <= all_domains:
        raise ValueError("exclusions must reference catalog domains")
    if any(not isinstance(reason, str) or not reason.strip() for reason in excluded.values()):
        raise ValueError("each excluded domain requires an explanation")
    return {"revision": catalog["revision"], "domains": sorted(active - set(excluded)), "excluded_zones": catalog["excluded_zones"], "service_states": states, "excluded_domains": excluded}


def compile_config(rules, settings, origins=None):
    domains = rules["domains"]
    if len(domains) > 20 or domains != sorted(set(domains)):
        raise ValueError("pilot requires 0..20 unique sorted exact domains")
    own = [hostname(z) for z in settings["own_zones"]]
    doh_host = hostname(settings["doh_host"])
    blocked = rules["excluded_zones"] + own + [doh_host]
    for d in domains:
        hostname(d)
        if any(d == zone or d.endswith("." + zone) for zone in blocked):
            raise ValueError("excluded or own domain")
    relay_ip = str(ipaddress.IPv4Address(settings["relay_ipv4"]))
    dynamic_origin = "origin_dns" in settings
    origins = {} if origins is None else origins
    if not isinstance(origins, dict):
        raise ValueError("origins must be a domain-to-IPv4 object")
    forbidden_ips = {relay_ip, "168.63.129.16"} | set(settings.get("own_public_ipv4", []))
    if dynamic_origin:
        if origins:
            raise ValueError("dynamic origin mode does not use fixed origin snapshots")
        origin_dns = settings["origin_dns"]
        if (not isinstance(origin_dns, list) or not origin_dns or
                any(not isinstance(address, str) for address in origin_dns) or len(origin_dns) != len(set(origin_dns))):
            raise ValueError("origin_dns requires unique literal public IPv4 DNS servers")
        origin_dns = [public_v4(address) for address in origin_dns]
        own_public = [public_v4(address) for address in settings.get("own_public_ipv4", [])]
        forbidden_ips = {relay_ip, "168.63.129.16", *own_public}
        forbidden_networks = [ipaddress.IPv4Network(network) for network in DENIED_ORIGIN_V4]
        if any(address in forbidden_ips or any(ipaddress.IPv4Address(address) in network for network in forbidden_networks)
               for address in origin_dns):
            raise ValueError("origin DNS points to nonpublic, own ingress or provider infrastructure")
    else:
        if set(origins) != set(domains):
            raise ValueError("origins must exactly cover the reviewed host set")
        origins = {d: public_v4(origins[d]) for d in domains}
        if any(ip in forbidden_ips for ip in origins.values()):
            raise ValueError("origin points to own ingress or provider infrastructure")
    ids = settings["client_ids"]
    if not ids or len(ids) != len(set(ids)) or any(not re.fullmatch(r"[0-9a-f]{32,64}", x) for x in ids):
        raise ValueError("use unique random 128..256-bit lowercase hexadecimal ClientIDs")
    admin = settings["admin_username"]
    password_hash = settings["admin_password_hash"]
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", admin):
        raise ValueError("admin username must be a simple lowercase account name")
    if not re.fullmatch(r"\$2[aby]\$(?:0[4-9]|[12][0-9]|3[01])\$[./A-Za-z0-9]{53}", password_hash):
        raise ValueError("admin password must be a bcrypt hash")
    fingerprint_inputs = {"rules": rules, "origins": origins}
    if dynamic_origin:
        fingerprint_inputs.update(origin_mode="dynamic-ipv4", origin_dns=origin_dns,
                                  denied_v4=list(DENIED_ORIGIN_V4) + sorted(forbidden_ips))
    fingerprint = hashlib.sha256(json.dumps(fingerprint_inputs, sort_keys=True).encode()).hexdigest()
    user_rules = []
    for d in domains:
        user_rules += [f"|{d}|$dnstype=A,dnsrewrite=NOERROR;A;{relay_ip}",
                       f"|{d}|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;"]
    agh = {
        "http": {"address": "0.0.0.0:3000", "doh": {"insecure_enabled": True}},
        "users": [{"name": admin, "password": password_hash}], "dns": {"bind_hosts": ["0.0.0.0"], "port": 5353,
          "serve_plain_dns": True, "allowed_clients": ids, "disallowed_clients": [],
          "upstream_dns": settings["upstream_dns"], "bootstrap_dns": settings["bootstrap_dns"],
          "ratelimit": 20, "cache_enabled": False, "fallback_dns": [], "use_private_ptr_resolvers": False,
          "hostsfile_enabled": False, "handle_ddr": False},
        "tls": {"enabled": False, "port_https": 0, "port_dns_over_tls": 0, "port_dns_over_quic": 0},
        "filters": [], "whitelist_filters": [], "user_rules": user_rules,
        "clients": {"runtime_sources": {"whois": False, "rdns": False, "arp": False, "dhcp": False, "hosts": False}},
        "querylog": {"enabled": False}, "statistics": {"enabled": False}, "schema_version": 34}
    dot = settings.get("dot")
    if dot is not None:
        if hostname(dot["server_name"]) != doh_host:
            raise ValueError("pilot DoH and DoT must use the same base server name")
        for key in ("certificate_path", "private_key_path"):
            if not isinstance(dot[key], str) or not dot[key] or "\0" in dot[key]:
                raise ValueError("DoT requires explicit certificate and private-key paths")
        agh["tls"].update(enabled=True, server_name=dot["server_name"], strict_sni_check=True,
                          port_dns_over_tls=853, certificate_path=dot["certificate_path"], private_key_path=dot["private_key_path"])
        agh["dns"]["serve_plain_dns"] = False
    hap = [f"# rule snapshot {fingerprint}", "global", "  log stdout format raw local0", "  maxconn 256"]
    if dynamic_origin:
        hap += ["  dns-accept-family ipv4"]
    hap += ["defaults", "  mode tcp", "  log global", "  option tcplog", "  timeout connect 5s", "  timeout client 60s", "  timeout server 60s", "frontend tls_relay", "  bind :8443", "  tcp-request inspect-delay 5s"]
    for i, d in enumerate(domains):
        hap += [f"  acl host_{i} req.ssl_sni,lower -m str {d}"]
    if domains:
        if dynamic_origin:
            hap += ["  tcp-request content reject unless { req.ssl_hello_type 1 }"]
        hap += ["  tcp-request content reject if { req.ssl_hello_type 1 } !" + " !".join(f"host_{i}" for i in range(len(domains)))]
        if dynamic_origin:
            hap += ["  tcp-request content set-var(sess.host) req.ssl_sni,lower",
                    "  tcp-request content do-resolve(sess.ip,origin_dns,ipv4) var(sess.host)",
                    "  tcp-request content reject unless { var(sess.ip) -m found }",
                    "  tcp-request content reject unless { var(sess.ip) -m ip 0.0.0.0/0 }",
                    "  tcp-request content reject if { var(sess.ip) -m ip -f /usr/local/etc/haproxy/denied-v4.txt }",
                    "  tcp-request content set-dst var(sess.ip)",
                    "  tcp-request content set-dst-port int(443)",
                    "  tcp-request content accept"]
        else:
            hap += ["  tcp-request content accept if { req.ssl_hello_type 1 }"]
    else:
        hap += ["  tcp-request content reject"]
    if dynamic_origin and domains:
        hap += ["  default_backend origin_dynamic", "backend origin_dynamic", "  server checked 0.0.0.0:0"]
    else:
        for i, d in enumerate(domains):
            hap += [f"  use_backend origin_{i} if host_{i}"]
        hap += ["  default_backend denied"]
    hap += ["backend denied", "  tcp-request content reject"]
    if dynamic_origin:
        hap += ["resolvers origin_dns"]
        for i, address in enumerate(origin_dns):
            hap += [f"  nameserver independent_{i} {address}:53"]
        hap += ["  resolve_retries 2", "  timeout resolve 1s", "  timeout retry 1s", "  hold valid 10s",
                "  hold nx 1s", "  hold timeout 1s", "  hold other 1s", "  hold refused 1s", "  hold obsolete 0s"]
    else:
        for i, d in enumerate(domains):
            hap += [f"backend origin_{i}", f"  # {d}; no runtime resolver, no dynamic destination", f"  server fixed {origins[d]}:443"]
    if dot is not None:
        # Dedicated fixed infrastructure backend; it is not client-selected SNI
        # forwarding. Docker DNS discovers AGH only, origin DNS is unaffected.
        hap += ["resolvers agh_internal", "  nameserver docker 127.0.0.11:53", "  timeout resolve 1s", "  timeout retry 1s",
                "frontend dot_dns", "  bind :8853", "  maxconn 32", "  tcp-request inspect-delay 5s",
                "  tcp-request content accept if { req.ssl_hello_type 1 }", "  tcp-request content reject if WAIT_END",
                "  default_backend agh_dot", "backend agh_dot", "  server dns dns:853 resolvers agh_internal init-addr none"]
    # Compose consumes $$ as a literal $, preserving the regex end anchor in labels.
    labels_dns = {"traefik.enable": "true", "traefik.http.routers.sd-doh.rule": f"Host(`{doh_host}`) && (Path(`/dns-query`) || PathRegexp(`^/dns-query/[0-9a-f]{{32,64}}$$`))", "traefik.http.routers.sd-doh.entrypoints": "websecure", "traefik.http.routers.sd-doh.tls": "true", "traefik.http.services.sd-doh.loadbalancer.server.port": "3000"}
    # Host() accepts case/port variants. Canonicalize before the native Host-keyed
    # budget, so these variants cannot create extra buckets. These are lab limits.
    labels_dns.update({
        "traefik.http.routers.sd-doh.middlewares": "sd-doh-host,sd-doh-rate,sd-doh-flight",
        "traefik.http.routers.sd-doh.observability.accesslogs": "false",
        "traefik.http.middlewares.sd-doh-host.headers.customrequestheaders.Host": doh_host,
        "traefik.http.middlewares.sd-doh-rate.ratelimit.average": "20",
        "traefik.http.middlewares.sd-doh-rate.ratelimit.period": "1s",
        "traefik.http.middlewares.sd-doh-rate.ratelimit.burst": "40",
        "traefik.http.middlewares.sd-doh-rate.ratelimit.sourcecriterion.requesthost": "true",
        "traefik.http.middlewares.sd-doh-flight.inflightreq.amount": "8",
        "traefik.http.middlewares.sd-doh-flight.inflightreq.sourcecriterion.requesthost": "true",
    })
    labels_relay = {"traefik.enable": "true", "traefik.tcp.routers.sd-relay.rule": " || ".join(f"HostSNI(`{d}`)" for d in domains), "traefik.tcp.routers.sd-relay.entrypoints": "websecure", "traefik.tcp.routers.sd-relay.tls.passthrough": "true", "traefik.tcp.services.sd-relay.loadbalancer.server.port": "8443"}
    if not domains:
        labels_relay = {"traefik.enable": "false"}
    bounded = {"restart": "no", "mem_limit": "128m", "cpus": 0.5, "pids_limit": 100, "logging": {"driver": "json-file", "options": {"max-size": "5m", "max-file": "2"}}, "cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
    services = {
        "dns": {**bounded, "image": IMAGES["agh"], "networks": ["dns"], "user": "${LOCAL_UID:-1000}:${LOCAL_GID:-1000}", "cap_add": ["NET_BIND_SERVICE"], "volumes": ["./agh-conf:/opt/adguardhome/conf"], "tmpfs": ["/opt/adguardhome/work:uid=${LOCAL_UID:-1000},gid=${LOCAL_GID:-1000}"], "labels": labels_dns},
        "relay": {**bounded, "image": IMAGES["relay"], "read_only": True, "ports": ["127.0.0.1:18444:8443"], "volumes": ["./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro"], "labels": labels_relay},
        "edge": {**bounded, "image": IMAGES["edge"], "networks": ["default", "dns"], "ports": ["127.0.0.1:18443:8443"], "volumes": ["/var/run/docker.sock:/var/run/docker.sock:ro"],
          "command": ["--entrypoints.websecure.address=:8443", "--providers.docker=true", "--providers.docker.exposedbydefault=false", "--providers.docker.constraints=Label(`smart-dns.lab`,`true`)", "--api.dashboard=false", "--accesslog=true", "--accesslog.format=json", "--accesslog.fields.defaultmode=drop", "--accesslog.fields.names.RouterName=keep", "--accesslog.fields.names.ServiceName=keep", "--accesslog.fields.names.DownstreamStatus=keep", "--accesslog.fields.headers.defaultmode=drop", "--accesslog.fields.headers.names.X-Lab-Case=keep"]},
        "existing-site": {**bounded, "image": IMAGES["fixture"], "labels": {"traefik.enable": "true", "traefik.http.routers.existing.rule": "Host(`existing.example.net`)", "traefik.http.routers.existing.entrypoints": "websecure", "traefik.http.routers.existing.tls": "true", "traefik.http.services.existing.loadbalancer.server.port": "80"}}
    }
    for service in services.values():
        service.setdefault("labels", {})["smart-dns.lab"] = "true"
    if dot is not None:
        services["dns"]["volumes"].append("${DOT_CERT_DIR:?private TLS directory required}:/certs:ro")
        services["relay"]["networks"] = ["default", "dns"]
        services["relay"]["ports"].append("127.0.0.1:1853:8853")
    artifacts = {"agh-conf/AdGuardHome.yaml": agh, "haproxy.cfg": "\n".join(hap) + "\n", "compose.lab.json": {"services": services, "networks": {"default": {}, "dns": {}}}, "snapshot.json": {"status": "candidate-not-applied", "sha256": fingerprint, "domains": domains, "desired_services": rules.get("service_states", []), "excluded_domains": rules.get("excluded_domains", {}), "origins": origins, "images": IMAGES}}
    if dynamic_origin:
        artifacts["denied-v4.txt"] = "\n".join(dict.fromkeys([*DENIED_ORIGIN_V4, *(address + "/32" for address in sorted(forbidden_ips))])) + "\n"
        services["relay"]["volumes"].append("./denied-v4.txt:/usr/local/etc/haproxy/denied-v4.txt:ro")
        artifacts["snapshot.json"].update(origin_mode="dynamic-ipv4", origin_dns=origin_dns)
    return artifacts


def write_new(artifacts, out):
    """Publish only a complete new directory; never overwrite an accepted set."""
    if out.exists():
        raise FileExistsError("output already exists; choose a new directory")
    out.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="." + out.name + "-", dir=out.parent) as staging:
        staging = Path(staging)
        for name, data in artifacts.items():
            path = staging / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n", encoding="utf-8")
            path.chmod(0o600 if name == "agh-conf/AdGuardHome.yaml" else 0o644)
        if out.exists():
            raise FileExistsError("output appeared during render; refusing overwrite")
        staging.rename(out)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", type=Path, default=ROOT / "rules/pilot.json")
    parser.add_argument("--settings", type=Path, required=True)
    parser.add_argument("--origins", type=Path, help="Fixed-mode origin snapshot; omit when settings.origin_dns is configured")
    parser.add_argument("--out", type=Path, default=ROOT / "generated")
    args = parser.parse_args()
    catalog, settings = (json.loads(p.read_text(encoding="utf-8")) for p in (args.rules, args.settings))
    origins = json.loads(args.origins.read_text(encoding="utf-8")) if args.origins is not None else None
    artifacts = compile_config(approved_rules(catalog), settings, origins)
    write_new(artifacts, args.out)
    print("Rendered", len(artifacts), "artifacts; no services started")


if __name__ == "__main__":
    main()
