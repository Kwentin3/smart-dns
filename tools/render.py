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
    """Project locally approved exact names and typed suffix roots, never regex."""
    if catalog.get("domain_policy") not in ("exact", "exact-and-suffix"):
        raise ValueError("only explicitly approved exact names and suffix roots are supported")
    services = catalog["services"]
    if not isinstance(services, list) or not services:
        raise ValueError("catalog requires at least one visible service")
    seen, all_domains, active, states = set(), set(), set(), []
    all_suffixes, active_suffixes = set(), set()
    for service in services:
        service_id = service["id"]
        if not isinstance(service_id, str) or not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", service_id) or service_id in seen:
            raise ValueError("service IDs must be unique simple lowercase names")
        seen.add(service_id)
        if type(service["enabled"]) is not bool or not isinstance(service["name"], str) or not service["name"].strip():
            raise ValueError("service requires a name and an explicit boolean enabled flag")
        if not isinstance(service["reason"], str) or not service["reason"].strip():
            raise ValueError("service state requires an explanation")
        kind = service.get("kind", "service")
        if kind not in ("service", "group"):
            raise ValueError("service kind must be service or group")
        domains, suffixes = service.get("domains", []), service.get("domain_suffixes", [])
        for values in (domains, suffixes):
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values) or values != sorted(set(values)):
                raise ValueError("service domain fields must be unique sorted lists")
        if service["enabled"] and not (domains or suffixes):
            raise ValueError("an enabled service requires an approved exact name or suffix root")
        for domain in domains + suffixes:
            hostname(domain)
        all_domains.update(domains)
        all_suffixes.update(suffixes)
        if service["enabled"]:
            active.update(domains)
            active_suffixes.update(suffixes)
        states.append({"id": service_id, "name": service["name"], "kind": kind, "enabled": service["enabled"], "reason": service["reason"], "domains": domains, "discovery_source": service.get("source"), "source_path": service.get("source_path")})
        if "domain_suffixes" in service:
            states[-1]["domain_suffixes"] = suffixes
        for key in ("references", "upstream", "upstream_state"):
            if key in service:
                states[-1][key] = service[key]
    excluded = catalog["excluded_domains"]
    if not isinstance(excluded, dict):
        raise ValueError("exclusions must reference catalog names or suffix descendants")
    for domain in excluded:
        hostname(domain)
        if domain not in all_domains and not any(domain == root or domain.endswith("." + root) for root in all_suffixes):
            raise ValueError("exclusions must reference catalog names or suffix descendants")
    if any(not isinstance(reason, str) or not reason.strip() for reason in excluded.values()):
        raise ValueError("each excluded domain requires an explanation")
    # Individual OFF overrides bulk group grants, but never withdraws a shared
    # namespace needed by another enabled individual. Preserve that conservative
    # overlap explicitly so the status owner can explain effective routing.
    individual_domains, individual_suffixes = set(), set()
    for state in states:
        if state["kind"] == "service" and state["enabled"]:
            individual_domains.update(state["domains"])
            individual_suffixes.update(state.get("domain_suffixes", []))
    excluded = dict(excluded)
    off_zones = set()
    for state in states:
        if state["kind"] != "service" or state["enabled"]:
            continue
        shared_domains, shared_suffixes = [], []
        for name in state["domains"]:
            if name in individual_domains or any(name == root or name.endswith("." + root) for root in individual_suffixes):
                shared_domains.append(name)
            else:
                excluded.setdefault(name, "Disabled service: " + state["id"])
        for root in state.get("domain_suffixes", []):
            if (any(name == root or name.endswith("." + root) for name in individual_domains) or
                    any(name == root or name.endswith("." + root) or root.endswith("." + name) for name in individual_suffixes)):
                shared_suffixes.append(root)
            else:
                off_zones.add(root)
        if shared_domains or shared_suffixes:
            state["shared_routing"] = {"domains": shared_domains, "domain_suffixes": shared_suffixes}
    zones = sorted(set(catalog["excluded_zones"]) | off_zones) if off_zones else list(catalog["excluded_zones"])
    projected = {"revision": catalog["revision"], "domains": sorted(active - set(excluded)), "excluded_zones": zones, "service_states": states, "excluded_domains": excluded}
    if any("domain_suffixes" in service for service in services):
        projected["domain_suffixes"] = sorted(active_suffixes)
    return projected


def compile_config(rules, settings, origins=None):
    domains = rules["domains"]
    suffixes = rules.get("domain_suffixes", [])
    for values in (domains, suffixes):
        if not isinstance(values, list) or any(not isinstance(value, str) for value in values) or values != sorted(set(values)):
            raise ValueError("policy requires unique sorted exact names and suffix roots")
    own = [hostname(z) for z in settings["own_zones"]]
    doh_host = hostname(settings["doh_host"])
    protected = own + [doh_host]
    blocked = rules["excluded_zones"] + protected
    for d in domains + suffixes:
        hostname(d)
        if any(d == zone or d.endswith("." + zone) for zone in protected):
            raise ValueError("excluded or own domain")
    # An approved broad suffix can contain a narrower own/excluded zone. Keep
    # that zone native and direct in all three consumers rather than widening it.
    zone_exceptions = sorted({zone for zone in blocked if any(zone.endswith("." + root) for root in suffixes)})
    exact_exceptions = sorted({name for name in rules.get("excluded_domains", {})
                               if name in domains or any(name == root or name.endswith("." + root) for root in suffixes)})
    for name in zone_exceptions + exact_exceptions:
        hostname(name)
    limit = settings.get("max_policy_entries", 2048)
    if type(limit) is not int or limit < 1 or len(domains) + len(suffixes) + len(zone_exceptions) + len(exact_exceptions) > limit:
        raise ValueError("policy exceeds its explicit pattern budget")
    # Keep desired inputs and validate their full budget before filtering. An
    # operator exclusion overrides source allows, including the same root.
    desired_domains, desired_suffixes = domains, suffixes
    domains = [name for name in domains if name not in rules.get("excluded_domains", {}) and
               not any(name == root or name.endswith("." + root) for root in rules["excluded_zones"])]
    suffixes = [name for name in suffixes if not any(name == root or name.endswith("." + root) for root in rules["excluded_zones"])]
    # AGH combines matching rewrite records: redundant exact/suffix positives
    # produce duplicate A answers. Project one minimal union in every consumer,
    # retaining the approved typed inputs separately from native wire patterns.
    suffixes = [root for root in suffixes if not any(root.endswith("." + parent) for parent in suffixes)]
    domains = [name for name in domains if not any(name == root or name.endswith("." + root) for root in suffixes)]
    wire_scope = {"domains": domains, "domain_suffixes": suffixes}
    relay_ip = str(ipaddress.IPv4Address(settings["relay_ipv4"]))
    dynamic_origin = "origin_dns" in settings
    if suffixes and not dynamic_origin:
        raise ValueError("suffix routing requires independent dynamic origin DNS")
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
        if set(origins) != set(desired_domains):
            raise ValueError("origins must exactly cover the reviewed host set")
        origins = {d: public_v4(origins[d]) for d in desired_domains}
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
    if "domain_suffixes" in rules or zone_exceptions or exact_exceptions or domains != desired_domains or suffixes != desired_suffixes:
        fingerprint_inputs["policy_exclusions"] = {"domains": exact_exceptions, "domain_suffixes": zone_exceptions}
        fingerprint_inputs["wire_scope"] = wire_scope
    if dynamic_origin:
        fingerprint_inputs.update(origin_mode="dynamic-ipv4", origin_dns=origin_dns,
                                  denied_v4=list(DENIED_ORIGIN_V4) + sorted(forbidden_ips))
    fingerprint = hashlib.sha256(json.dumps(fingerprint_inputs, sort_keys=True).encode()).hexdigest()
    user_rules = []
    for d in domains:
        user_rules += [f"|{d}|$dnstype=A,dnsrewrite=NOERROR;A;{relay_ip}",
                       f"|{d}|$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;"]
    for root in suffixes:
        user_rules += [f"||{root}^$dnstype=A,dnsrewrite=NOERROR;A;{relay_ip}",
                       f"||{root}^$dnstype=AAAA|HTTPS|SVCB,dnsrewrite=NOERROR;;"]
    user_rules += [f"@@|{name}|$dnsrewrite" for name in exact_exceptions]
    user_rules += [f"@@||{root}^$dnsrewrite" for root in zone_exceptions]
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
        "querylog": {"enabled": False}, "statistics": {"enabled": False},
        # Native strict-SNI warnings otherwise persist the revocable hostname ID.
        # The v0.107.80 legacy logger is separate: keep runtime canary acceptance.
        "log": {"enabled": False}, "schema_version": 34}
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
    # Repeated declarations of one native ACL are OR alternatives. Keep the
    # guard constant-sized: one reference per domain exceeds HA's word limit.
    for d in domains:
        hap += [f"  acl policy_allowed req.ssl_sni,lower -m str {d}"]
    for root in suffixes:
        hap += [f"  acl policy_allowed req.ssl_sni,lower -m str {root}",
                f"  acl policy_allowed req.ssl_sni,lower -m end .{root}"]
    for name in exact_exceptions:
        hap += [f"  acl policy_excluded req.ssl_sni,lower -m str {name}"]
    for root in zone_exceptions:
        hap += [f"  acl policy_excluded req.ssl_sni,lower -m str {root}",
                f"  acl policy_excluded req.ssl_sni,lower -m end .{root}"]
    if exact_exceptions or zone_exceptions:
        hap += ["  tcp-request content reject if { req.ssl_hello_type 1 } policy_excluded"]
    if domains or suffixes:
        if dynamic_origin:
            hap += ["  tcp-request content reject unless { req.ssl_hello_type 1 }"]
        hap += ["  tcp-request content reject if { req.ssl_hello_type 1 } !policy_allowed"]
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
    if dynamic_origin and (domains or suffixes):
        hap += ["  default_backend origin_dynamic", "backend origin_dynamic", "  server checked 0.0.0.0:0"]
    else:
        for i, d in enumerate(domains):
            hap += [f"  use_backend origin_{i} if {{ req.ssl_sni,lower -m str {d} }}"]
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
    def root_sni(root):
        escaped = root.replace(".", "\\.")
        # Compose consumes $$; the native regex must retain its final anchor.
        return f"(HostSNI(`{root}`) || HostSNIRegexp(`^([a-z0-9-]+\\.)+{escaped}$$`))"
    relay_rule = " || ".join([f"HostSNI(`{d}`)" for d in domains] + [root_sni(root) for root in suffixes])
    excluded_sni = [f"HostSNI(`{d}`)" for d in exact_exceptions] + [root_sni(root) for root in zone_exceptions]
    if excluded_sni:
        relay_rule = f"({relay_rule}) && !({' || '.join(excluded_sni)})"
    labels_relay = {"traefik.enable": "true", "traefik.tcp.routers.sd-relay.rule": relay_rule, "traefik.tcp.routers.sd-relay.entrypoints": "websecure", "traefik.tcp.routers.sd-relay.tls.passthrough": "true", "traefik.tcp.services.sd-relay.loadbalancer.server.port": "8443"}
    if not (domains or suffixes):
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
    artifacts = {"agh-conf/AdGuardHome.yaml": agh, "haproxy.cfg": "\n".join(hap) + "\n", "compose.lab.json": {"services": services, "networks": {"default": {}, "dns": {}}}, "snapshot.json": {"status": "candidate-not-applied", "sha256": fingerprint, "domains": desired_domains, "desired_services": rules.get("service_states", []), "excluded_domains": rules.get("excluded_domains", {}), "origins": origins, "images": IMAGES}}
    if "domain_suffixes" in rules or zone_exceptions or exact_exceptions or domains != desired_domains or suffixes != desired_suffixes:
        artifacts["snapshot.json"].update(domain_suffixes=desired_suffixes, wire_scope=wire_scope,
            policy_exclusions={"domains": exact_exceptions, "domain_suffixes": zone_exceptions})
    # AGH owns and rewrites its live YAML. Keep only this derived immutable
    # bootstrap identity and service projection outside that mutable directory.
    infrastructure = {key: value for key, value in agh.items() if key != "user_rules"}
    artifacts["snapshot.json"].update(service_rules=user_rules,
        agh_bootstrap_sha256=hashlib.sha256(json.dumps(infrastructure, sort_keys=True).encode()).hexdigest())
    if dynamic_origin:
        artifacts["denied-v4.txt"] = "\n".join(dict.fromkeys([*DENIED_ORIGIN_V4, *(address + "/32" for address in sorted(forbidden_ips))])) + "\n"
        services["relay"]["volumes"].append("./denied-v4.txt:/usr/local/etc/haproxy/denied-v4.txt:ro")
        artifacts["snapshot.json"].update(origin_mode="dynamic-ipv4", origin_dns=origin_dns)
    artifacts["snapshot.json"]["relay_files_sha256"] = {
        name: hashlib.sha256(artifacts[name].encode()).hexdigest()
        for name in ("haproxy.cfg", "denied-v4.txt") if name in artifacts}
    return artifacts


def catalog_rules(catalog, registry=None):
    """Composition seam: source membership + local approvals -> native policy."""
    if any("upstream" in service for service in catalog["services"]):
        import sys
        sys.path.insert(0, str(ROOT))
        from tools.catalog import project_catalog
        catalog = project_catalog(catalog, registry, hostname)
    return approved_rules(catalog)


def compile_production(rules, settings, origins=None):
    """Adapt native policy artifacts to the separately approved two-service pilot.

    The existing edge and its logging/network configuration stay operator-owned;
    this representation never creates, mounts the daemon socket into, or runs it.
    """
    if settings.get("dot") is None:
        raise ValueError("production pilot requires native DoT certificate settings")
    artifacts = compile_config(rules, settings, origins)
    compose = artifacts.pop("compose.lab.json")
    compose["services"] = {name: service for name, service in compose["services"].items() if name in ("dns", "relay")}
    compose["networks"] = {"dns": {"name": "smart-dns_dns"}, "edge": {"external": True, "name": "edge"}}
    dns, relay = compose["services"]["dns"], compose["services"]["relay"]
    dns.update(user="65532:65532", ports=["127.0.0.1:13000:3000"],
               tmpfs=["/opt/adguardhome/work:uid=65532,gid=65532,mode=0700"])
    relay.update(networks=["edge", "dns"], ports=["0.0.0.0:853:8853"])
    for service in (dns, relay):
        service["restart"] = "unless-stopped"
        service["labels"].pop("smart-dns.lab")
    dns["labels"].update({"traefik.docker.network": "smart-dns_dns",
                           "traefik.http.routers.sd-doh.tls.certresolver": "le"})
    relay["labels"]["traefik.docker.network"] = "edge"
    artifacts["compose.production.json"] = compose
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
            with path.open("w", encoding="utf-8", newline="\n") as stream:
                stream.write(data if isinstance(data, str) else json.dumps(data, indent=2) + "\n")
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
    parser.add_argument("--production", action="store_true", help="Prepare the approved two-service representation; never deploy")
    parser.add_argument("--registry", type=Path, default=ROOT / "rules/registry.json")
    args = parser.parse_args()
    catalog, settings = (json.loads(p.read_text(encoding="utf-8")) for p in (args.rules, args.settings))
    origins = json.loads(args.origins.read_text(encoding="utf-8")) if args.origins is not None else None
    compiler = compile_production if args.production else compile_config
    registry = json.loads(args.registry.read_text(encoding="utf-8")) if args.registry.exists() else None
    artifacts = compiler(catalog_rules(catalog, registry), settings, origins)
    write_new(artifacts, args.out)
    print("Rendered", len(artifacts), "artifacts; no services started")


if __name__ == "__main__":
    main()
