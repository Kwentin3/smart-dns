"""Deploy an existing Certbot lineage to AGH's watched TLS files; no issuance.

The mounted directory stays in place. Each file replacement is atomic, the pair
is not crash-atomic. No restart, AGH API write, DNS update or private-key output.
"""
import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import ssl
import stat
import subprocess
import tempfile
import time


class DeployError(ValueError):
    def __init__(self, message, rollback_verified=None):
        super().__init__(message)
        self.rollback_verified = rollback_verified


def openssl(*arguments, data=None):
    try:
        result = subprocess.run(["openssl", *map(str, arguments)], input=data,
                                capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        raise DeployError("OpenSSL unavailable or timed out") from None
    if result.returncode:
        raise DeployError("certificate validation failed")
    return result.stdout


def fingerprint(certificate):
    pem = certificate.decode("ascii")
    leaf = pem[:pem.index("-----END CERTIFICATE-----") + len("-----END CERTIFICATE-----")]
    return hashlib.sha256(ssl.PEM_cert_to_DER_cert(leaf)).hexdigest()


def validate(chain, key, hostname, days, ca=None):
    sans = openssl("x509", "-in", chain, "-noout", "-ext", "subjectAltName").decode("ascii")
    names = re.findall(r"DNS:([^,\s]+)", sans)
    if set(names) != {hostname, "*." + hostname}:
        raise DeployError("certificate must contain only the base and wildcard DNS names")
    openssl("x509", "-in", chain, "-noout", "-checkend", str(days * 86400))
    cert_public = openssl("x509", "-in", chain, "-pubkey", "-noout")
    key_public = openssl("pkey", "-in", key, "-pubout")
    if cert_public != key_public:
        raise DeployError("certificate and private key do not match")
    # The leaf is checked against system roots (or an explicitly supplied lab
    # root), with intermediates supplied by the existing fullchain.
    arguments = ["verify", "-purpose", "sslserver", "-verify_hostname", hostname]
    if ca is not None:
        arguments += ["-CAfile", str(ca)]
    openssl(*arguments, "-untrusted", chain, chain)


def served_fingerprint(hostname, connect_host, port, timeout, ca=None):
    context = ssl.create_default_context(cafile=str(ca) if ca is not None else None)
    with socket.create_connection((connect_host, port), timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=hostname) as tls:
            return hashlib.sha256(tls.getpeercert(binary_form=True)).hexdigest()


def wait_served(expected, hostname, connect_host, port, timeout, ca=None):
    deadline = time.monotonic() + timeout
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeployError("verified TLS fingerprint readback timed out")
        try:
            actual = served_fingerprint(hostname, connect_host, port, min(3, remaining), ca)
            if actual == expected:
                return
        except (OSError, ssl.SSLError):
            pass
        time.sleep(min(.2, max(0, deadline - time.monotonic())))


def replace_file(path, data, metadata):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".tls-", delete=False) as stream:
            temporary = Path(stream.name)
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            if hasattr(os, "fchown"):
                os.fchown(stream.fileno(), metadata.st_uid, metadata.st_gid)
            os.chmod(temporary, stat.S_IMODE(metadata.st_mode))
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


@contextmanager
def exclusive(directory):
    lock = directory / ".certificate-deploy.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        try:
            if os.name == "nt":
                import msvcrt
                if os.fstat(descriptor).st_size == 0:
                    os.write(descriptor, b"\0")
                os.lseek(descriptor, 0, os.SEEK_SET)
                msvcrt.locking(descriptor, msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise DeployError("certificate deployment already running") from None
        yield
    finally:
        # Kernel-owned lock releases on process death. Keep the inode stable:
        # unlinking a lock file permits different processes to lock two inodes.
        os.close(descriptor)


def deploy(lineage, destination, hostname, connect_host, *, port=853,
           cert_name="fullchain.pem", key_name="privkey.pem", min_valid_days=7,
           timeout=20, lab_ca=None):
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname) or "." not in hostname:
        raise DeployError("lowercase DNS base hostname required")
    if not 1 <= port <= 65535 or not 1 <= timeout <= 60 or not 1 <= min_valid_days <= 365:
        raise DeployError("invalid bounded deployment settings")
    if cert_name == key_name or any(Path(name).name != name or name in ("", ".", "..") for name in (cert_name, key_name)):
        raise DeployError("distinct certificate and key filenames required")
    destination, lineage = Path(destination).resolve(), Path(lineage).resolve()
    if not destination.is_dir():
        raise DeployError("existing mounted TLS directory required")
    cert, key = destination / cert_name, destination / key_name
    with exclusive(destination):
        if any(not path.is_file() or path.is_symlink() for path in (cert, key)):
            raise DeployError("existing regular destination certificate and key required")
        old_cert, old_key = cert.read_bytes(), key.read_bytes()
        metadata = {path: path.stat() for path in (cert, key)}
        old_fingerprint = fingerprint(old_cert)
        # Capture issuer files once. Validation and deployment use these exact
        # bytes even if Certbot later changes its live symlink targets.
        new_cert = (lineage / "fullchain.pem").read_bytes()
        new_key = (lineage / "privkey.pem").read_bytes()
        with tempfile.TemporaryDirectory(prefix=".tls-validate-", dir=destination) as staging:
            staged_cert, staged_key = Path(staging) / "chain.pem", Path(staging) / "key.pem"
            staged_cert.write_bytes(new_cert)
            staged_key.write_bytes(new_key)
            staged_key.chmod(0o600)
            validate(staged_cert, staged_key, hostname, min_valid_days, lab_ca)
        new_fingerprint = fingerprint(new_cert)
        wait_served(old_fingerprint, hostname, connect_host, port, timeout, lab_ca)
        if old_cert == new_cert and old_key == new_key:
            return {"status": "unchanged", "fingerprint_sha256": old_fingerprint}
        try:
            # Key first, certificate last: AGH also gates reload on cert mtime.
            replace_file(key, new_key, metadata[key])
            replace_file(cert, new_cert, metadata[cert])
            wait_served(new_fingerprint, hostname, connect_host, port, timeout, lab_ca)
        except BaseException:
            try:
                replace_file(key, old_key, metadata[key])
                replace_file(cert, old_cert, metadata[cert])
                wait_served(old_fingerprint, hostname, connect_host, port, timeout, lab_ca)
            except BaseException:
                raise DeployError("deployment failed; rollback NOT verified", False) from None
            raise DeployError("deployment failed; previous certificate restored and verified", True) from None
        return {"status": "deployed", "fingerprint_sha256": new_fingerprint}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lineage", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--connect-host", required=True)
    parser.add_argument("--port", type=int, default=853)
    parser.add_argument("--cert-name", default="fullchain.pem")
    parser.add_argument("--key-name", default="privkey.pem")
    parser.add_argument("--min-valid-days", type=int, default=7)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--lab-ca", type=Path, help="Explicit lab trust root; still verifies hostname")
    args = parser.parse_args()
    try:
        result = deploy(args.lineage, args.destination, args.hostname, args.connect_host,
                        port=args.port, cert_name=args.cert_name, key_name=args.key_name,
                        min_valid_days=args.min_valid_days, timeout=args.timeout, lab_ca=args.lab_ca)
    except DeployError as error:
        print(json.dumps({"status": "failed", "reason": str(error), "rollback_verified": error.rollback_verified}))
        raise SystemExit(1)
    except (OSError, ValueError):
        print(json.dumps({"status": "failed", "reason": "certificate input or filesystem operation failed"}))
        raise SystemExit(1)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
