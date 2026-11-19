"""Validate and operate the same-origin deployment without printing resolved credentials."""

import argparse
import json
import shutil
import subprocess
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
DOCKER = shutil.which("docker")


def command(env_file, project, mode="production"):
    if not DOCKER:
        raise RuntimeError("Docker Compose is required")
    args = [
        DOCKER,
        "compose",
        "--env-file",
        str(env_file),
        "-p",
        project,
        "-f",
        "compose.yaml",
        "-f",
        "compose.production.yaml",
    ]
    if mode == "local-test":
        args += ["-f", "compose.production-test.yaml"]
    if mode == "tunnel":
        args += ["-f", "compose.tunnel.yaml"]
    return args


def validate(config, mode="production"):
    services = config["services"]
    admin = services["admin-api"]
    env = admin["environment"]
    if (
        env["SENTINEL_ENVIRONMENT"] != "production"
        or env["SENTINEL_ADMIN_DEPLOYMENT"] != "production"
    ):
        raise ValueError("Production authentication must be enabled")
    if str(env["SENTINEL_ADMIN_COOKIE_SECURE"]).lower() != "true":
        raise ValueError("Secure cookies are required")
    origins = json.loads(env["SENTINEL_ADMIN_ALLOWED_ORIGINS"])
    if len(origins) != 1 or not origins[0].startswith("https://") or ".invalid" in origins[0]:
        raise ValueError("One exact HTTPS origin is required")
    parsed = urlsplit(origins[0])
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("Origin must contain only scheme, DNS host and optional HTTPS port")
    if mode == "local-test":
        if origins != ["https://localhost:8443"]:
            raise ValueError("Local acceptance requires the fixed loopback HTTPS origin")
    elif parsed.hostname == "localhost" or parsed.port not in (None, 443):
        raise ValueError("Public deployment requires a DNS origin on HTTPS port 443")
    if env["SENTINEL_TRUSTED_PROXY_CIDRS"] != '["172.30.90.2/32"]':
        raise ValueError("Trust only the fixed ingress address")
    if str(services["demo-api"]["environment"]["SENTINEL_DEMO_AUTH_ENABLED"]).lower() != "false":
        raise ValueError("The development-only login cannot run in production")
    for name in (
        "admin-api",
        "demo-api",
        "event-worker",
        "postgres",
        "redis",
        "rabbitmq",
        "prometheus",
    ):
        if services[name].get("ports"):
            raise ValueError("Private service unexpectedly publishes a port: " + name)
    for port in services["grafana"].get("ports", []):
        if port.get("host_ip") != "127.0.0.1":
            raise ValueError("Grafana must be loopback-only")
    ingress = services["ingress"]
    if (
        ingress.get("user") != "10001:10001"
        or not ingress.get("read_only")
        or ingress.get("privileged")
    ):
        raise ValueError("Ingress requires the configured non-root read-only sandbox")
    ports = ingress.get("ports", [])
    expected = (
        {"80", "443"}
        if mode == "production"
        else ({"8080", "8443"} if mode == "local-test" else {"8080"})
    )
    if {str(p["published"]) for p in ports} != expected:
        raise ValueError("Unexpected ingress ports")
    if mode != "production" and any(p.get("host_ip") != "127.0.0.1" for p in ports):
        raise ValueError("Local test/tunnel origin must be loopback-only")
    if not config["networks"]["edge"].get("internal"):
        raise ValueError("Proxy/backend edge must be internal")
    for secret in config["secrets"].values():
        path = Path(secret["file"])
        if not path.is_file() or not path.read_text().strip():
            raise ValueError("A required secret file is absent/empty")
    return {
        "origin": origins[0],
        "published_ingress_ports": sorted(expected),
        "private_services": 7,
        "non_root_ingress": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["validate", "build", "up", "stop", "status"])
    parser.add_argument("--env-file", type=Path, default=ROOT / ".env.production")
    parser.add_argument("--project", default="sentinel-production")
    parser.add_argument(
        "--mode", choices=["production", "local-test", "tunnel"], default="production"
    )
    args = parser.parse_args()
    base = command(args.env_file, args.project, args.mode)
    result = subprocess.run(
        [*base, "config", "--format", "json"], cwd=ROOT, capture_output=True, text=True, check=True
    )
    report = validate(json.loads(result.stdout), args.mode)
    print(json.dumps(report))
    if args.action == "validate":
        return
    operations = {
        "build": ["build"],
        "up": ["up", "--build", "-d", "--wait", "--wait-timeout", "240"],
        "stop": ["stop"],
        "status": ["ps"],
    }
    subprocess.run([*base, *operations[args.action]], cwd=ROOT, check=True)


if __name__ == "__main__":
    main()
