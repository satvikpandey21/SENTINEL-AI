"""Export the exact frontend OpenAPI contract without connecting to services."""

import argparse
import json
import secrets
from pathlib import Path

from sentinel_api.main import create_app
from sentinel_api.settings import AdminSettings
from sentinel_security.config import Settings
from sentinel_security.realtime import SecurityNotification


def contract():
    app = create_app(
        Settings(
            environment="test",
            database_url="postgresql+asyncpg://contract@localhost/contract",
            redis_url="redis://localhost/0",
            rabbitmq_url="amqp://localhost/",
            dynamic_policies=False,
        ),
        AdminSettings(signing_key=secrets.token_hex(32)),
    )
    return json.dumps(app.openapi(), indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("docs/admin-openapi.json"))
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    body = contract()
    schema_path = args.output.with_name("security-notification-v1.schema.json")
    schema = json.dumps(SecurityNotification.model_json_schema(), indent=2, sort_keys=True) + "\n"
    if args.check:
        if schema_path.read_text(encoding="utf-8") != schema:
            raise SystemExit("Notification schema drift: regenerate contracts")
        if args.output.read_text(encoding="utf-8") != body:
            raise SystemExit("OpenAPI contract drift: regenerate docs/admin-openapi.json")
        print("OpenAPI contract matches the implementation.")
    else:
        args.output.write_text(body, encoding="utf-8")
        schema_path.write_text(schema, encoding="utf-8")
        print("Exported administrative HTTP and notification contracts.")


if __name__ == "__main__":
    main()
