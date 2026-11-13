"""Redis-only managed policy reads; enforcement never queries PostgreSQL."""

import json

from sentinel_security.policies import EndpointPolicy, validate_policies

POLICY_KEY = "sentinel:effective-policies:v1"


class PolicyUnavailable(Exception):
    pass


def snapshot(version, policies):
    return json.dumps({"version": version, "policies": policies}, sort_keys=True)


async def load_effective(redis):
    raw = await redis.get(POLICY_KEY)
    if raw is None:
        raise PolicyUnavailable
    try:
        document = json.loads(raw)
        if "updating" in document or document["version"] < 1:
            raise PolicyUnavailable
        return validate_policies(
            tuple(EndpointPolicy.model_validate(p) for p in document["policies"])
        )
    except (ValueError, KeyError, TypeError) as error:
        raise PolicyUnavailable from error
