import json
import pathlib

import pytest
from jsonschema import Draft202012Validator, ValidationError

ROOT = pathlib.Path(__file__).resolve().parents[2]
S = ROOT / "schemas"

def load(n): return json.loads((S / f"{n}.schema.json").read_text())

@pytest.mark.parametrize("name", ["action", "observation", "decision"])
def test_schema_is_valid(name):
    Draft202012Validator.check_schema(load(name))

BASE = {
    "schema_version": "0.1", "agent_id": "ops-agent-1", "action": "UNLOCK_DOOR",
    "target": {"resource": "door", "id": "door-3"}, "parameters": {"duration_s": 10},
    "timestamp": "2026-10-07T09:12:44Z",
    "context": {"on_behalf_of": {"principal_id": "svc", "channel": "autonomous"}, "justification": "x",
                "inputs": [{"ref": "obs-1", "origin": "sensor_ocr"}]},
}

def test_valid_action_accepted():
    Draft202012Validator(load("action")).validate(BASE)

@pytest.mark.parametrize("mutate", [
    lambda a: a.update(extra="x"),                                   # unknown top-level field
    lambda a: a["target"].update(extra="x"),                          # unknown nested field
    lambda a: a.update(action="unlock_door"),                         # bad verb casing
    lambda a: a["context"]["inputs"][0].update(origin="trusted_magic"),  # unknown origin
    lambda a: a["context"]["on_behalf_of"].update(channel="telepathy"),
    lambda a: a.pop("context"),
    lambda a: a.update(schema_version="9.9"),
])
def test_invalid_actions_rejected(mutate):
    a = json.loads(json.dumps(BASE))
    mutate(a)
    with pytest.raises(ValidationError):
        Draft202012Validator(load("action")).validate(a)
