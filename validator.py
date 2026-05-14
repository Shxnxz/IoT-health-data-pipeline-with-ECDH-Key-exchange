# validator.py
import json
import jsonschema

with open("schema.json") as f:
    SCHEMA = json.load(f)

def validate_payload(payload: dict) -> bool:
    """Returns True if valid, raises jsonschema.ValidationError if not."""
    jsonschema.validate(instance=payload, schema=SCHEMA)

    # Extra rule the schema can't express: sleep stages must sum to 100
    stages = payload["sleep"]["stages_pct"]
    total = sum(stages.values())
    if total != 100:
        raise ValueError(f"Sleep stages sum to {total}, expected 100")

    return True