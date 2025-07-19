import os
import json

def append_json_log(filepath, entry):
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    try:
        with open(filepath, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as e:
        print(f"[Utils] Failed to write to {filepath}: {e}")
