import json

def emit_json(event):
    print(json.dumps(event, indent=2))