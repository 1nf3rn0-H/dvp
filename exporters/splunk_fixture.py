import json

def emit_splunk_fixture(event):
    fixture = {
        "rule_test": {
            "expected_detection": True,
            "event": event
        }
    }

    print("\n--- SPLUNK TEST FIXTURE ---")
    print(json.dumps(fixture, indent=2))