"""Pure, deterministic detections. No commands, sockets, or host interaction."""
from datetime import datetime

RULES = [
    dict(id="AUTH-001", name="Repeated password guessing", severity="high", technique="T1110.001", tactic="Credential Access", description="5 failed logins for the same user and source IP within 5 minutes.", threshold="≥ 5 failures / 5 min", false_positive="A stale saved password or a misconfigured service.", steps=["Verify the user's recent sign-in activity.", "Check for a successful login after the failures.", "If unauthorized, revoke sessions and reset credentials through approved tooling."]),
    dict(id="EXEC-002", name="Encoded PowerShell execution", severity="high", technique="T1059.001", tactic="Execution", description="PowerShell or pwsh launched with an encoded-command flag.", threshold="Encoded command flag", false_positive="An approved administration or deployment script.", steps=["Review the process parent and owner.", "Obtain the full script from approved endpoint telemetry.", "Validate against change records before considering containment."]),
    dict(id="EXFIL-003", name="Large cloud storage upload", severity="critical", technique="T1567.002", tactic="Exfiltration", description="At least 100 MiB uploaded to a cloud-storage destination in one event.", threshold="≥ 100 MiB upload", false_positive="An approved backup or large file collaboration.", steps=["Validate the destination and business justification.", "Determine which files and data classifications were involved.", "Escalate confirmed unauthorized transfer to the incident lead."]),
]

def detect(events):
    findings = []
    groups = {}
    for event in sorted(events, key=lambda e: e["timestamp"]):
        kind, data = event["kind"], event["data"]
        if kind == "auth" and data.get("outcome") == "failure":
            key = (event["host"], event["user"], data.get("source_ip"))
            groups.setdefault(key, []).append(event)
        if kind == "process" and data.get("process", "").lower() in ("powershell.exe", "powershell", "pwsh", "pwsh.exe"):
            flags = data.get("command_line", "").lower().split()
            if any(flag in flags for flag in ("-enc", "-encodedcommand", "-encodedcommand:")):
                findings.append((RULES[1], [event]))
        if kind == "network" and data.get("destination_category") == "cloud_storage" and data.get("bytes_sent", 0) >= 100 * 1024 * 1024:
            findings.append((RULES[2], [event]))
    for group in groups.values():
        for end in range(4, len(group)):
            window = [e for e in group[:end+1] if (datetime.fromisoformat(group[end]["timestamp"]) - datetime.fromisoformat(e["timestamp"])).total_seconds() <= 300]
            if len(window) >= 5:
                findings.append((RULES[0], window))
                break
    return findings
