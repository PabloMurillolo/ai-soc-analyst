"""Fixtures only: never run payloads or contact the named destinations."""
from datetime import datetime, timedelta, timezone
from uuid import uuid4

SCENARIOS = {
    "password-guessing": {"name": "Password guessing", "description": "Six failed sign-ins from one synthetic source.", "technique": "T1110.001"},
    "encoded-powershell": {"name": "Encoded PowerShell", "description": "One inert process-creation record with an encoded flag.", "technique": "T1059.001"},
    "cloud-exfiltration": {"name": "Cloud exfiltration", "description": "A synthetic 240 MiB upload to reserved example storage.", "technique": "T1567.002"},
    "benign-activity": {"name": "Benign baseline", "description": "Normal sign-in and small transfer; no alert expected.", "technique": None},
}

def generate(scenario):
    now = datetime.now(timezone.utc)
    def event(kind, host, user, data, offset=0):
        return dict(id=str(uuid4()), timestamp=(now-timedelta(seconds=offset)).isoformat(), kind=kind, host=host, user=user, data=data, synthetic=True)
    if scenario == "password-guessing":
        return [event("auth", "identity-gateway", "alex.morgan", {"source_ip":"192.0.2.42", "outcome":"failure", "service":"SSO"}, (5-i)*30) for i in range(6)]
    if scenario == "encoded-powershell":
        return [event("process", "workstation-024", "sam.rivera", {"process":"powershell.exe", "parent":"winword.exe", "command_line":"powershell.exe -enc SYNTHETIC_NON_EXECUTABLE"})]
    if scenario == "cloud-exfiltration":
        return [event("network", "finance-laptop-07", "jordan.lee", {"destination":"storage.example", "destination_category":"cloud_storage", "bytes_sent":251658240})]
    if scenario == "benign-activity":
        return [event("auth", "workstation-012", "taylor.chen", {"source_ip":"198.51.100.10", "outcome":"success"}), event("network", "workstation-012", "taylor.chen", {"destination":"storage.example", "destination_category":"cloud_storage", "bytes_sent":1024})]
    raise ValueError("Unknown scenario")
