#!/usr/bin/env python3
"""Builds a small BUNDLED SAMPLE Sigma pack. This is NOT the complete Sigma repository —
it is a representative sample for offline demonstration and import-format testing.
Analysts can import the full Sigma repository via Framework Database / rule import."""
import json, os, datetime
HERE = os.path.dirname(os.path.abspath(__file__))
rules = [
 {"id":"a1b2c3d4-0001-4000-8000-000000000001","title":"Kerberoasting - Many TGS Requests","techniques":["T1558.003"],"level":"high","logsource":{"product":"windows","service":"security"},"detection":"selection:\n  EventID: 4769\n  TicketEncryptionType: '0x17'\ncondition: selection | count() by TargetUserName > 10"},
 {"id":"a1b2c3d4-0002-4000-8000-000000000002","title":"LSASS Access via Suspicious Process","techniques":["T1003.001"],"level":"critical","logsource":{"product":"windows","category":"process_access"},"detection":"selection:\n  TargetImage|endswith: '\\\\lsass.exe'\ncondition: selection"},
 {"id":"a1b2c3d4-0003-4000-8000-000000000003","title":"PowerShell Encoded Command","techniques":["T1059.001"],"level":"high","logsource":{"product":"windows","service":"powershell"},"detection":"selection:\n  CommandLine|contains: '-enc'\ncondition: selection"},
 {"id":"a1b2c3d4-0004-4000-8000-000000000004","title":"Scheduled Task Created","techniques":["T1053.005"],"level":"medium","logsource":{"product":"windows","service":"security"},"detection":"selection:\n  EventID: 4698\ncondition: selection"},
 {"id":"a1b2c3d4-0005-4000-8000-000000000005","title":"Windows Event Log Cleared","techniques":["T1070.001"],"level":"high","logsource":{"product":"windows","service":"security"},"detection":"selection:\n  EventID:\n    - 1102\n    - 104\ncondition: selection"},
 {"id":"a1b2c3d4-0006-4000-8000-000000000006","title":"Password Spraying - Many Failed Logons","techniques":["T1110.003"],"level":"high","logsource":{"product":"windows","service":"security"},"detection":"selection:\n  EventID: 4625\ncondition: selection | count() by IpAddress > 15"},
 {"id":"a1b2c3d4-0007-4000-8000-000000000007","title":"Shadow Copy Deletion","techniques":["T1490"],"level":"critical","logsource":{"product":"windows","category":"process_creation"},"detection":"selection:\n  CommandLine|contains:\n    - 'delete shadows'\n    - 'recoveryenabled no'\ncondition: selection"},
 {"id":"a1b2c3d4-0008-4000-8000-000000000008","title":"New Service Installed","techniques":["T1543.003"],"level":"medium","logsource":{"product":"windows","service":"system"},"detection":"selection:\n  EventID: 7045\ncondition: selection"},
 {"id":"a1b2c3d4-0009-4000-8000-000000000009","title":"DNS Query to Long Label (possible tunneling)","techniques":["T1071.004"],"level":"medium","logsource":{"product":"windows","category":"dns_query"},"detection":"selection:\n  EventID: 22\ncondition: selection"},
 {"id":"a1b2c3d4-0010-4000-8000-000000000010","title":"Security Service Stopped","techniques":["T1562.001"],"level":"high","logsource":{"product":"windows","service":"system"},"detection":"selection:\n  EventID: 7036\ncondition: selection"},
 {"id":"a1b2c3d4-0011-4000-8000-000000000011","title":"AS-REP Roasting - No PreAuth TGT","techniques":["T1558.004"],"level":"high","logsource":{"product":"windows","service":"security"},"detection":"selection:\n  EventID: 4768\n  PreAuthType: '0'\ncondition: selection"},
 {"id":"a1b2c3d4-0012-4000-8000-000000000012","title":"Web Shell File Written to Web Root","techniques":["T1505.003"],"level":"high","logsource":{"product":"windows","category":"file_event"},"detection":"selection:\n  TargetFilename|contains: '\\\\wwwroot\\\\'\n  TargetFilename|endswith: '.aspx'\ncondition: selection"},
]
out={"framework":"Sigma (bundled sample pack)","dataset_kind":"bundled-sample","version":"sample-1.0","note":"Representative sample only; not the complete Sigma repository. Import the full repository separately.","generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),"rules":rules}
with open(os.path.join(HERE,"sigma-sample-pack.json"),"w") as f: json.dump(out,f,indent=1)
print("sigma sample rules:",len(rules))
