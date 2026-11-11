/* SENTINEL MATRIX — rule import adapters and normalisation engine. */
(function (SM) {
  'use strict';
  const IMP = {};
  const PLATFORMS = ['qradar', 'splunk', 'elastic', 'sentinel', 'sigma', 'generic'];
  IMP.PLATFORMS = PLATFORMS;

  // ------- Normalised rule factory -------
  IMP.blank = () => ({
    rule_id: '', rule_name: '', description: '', source_platform: 'generic', source_instance: 'default', source_format: 'json', rule_type: 'detection',
    enabled_status: 'unknown', severity: 'unknown', risk_score: null, detection_logic: '', conditions: [], event_fields: [], event_ids: [], log_sources: [], log_source_types: [],
    time_window: null, threshold: null, grouping_fields: [], suppression_conditions: [], entity_context: [],
    attack_tactics: [], attack_techniques: [], attack_subtechniques: [], mapping_source: 'none', inferred_techniques: [], d3fend_mapping: [], capec_mapping: [],
    false_positive_notes: '', deployment_status: 'unknown', validation_status: 'not_validated', last_triggered: null, last_modified: null, owner: '', version: '', dependencies: [],
    original_rule_content: null, fingerprint: '', import_batch: '', imported_at: '', lifecycle_stage: 'Deployed', tags: [], quality_flags: [], trigger_count: null, alert_count_30d: null
  });

  // ------- Field heuristics shared across adapters -------
  const pick = (o, keys) => { for (const k of keys) { if (o && o[k] !== undefined && o[k] !== null && o[k] !== '') return o[k]; } return undefined; };
  const deepPick = (o, path) => path.split('.').reduce((a, k) => (a && a[k] !== undefined) ? a[k] : undefined, o);
  const EVENT_ID_RE = /\b(?:EventID|EventCode|event_id|eventid|Event ID|EventIdentifier)\s*(?:=|==|:|IN|in)\s*\(?\s*["']?(\d{1,5})(?:["']?\s*,\s*["']?(\d{1,5}))*/gi;
  const EID_LIST_RE = /\b(?:EventID|EventCode|event_id|eventid|EventIdentifier)\b[^\n;|]{0,120}/gi;
  IMP.extractEventIds = (logic) => {
    const out = new Set(); const s = SM.str(logic);
    for (const m of s.matchAll(EID_LIST_RE)) { for (const n of m[0].matchAll(/\b(\d{1,5})\b/g)) { const v = parseInt(n[1], 10); if (v > 0 && v < 70000) out.add(v); } }
    return Array.from(out).slice(0, 40);
  };
  const LOG_HINTS = [[/sysmon|microsoft-windows-sysmon/i, 'sysmon'], [/powershell/i, 'powershell'], [/securityevent|security\.evtx|winlog|wineventlog:security|windows security|eventlog/i, 'windows_security'], [/auditd|linux|syslog/i, 'linux_auditd'], [/dns/i, 'dns'], [/proxy|squid|zscaler|bluecoat|websense/i, 'proxy'], [/firewall|palo|fortigate|checkpoint|asa\b|ftd/i, 'firewall'], [/vpn|anyconnect|globalprotect/i, 'vpn'], [/edr|crowdstrike|defender|sentinelone|carbon/i, 'edr'], [/cloudtrail|azureactivity|aws|gcp|azure/i, 'cloud_audit'], [/signinlogs|aadsignin|okta|entra|ise\b|adfs|identity/i, 'identity'], [/netflow|ipfix|flow/i, 'netflow'], [/ids|ips|snort|suricata/i, 'ids_ips'], [/email|exchange|proofpoint|mimecast|office|o365/i, 'email_security'], [/kube|k8s|container|docker/i, 'kubernetes_audit'], [/iis|apache|nginx|web|http/i, 'web_server'], [/sql|database|oracle/i, 'database'], [/cisco|ios|nxos|aci/i, 'network_device'], [/active.?directory|domain controller|ldap|kerberos|ntds/i, 'active_directory']];
  IMP.inferLogSourceTypes = (texts) => { const s = texts.join(' '); return SM.uniq(LOG_HINTS.filter(([re]) => re.test(s)).map(([, t]) => t)).slice(0, 6); };
  IMP.extractFields = (logic) => SM.uniq((SM.str(logic).match(/\b[A-Za-z_][A-Za-z0-9_.]{2,40}\s*(?:=|==|!=|:|<|>|=~|contains|startswith|endswith|in\b|has\b)/g) || []).map(x => x.replace(/\s*(=|==|!=|:|<|>|=~|contains|startswith|endswith|in\b|has\b)$/, '').trim()).filter(f => !/^(and|or|not|where|by|as|table|project|summarize|count|sort|stats|search|index|sourcetype|rule|select|from|if|then|else|let|join|on|in|has|contains|startswith|endswith|eval|case|timeframe|condition|selection|filter)$/i.test(f))).slice(0, 30);
  IMP.extractTimeWindow = (s) => { const m = SM.str(s).match(/\b(\d+)\s*(s|sec|secs|seconds?|m|min|mins|minutes?|h|hr|hrs|hours?|d|days?)\b/i); if (!m) return null; const n = parseInt(m[1], 10); const u = m[2].toLowerCase()[0]; return { value: n, unit: { s: 'seconds', m: 'minutes', h: 'hours', d: 'days' }[u], text: m[0] }; };
  IMP.extractThreshold = (s) => { const m = SM.str(s).match(/\b(?:count|cnt|total|events?|occurrences)\b[^\n]{0,25}?(>=|>|at least|more than|exceeds)\s*(\d+)/i) || SM.str(s).match(/\bthreshold\D{0,10}(\d+)/i); if (!m) return null; return { operator: m[2] ? (m[1] === '>' || /more|exceed/i.test(m[1]) ? '>' : '>=') : '>=', value: parseInt(m[2] || m[1], 10) }; };
  IMP.extractGrouping = (s) => { const m = SM.str(s).match(/\b(?:by|group by|GROUP BY|partition by)\s+([A-Za-z0-9_.,\s]+?)(?:\s*(?:\||$|\n|where|having|limit))/i); return m ? SM.uniq(m[1].split(',').map(x => x.trim()).filter(Boolean)).slice(0, 6) : []; };
  IMP.extractEntities = (fields) => { const E = []; const f = fields.join(' ').toLowerCase(); if (/user|account|subject|target.?user|src_user|dest_user/.test(f)) E.push('user'); if (/host|computer|device|machine|endpoint/.test(f)) E.push('host'); if (/ip|src|dst|dest|address/.test(f)) E.push('ip'); if (/process|image|command/.test(f)) E.push('process'); if (/file|path|hash/.test(f)) E.push('file'); if (/domain|url|dns|query/.test(f)) E.push('domain'); return E; };

  const normaliseTactic = (s) => { s = SM.str(s).toLowerCase().replace(/[^a-z]/g, ''); const map = { reconnaissance: 'TA0043', resourcedevelopment: 'TA0042', initialaccess: 'TA0001', execution: 'TA0002', persistence: 'TA0003', privilegeescalation: 'TA0004', defenseevasion: 'TA0005', defenceevasion: 'TA0005', credentialaccess: 'TA0006', discovery: 'TA0007', lateralmovement: 'TA0008', collection: 'TA0009', commandandcontrol: 'TA0011', exfiltration: 'TA0010', impact: 'TA0040' }; if (/^ta\d{4}$/.test(s)) return s.toUpperCase(); return map[s] || null; };
  IMP.normaliseTactic = normaliseTactic;

  // Attach explicit + inferred ATT&CK mappings. Inference only from name/tags/description via strict T-ID regex,
  // plus a small keyword knowledge base that is ALWAYS marked inferred.
  const KEYWORD_KB = [[/kerberoast/i, 'T1558.003'], [/as-?rep\s*roast/i, 'T1558.004'], [/golden\s*ticket/i, 'T1558.001'], [/silver\s*ticket/i, 'T1558.002'], [/dcsync/i, 'T1003.006'], [/dcshadow/i, 'T1207'], [/lsass/i, 'T1003.001'], [/mimikatz/i, 'T1003.001'], [/ntds\.?dit/i, 'T1003.003'], [/pass.?the.?hash|\bpth\b/i, 'T1550.002'], [/pass.?the.?ticket|\bptt\b/i, 'T1550.003'], [/password\s*spray/i, 'T1110.003'], [/brute.?force/i, 'T1110'], [/psexec|service\s+execution/i, 'T1569.002'], [/\bwmi\b|wmic/i, 'T1047'], [/powershell/i, 'T1059.001'], [/scheduled\s*task|schtasks/i, 'T1053.005'], [/\bcron\b/i, 'T1053.003'], [/new service|service (creation|installed)|7045/i, 'T1543.003'], [/run\s*key|startup\s*folder/i, 'T1547.001'], [/rundll32/i, 'T1218.011'], [/regsvr32/i, 'T1218.010'], [/mshta/i, 'T1218.005'], [/certutil/i, 'T1140'], [/msbuild/i, 'T1127.001'], [/uac\s*bypass/i, 'T1548.002'], [/process\s*injection|createremotethread/i, 'T1055'], [/process\s*hollow/i, 'T1055.012'], [/event\s*log\s*clear|1102|wevtutil/i, 'T1070.001'], [/shadow\s*cop|vssadmin|wbadmin|bcdedit/i, 'T1490'], [/ransom|encrypt(ed|ion) for impact/i, 'T1486'], [/web\s*shell/i, 'T1505.003'], [/\brdp\b|remote desktop|3389/i, 'T1021.001'], [/admin\s*share|\badmin\$|c\$|smb\b/i, 'T1021.002'], [/winrm|wsman|5985/i, 'T1021.006'], [/\bssh\b/i, 'T1021.004'], [/phish/i, 'T1566'], [/macro|vba/i, 'T1059.005'], [/\bdns\s*(tunnel|c2|beacon)/i, 'T1071.004'], [/\bdga\b|domain generation/i, 'T1568.002'], [/beacon|c2|command.?and.?control/i, 'T1071.001'], [/exfil/i, 'T1041'], [/cloud storage|s3|blob/i, 'T1567.002'], [/account\s*(creat|added)|4720/i, 'T1136'], [/group\s*member|4728|4732|4756/i, 'T1098'], [/port\s*scan|nmap|masscan/i, 'T1046'], [/net\s+group|net\s+user|domain admins enumer/i, 'T1087.002'], [/bloodhound|sharphound|ldap recon/i, 'T1087.002'], [/defender\s*(disabled|tamper)|amsi\s*bypass|security tool/i, 'T1562.001'], [/audit\s*policy|auditpol/i, 'T1562.002'], [/firewall\s*(rule|disabled|modif)/i, 'T1562.004'], [/llmnr|nbt-?ns|responder/i, 'T1557.001'], [/keylog/i, 'T1056.001'], [/credential\s*manager|vaultcmd/i, 'T1555.004'], [/browser\s*(credential|password)/i, 'T1555.003'], [/gpp|groups\.xml|cpassword/i, 'T1552.006'], [/adcs|certificate\s*(request|template)|esc\d/i, 'T1649'], [/sid\s*history/i, 'T1134.005'], [/gpo|group\s*policy\s*(modif|chang)/i, 'T1484.001'], [/token\s*(impersonat|theft|manipul)/i, 'T1134.001'], [/dll\s*(side.?load|hijack|search\s*order)/i, 'T1574.001'], [/named\s*pipe/i, 'T1570'], [/ingress|download\s*(cradle|tool)|bitsadmin|wget|curl/i, 'T1105'], [/archive|7z|winrar|compress/i, 'T1560.001'], [/screen\s*capture|screenshot/i, 'T1113'], [/clipboard/i, 'T1115'], [/mailbox\s*(rule|forward)|inbox\s*rule/i, 'T1114.003'], [/usb|removable/i, 'T1091'], [/vpn\s*(login|anomal|impossible)/i, 'T1133'], [/impossible\s*travel|atypical travel/i, 'T1078.004'], [/mfa\s*(fatigue|bomb|push)/i, 'T1621'], [/log\s*source\s*(stopped|silent)|collector/i, 'T1562.006'], [/service\s*stop|net\s+stop/i, 'T1489'], [/shutdown|reboot/i, 'T1529'], [/cryptomin|xmrig|miner/i, 'T1496'], [/sudo/i, 'T1548.003'], [/setuid|setgid/i, 'T1548.001'], [/kernel\s*module|insmod|modprobe/i, 'T1547.006'], [/ld_preload/i, 'T1574.006'], [/\/etc\/shadow|\/etc\/passwd/i, 'T1003.008'], [/sql\s*inject|exploit.*(public|web)|webshell|cve-/i, 'T1190'], [/proxy\s*(anomal|tunnel)|socks/i, 'T1090'], [/non.?standard\s*port/i, 'T1571'], [/tor\b|onion/i, 'T1090.003'], [/wiper|disk\s*wipe|mbr/i, 'T1561'], [/data\s*destruction|mass\s*delete/i, 'T1485']];
  IMP.applyMappings = (rule, explicitTechs, explicitTactics, text) => {
    const FW = SM.FW; const explicit = SM.uniq(explicitTechs.map(x => SM.str(x).toUpperCase()).filter(x => /^T\d{4}(\.\d{3})?$/.test(x)));
    const fromText = SM.extractTechniqueIds(text).filter(x => !explicit.includes(x));
    let inferred = [];
    if (!explicit.length && !fromText.length) { for (const [re, tid] of KEYWORD_KB) if (re.test(text)) inferred.push(tid); inferred = SM.uniq(inferred).slice(0, 3); }
    const all = SM.uniq([...explicit, ...fromText, ...inferred]);
    rule.attack_techniques = all.filter(x => !FW || !FW.loaded || FW.technique(x) || true);
    rule.attack_subtechniques = all.filter(x => x.includes('.'));
    rule.inferred_techniques = SM.uniq([...fromText.filter(x => !explicit.includes(x)), ...inferred]);
    rule.mapping_source = explicit.length ? (rule.inferred_techniques.length ? 'explicit+inferred' : 'explicit') : (fromText.length ? 'text-reference' : (inferred.length ? 'inferred' : 'none'));
    const tactics = SM.uniq(explicitTactics.map(normaliseTactic).filter(Boolean));
    if (FW && FW.loaded) for (const t of all) { const tech = FW.technique(t); if (tech) tactics.push(...tech.tactics); }
    rule.attack_tactics = SM.uniq(tactics);
    if (FW && FW.loaded) { rule.d3fend_mapping = SM.uniq(all.flatMap(t => FW.d3fendFor(t).map(d => d.id))).slice(0, 10); rule.capec_mapping = SM.uniq(all.flatMap(t => FW.capecFor(t).map(d => d.id))).slice(0, 10); }
  };

  IMP.finalise = (rule, raw) => {
    rule.original_rule_content = raw;
    rule.severity = SM.normSeverity(rule.severity);
    if (rule.risk_score === null || rule.risk_score === undefined || isNaN(rule.risk_score)) rule.risk_score = SM.riskFromSeverity(rule.severity);
    rule.risk_score = SM.clamp(Number(rule.risk_score), 0, 100);
    if (!rule.event_ids.length) rule.event_ids = IMP.extractEventIds(rule.detection_logic);
    if (!rule.event_fields.length) rule.event_fields = IMP.extractFields(rule.detection_logic);
    if (!rule.log_source_types.length) rule.log_source_types = IMP.inferLogSourceTypes([rule.detection_logic, rule.log_sources.join(' '), rule.rule_name, rule.description]);
    if (!rule.time_window) rule.time_window = IMP.extractTimeWindow(rule.detection_logic);
    if (!rule.threshold) rule.threshold = IMP.extractThreshold(rule.detection_logic);
    if (!rule.grouping_fields.length) rule.grouping_fields = IMP.extractGrouping(rule.detection_logic);
    if (!rule.entity_context.length) rule.entity_context = IMP.extractEntities([...rule.event_fields, ...rule.grouping_fields]);
    if (!rule.rule_id) rule.rule_id = rule.source_platform + ':' + SM.hash(rule.rule_name + '|' + rule.detection_logic);
    rule.rule_id = SM.str(rule.rule_id).slice(0, 200);
    rule.fingerprint = SM.hash(SM.normaliseLogic(rule.detection_logic) || SM.normaliseLogic(rule.rule_name));
    rule.lifecycle_stage = rule.enabled_status === 'enabled' ? 'Deployed' : (rule.enabled_status === 'disabled' ? 'Deprecated' : 'Deployed');
    // quality flags
    const f = [];
    if (!rule.description) f.push('missing_description'); if (!rule.attack_techniques.length) f.push('missing_mapping'); if (rule.mapping_source === 'inferred') f.push('inferred_mapping_only');
    if (!rule.detection_logic || rule.detection_logic.length < 8) f.push('malformed_or_missing_logic'); if (!rule.log_source_types.length) f.push('unknown_log_source');
    if (rule.severity === 'unknown') f.push('missing_severity'); if (rule.enabled_status === 'unknown') f.push('unknown_enabled_state');
    rule.quality_flags = f; return rule;
  };

  // ------- Adapters -------
  IMP.adapters = {};
  // Generic / Sentinel Matrix native JSON. Accepts: array of objects; {rules:[...]}; {items:[...]}; single object.
  IMP.adapters.generic = { id: 'generic', label: 'Generic / custom structured JSON or CSV', formats: ['json', 'ndjson', 'csv'],
    detect(obj) { return Array.isArray(obj) || (obj && (Array.isArray(obj.rules) || Array.isArray(obj.items))); },
    parse(obj, ctx) {
      const list = Array.isArray(obj) ? obj : (obj.rules || obj.items || [obj]);
      return list.map((o, i) => { if (!o || typeof o !== 'object') return { error: 'Record ' + i + ' is not an object', raw: o }; const r = IMP.blank(); r.source_platform = ctx.platform || SM.str(pick(o, ['platform', 'source_platform', 'siem'])).toLowerCase() || 'generic'; r.source_format = ctx.format;
        r.rule_id = SM.str(pick(o, ['rule_id', 'id', 'ruleId', 'uuid', 'name_id', 'Rule ID']));
        r.rule_name = SM.str(pick(o, ['rule_name', 'name', 'title', 'ruleName', 'Rule Name', 'display_name', 'displayName']));
        r.description = SM.str(pick(o, ['description', 'desc', 'summary', 'Description']));
        r.rule_type = SM.str(pick(o, ['rule_type', 'type', 'kind'])) || 'detection';
        const en = pick(o, ['enabled', 'enabled_status', 'is_enabled', 'status', 'disabled', 'Enabled']);
        r.enabled_status = en === undefined ? 'unknown' : (typeof en === 'boolean' ? (o.disabled !== undefined && pick(o, ['enabled', 'enabled_status', 'is_enabled', 'status', 'Enabled']) === undefined ? (en ? 'disabled' : 'enabled') : (en ? 'enabled' : 'disabled')) : (/^(true|1|enabled|active|on|yes)$/i.test(SM.str(en)) ? 'enabled' : (/^(false|0|disabled|inactive|off|no)$/i.test(SM.str(en)) ? 'disabled' : 'unknown')));
        r.severity = SM.str(pick(o, ['severity', 'level', 'priority', 'Severity']));
        const rs = pick(o, ['risk_score', 'riskScore', 'risk', 'score']); r.risk_score = rs === undefined ? null : Number(rs);
        r.detection_logic = SM.str(pick(o, ['detection_logic', 'query', 'search', 'logic', 'rule', 'detection', 'condition', 'tests', 'spl', 'kql', 'Query']));
        r.log_sources = SM.asArray(pick(o, ['log_sources', 'logsources', 'data_sources', 'index', 'sourcetype', 'tables', 'Log Sources'])).map(SM.str).filter(Boolean);
        r.event_ids = SM.asArray(pick(o, ['event_ids', 'eventIds', 'EventIDs'])).map(x => parseInt(x, 10)).filter(x => !isNaN(x));
        r.false_positive_notes = SM.asArray(pick(o, ['false_positive_notes', 'falsepositives', 'false_positives', 'fp_notes'])).map(SM.str).join('; ');
        r.owner = SM.str(pick(o, ['owner', 'author', 'created_by'])); r.version = SM.str(pick(o, ['version', 'revision']));
        r.last_modified = pick(o, ['last_modified', 'modified', 'updated_at', 'modification_date', 'updated']) || null; r.last_triggered = pick(o, ['last_triggered', 'last_fired', 'lastTriggered']) || null;
        r.tags = SM.asArray(pick(o, ['tags', 'labels'])).map(SM.str);
        const tw = pick(o, ['time_window', 'timeframe', 'window']); if (tw) r.time_window = typeof tw === 'object' ? tw : IMP.extractTimeWindow(SM.str(tw));
        const th = pick(o, ['threshold']); if (th !== undefined) r.threshold = typeof th === 'object' ? th : { operator: '>=', value: Number(th) };
        r.grouping_fields = SM.asArray(pick(o, ['grouping_fields', 'group_by', 'groupBy'])).map(SM.str);
        const techs = SM.asArray(pick(o, ['attack_techniques', 'techniques', 'mitre_techniques', 'technique', 'mitre', 'attack', 'ATT&CK', 'mitre_attack_id'])).map(SM.str).flatMap(x => x.split(/[,\s]+/)).filter(Boolean);
        const tacs = SM.asArray(pick(o, ['attack_tactics', 'tactics', 'mitre_tactics', 'tactic'])).map(SM.str);
        const tagTechs = r.tags.filter(t => /attack\.t\d{4}/i.test(t)).map(t => t.replace(/^attack\./i, ''));
        IMP.applyMappings(r, [...techs, ...tagTechs], [...tacs, ...r.tags.filter(t => /^attack\.[a-z_]+$/i.test(t)).map(t => t.replace(/^attack\./i, ''))], [r.rule_name, r.description, r.tags.join(' '), techs.join(' ')].join(' '));
        return IMP.finalise(r, o); });
    } };

  // Sigma YAML
  IMP.adapters.sigma = { id: 'sigma', label: 'Sigma YAML', formats: ['yaml'],
    parse(docs, ctx) { return docs.map(d => { if (!d || typeof d !== 'object' || !d.title) return { error: 'Not a Sigma rule (missing title)', raw: d }; const r = IMP.blank(); r.source_platform = 'sigma'; r.source_format = 'yaml'; r.rule_id = SM.str(d.id || ''); r.rule_name = SM.str(d.title); r.description = SM.str(d.description || ''); r.severity = SM.str(d.level || ''); r.enabled_status = d.status === 'deprecated' ? 'disabled' : 'enabled'; r.rule_type = 'sigma'; r.detection_logic = SM.toYAML(d.detection || {}); r.conditions = SM.asArray(d.detection && d.detection.condition).map(SM.str);
      const ls = d.logsource || {}; r.log_sources = SM.uniq([ls.product, ls.category, ls.service].filter(Boolean).map(SM.str)); r.log_source_types = IMP.inferLogSourceTypes([Object.values(ls).join(' '), r.rule_name]);
      if (ls.category === 'process_creation') r.log_source_types = SM.uniq(['sysmon', 'windows_security', 'edr', ...r.log_source_types]); if (ls.service === 'security') r.log_source_types = SM.uniq(['windows_security', ...r.log_source_types]); if (ls.service === 'sysmon') r.log_source_types = SM.uniq(['sysmon', ...r.log_source_types]); if (ls.product === 'linux') r.log_source_types = SM.uniq(['linux_auditd', ...r.log_source_types]); if (ls.service === 'powershell') r.log_source_types = SM.uniq(['powershell', ...r.log_source_types]);
      r.false_positive_notes = SM.asArray(d.falsepositives).map(SM.str).join('; '); r.owner = SM.str(d.author || ''); r.last_modified = d.modified || d.date || null; r.tags = SM.asArray(d.tags).map(SM.str); r.event_ids = IMP.extractEventIds(r.detection_logic);
      const tf = d.detection && d.detection.timeframe; if (tf) r.time_window = IMP.extractTimeWindow(SM.str(tf));
      const techs = r.tags.filter(t => /^attack\.t\d{4}/i.test(t)).map(t => t.replace(/^attack\./i, '')); const tacs = r.tags.filter(t => /^attack\.[a-z_]+$/i.test(t)).map(t => t.replace(/^attack\./i, ''));
      IMP.applyMappings(r, techs, tacs, [r.rule_name, r.description, r.tags.join(' ')].join(' ')); return IMP.finalise(r, d); }); } };

  // Elastic Security (ndjson export / API list)
  IMP.adapters.elastic = { id: 'elastic', label: 'Elastic Security detection rules (ndjson / JSON)', formats: ['json', 'ndjson'],
    detect(o) { const x = Array.isArray(o) ? o[0] : (o && o.data ? o.data[0] : o); return !!(x && (x.rule_id !== undefined || x.threat !== undefined) && (x.query !== undefined || x.type !== undefined) && x.risk_score !== undefined); },
    parse(obj, ctx) { const list = Array.isArray(obj) ? obj : (obj.data || [obj]); return list.filter(o => o && o.type !== 'exceptions-list' && o.exported_count === undefined).map(o => { const r = IMP.blank(); r.source_platform = 'elastic'; r.source_format = ctx.format; r.rule_id = SM.str(o.rule_id || o.id); r.rule_name = SM.str(o.name); r.description = SM.str(o.description || ''); r.rule_type = SM.str(o.type || 'query'); r.enabled_status = o.enabled === false ? 'disabled' : (o.enabled === true ? 'enabled' : 'unknown'); r.severity = SM.str(o.severity); r.risk_score = o.risk_score !== undefined ? Number(o.risk_score) : null; r.detection_logic = SM.str(o.query || (o.threshold ? JSON.stringify(o.threshold) : '') || (o.new_terms_fields ? 'new_terms: ' + o.new_terms_fields.join(',') : '')); r.log_sources = SM.asArray(o.index).map(SM.str); r.false_positive_notes = SM.asArray(o.false_positives).map(SM.str).join('; '); r.owner = SM.asArray(o.author).map(SM.str).join(', '); r.version = SM.str(o.version || ''); r.last_modified = o.updated_at || null; r.tags = SM.asArray(o.tags).map(SM.str); r.time_window = o.from ? IMP.extractTimeWindow(SM.str(o.from).replace('now-', '')) : null; if (o.threshold) { r.threshold = { operator: '>=', value: Number(o.threshold.value) }; r.grouping_fields = SM.asArray(o.threshold.field).map(SM.str); }
      const techs = []; const tacs = []; for (const th of SM.asArray(o.threat)) { if (th.tactic) tacs.push(th.tactic.id || th.tactic.name); for (const t of SM.asArray(th.technique)) { techs.push(t.id); for (const s of SM.asArray(t.subtechnique)) techs.push(s.id); } }
      IMP.applyMappings(r, techs, tacs, [r.rule_name, r.description, r.tags.join(' ')].join(' ')); return IMP.finalise(r, o); }); } };

  // Microsoft Sentinel analytics rules (ARM template export or API list)
  IMP.adapters.sentinel = { id: 'sentinel', label: 'Microsoft Sentinel analytics rules (ARM / API JSON)', formats: ['json'],
    detect(o) { if (o && Array.isArray(o.resources)) return o.resources.some(r => /alertRules/i.test(SM.str(r.type))); const x = Array.isArray(o) ? o[0] : (o && o.value ? o.value[0] : o); return !!(x && x.properties && (x.properties.query !== undefined || x.kind !== undefined) && /alertRules/i.test(SM.str(x.type || 'alertRules'))); },
    parse(obj, ctx) { const list = Array.isArray(obj) ? obj : (obj.resources || obj.value || [obj]); return list.filter(o => o && o.properties).map(o => { const p = o.properties; const r = IMP.blank(); r.source_platform = 'sentinel'; r.source_format = ctx.format; r.rule_id = SM.str(p.alertRuleTemplateName || o.name || o.id).split('/').pop(); r.rule_name = SM.str(p.displayName || o.name); r.description = SM.str(p.description || ''); r.rule_type = SM.str(o.kind || 'Scheduled'); r.enabled_status = p.enabled === false ? 'disabled' : (p.enabled === true ? 'enabled' : 'unknown'); r.severity = SM.str(p.severity); r.detection_logic = SM.str(p.query || ''); r.log_sources = SM.uniq((r.detection_logic.match(/^\s*([A-Z][A-Za-z0-9_]+)\s*$|^\s*([A-Z][A-Za-z0-9_]+)\s*\|/gm) || []).map(x => x.replace(/[\s|]/g, ''))); r.time_window = p.queryFrequency ? IMP.extractTimeWindow(SM.str(p.queryPeriod || p.queryFrequency).replace(/^PT?/, '').toLowerCase()) : null; if (p.triggerThreshold !== undefined) r.threshold = { operator: ({ GreaterThan: '>', GreaterThanOrEqual: '>=', LessThan: '<', Equal: '==' }[p.triggerOperator] || '>'), value: Number(p.triggerThreshold) }; r.suppression_conditions = p.suppressionEnabled ? ['suppression ' + p.suppressionDuration] : []; r.last_modified = p.lastModifiedUtc || null; r.version = SM.str(p.templateVersion || ''); r.entity_context = SM.asArray(p.entityMappings).map(e => SM.str(e.entityType).toLowerCase()); r.grouping_fields = SM.asArray(deepPick(p, 'incidentConfiguration.groupingConfiguration.groupByEntities')).map(SM.str);
      IMP.applyMappings(r, SM.asArray(p.techniques).concat(SM.asArray(p.subTechniques)), SM.asArray(p.tactics), [r.rule_name, r.description].join(' ')); return IMP.finalise(r, o); }); } };

  // Splunk ES correlation searches: REST JSON (/servicesNS/.../saved/searches) or savedsearches.conf text
  IMP.adapters.splunk = { id: 'splunk', label: 'Splunk correlation searches (REST JSON / savedsearches.conf)', formats: ['json', 'splunk-conf'],
    detect(o) { const x = Array.isArray(o) ? o[0] : (o && o.entry ? o.entry[0] : o); return !!(x && (x.content && (x.content.search !== undefined)) || (x && x.search !== undefined && x.name !== undefined && x.cron_schedule !== undefined)); },
    parseConf(text) { const out = []; let cur = null; for (const line of text.split(/\r?\n/)) { const m = line.match(/^\[(.+)\]\s*$/); if (m) { if (cur) out.push(cur); cur = { name: m[1], content: {} }; continue; } if (!cur) continue; const kv = line.match(/^([^=\s][^=]*?)\s*=\s*(.*)$/); if (kv) cur.content[kv[1].trim()] = kv[2].replace(/\\$/, ''); } if (cur) out.push(cur); return out; },
    parse(obj, ctx) { const list = typeof obj === 'string' ? IMP.adapters.splunk.parseConf(obj) : (Array.isArray(obj) ? obj : (obj.entry || [obj])); return list.map(o => { const c = o.content || o; const r = IMP.blank(); r.source_platform = 'splunk'; r.source_format = ctx.format; r.rule_name = SM.str(o.name || c.name); r.rule_id = SM.str(c['action.correlationsearch.label'] || o.id || r.rule_name); r.description = SM.str(c.description || ''); r.rule_type = c['action.correlationsearch.enabled'] ? 'correlation_search' : 'saved_search'; r.enabled_status = (SM.str(c.disabled) === '1' || c.disabled === true) ? 'disabled' : (c.disabled !== undefined ? 'enabled' : 'unknown'); r.severity = SM.str(c['action.risk.param._risk_score'] ? '' : (c['action.notable.param.severity'] || c['alert.severity'] || '')); const rsk = c['action.risk.param._risk_score'] || c['action.risk.param._risk'] ; if (rsk) { const n = parseFloat(SM.str(rsk).match(/\d+/) ? SM.str(rsk).match(/\d+/)[0] : 'NaN'); if (!isNaN(n)) r.risk_score = n; } if (!r.severity && c['alert.severity']) r.severity = ({ 1: 'informational', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical', 6: 'critical' }[SM.str(c['alert.severity'])] || ''); r.detection_logic = SM.str(c.search || ''); r.log_sources = SM.uniq((r.detection_logic.match(/(?:index|sourcetype)\s*=\s*"?([A-Za-z0-9_:*.-]+)/g) || []).map(x => x.split('=').pop().replace(/"/g, ''))); r.time_window = IMP.extractTimeWindow(SM.str(c['dispatch.earliest_time'] || '').replace(/^-/, '').replace(/@.*/, '')); r.owner = SM.str((o.acl && o.acl.owner) || c.owner || ''); r.last_modified = o.updated || null;
      let techs = [], tacs = []; const ann = c['action.correlationsearch.annotations']; if (ann) { try { const a = typeof ann === 'string' ? SM.safeJSON(ann) : ann; techs = SM.asArray(a.mitre_attack).map(SM.str); } catch (e) { techs = SM.extractTechniqueIds(SM.str(ann)); } }
      IMP.applyMappings(r, techs, tacs, [r.rule_name, r.description, SM.str(ann)].join(' ')); return IMP.finalise(r, o); }); } };

  // IBM QRadar: API JSON (/api/analytics/rules) or Content Management Tool XML export (best effort)
  IMP.adapters.qradar = { id: 'qradar', label: 'IBM QRadar (API JSON / CMT XML export)', formats: ['json', 'xml'],
    detect(o) { const x = Array.isArray(o) ? o[0] : o; return !!(x && x.origin !== undefined && x.enabled !== undefined && (x.type === 'EVENT' || x.type === 'FLOW' || x.type === 'COMMON' || x.type === 'OFFENSE' || x.owner !== undefined) && x.identifier !== undefined); },
    parse(obj, ctx) {
      if (ctx.format === 'xml') return IMP.adapters.qradar.parseXML(obj, ctx);
      const list = Array.isArray(obj) ? obj : [obj];
      return list.map(o => { const r = IMP.blank(); r.source_platform = 'qradar'; r.source_format = 'json'; r.rule_id = SM.str(o.identifier || o.id); r.rule_name = SM.str(o.name); r.rule_type = SM.str(o.type || 'EVENT'); r.enabled_status = o.enabled === true ? 'enabled' : (o.enabled === false ? 'disabled' : 'unknown'); r.owner = SM.str(o.owner || ''); r.last_modified = o.modification_date ? new Date(Number(o.modification_date)).toISOString() : null; r.deployment_status = o.origin === 'SYSTEM' ? 'vendor' : (o.origin === 'USER' ? 'custom' : 'unknown'); r.description = SM.str(o.notes || o.description || ''); r.detection_logic = SM.str(o.rule_tests || o.tests || (o.rule_data && typeof o.rule_data === 'string' ? IMP.adapters.qradar.testsFromRuleXml(o.rule_data) : '') || ''); r.severity = o.severity !== undefined ? SM.str(o.severity) : ''; if (o.creation_date) r.version = 'created ' + new Date(Number(o.creation_date)).toISOString().slice(0, 10); r.tags = SM.asArray(o.rule_groups || o.groups).map(SM.str); r.conditions = r.detection_logic ? r.detection_logic.split('\n').filter(Boolean) : [];
        IMP.applyMappings(r, [], [], [r.rule_name, r.description, r.tags.join(' '), r.detection_logic].join(' ')); return IMP.finalise(r, o); });
    },
    // QRadar rule XML (as found in CMT exports or rule_data) contains <rule><name>, <notes>, <testDefinitions><test text="..."/> etc.
    testsFromRuleXml(xmlText) { try { const doc = SM.parseXML(xmlText); const tests = Array.from(doc.getElementsByTagName('test')).map(t => (t.getAttribute('text') || t.textContent || '').trim()).filter(Boolean); return tests.join('\n'); } catch (e) { return ''; } },
    parseXML(doc, ctx) {
      const out = []; const b64 = (s) => { try { return decodeURIComponent(escape(atob(s.replace(/\s+/g, '')))); } catch (e) { try { return atob(s.replace(/\s+/g, '')); } catch (e2) { return ''; } } };
      let ruleEls = Array.from(doc.getElementsByTagName('custom_rule')); if (!ruleEls.length) ruleEls = Array.from(doc.getElementsByTagName('rule'));
      for (const el of ruleEls) {
        const get = (tag) => { const n = el.getElementsByTagName(tag)[0]; return n ? (n.textContent || '').trim() : ''; };
        let inner = null; const rd = get('rule_data'); if (rd) { const dec = /^[A-Za-z0-9+/=\s]+$/.test(rd) ? b64(rd) : rd; try { inner = SM.parseXML(dec); } catch (e) { inner = null; } }
        const iget = (tag) => { if (!inner) return ''; const n = inner.getElementsByTagName(tag)[0]; return n ? (n.textContent || '').trim() : ''; };
        const r = IMP.blank(); r.source_platform = 'qradar'; r.source_format = 'xml'; r.rule_id = get('id') || iget('id') || get('uuid'); r.rule_name = get('name') || iget('name') || el.getAttribute('name') || ''; r.description = get('notes') || iget('notes'); r.rule_type = get('rule_type') || iget('ruleType') || 'EVENT'; const en = (get('enabled') || iget('enabled')).toLowerCase(); r.enabled_status = en === 'true' ? 'enabled' : (en === 'false' ? 'disabled' : 'unknown'); r.owner = get('owner') || iget('owner');
        const tests = Array.from((inner || el).getElementsByTagName('test')).map(t => (t.getAttribute('text') || t.textContent || '').replace(/<[^>]+>/g, '').trim()).filter(Boolean); r.detection_logic = tests.join('\n'); r.conditions = tests; r.tags = Array.from((inner || el).getElementsByTagName('group')).map(g => (g.textContent || '').trim()).filter(Boolean);
        const bbDeps = tests.flatMap(t => (t.match(/BB:[^\s,)]+/g) || [])); r.dependencies = SM.uniq(bbDeps);
        if (!r.rule_name) { out.push({ error: 'QRadar rule element without a name', raw: el.outerHTML.slice(0, 500) }); continue; }
        IMP.applyMappings(r, [], [], [r.rule_name, r.description, r.tags.join(' '), r.detection_logic].join(' ')); out.push(IMP.finalise(r, el.outerHTML.slice(0, 20000)));
      }
      if (!out.length) out.push({ error: 'No <custom_rule> or <rule> elements found in XML', raw: null });
      return out;
    } };

  // CSV adapter: header mapping heuristics
  IMP.adapters.csv = { id: 'csv', label: 'CSV rule inventory', formats: ['csv'], parse(parsed, ctx) { return IMP.adapters.generic.parse(parsed.records, ctx); } };

  // ------- Orchestrated import -------
  IMP.parseFile = async (file, { platform = 'auto', instance = 'default' } = {}) => {
    const text = await SM.readFileText(file); const format = SM.detectFormat(file.name, text); const ctx = { format, platform: platform === 'auto' ? undefined : platform, instance, filename: file.name };
    const result = { filename: file.name, size: file.size, format, adapter: null, rules: [], errors: [], detected_platform: null };
    let obj = null;
    try {
      if (format === 'json') obj = SM.safeJSON(text);
      else if (format === 'ndjson') obj = text.split(/\r?\n/).filter(l => l.trim()).map((l, i) => { try { return SM.safeJSON(l); } catch (e) { result.errors.push({ line: i + 1, error: 'Invalid JSON line' }); return null; } }).filter(Boolean);
      else if (format === 'csv') obj = SM.parseCSV(text);
      else if (format === 'yaml') obj = SM.parseYAML(text);
      else if (format === 'xml') obj = SM.parseXML(text);
      else if (format === 'splunk-conf') obj = text;
      else { result.errors.push({ error: 'Unrecognised file format. Supported: JSON, NDJSON, CSV, Sigma YAML, QRadar XML, savedsearches.conf' }); return result; }
    } catch (e) { result.errors.push({ error: 'Parse failure: ' + e.message }); return result; }
    let adapter;
    if (platform && platform !== 'auto' && IMP.adapters[platform] && IMP.adapters[platform].formats.includes(format)) adapter = IMP.adapters[platform];
    else if (format === 'yaml') adapter = IMP.adapters.sigma;
    else if (format === 'xml') adapter = IMP.adapters.qradar;
    else if (format === 'splunk-conf') adapter = IMP.adapters.splunk;
    else if (format === 'csv') adapter = IMP.adapters.csv;
    else adapter = [IMP.adapters.sentinel, IMP.adapters.elastic, IMP.adapters.qradar, IMP.adapters.splunk].find(a => { try { return a.detect(obj); } catch (e) { return false; } }) || IMP.adapters.generic;
    result.adapter = adapter.id; result.detected_platform = adapter.id === 'generic' || adapter.id === 'csv' ? (ctx.platform || 'generic') : adapter.id;
    ctx.platform = ctx.platform || result.detected_platform;
    let parsed; try { parsed = adapter.parse(obj, ctx); } catch (e) { result.errors.push({ error: 'Adapter ' + adapter.id + ' failed: ' + e.message }); return result; }
    for (const p of parsed) { if (p.error) result.errors.push({ error: p.error, raw: SM.truncate(SM.str(p.raw), 200) }); else { p.source_instance = instance; result.rules.push(p); } }
    return result;
  };

  // Deduplicate within the batch and against existing rules; produce quality summary
  IMP.analyseBatch = (rules, existing) => {
    const byFp = new Map(); const byName = new Map(); const exFp = new Map((existing || []).map(r => [r.fingerprint, r])); const exId = new Set((existing || []).map(r => r.rule_id));
    for (const r of rules) { r.duplicate_of = null; r.name_duplicate_of = null; const k = r.fingerprint; if (byFp.has(k)) r.duplicate_of = byFp.get(k).rule_id; else byFp.set(k, r); if (exFp.has(k) && exFp.get(k).rule_id !== r.rule_id) r.duplicate_of = r.duplicate_of || exFp.get(k).rule_id; const nk = SM.normaliseLogic(r.rule_name); if (nk) { if (byName.has(nk) && byName.get(nk).rule_id !== r.rule_id) r.name_duplicate_of = byName.get(nk).rule_id; else byName.set(nk, r); } r.replaces_existing = exId.has(r.rule_id); }
    const q = { total: rules.length, duplicates: rules.filter(r => r.duplicate_of).length, name_duplicates: rules.filter(r => r.name_duplicate_of && !r.duplicate_of).length, replacing_existing: rules.filter(r => r.replaces_existing).length, missing_description: rules.filter(r => r.quality_flags.includes('missing_description')).length, missing_mapping: rules.filter(r => r.quality_flags.includes('missing_mapping')).length, inferred_only: rules.filter(r => r.quality_flags.includes('inferred_mapping_only')).length, malformed_logic: rules.filter(r => r.quality_flags.includes('malformed_or_missing_logic')).length, unknown_log_source: rules.filter(r => r.quality_flags.includes('unknown_log_source')).length, missing_severity: rules.filter(r => r.quality_flags.includes('missing_severity')).length, enabled: rules.filter(r => r.enabled_status === 'enabled').length, disabled: rules.filter(r => r.enabled_status === 'disabled').length, by_platform: SM.countBy(rules, 'source_platform') };
    const fieldFreq = SM.countBy(rules.flatMap(r => r.event_fields)); const KNOWN = /^(eventid|eventcode|event_id|image|commandline|parentimage|parentcommandline|user|targetusername|subjectusername|computer|hostname|host|src_ip|dest_ip|sourceip|destinationip|destinationport|sourceport|processname|processid|logonType|logontype|targetdomainname|servicename|ticketencryptiontype|status|accountname|objectname|sharename|queryname|url|useragent|action|signature|severity|category|dst_port|src_port|dest_port|process_name|process_command_line|file_path|file_name|hash|md5|sha256|registry_path|registry_value|qidname|username|sourcemac|eventname|logsourcename|lowlevelcategory|highlevelcategory|payload|devicetime|starttime|magnitude|credibility|relevance|protocolid|qid|domainname|sourcev6|destinationv6|utf8|accountdomain|processguid|parentprocessguid|destinationhostname|initiated|ruleName|targetobject|details|imageloaded|signed|signature|pipename|querystatus|queryresults|eventtype|operation|user_name|user_id|process_cmdline|dst_ip|src_user|dest_user|dest|src|app|signature_id|command|parent_process|parent_process_name|process|device|ipaddress|resultType|userprincipalname|appdisplayname|location|operationName|activityDisplayName|initiatedBy|targetResources|caller|requestUri|queryText|clientIp|eventName|eventSource|sourceIPAddress|userIdentity|requestParameters|responseElements|errorCode|awsRegion|instanceId|bucketName|principalId|accountId)$/i; q.unsupported_field_names = Object.entries(fieldFreq).filter(([f]) => !KNOWN.test(f)).sort((a, b) => b[1] - a[1]).slice(0, 25).map(([f, n]) => ({ field: f, count: n }));
    return q;
  };
  SM.Import = IMP;
})(globalThis.SM = globalThis.SM || {});
