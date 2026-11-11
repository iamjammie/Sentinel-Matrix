/* SENTINEL MATRIX — deterministic, template-driven detection rule generator.
   Renders a scenario specification to Sigma / Splunk SPL / Elastic KQL+ES|QL / Sentinel KQL / QRadar spec / generic.
   NO AI model, NO network. Output is a SPECIFICATION by default; it is clearly labelled by maturity. */
(function (SM) {
  'use strict';
  const GEN = {};
  // canonical field → per-platform field name
  const FIELD_MAP = {
    EventID: { sigma: 'EventID', splunk: 'EventCode', sentinel: 'EventID', elastic: 'event.code', qradar: 'Event ID (QID mapped)' },
    CommandLine: { sigma: 'CommandLine', splunk: 'Processes.process', sentinel: 'ProcessCommandLine', elastic: 'process.command_line', qradar: 'Payload matches (command line)' },
    Image: { sigma: 'Image', splunk: 'Processes.process_path', sentinel: 'NewProcessName', elastic: 'process.executable', qradar: 'Filename' },
    ParentImage: { sigma: 'ParentImage', splunk: 'Processes.parent_process_path', sentinel: 'InitiatingProcessFileName', elastic: 'process.parent.executable', qradar: 'Parent Filename' },
    TargetImage: { sigma: 'TargetImage', splunk: 'target_process', sentinel: 'TargetProcessName', elastic: 'process.target.executable', qradar: 'Target Process' },
    SourceImage: { sigma: 'SourceImage', splunk: 'source_process', sentinel: 'InitiatingProcessFileName', elastic: 'process.executable', qradar: 'Source Process' },
    GrantedAccess: { sigma: 'GrantedAccess', splunk: 'granted_access', sentinel: 'GrantedAccess', elastic: 'winlog.event_data.GrantedAccess', qradar: 'Granted Access' },
    TargetUserName: { sigma: 'TargetUserName', splunk: 'user', sentinel: 'TargetUserName', elastic: 'user.target.name', qradar: 'Username' },
    SubjectUserName: { sigma: 'SubjectUserName', splunk: 'src_user', sentinel: 'SubjectUserName', elastic: 'user.name', qradar: 'Source Username' },
    ServiceName: { sigma: 'ServiceName', splunk: 'service', sentinel: 'ServiceName', elastic: 'winlog.event_data.ServiceName', qradar: 'Service Name' },
    TicketEncryptionType: { sigma: 'TicketEncryptionType', splunk: 'Ticket_Encryption_Type', sentinel: 'TicketEncryptionType', elastic: 'winlog.event_data.TicketEncryptionType', qradar: 'Ticket Encryption Type' },
    IpAddress: { sigma: 'IpAddress', splunk: 'src_ip', sentinel: 'IpAddress', elastic: 'source.ip', qradar: 'Source IP' },
    LogonType: { sigma: 'LogonType', splunk: 'Logon_Type', sentinel: 'LogonType', elastic: 'winlog.event_data.LogonType', qradar: 'Logon Type' },
    AuthenticationPackageName: { sigma: 'AuthenticationPackageName', splunk: 'Authentication_Package', sentinel: 'AuthenticationPackageName', elastic: 'winlog.event_data.AuthenticationPackageName', qradar: 'Authentication Package' },
    TargetFilename: { sigma: 'TargetFilename', splunk: 'file_path', sentinel: 'FolderPath', elastic: 'file.path', qradar: 'Filename' },
    ObjectName: { sigma: 'ObjectName', splunk: 'object', sentinel: 'RegistryKey', elastic: 'registry.path', qradar: 'Object Name' },
    ScriptBlockText: { sigma: 'ScriptBlockText', splunk: 'ScriptBlockText', sentinel: 'ScriptBlockText', elastic: 'powershell.command.value', qradar: 'Payload' },
    ServiceName2: { sigma: 'ServiceName', splunk: 'service' }
  };
  const fname = (canonical, platform) => (FIELD_MAP[canonical] && FIELD_MAP[canonical][platform]) || canonical;
  const SM_SEV2RISK = SM.riskFromSeverity;

  GEN.resolveFields = (predicates, platform) => predicates.map(p => Object.assign({}, p, { platformField: fname(p.field, platform) }));

  // ---------- Sigma ----------
  GEN.toSigma = (spec) => {
    const detection = {}; const selNames = [];
    const toCond = (p) => { const v = p.value; switch (p.op) {
      case 'eq': return { [p.field]: v };
      case 'in': return { [p.field]: v };
      case 'ne': return { [p.field + '|re']: '(?!^' + GEN.esc(v) + '$)' };
      case 'contains': return { [p.field + '|contains']: v };
      case 'contains_any': return { [p.field + '|contains']: v };
      case 'endswith': return { [p.field + '|endswith']: v };
      case 'endswith_any': return { [p.field + '|endswith']: v };
      case 'not_in': return { [p.field + '|endswith']: v };
      case 'gt': return { [p.field + '|gt']: v };
      case 'regex': return { [p.field + '|re']: v };
      default: return { [p.field]: v }; } };
    (spec.selection || []).forEach((p, i) => { const n = 'selection' + (spec.selection.length > 1 ? '_' + i : ''); detection[n] = toCond(p); selNames.push(n); });
    const filterNames = []; (spec.exclusions || []).forEach((p, i) => { const n = 'filter_' + i; detection[n] = toCond(p); filterNames.push(n); });
    let condition = selNames.length > 1 ? 'all of selection*' : (selNames[0] || 'selection');
    if (filterNames.length) condition += ' and not (' + filterNames.join(' or ') + ')';
    if (spec.agg && (spec.agg.fn === 'count' || spec.agg.fn === 'zscore')) { const by = (spec.agg.group_by || []).join(', '); condition += ' | count(' + (spec.agg.distinct || '') + ') by ' + by + ' > ' + (spec.agg.threshold || 1); if (spec.agg.window_minutes) detection.timeframe = spec.agg.window_minutes + 'm'; }
    const logsource = GEN.sigmaLogsource(spec);
    const doc = { title: spec.title, id: spec.uuid, status: 'experimental', description: spec.description, references: spec.references || [], author: spec.author || 'SENTINEL MATRIX (generated specification)', date: (spec.date || new Date().toISOString().slice(0, 10)), tags: spec.tags, logsource, detection, falsepositives: spec.fp && spec.fp.length ? spec.fp : ['Unknown'], level: spec.severity === 'informational' ? 'informational' : spec.severity };
    return SM.toYAML(doc);
  };
  GEN.esc = (s) => SM.str(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  GEN.sigmaLogsource = (spec) => { const t = spec.log_source_types || []; if (t.includes('sysmon')) return { product: 'windows', service: 'sysmon' }; if (t.includes('powershell')) return { product: 'windows', service: 'powershell', category: 'ps_script' }; if (t.includes('active_directory') || t.includes('windows_security')) return { product: 'windows', service: 'security' }; if (t.includes('linux_auditd')) return { product: 'linux', service: 'auditd' }; if (t.includes('dns')) return { product: 'windows', category: 'dns_query' }; if (t.includes('web_server')) return { category: 'webserver' }; return { product: (spec.platforms_hint || 'windows') }; };

  // ---------- Splunk SPL ----------
  GEN.toSPL = (spec) => {
    const idx = GEN.splunkIndex(spec);
    const w = (spec.selection || []).map(p => GEN.splClause(p)).filter(Boolean);
    const ex = (spec.exclusions || []).map(p => 'NOT ' + GEN.splClause(p)).filter(Boolean);
    let spl = '`comment("' + spec.title.replace(/"/g, "'") + ' — generated specification; validate index/sourcetype and field names for your environment")`\n';
    spl += 'search ' + idx + ' ' + [...w, ...ex].join(' ');
    if (spec.agg) {
      const a = spec.agg; const by = (a.group_by || []).join(' ');
      if (a.fn === 'count') spl += '\n| bin _time span=' + (a.window_minutes || 5) + 'm\n| stats ' + (a.distinct ? 'dc(' + a.distinct + ') as distinct_count count ' : 'count ') + 'by _time ' + by + '\n| where ' + (a.distinct ? 'distinct_count' : 'count') + ' >= ' + a.threshold;
      else if (a.fn === 'zscore') spl += '\n| bin _time span=1d\n| stats count as n by ' + by + ' _time\n| eventstats avg(n) as avg stdev(n) as sd by ' + by + '\n| eval z=(n-avg)/sd\n| where z >= ' + a.threshold;
      else if (a.fn === 'new_value') spl += '\n| stats earliest(_time) as first_seen by ' + (a.group_by || []).join(' ') + ' ' + (a.observe || '') + '\n| where first_seen >= relative_time(now(), "-' + (a.window_minutes || 1440) + 'm")';
      else if (a.fn === 'sequence') spl += '\n`comment("sequence correlation — implement with transaction or two-search join: ' + (a.steps || []).join(' THEN ') + '")`';
      else if (a.fn === 'absence') spl += '\n| stats latest(_time) as last by log_source_id\n| where last < relative_time(now(), "-' + (a.window_minutes || 60) + 'm")';
    }
    spl += '\n| eval risk_score=' + GEN.riskFor(spec) + ', mitre_technique="' + spec.technique + '"';
    return spl;
  };
  GEN.splClause = (p) => { const f = fname(p.field, 'splunk'); const v = p.value; const q = (x) => '"' + SM.str(x).replace(/"/g, '\\"') + '"'; switch (p.op) {
    case 'eq': return f + '=' + q(v); case 'in': return '(' + v.map(x => f + '=' + q(x)).join(' OR ') + ')';
    case 'ne': return f + '!=' + q(v); case 'contains': return f + '=' + q('*' + v + '*'); case 'contains_any': return '(' + v.map(x => f + '=' + q('*' + x + '*')).join(' OR ') + ')';
    case 'endswith': return f + '=' + q('*' + v); case 'endswith_any': return '(' + v.map(x => f + '=' + q('*' + x)).join(' OR ') + ')'; case 'not_in': return 'NOT (' + v.map(x => f + '=' + q('*' + x)).join(' OR ') + ')';
    case 'gt': return f + '>' + Number(v); case 'regex': return 'match(' + f + ', "' + SM.str(v).replace(/"/g, '\\"') + '")'; default: return ''; } };
  GEN.splunkIndex = (spec) => { const t = spec.log_source_types || []; const map = { windows_security: 'index=wineventlog (source="WinEventLog:Security" OR sourcetype="WinEventLog:Security")', active_directory: 'index=wineventlog sourcetype="WinEventLog:Security"', sysmon: 'index=sysmon (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="xmlwineventlog")', powershell: 'index=wineventlog sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational"', linux_auditd: 'index=linux sourcetype=linux_audit', dns: 'index=dns sourcetype=stream:dns', web_server: 'index=web', edr: 'index=edr', firewall: 'index=network', identity: 'index=identity', cloud_audit: 'index=cloud' }; for (const x of t) if (map[x]) return map[x]; return 'index=* `comment("set your index/sourcetype")`'; };

  // ---------- KQL (Sentinel / Elastic) ----------
  GEN.toKQL = (spec, dialect) => {
    const table = GEN.kqlTable(spec);
    const clause = (p) => { const f = fname(p.field, 'sentinel'); const v = p.value; const q = (x) => '"' + SM.str(x).replace(/"/g, '\\"') + '"'; switch (p.op) {
      case 'eq': return f + ' == ' + (typeof v === 'number' ? v : q(v)); case 'in': return f + ' in (' + v.map(q).join(', ') + ')';
      case 'ne': return f + ' != ' + q(v); case 'contains': return f + ' contains ' + q(v); case 'contains_any': return f + ' has_any (' + v.map(q).join(', ') + ')';
      case 'endswith': return f + ' endswith ' + q(v); case 'endswith_any': return '(' + v.map(x => f + ' endswith ' + q(x)).join(' or ') + ')'; case 'not_in': return 'not (' + v.map(x => f + ' endswith ' + q(x)).join(' or ') + ')';
      case 'gt': return f + ' > ' + Number(v); case 'regex': return f + ' matches regex ' + q(v); default: return ''; } };
    let k = '// ' + spec.title + ' — generated ' + (dialect === 'elastic' ? 'KQL/ES|QL-style' : 'Sentinel KQL') + ' specification. Validate table and column names for your schema.\n';
    k += table + '\n| where ' + (spec.selection || []).map(clause).filter(Boolean).join('\n    and ');
    for (const p of (spec.exclusions || [])) k += '\n| where not (' + clause(p) + ')';
    if (spec.agg) { const a = spec.agg; const by = (a.group_by || []).map(f => fname(f, 'sentinel')).join(', ');
      if (a.fn === 'count') k += '\n| summarize ' + (a.distinct ? 'dc_val = dcount(' + fname(a.distinct, 'sentinel') + '), ' : '') + 'event_count = count() by ' + by + (a.window_minutes ? ', bin(TimeGenerated, ' + a.window_minutes + 'm)' : '') + '\n| where ' + (a.distinct ? 'dc_val' : 'event_count') + ' >= ' + a.threshold;
      else if (a.fn === 'zscore') k += '\n| summarize n = count() by ' + by + ', bin(TimeGenerated, 1d)\n| summarize avg_n = avg(n), sd_n = stdev(n), arg_max(TimeGenerated, n) by ' + by + '\n| extend z = (n - avg_n) / sd_n\n| where z >= ' + a.threshold;
      else if (a.fn === 'new_value') k += '\n| summarize first_seen = min(TimeGenerated) by ' + by + ', ' + fname(a.observe, 'sentinel') + '\n| where first_seen > ago(' + (a.window_minutes || 1440) + 'm)';
      else if (a.fn === 'sequence') k += '\n// sequence correlation — implement with join/partition: ' + (a.steps || []).join('  THEN  ');
      else if (a.fn === 'absence') k += '\n| summarize last_seen = max(TimeGenerated) by log_source_id\n| where last_seen < ago(' + (a.window_minutes || 60) + 'm)';
    }
    k += '\n| extend RiskScore = ' + GEN.riskFor(spec) + ', Technique = "' + spec.technique + '"';
    return k;
  };
  GEN.kqlTable = (spec) => { const t = spec.log_source_types || []; const map = { windows_security: 'SecurityEvent', active_directory: 'SecurityEvent', sysmon: 'Sysmon // or DeviceProcessEvents / DeviceEvents (Defender XDR)', edr: 'DeviceProcessEvents', powershell: 'Event // Microsoft-Windows-PowerShell/Operational (or DeviceEvents)', linux_auditd: 'Syslog // or auditd via AMA', dns: 'DnsEvents', identity: 'SigninLogs', cloud_audit: 'AzureActivity', web_server: 'W3CIISLog', firewall: 'CommonSecurityLog' }; for (const x of t) if (map[x]) return map[x]; return 'union * // set the table for your log source'; };

  // ---------- QRadar specification (NOT CRE syntax — intentionally a build spec) ----------
  GEN.toQRadarSpec = (spec) => {
    const L = [];
    L.push('QRADAR RULE SPECIFICATION — BUILD IN THE QRADAR RULE WIZARD (CRE)');
    L.push('===================================================================');
    L.push('IMPORTANT: This is a rule SPECIFICATION, not QRadar CRE syntax. QRadar custom');
    L.push('rules are constructed in the Rule Wizard; this document lists the exact tests,');
    L.push('building blocks, and parameters to configure. It is NOT auto-deployable.');
    L.push('');
    L.push('Rule name      : ' + spec.title);
    L.push('Rule type      : ' + (spec.agg && (spec.agg.fn === 'count' || spec.agg.fn === 'zscore' || spec.agg.fn === 'sequence') ? 'EVENT rule with counter / sequence test' : 'EVENT rule (simple test)'));
    L.push('Enabled        : No (create disabled; enable after validation)');
    L.push('ATT&CK         : ' + spec.technique + (spec.technique_name ? ' — ' + spec.technique_name : ''));
    L.push('Severity       : ' + spec.severity + '   Suggested magnitude inputs — Severity: ' + Math.round(GEN.riskFor(spec) / 10) + '/10, Credibility: 6/10, Relevance: by asset');
    L.push('');
    L.push('REQUIRED LOG SOURCES (ensure these are feeding QRadar and DSM-parsed):');
    (spec.log_source_types || []).forEach(t => L.push('  - ' + (SM.FW ? SM.FW.logSourceType(t).name : t)));
    L.push('');
    L.push('REQUIRED EVENT IDs / QIDs (map to QRadar QIDs via Log Activity → map to the right QID):');
    L.push('  ' + ((spec.event_ids && spec.event_ids.length) ? spec.event_ids.join(', ') : 'see field tests below'));
    L.push('');
    L.push('RULE TESTS (add each in the Rule Wizard; AND unless noted):');
    let n = 1;
    for (const p of (spec.selection || [])) L.push('  ' + (n++) + '. ' + GEN.qrTest(p));
    for (const p of (spec.exclusions || [])) L.push('  ' + (n++) + '. AND NOT: ' + GEN.qrTest(p));
    if (spec.agg) { const a = spec.agg;
      if (a.fn === 'count') L.push('  ' + (n++) + '. Counter test: "when at least ' + a.threshold + ' events are seen with the same ' + (a.group_by || []).join(' and ') + (a.distinct ? ' and different ' + a.distinct : '') + ' in ' + (a.window_minutes || 5) + ' minutes"');
      else if (a.fn === 'zscore') L.push('  ' + (n++) + '. Behavioural: use a QRadar Anomaly/Behavioural rule or an accumulated reference-set baseline; CRE counter cannot compute z-score directly. Specification: per ' + (a.group_by || []).join('/') + ', alert when daily count exceeds mean+' + a.threshold + 'σ of a 30-day baseline (maintain via accumulator).');
      else if (a.fn === 'new_value') L.push('  ' + (n++) + '. First-seen test: maintain a reference set of known ' + (a.observe || 'values') + ' per ' + (a.group_by || []).join('/') + '; test "when ' + (a.observe || 'value') + ' is NOT contained in reference set" and then add it (use a rule response to add to the set).');
      else if (a.fn === 'sequence') { L.push('  ' + (n++) + '. Sequence: implement with two rules + a reference set, or the "when these rules match in this order" test:'); (a.steps || []).forEach((s, i) => L.push('       step ' + (i + 1) + ': ' + s)); L.push('       window: ' + (a.window_minutes || 30) + ' minutes'); }
      else if (a.fn === 'absence') L.push('  ' + (n++) + '. Log source silence: use a QRadar "Log Source" health rule / anomaly detection — alert when an expected log source stops sending for ' + (a.window_minutes || 60) + ' minutes.');
    }
    if (spec.dependencies && spec.dependencies.length) { L.push(''); L.push('BUILDING BLOCK / REFERENCE SET DEPENDENCIES:'); spec.dependencies.forEach(d => L.push('  - ' + d)); }
    L.push('');
    L.push('RULE RESPONSE: Dispatch new event + ensure the offense is indexed by ' + ((spec.agg && spec.agg.group_by && spec.agg.group_by[0]) || 'Username/Source IP') + '. Do NOT auto-remediate.');
    L.push('');
    L.push('TUNING:'); (spec.tuning || ['Baseline before enabling.']).forEach(t => L.push('  - ' + t));
    L.push('KNOWN FALSE POSITIVES:'); (spec.fp || ['Unknown']).forEach(t => L.push('  - ' + t));
    return L.join('\n');
  };
  GEN.qrTest = (p) => { const f = fname(p.field, 'qradar'); const quoted = (x) => Array.isArray(x) ? x.map(y => '"' + y + '"').join(' or ') : '"' + x + '"'; switch (p.op) {
    case 'eq': case 'in': return 'when the event "' + f + '" is ' + quoted(p.value);
    case 'ne': return 'when the event "' + f + '" is NOT ' + quoted(p.value);
    case 'contains': case 'contains_any': return 'when the Payload / "' + f + '" matches (contains) ' + quoted(p.value) + ' (use AQL/custom property or regex)';
    case 'endswith': case 'endswith_any': case 'not_in': return 'when "' + f + '" ends with ' + quoted(p.value) + ' (regex custom property)';
    case 'gt': return 'when "' + f + '" is greater than ' + p.value;
    case 'regex': return 'when "' + f + '" matches regex "' + p.value + '"'; default: return JSON.stringify(p); } };

  GEN.riskFor = (spec) => spec.risk_score != null ? spec.risk_score : SM_SEV2RISK(spec.severity);

  // Build a full spec object from a scenario + inputs
  GEN.buildSpec = (scenario, { technique, techniqueName, platform, environment, severity, risk_score, extraTags = [], references = [] } = {}) => {
    const t = SM.FW && SM.FW.technique(technique);
    const tags = SM.uniq(['attack.' + technique.toLowerCase(), ...(t ? (t.tactics || []).map(x => 'attack.' + (SM.FW.tacticShort(x) || '').replace(/-/g, '_')) : []), ...extraTags]);
    return { title: scenario.name + ' (' + technique + ')', uuid: GEN.pseudoUuid(technique + scenario.id + (platform || '')), technique, technique_name: techniqueName || (t && t.name), scenario_id: scenario.id, objective: scenario.objective, description: scenario.objective + '  [ATT&CK ' + technique + (t ? ': ' + t.name : '') + ']', severity: severity || scenario.severity, risk_score: risk_score, log_source_types: scenario.log_source_types, event_ids: scenario.event_ids, selection: scenario.selection, exclusions: scenario.exclusions, agg: scenario.agg, fp: scenario.fp, tuning: scenario.tuning, tags, references, platforms_hint: environment && environment.platforms && environment.platforms[0], logic_type: scenario.logic_type, tests: scenario.tests };
  };
  GEN.pseudoUuid = (seed) => { const h = SM.hash(seed) + SM.hash(seed + 'x') + SM.hash(seed + 'yy') + SM.hash(seed + 'zzz'); return [h.slice(0, 8), h.slice(8, 12), '4' + h.slice(13, 16), '8' + h.slice(17, 20), h.slice(20, 32)].join('-'); };

  GEN.render = (spec, format) => { switch (format) {
    case 'sigma': return { body: GEN.toSigma(spec), lang: 'yaml' };
    case 'splunk': return { body: GEN.toSPL(spec), lang: 'spl' };
    case 'sentinel': return { body: GEN.toKQL(spec, 'sentinel'), lang: 'kql' };
    case 'elastic': return { body: GEN.toKQL(spec, 'elastic'), lang: 'kql' };
    case 'qradar': return { body: GEN.toQRadarSpec(spec), lang: 'text' };
    case 'json': return { body: JSON.stringify(spec, null, 2), lang: 'json' };
    case 'generic': return { body: GEN.toGeneric(spec), lang: 'text' };
    default: return { body: GEN.toSigma(spec), lang: 'yaml' }; } };
  GEN.toGeneric = (spec) => {
    const L = ['SIEM-NEUTRAL DETECTION SPECIFICATION', '====================================', 'Title: ' + spec.title, 'ATT&CK: ' + spec.technique + (spec.technique_name ? ' — ' + spec.technique_name : ''), 'Objective: ' + spec.objective, 'Logic type: ' + spec.logic_type, 'Severity: ' + spec.severity + '   Risk: ' + GEN.riskFor(spec), '', 'Data sources: ' + (spec.log_source_types || []).join(', '), 'Event IDs: ' + (spec.event_ids || []).join(', '), '', 'Match conditions (ALL):'];
    (spec.selection || []).forEach(p => L.push('  - ' + p.field + ' ' + p.op + ' ' + JSON.stringify(p.value)));
    if ((spec.exclusions || []).length) { L.push('Exclusions (NOT any):'); spec.exclusions.forEach(p => L.push('  - ' + p.field + ' ' + p.op + ' ' + JSON.stringify(p.value))); }
    if (spec.agg) L.push('', 'Aggregation: ' + JSON.stringify(spec.agg));
    L.push('', 'Tuning:'); (spec.tuning || []).forEach(t => L.push('  - ' + t)); L.push('False positives:'); (spec.fp || []).forEach(t => L.push('  - ' + t));
    L.push('', 'Validation test cases:'); (spec.tests || []).forEach(t => L.push('  - [' + t.expected + '] ' + t.name));
    return L.join('\n');
  };

  // Generate all scenarios for a technique as generated_rule records
  GEN.generateForTechnique = (technique, opts = {}) => {
    const kb = SM.Scenarios.get(technique); const t = SM.FW && SM.FW.technique(technique);
    if (!kb) return { technique, scenarios: [], note: 'No scenario template bundled for ' + technique + '. Use the custom scenario builder to author one, or map it to a parent technique.' };
    const platform = opts.platform || 'sigma';
    const recs = kb.scenarios.map(sc => { const spec = GEN.buildSpec(sc, { technique, techniqueName: kb.name, platform, environment: opts.environment, severity: opts.severity, risk_score: opts.risk_score }); const rendered = GEN.render(spec, platform); return { id: SM.uid('gen'), technique, technique_name: kb.name, scenario_id: sc.id, scenario_name: sc.name, objective: sc.objective, logic_type: sc.logic_type, target_platform: platform, severity: spec.severity, risk_score: GEN.riskFor(spec), spec, rendered_format: platform, rendered_body: rendered.body, rendered_lang: rendered.lang, required_telemetry: sc.log_source_types, event_ids: sc.event_ids, false_positives: sc.fp, tuning: sc.tuning, test_cases: sc.tests, expected_result: sc.tests && sc.tests[0] ? sc.tests[0].expected : 'match', maturity: 'generated_specification', lifecycle_stage: 'Proposed', created_at: SM.now(), siem_compatibility: GEN.compat(sc) }; });
    return { technique, technique_name: kb.name, scenarios: recs };
  };
  GEN.compat = (sc) => { const c = {}; const hasAgg = !!sc.agg; const seq = sc.agg && sc.agg.fn === 'sequence'; const stat = sc.agg && (sc.agg.fn === 'zscore' || sc.agg.fn === 'absence'); c.sigma = 'yes (correlation needs sigma-correlation for aggregation)'; c.splunk = 'yes'; c.sentinel = 'yes'; c.elastic = seq ? 'partial (sequence → EQL)' : 'yes'; c.qradar = stat ? 'spec only (behavioural/anomaly rule)' : (seq ? 'spec (multi-rule + reference set)' : 'spec (CRE rule wizard)'); return c; };
  SM.Generator = GEN;
})(globalThis.SM = globalThis.SM || {});
