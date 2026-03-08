from graphviz import Digraph

d = Digraph('PhishGuard', format='png')
d.attr(rankdir='TB', bgcolor='#070d14', fontname='Helvetica', pad='0.5', splines='ortho', nodesep='0.6', ranksep='0.7')

node_style = dict(fontname='Helvetica', fontsize='11', fontcolor='#e2eaf5', style='filled', height='0.45', margin='0.2,0.1')

d.node('input',  'Email Input\n(.eml / paste / Gmail)',          shape='rectangle', fillcolor='#112233', color='#1a8fff', penwidth='1.5', **node_style)
d.node('parser', 'Stage 1: Email Parser\nemail_parser.py',       shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)
d.node('ioc',    'Stage 2: IOC Extraction\nGroq LLaMA 3.1 + Regex', shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)

with d.subgraph() as s:
    s.attr(rank='same')
    s.node('enrich', 'Stage 3a: Threat Intel\nVirusTotal · AbuseIPDB',  shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)
    s.node('attach', 'Stage 3b: Attachment Scan\nVirusTotal Files API', shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)

d.node('score',  'Stage 4: Risk Scoring\nWeighted Signal Model (0-100)', shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)
d.node('mitre',  'MITRE ATT&CK Mapping\nT1566 · T1598 · T1583',         shape='rectangle', fillcolor='#112233', color='#a78bfa', penwidth='1.5', **node_style)
d.node('report', 'Stage 5: Incident Report\nAI-Generated SOC Report',   shape='rectangle', fillcolor='#0f1e2e', color='#1e3a5f', **node_style)

with d.subgraph() as s:
    s.attr(rank='same')
    s.node('dashboard', 'Web Dashboard\nFlask · 5 Views',             shape='rectangle', fillcolor='#112233', color='#1a8fff', penwidth='1.5', **node_style)
    s.node('slack',     'Slack Alert\n#soc-alerts',                    shape='rectangle', fillcolor='#112233', color='#2ed573', penwidth='1.5', **node_style)
    s.node('siem',      'SIEM Log\nECS NDJSON - Splunk/Elastic/Wazuh', shape='rectangle', fillcolor='#112233', color='#2ed573', penwidth='1.5', **node_style)

e = dict(color='#1e3a5f', arrowsize='0.7')
d.edge('input','parser',**e); d.edge('parser','ioc',**e)
d.edge('ioc','enrich',**e);   d.edge('ioc','attach',**e)
d.edge('enrich','score',**e); d.edge('attach','score',**e)
d.edge('score','mitre',**e);  d.edge('mitre','report',**e)
d.edge('report','dashboard',**e); d.edge('report','slack',**e); d.edge('report','siem',**e)

d.render('screenshot/architecture', cleanup=True)
print("Saved: screenshot/architecture.png")
