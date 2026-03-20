# sentinel_web.py
# SENTINEL — Web Dashboard
# Run: python sentinel_web.py
# Open: http://localhost:5000

from flask import Flask, jsonify, request, Response
import os, sys, re, json, threading
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# Add the project folder to sys.path so email_forensics can be imported
# without requiring the user to set PYTHONPATH manually.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import email_forensics as ef

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Shared state — all mutations must hold _lock
# ---------------------------------------------------------------------------
_lock              = threading.Lock()
results_store      = []
analysis_running   = False
analysis_progress  = {"current": 0, "total": 0, "status": "idle"}


# ---------------------------------------------------------------------------
# Core analysis function — mirrors generate_report() but returns a dict
# ---------------------------------------------------------------------------

def generate_report_data(filename, offline=False):
    """Runs the full SENTINEL analysis pipeline for a single email file and
    returns a structured dict instead of printing to the terminal.

    Mirrors the logic in generate_report() exactly so results are identical
    to what the CLI produces. The web dashboard calls this function in a
    background thread and stores the returned dict in results_store so the
    browser can fetch it via /results.

    Args:
        filename: Email filename (basename only). validate_file_path() inside
                  email_forensics resolves it against the emails/ directory.
        offline:  When True, suppresses all external HTTP calls and uses
                  the local GeoLite2 DB and MySQL cache instead.

    Returns:
        dict of analysis results, or None if the file could not be read.
    """
    ef.set_offline_mode(offline)

    # --- Read header ---
    header = ef.read_header_file(filename)
    if not header:
        return None

    # --- Extract fields ---
    from_field  = ef.extract_field(header, "From")
    reply_to    = ef.extract_field(header, "Reply-To")
    return_path = ef.extract_field(header, "Return-Path")
    subject     = ef.extract_field(header, "Subject")

    # --- IPs ---
    ips            = ef.extract_ip_addresses(header)
    originating_ip = ips[0] if ips else ""

    # --- Spoofing ---
    flags        = ef.check_spoofing(from_field, reply_to, return_path)
    tld_detected = any("uses a TLD" in flag for flag in flags)

    # --- IP intelligence ---
    tor_vpn_detected      = False
    malicious_ip_detected = False
    max_abuse_score       = 0
    for ip in ips:
        result = ef.analyze_ip_intelligence(ip)
        if result["tor_vpn_detected"]:
            tor_vpn_detected = True
        if result["malicious_ip"]:
            malicious_ip_detected = True
        max_abuse_score = max(max_abuse_score, result["abuse_score"])

    # --- SPF / DKIM ---
    domain_match  = re.search(r'@([\w.-]+)', from_field)
    sender_domain = domain_match.group(1) if domain_match else None
    if sender_domain:
        spf_result  = ef.check_spf(sender_domain)
        dkim_result = ef.check_dkim(header, sender_domain)
    else:
        spf_result  = {"spf_pass": False}
        dkim_result = {"dkim_key_found": False}

    # --- Urgency ---
    urgency_result = ef.detect_urgency(subject, None)

    # --- MITRE mapping ---
    mitre_findings = {
        "spoofing_detected": bool(flags),
        "tor_vpn_detected":  tor_vpn_detected,
        "malicious_ip":      malicious_ip_detected,
        "spf_pass":          spf_result.get("spf_pass",        True),
        "dkim_pass":         dkim_result.get("dkim_key_found", True),
        "urgency_detected":  urgency_result["urgency_detected"],
    }
    techniques = ef.map_to_mitre(mitre_findings)

    # --- Confidence score ---
    confidence_findings = {
        "spoofing_detected": bool(flags),
        "malicious_ip":      malicious_ip_detected,
        "tor_vpn_detected":  tor_vpn_detected,
        "spf_pass":          spf_result.get("spf_pass",        True),
        "dkim_pass":         dkim_result.get("dkim_key_found", True),
        "urgency_detected":  urgency_result["urgency_detected"],
        "urgency_score":     urgency_result["urgency_score"],
        "abuse_score":       max_abuse_score,
        "techniques_count":  len(techniques),
        "suspicious_tld":    tld_detected,
    }
    confidence = ef.calculate_confidence(confidence_findings)

    # --- Analyst notes ---
    notes_findings = {
        "spf_pass":          spf_result.get("spf_pass",        False),
        "dkim_pass":         dkim_result.get("dkim_key_found", False),
        "tor_vpn_detected":  tor_vpn_detected,
        "abuse_score":       max_abuse_score,
        "urgency_detected":  urgency_result["urgency_detected"],
        "body_analyzed":     False,
        "risk_level":        confidence["risk_level"],
        "confidence_score":  confidence["confidence_score"],
        "spoofing_detected": bool(flags),
    }
    analyst_notes = ef.generate_analyst_notes(notes_findings)

    # --- AI analysis ---
    report_summary = (
        f"Risk level: {confidence['risk_level']}\n"
        f"Confidence score: {confidence['confidence_score']}/100\n"
        f"Spoofing detected: {bool(flags)}\n"
        f"Malicious IP: {malicious_ip_detected}\n"
        f"Tor/VPN detected: {tor_vpn_detected}\n"
        f"SPF: {'PASS' if spf_result.get('spf_pass') else 'FAIL'}\n"
        f"DKIM: {'PASS' if dkim_result.get('dkim_key_found') else 'FAIL'}\n"
        f"Urgency detected: {urgency_result['urgency_detected']}\n"
        f"MITRE techniques: {len(techniques)}"
    )
    ai_analysis      = ef.analyze_with_ai(mitre_findings, report_summary)
    react_assessment = ef.run_react_agent(mitre_findings, header, max_steps=5)

    return {
        "filename":          os.path.basename(filename),
        "risk_level":        confidence["risk_level"],
        "confidence_score":  confidence["confidence_score"],
        "score_breakdown":   confidence.get("score_breakdown", []),
        "spoofing_detected": bool(flags),
        "spf_pass":          bool(spf_result.get("spf_pass")),
        "dkim_pass":         bool(dkim_result.get("dkim_key_found")),
        "tor_vpn_detected":  tor_vpn_detected,
        "malicious_ip":      malicious_ip_detected,
        "abuse_score":       max_abuse_score,
        "urgency_detected":  urgency_result["urgency_detected"],
        "techniques":        techniques,
        "analyst_notes":     analyst_notes,
        "ai_analysis":       ai_analysis,
        "react_assessment":  react_assessment,
        "from_field":        from_field,
        "subject":           subject,
        "originating_ip":    originating_ip,
        "timestamp":         datetime.now().isoformat(),
    }


# ---------------------------------------------------------------------------
# Background analysis thread
# ---------------------------------------------------------------------------

def _run_analysis(folder, offline):
    """Scans folder for .txt/.eml files and analyses each one.

    Runs in a daemon thread. Updates analysis_progress under _lock so the
    main thread (serving /progress requests) always sees a consistent state.
    On completion sets analysis_running = False so the browser stops polling.
    """
    global results_store, analysis_running, analysis_progress

    import pathlib
    folder_path = pathlib.Path(folder)
    email_files = (
        list(folder_path.glob("*.txt")) +
        list(folder_path.glob("*.eml"))
    )

    with _lock:
        results_store                 = []
        analysis_progress["total"]    = len(email_files)
        analysis_progress["current"]  = 0
        analysis_progress["status"]   = "running"

    for i, f in enumerate(email_files):
        with _lock:
            analysis_progress["current"] = i
            analysis_progress["status"]  = f"Analyzing {f.name}..."

        try:
            data = generate_report_data(f.name, offline)
            if data:
                with _lock:
                    results_store.append(data)
        except Exception as e:
            # type(e).__name__ only — raw messages may contain file paths
            with _lock:
                results_store.append({
                    "filename":         f.name,
                    "risk_level":       "ERROR",
                    "confidence_score": 0,
                    "error":            type(e).__name__,
                })

    with _lock:
        analysis_progress["current"] = len(email_files)
        analysis_progress["status"]  = "complete"
        analysis_running             = False


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    """Serves the dashboard HTML page."""
    return Response(DASHBOARD_HTML, content_type="text/html; charset=utf-8")


@app.route("/analyze", methods=["POST"])
def analyze():
    """Accepts {folder, offline} JSON and starts analysis in a background thread."""
    global analysis_running

    data    = request.get_json(silent=True) or {}
    folder  = data.get("folder",  "emails")
    offline = bool(data.get("offline", False))

    # --- Input validation: folder ---
    if not isinstance(folder, str):
        folder = "emails"
    folder = folder.strip()
    folder = re.sub(r'[\x00-\x1f\x7f]', '', folder)
    if not folder:
        folder = "emails"

    # Resolve against script dir and confirm the directory exists.
    # os.path.realpath() collapses any '..' traversal attempts so the
    # resolved path cannot escape the project root.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    resolved   = os.path.realpath(os.path.join(script_dir, folder))
    if not os.path.isdir(resolved):
        return jsonify({"status": "error", "message": "Folder not found"}), 400

    with _lock:
        if analysis_running:
            return jsonify({"status": "busy"}), 409
        analysis_running = True

    t = threading.Thread(
        target=_run_analysis,
        args=(resolved, offline),
        daemon=True,
    )
    t.start()
    return jsonify({"status": "started"})


@app.route("/progress")
def progress():
    """Returns current progress and running state as JSON."""
    with _lock:
        return jsonify({
            "running":  analysis_running,
            "progress": dict(analysis_progress),
        })


@app.route("/results")
def results():
    """Returns the completed results store as JSON."""
    with _lock:
        return jsonify(list(results_store))


# ---------------------------------------------------------------------------
# Dashboard HTML — single self-contained page, no external dependencies
# ---------------------------------------------------------------------------

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL Dashboard</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }

  /* ── Header ── */
  header {
    background: #1e293b;
    border-bottom: 1px solid #334155;
    padding: 1rem 2rem;
    display: flex;
    align-items: center;
    gap: 1rem;
  }
  header .logo { font-size: 1.5rem; font-weight: 800; color: #3b82f6; letter-spacing: -.02em; }
  header .sub  { color: #64748b; font-size: 0.85rem; }

  /* ── Layout ── */
  main {
    flex: 1;
    display: grid;
    grid-template-columns: 300px 1fr;
    gap: 1.5rem;
    padding: 1.5rem 2rem;
    align-items: start;
  }
  @media (max-width: 768px) { main { grid-template-columns: 1fr; } }

  /* ── Cards / Panels ── */
  .panel {
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 10px;
    padding: 1.25rem;
  }
  .panel h2 {
    font-size: 0.8rem;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: .08em;
    margin-bottom: 1rem;
  }

  /* ── Control Panel ── */
  label.field-label {
    display: block;
    font-size: 0.82rem;
    color: #94a3b8;
    margin-bottom: .3rem;
    margin-top: .8rem;
  }
  input[type=text] {
    width: 100%;
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 6px;
    color: #e2e8f0;
    padding: .5rem .75rem;
    font-size: 0.9rem;
    outline: none;
  }
  input[type=text]:focus { border-color: #3b82f6; }

  .mode-group {
    display: flex;
    gap: 1.2rem;
    margin-top: .8rem;
    font-size: 0.88rem;
    color: #94a3b8;
  }
  .mode-group label { display: flex; align-items: center; gap: .4rem; cursor: pointer; }

  .btn-primary {
    width: 100%;
    margin-top: 1rem;
    padding: .65rem 1rem;
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 7px;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    transition: background .15s;
  }
  .btn-primary:hover { background: #2563eb; }
  .btn-primary:disabled { background: #334155; color: #64748b; cursor: not-allowed; }

  /* ── Progress ── */
  #progress-wrap { margin-top: 1rem; display: none; }
  .progress-track {
    background: #0f172a;
    border-radius: 999px;
    height: 8px;
    overflow: hidden;
  }
  #progress-fill {
    background: #3b82f6;
    height: 8px;
    width: 0%;
    border-radius: 999px;
    transition: width .3s;
  }
  #status-text { font-size: 0.8rem; color: #64748b; margin-top: .4rem; }

  /* ── Summary Cards ── */
  .summary-cards {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: .75rem;
    margin-bottom: 1.25rem;
  }
  .s-card {
    background: #0f172a;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: .75rem;
    text-align: center;
  }
  .s-card .s-num { font-size: 1.8rem; font-weight: 800; line-height: 1; }
  .s-card .s-lbl { font-size: 0.72rem; color: #64748b; margin-top: .25rem; text-transform: uppercase; letter-spacing: .06em; }
  .s-card.high   .s-num { color: #dc2626; }
  .s-card.medium .s-num { color: #d97706; }
  .s-card.low    .s-num { color: #16a34a; }

  /* ── Results Table ── */
  .table-wrap { overflow-x: auto; }
  table { width: 100%; border-collapse: collapse; font-size: 0.87rem; }
  th {
    text-align: left;
    padding: .55rem .75rem;
    background: #0f172a;
    color: #64748b;
    font-weight: 600;
    border-bottom: 1px solid #334155;
    white-space: nowrap;
  }
  td { padding: .55rem .75rem; border-bottom: 1px solid #1e293b; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #0f172a44; }

  /* ── Badges ── */
  .badge {
    display: inline-block;
    padding: 2px 9px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 700;
    letter-spacing: .04em;
  }
  .badge.high   { background: #dc2626; color: #fff; }
  .badge.medium { background: #d97706; color: #fff; }
  .badge.low    { background: #16a34a; color: #fff; }
  .badge.error  { background: #6b7280; color: #fff; }
  .ok  { color: #16a34a; font-weight: 600; }
  .bad { color: #dc2626; font-weight: 600; }

  .btn-sm {
    padding: 4px 12px;
    background: #3b82f6;
    color: #fff;
    border: none;
    border-radius: 5px;
    font-size: 0.8rem;
    cursor: pointer;
    white-space: nowrap;
  }
  .btn-sm:hover { background: #2563eb; }

  /* ── Modal ── */
  #modal {
    display: none;
    position: fixed;
    inset: 0;
    z-index: 1000;
    align-items: flex-start;
    justify-content: center;
    padding: 2rem 1rem;
  }
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background: #000a;
  }
  .modal-content {
    position: relative;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 12px;
    width: 100%;
    max-width: 780px;
    max-height: 88vh;
    overflow-y: auto;
    padding: 1.75rem;
    z-index: 1;
  }
  .modal-close {
    position: absolute;
    top: 1rem;
    right: 1rem;
    background: #334155;
    border: none;
    color: #e2e8f0;
    border-radius: 6px;
    padding: 4px 10px;
    cursor: pointer;
    font-size: 1rem;
  }
  .modal-close:hover { background: #475569; }
  .modal-section { margin-top: 1.25rem; }
  .modal-section h3 {
    font-size: 0.78rem;
    font-weight: 700;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: .07em;
    margin-bottom: .65rem;
    padding-bottom: .4rem;
    border-bottom: 1px solid #334155;
  }
  .kv { display: grid; grid-template-columns: 150px 1fr; gap: .3rem .75rem; font-size: 0.88rem; margin-bottom: .25rem; }
  .kv span:first-child { color: #94a3b8; }
  .kv span:last-child  { word-break: break-all; }
  .inner-table { width: 100%; border-collapse: collapse; font-size: 0.84rem; }
  .inner-table th { background: #0f172a; color: #64748b; padding: .4rem .6rem; text-align: left; border-bottom: 1px solid #334155; }
  .inner-table td { padding: .4rem .6rem; border-bottom: 1px solid #1e293b44; vertical-align: top; }
  .pre-text { white-space: pre-wrap; font-size: 0.88rem; color: #cbd5e1; line-height: 1.7; }
  ul.plain { padding-left: 1.25rem; }
  ul.plain li { font-size: 0.88rem; margin-bottom: .4rem; color: #cbd5e1; }

  /* ── Footer ── */
  footer {
    background: #1e293b;
    border-top: 1px solid #334155;
    padding: .75rem 2rem;
    font-size: 0.78rem;
    color: #475569;
    display: flex;
    justify-content: space-between;
  }
  .empty-msg { color: #475569; font-style: italic; font-size: 0.88rem; padding: 1.5rem 0; text-align: center; }
</style>
</head>
<body>

<header>
  <div>
    <div class="logo">&#x1F6E1; SENTINEL</div>
    <div class="sub">Local AI Phishing Intelligence</div>
  </div>
</header>

<main>

  <!-- ── Control Panel ── -->
  <div class="panel">
    <h2>Analysis</h2>

    <label class="field-label">Emails Folder</label>
    <input type="text" id="folder" value="emails" placeholder="emails">

    <label class="field-label">Mode</label>
    <div class="mode-group">
      <label><input type="radio" name="mode" value="online" checked> Online</label>
      <label><input type="radio" name="mode" value="offline"> Offline</label>
    </div>

    <button class="btn-primary" id="start-btn" onclick="startAnalysis()">
      &#9654; Start Analysis
    </button>

    <div id="progress-wrap">
      <div class="progress-track"><div id="progress-fill"></div></div>
      <div id="status-text">Idle</div>
    </div>
  </div>

  <!-- ── Results Panel ── -->
  <div class="panel">
    <h2>Results</h2>

    <div class="summary-cards">
      <div class="s-card">
        <div class="s-num" id="cnt-total">0</div>
        <div class="s-lbl">Total</div>
      </div>
      <div class="s-card high">
        <div class="s-num" id="cnt-high">0</div>
        <div class="s-lbl">High Risk</div>
      </div>
      <div class="s-card medium">
        <div class="s-num" id="cnt-medium">0</div>
        <div class="s-lbl">Medium</div>
      </div>
      <div class="s-card low">
        <div class="s-num" id="cnt-low">0</div>
        <div class="s-lbl">Low</div>
      </div>
    </div>

    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Filename</th>
            <th>Risk</th>
            <th>Score</th>
            <th>Spoofing</th>
            <th>SPF</th>
            <th>DKIM</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="results-body">
          <tr><td colspan="7"><p class="empty-msg">No results yet. Run an analysis to begin.</p></td></tr>
        </tbody>
      </table>
    </div>
  </div>

</main>

<!-- ── Modal ── -->
<div id="modal">
  <div class="modal-backdrop" onclick="closeModal()"></div>
  <div class="modal-content">
    <button class="modal-close" onclick="closeModal()">&#x2715;</button>
    <div id="modal-body"></div>
  </div>
</div>

<footer>
  <span>&#x1F512; Analysis performed on-device &mdash; no email content leaves this machine</span>
  <span>SENTINEL v0.8</span>
</footer>

<script>
"use strict";

let allResults = [];
let pollTimer  = null;

// ── XSS-safe HTML escape (mirrors Python html.escape) ──
function esc(s) {
  if (s === null || s === undefined) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function truncate(s, n) {
  s = s || '';
  return s.length > n ? s.slice(0, n) + '\u2026' : s;
}

// ── Start analysis ──
function startAnalysis() {
  const folder  = document.getElementById('folder').value.trim();
  const offline = document.querySelector('input[name="mode"]:checked').value === 'offline';
  const btn     = document.getElementById('start-btn');

  btn.disabled = true;
  document.getElementById('progress-wrap').style.display = 'block';
  document.getElementById('status-text').textContent     = 'Starting\u2026';
  document.getElementById('progress-fill').style.width   = '0%';

  fetch('/analyze', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({folder, offline}),
  })
  .then(r => r.json())
  .then(d => {
    if (d.status === 'started') {
      pollTimer = setInterval(pollProgress, 1000);
    } else if (d.status === 'busy') {
      alert('An analysis is already running.');
      btn.disabled = false;
    } else {
      alert('Error: ' + (d.message || d.status));
      btn.disabled = false;
    }
  })
  .catch(e => {
    alert('Failed to start analysis: ' + e);
    btn.disabled = false;
  });
}

// ── Poll /progress every second ──
function pollProgress() {
  fetch('/progress')
    .then(r => r.json())
    .then(d => {
      const p   = d.progress;
      const pct = p.total > 0 ? Math.round((p.current / p.total) * 100) : 0;
      document.getElementById('progress-fill').style.width = pct + '%';
      document.getElementById('status-text').textContent   = p.status;

      if (!d.running && p.status === 'complete') {
        clearInterval(pollTimer);
        pollTimer = null;
        document.getElementById('start-btn').disabled = false;
        loadResults();
      }
    })
    .catch(() => {});
}

// ── Fetch and render results ──
function loadResults() {
  fetch('/results')
    .then(r => r.json())
    .then(data => {
      allResults = data;
      renderCards(data);
      renderTable(data);
    })
    .catch(e => alert('Failed to load results: ' + e));
}

function renderCards(data) {
  document.getElementById('cnt-total').textContent  = data.length;
  document.getElementById('cnt-high').textContent   = data.filter(r => r.risk_level === 'HIGH').length;
  document.getElementById('cnt-medium').textContent = data.filter(r => r.risk_level === 'MEDIUM').length;
  document.getElementById('cnt-low').textContent    = data.filter(r => r.risk_level === 'LOW').length;
}

function renderTable(data) {
  const tbody = document.getElementById('results-body');
  if (!data.length) {
    tbody.innerHTML = '<tr><td colspan="7"><p class="empty-msg">No emails found in the specified folder.</p></td></tr>';
    return;
  }
  tbody.innerHTML = '';
  data.forEach(function(r, i) {
    const lvl = (r.risk_level || 'unknown').toLowerCase();
    const tr  = document.createElement('tr');
    tr.innerHTML =
      '<td title="' + esc(r.filename) + '">' + esc(truncate(r.filename, 32)) + '</td>' +
      '<td><span class="badge ' + lvl + '">' + esc(r.risk_level || 'UNKNOWN') + '</span></td>' +
      '<td>' + (r.confidence_score || 0) + '/100</td>' +
      '<td>' + (r.spoofing_detected ? '<span class="bad">&#x26A0;&#xFE0F; Yes</span>' : '<span class="ok">&#x2705; No</span>') + '</td>' +
      '<td>' + (r.spf_pass  ? '<span class="ok">PASS</span>' : '<span class="bad">FAIL</span>') + '</td>' +
      '<td>' + (r.dkim_pass ? '<span class="ok">PASS</span>' : '<span class="bad">FAIL</span>') + '</td>' +
      '<td><button class="btn-sm" onclick="showModal(' + i + ')">View Report</button></td>';
    tbody.appendChild(tr);
  });
}

// ── Modal ──
function showModal(i) {
  const r = allResults[i];
  if (!r) return;

  const riskCols  = {HIGH: '#dc2626', MEDIUM: '#d97706', LOW: '#16a34a'};
  const riskColor = riskCols[r.risk_level] || '#6b7280';

  // MITRE table rows
  let techRows = '';
  (r.techniques || []).forEach(function(t) {
    if (typeof t !== 'object' || !t) return;
    techRows +=
      '<tr>' +
      '<td>' + esc(t.technique_id   || '') + '</td>' +
      '<td>' + esc(t.technique_name || '') + '</td>' +
      '<td>' + esc(t.tactic         || '') + '</td>' +
      '<td>' + esc(t.reason         || '') + '</td>' +
      '</tr>';
  });

  // Score breakdown
  let bdItems = '';
  (r.score_breakdown || []).forEach(function(b) {
    bdItems += '<li>' + esc(String(b)) + '</li>';
  });

  // Analyst notes
  let noteItems = '';
  (r.analyst_notes || []).forEach(function(n) {
    noteItems += '<li>' + esc(String(n)) + '</li>';
  });

  document.getElementById('modal-body').innerHTML =
    '<div style="border-left:5px solid ' + riskColor + ';padding-left:1rem;margin-bottom:1.5rem">' +
      '<h2 style="font-size:1.15rem;margin-bottom:.3rem">' + esc(r.filename || '') + '</h2>' +
      '<span style="background:' + riskColor + ';color:#fff;padding:3px 12px;border-radius:4px;font-weight:700;font-size:.85rem">' +
        esc(r.risk_level || 'UNKNOWN') + ' RISK &mdash; ' + (r.confidence_score || 0) + '/100' +
      '</span>' +
    '</div>' +

    '<div class="modal-section">' +
      '<h3>Email Details</h3>' +
      '<div class="kv"><span>From</span><span>'            + esc(r.from_field      || '\u2014') + '</span></div>' +
      '<div class="kv"><span>Subject</span><span>'         + esc(r.subject         || '\u2014') + '</span></div>' +
      '<div class="kv"><span>Originating IP</span><span>'  + esc(r.originating_ip  || '\u2014') + '</span></div>' +
      '<div class="kv"><span>Analysed</span><span>'        + esc(r.timestamp       || '\u2014') + '</span></div>' +
    '</div>' +

    '<div class="modal-section">' +
      '<h3>Indicators</h3>' +
      '<div class="kv"><span>Spoofing</span><span>'       + (r.spoofing_detected ? '<span class="bad">&#x26A0;&#xFE0F; Detected</span>' : '<span class="ok">&#x2705; None</span>')   + '</span></div>' +
      '<div class="kv"><span>SPF</span><span>'            + (r.spf_pass          ? '<span class="ok">&#x2705; PASS</span>'              : '<span class="bad">&#x274C; FAIL</span>')  + '</span></div>' +
      '<div class="kv"><span>DKIM</span><span>'           + (r.dkim_pass         ? '<span class="ok">&#x2705; PASS</span>'              : '<span class="bad">&#x274C; FAIL</span>')  + '</span></div>' +
      '<div class="kv"><span>Tor / VPN</span><span>'      + (r.tor_vpn_detected  ? '<span class="bad">&#x26A0;&#xFE0F; Detected</span>' : '<span class="ok">&#x2705; None</span>')   + '</span></div>' +
      '<div class="kv"><span>Malicious IP</span><span>'   + (r.malicious_ip      ? '<span class="bad">&#x1F6A8; Yes</span>'             : '<span class="ok">&#x2705; No</span>')     + '</span></div>' +
      '<div class="kv"><span>AbuseIPDB Score</span><span>' + (r.abuse_score || 0) + '/100</span></div>' +
      '<div class="kv"><span>Urgency Language</span><span>' + (r.urgency_detected ? '<span class="bad">&#x26A0;&#xFE0F; Detected</span>' : '<span class="ok">&#x2705; None</span>')  + '</span></div>' +
    '</div>' +

    (bdItems
      ? '<div class="modal-section"><h3>Score Breakdown</h3><ul class="plain">' + bdItems + '</ul></div>'
      : '') +

    (techRows
      ? '<div class="modal-section"><h3>MITRE ATT&amp;CK</h3>' +
          '<table class="inner-table"><thead><tr><th>ID</th><th>Technique</th><th>Tactic</th><th>Reason</th></tr></thead>' +
          '<tbody>' + techRows + '</tbody></table></div>'
      : '') +

    (noteItems
      ? '<div class="modal-section"><h3>Analyst Notes</h3><ul class="plain">' + noteItems + '</ul></div>'
      : '') +

    '<div class="modal-section">' +
      '<h3>&#x1F916; AI Analysis (Mistral 7B &mdash; Local)</h3>' +
      '<p class="pre-text">' + esc(r.ai_analysis || 'Not available.') + '</p>' +
    '</div>' +

    '<div class="modal-section">' +
      '<h3>&#x1F50D; ReAct Agent Assessment</h3>' +
      '<p class="pre-text">' + esc(r.react_assessment || 'Not available.') + '</p>' +
    '</div>';

  document.getElementById('modal').style.display = 'flex';
}

function closeModal() {
  document.getElementById('modal').style.display = 'none';
}

// Close modal on Escape key
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') closeModal();
});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # host="127.0.0.1" — localhost only, never exposed on the network.
    # debug=False — never enable debug mode in production; the Werkzeug
    # debugger exposes a remote code execution surface if reachable.
    app.run(debug=False, host="127.0.0.1", port=5000)
