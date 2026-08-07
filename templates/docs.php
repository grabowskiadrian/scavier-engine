<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ScavierEngine</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }

body {
    font-family: -apple-system, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
    background: #0a0a0a;
    color: #e0e0e0;
    line-height: 1.6;
}

.container { max-width: 960px; margin: 0 auto; padding: 48px 24px; }

.header { display: flex; align-items: baseline; gap: 12px; margin-bottom: 8px; }
.header h1 { font-size: 1.4rem; font-weight: 700; color: #fff; letter-spacing: -0.02em; }
.header .ver { font-size: 0.75rem; color: #444; font-weight: 400; }

.header-desc {
    color: #777; font-size: 0.85rem; margin-bottom: 40px;
    padding-bottom: 32px; border-bottom: 1px solid #1a1a1a;
}

/* Analyze */
.analyze-bar { margin-bottom: 48px; }
.analyze-label { font-size: 0.7rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.1em; color: #555; margin-bottom: 10px; }

.input-row { display: flex; gap: 10px; margin-bottom: 14px; }
.input-row input {
    flex: 1; background: #222; border: 1px solid #555; border-radius: 6px;
    padding: 12px 16px; color: #fff;
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.9rem;
    outline: none; transition: border-color 0.2s, box-shadow 0.2s;
}
.input-row input:focus { border-color: #999; box-shadow: 0 0 0 1px #444; }
.input-row input::placeholder { color: #888; }

.input-row button {
    background: #fff; color: #000; border: none; border-radius: 6px;
    padding: 10px 24px; font-size: 0.8rem; font-weight: 600;
    cursor: pointer; transition: opacity 0.2s; white-space: nowrap;
}
.input-row button:hover { opacity: 0.85; }
.input-row button:disabled { opacity: 0.4; cursor: not-allowed; }

/* Chips */
.chip-section { margin-bottom: 16px; }

.chip-cat {
    font-size: 0.6rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.1em; color: #555; margin: 10px 0 6px 0; cursor: pointer;
    user-select: none; transition: color 0.2s;
}
.chip-cat:first-child { margin-top: 0; }
.chip-cat:hover { color: #888; }

.chip-row { display: flex; flex-wrap: wrap; gap: 5px; }

.chip {
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.7rem; padding: 3px 10px; border-radius: 4px;
    border: 1px solid #282845; background: #181828; color: #a5b4fc;
    cursor: pointer; user-select: none; transition: all 0.15s;
    position: relative;
}

.chip:hover { border-color: #4040a0; background: #202048; }
.chip.off { background: #111; color: #444; border-color: #1a1a1a; }
.chip.off:hover { color: #666; border-color: #333; }

/* Tooltip */
.chip .tip {
    display: none; position: absolute; bottom: calc(100% + 6px); left: 50%;
    transform: translateX(-50%); background: #222; color: #bbb;
    font-family: -apple-system, sans-serif; font-size: 0.68rem;
    padding: 5px 9px; border-radius: 4px; white-space: nowrap;
    border: 1px solid #333; z-index: 10; pointer-events: none;
    box-shadow: 0 4px 12px rgba(0,0,0,0.4);
}
.chip .tip::after {
    content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%);
    border: 4px solid transparent; border-top-color: #333;
}
.chip:hover .tip { display: block; }

.chip-actions {
    display: flex; gap: 12px; margin-top: 8px;
}
.chip-action {
    font-size: 0.6rem; color: #444; cursor: pointer;
    text-transform: uppercase; letter-spacing: 0.05em;
    border: none; background: none; transition: color 0.2s;
}
.chip-action:hover { color: #888; }

/* Result */
.result-area { margin-top: 16px; display: none; }
.result-area.visible { display: block; }
.result-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; }
.result-meta { font-size: 0.7rem; color: #666; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; }
.result-meta .status-ok { color: #4ade80; }
.result-meta .status-err { color: #f87171; }
.result-copy {
    background: none; border: 1px solid #333; border-radius: 4px;
    padding: 2px 8px; font-size: 0.65rem; color: #666; cursor: pointer;
    text-transform: uppercase; letter-spacing: 0.05em; transition: all 0.2s;
}
.result-copy:hover { border-color: #444; color: #888; }
.result-copy.copied { border-color: #4ade80; color: #4ade80; }

.result-json {
    background: #111; border: 1px solid #252525; border-radius: 6px;
    padding: 16px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.78rem; color: #999; overflow-x: auto; white-space: pre;
    max-height: 500px; overflow-y: auto; line-height: 1.5;
}
.result-json .json-key { color: #c9a0ff; }
.result-json .json-str { color: #4ade80; }
.result-json .json-num { color: #fbbf24; }
.result-json .json-bool { color: #60a5fa; }
.result-json .json-null { color: #555; }

/* Sections */
.section { margin-bottom: 48px; }
.section-title {
    font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.1em; color: #888; margin-bottom: 14px;
    padding-bottom: 8px; border-bottom: 1px solid #1e1e1e;
}

.endpoint { background: #111; border: 1px solid #252525; border-radius: 6px; padding: 16px 20px; margin-bottom: 12px; }
.endpoint .method { display: inline-block; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; padding: 2px 7px; border-radius: 3px; margin-right: 8px; vertical-align: middle; }
.method-get { background: #1a2e1a; color: #4ade80; }
.method-post { background: #2e2a1a; color: #facc15; }
.endpoint .path { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.9rem; color: #ddd; }
.endpoint .ep-desc { color: #777; font-size: 0.78rem; margin-top: 8px; line-height: 1.6; }
.params { margin-top: 10px; font-size: 0.8rem; }
.params code { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; color: #c9a0ff; font-size: 0.78rem; }
.params .required { color: #f87171; font-size: 0.65rem; font-weight: 600; text-transform: uppercase; margin-left: 4px; }
.params .optional { color: #666; font-size: 0.65rem; margin-left: 4px; }

.code-block {
    background: #111; border: 1px solid #252525; border-radius: 6px;
    padding: 12px 16px; margin-bottom: 8px;
    font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; font-size: 0.78rem;
    color: #999; overflow-x: auto; cursor: pointer; position: relative; transition: border-color 0.2s;
}
.code-block:hover { border-color: #333; }
.code-block::after { content: 'copy'; position: absolute; right: 10px; top: 50%; transform: translateY(-50%); font-size: 0.6rem; color: #444; text-transform: uppercase; letter-spacing: 0.05em; transition: color 0.2s; }
.code-block:hover::after { color: #666; }
.code-block.copied::after { content: 'copied'; color: #4ade80; }
.code-block .hi { color: #ccc; }

.pre-block {
    background: #111; border: 1px solid #252525; border-radius: 6px;
    padding: 14px 16px; font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
    font-size: 0.78rem; color: #999; white-space: pre; overflow-x: auto;
    cursor: pointer; position: relative; transition: border-color 0.2s;
}
.pre-block:hover { border-color: #333; }
.pre-block::after { content: 'copy'; position: absolute; right: 10px; top: 10px; font-size: 0.6rem; color: #444; text-transform: uppercase; letter-spacing: 0.05em; }
.pre-block:hover::after { color: #666; }
.pre-block.copied::after { content: 'copied'; color: #4ade80; }
.pre-block .key { color: #c9a0ff; }
.pre-block .str { color: #4ade80; }

.two-col { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
.col-label { font-size: 0.65rem; text-transform: uppercase; letter-spacing: 0.1em; color: #666; margin-bottom: 8px; font-weight: 600; }
.example-prompt { background: #111; border: 1px solid #252525; border-radius: 6px; padding: 16px; font-size: 0.82rem; color: #888; line-height: 1.7; }
.example-prompt .prompt-text { color: #bbb; margin-bottom: 10px; }
.example-prompt .prompt-note { color: #666; font-size: 0.75rem; }

footer {
    margin-top: 48px; padding-top: 20px; border-top: 1px solid #1e1e1e;
    display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px;
}
.gh-link { display: inline-flex; align-items: center; gap: 6px; color: #666; text-decoration: none; font-size: 0.78rem; transition: color 0.2s; }
.gh-link:hover { color: #888; }
.gh-link svg { width: 16px; height: 16px; fill: currentColor; }
.license { font-size: 0.7rem; color: #555; }

@media (max-width: 700px) {
    .two-col { grid-template-columns: 1fr; }
    .header h1 { font-size: 1.2rem; }
}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>ScavierEngine</h1>
    <span class="ver">v<?= \Scavier\Engine\Scavier::VERSION ?></span>
</div>
<p class="header-desc">Website intelligence engine. Scans any public URL and returns structured JSON — technology stack, infrastructure, security posture, business data, SEO, and more. Self-hosted, zero dependencies.</p>

<!-- Analyze -->
<div class="analyze-bar">
    <div class="analyze-label">Analyze a URL</div>
    <div class="input-row">
        <input type="url" id="tryUrl" placeholder="https://example.com" spellcheck="false" />
        <button id="tryBtn" onclick="tryAnalyze()">Analyze</button>
    </div>

    <!-- Detector chips -->
    <div class="chip-section">
        <?php foreach ($categories as $cat => $items): ?>
        <div class="chip-cat" onclick="toggleCat('<?= $cat ?>')"><?= htmlspecialchars($cat) ?></div>
        <div class="chip-row" data-cat="<?= $cat ?>">
            <?php foreach ($items as $name): ?>
            <span class="chip on" data-name="<?= htmlspecialchars($name) ?>" onclick="toggleChip(this)">
                <?= htmlspecialchars($name) ?>
                <span class="tip"><?= htmlspecialchars(\Scavier\Engine\DetectorInfo::description($name)) ?></span>
            </span>
            <?php endforeach; ?>
        </div>
        <?php endforeach; ?>
        <div class="chip-actions">
            <button class="chip-action" onclick="setAllChips(true)">Select all</button>
            <button class="chip-action" onclick="setAllChips(false)">Deselect all</button>
        </div>
    </div>

    <div class="result-area" id="resultArea">
        <div class="result-header">
            <span class="result-meta" id="resultMeta"></span>
            <button class="result-copy" onclick="copyResult(this)">Copy</button>
        </div>
        <div class="result-json" id="resultJson"></div>
    </div>
</div>

<!-- REST API -->
<div class="section">
    <div class="section-title">REST API</div>
    <div class="endpoint">
        <span class="method method-get">GET</span>
        <span class="path">/analyze</span>
        <p class="ep-desc">Run detectors on a URL. Returns <code style="font-family:monospace;color:#a5b4fc;font-size:0.75rem">{success, data, error}</code> envelope with <code style="font-family:monospace;color:#a5b4fc;font-size:0.75rem">_meta</code> (scan duration, timestamp, version).</p>
        <div class="params">
            <div><code>url</code><span class="required">required</span> — full URL to analyze</div>
            <div><code>detectors</code><span class="optional">optional</span> — comma-separated detector names (omit for all)</div>
        </div>
    </div>
    <div class="code-block" onclick="copyCodeBlock(this)"><span class="hi">curl</span> <?= htmlspecialchars($baseUrl) ?>/analyze?url=https://example.com</div>
    <div class="code-block" onclick="copyCodeBlock(this)"><span class="hi">curl</span> <?= htmlspecialchars($baseUrl) ?>/analyze?url=https://example.com&amp;detectors=server,cms,hosting</div>
</div>

<!-- MCP -->
<div class="section">
    <div class="section-title">MCP Server</div>
    <p style="color: #777; font-size: 0.8rem; margin-bottom: 16px; line-height: 1.7;">
        ScavierEngine implements <span style="color:#bbb">Model Context Protocol</span> — add it to Claude Desktop, Cursor, or any MCP client.
    </p>
    <div class="two-col">
        <div>
            <div class="col-label">MCP config</div>
            <div class="pre-block" onclick="copyPreBlock(this)">{
  <span class="key">"mcpServers"</span>: {
    <span class="key">"scavier"</span>: {
      <span class="key">"url"</span>: <span class="str">"<?= htmlspecialchars($baseUrl) ?>/mcp"</span>
    }
  }
}</div>
        </div>
        <div>
            <div class="col-label">Example prompt</div>
            <div class="example-prompt">
                <div class="prompt-text">"Analyze apposto.pl — what's their tech stack, security posture, and hosting?"</div>
                <div class="prompt-note">The AI calls ScavierEngine, gets structured JSON with confidence scores, and presents findings in natural language.</div>
            </div>
        </div>
    </div>
</div>

<footer>
    <a href="https://github.com/grabowskiadrian/scavier-engine" class="gh-link" target="_blank" rel="noopener">
        <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0024 12c0-6.63-5.37-12-12-12z"/></svg>
        grabowskiadrian/scavier-engine
    </a>
    <span class="license">MIT License · <?= count($detectors) ?> detectors</span>
</footer>

</div>
<script>
const BASE = window.location.origin;
let lastResult = '';

function toggleChip(el) {
    el.classList.toggle('on');
    el.classList.toggle('off');
}

function toggleCat(cat) {
    const chips = document.querySelectorAll('.chip-row[data-cat="' + cat + '"] .chip');
    const allOn = [...chips].every(c => c.classList.contains('on'));
    chips.forEach(c => { c.classList.toggle('on', !allOn); c.classList.toggle('off', allOn); });
}

function setAllChips(on) {
    document.querySelectorAll('.chip').forEach(c => { c.classList.toggle('on', on); c.classList.toggle('off', !on); });
}

function getSelectedDetectors() {
    const on = document.querySelectorAll('.chip.on');
    const all = document.querySelectorAll('.chip');
    if (on.length === all.length) return '';
    return [...on].map(c => c.dataset.name).join(',');
}

async function tryAnalyze() {
    const input = document.getElementById('tryUrl');
    const btn = document.getElementById('tryBtn');
    const area = document.getElementById('resultArea');
    const meta = document.getElementById('resultMeta');
    const json = document.getElementById('resultJson');

    let url = input.value.trim();
    if (!url) return;
    if (!/^https?:\/\//.test(url)) url = 'https://' + url;

    const det = getSelectedDetectors();
    let apiUrl = BASE + '/analyze?url=' + encodeURIComponent(url);
    if (det) apiUrl += '&detectors=' + encodeURIComponent(det);

    btn.disabled = true;
    btn.textContent = 'Analyzing...';
    area.classList.add('visible');
    json.innerHTML = '<span style="color:#444">Scanning...</span>';
    meta.innerHTML = '';

    const start = performance.now();
    try {
        const res = await fetch(apiUrl);
        const data = await res.json();
        const time = ((performance.now() - start) / 1000).toFixed(2);
        lastResult = JSON.stringify(data, null, 2);
        json.innerHTML = syntaxHighlight(lastResult);
        meta.innerHTML = '<span class="' + (res.ok ? 'status-ok' : 'status-err') + '">' + res.status + '</span> · ' + time + 's';
    } catch (e) {
        json.innerHTML = '<span style="color:#f87171">' + e.message + '</span>';
        meta.innerHTML = '<span class="status-err">error</span>';
        lastResult = '';
    }
    btn.disabled = false;
    btn.textContent = 'Analyze';
}

function syntaxHighlight(str) {
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/"([^"]+)"(?=\s*:)/g, '<span class="json-key">"$1"</span>')
        .replace(/:\s*"([^"]*)"/g, ': <span class="json-str">"$1"</span>')
        .replace(/:\s*(\d+\.?\d*)/g, ': <span class="json-num">$1</span>')
        .replace(/:\s*(true|false)/g, ': <span class="json-bool">$1</span>')
        .replace(/:\s*(null)/g, ': <span class="json-null">$1</span>');
}

function copyResult(btn) {
    if (!lastResult) return;
    navigator.clipboard.writeText(lastResult);
    btn.classList.add('copied'); btn.textContent = 'Copied';
    setTimeout(() => { btn.classList.remove('copied'); btn.textContent = 'Copy'; }, 1500);
}

function copyCodeBlock(el) {
    navigator.clipboard.writeText(el.textContent.replace('copy','').replace('copied','').trim());
    el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 1500);
}

function copyPreBlock(el) {
    navigator.clipboard.writeText(el.textContent.replace('copy','').replace('copied','').trim());
    el.classList.add('copied'); setTimeout(() => el.classList.remove('copied'), 1500);
}

document.getElementById('tryUrl').addEventListener('keydown', e => { if (e.key === 'Enter') tryAnalyze(); });
</script>
</body>
</html>
