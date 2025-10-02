/**
 * bot.js — Lombaohsint single-file (Render-ready) Telegram bot
 *
 * - Single-file deployable on Render (webhook) or any Node environment (polling fallback).
 * - Only external dependency: node-telegram-bot-api
 *     npm install node-telegram-bot-api
 * - Safe skeleton: simulated scan (no illegal scraping), command handlers, encrypted report packing,
 *   basic admin dashboard (SSE logs + /status), config auto-create, robust error handling.
 *
 * Usage:
 * - Set BOT_TOKEN in Render environment variables (recommended) or in config.json.
 * - Optionally set APP_URL to your Render service URL to enable webhook mode.
 * - Start command: `node bot.js`
 *
 * Notes:
 * - Keep secrets (BOT_TOKEN) in Render env vars. Do NOT commit tokens to GitHub.
 * - Data directory is ./data/bot and is ignored via .gitignore recommended.
 */

'use strict';

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const http = require('http');
const os = require('os');
const { spawn } = require('child_process');

const TelegramBot = require('node-telegram-bot-api'); // external dependency

/* ------------------ paths & defaults ------------------ */
const ROOT = process.cwd();
const CONFIG_PATH = path.join(ROOT, 'config.json');
const DATA_DIR = path.join(ROOT, 'data', 'bot');
const LOG_DIR = path.join(DATA_DIR, 'logs');
const REPORTS_DIR = path.join(DATA_DIR, 'reports');
const KEYS_DIR = path.join(DATA_DIR, 'keys');
const LOG_FILE = path.join(LOG_DIR, 'bot.log');
const HARV_METADATA = path.join(KEYS_DIR, 'harvested.json');

const DEFAULT_PORT = process.env.PORT ? Number(process.env.PORT) : 8080;

/* ------------------ default config ------------------ */
let config = {
  bot_token: "",
  admin_chat_id: null,
  authorized_users: [],
  max_scan_concurrency: 1,
  scan_timeout_minutes: 30,
  use_encryption: false,
  encryption_key: "", // 64 hex chars
  lombaohsint_path: "",
  api_keys: {},
  banned_users: [],
  admin_basic_user: "admin",
  admin_basic_pass_hash: "", // sha256 of password for dashboard basic auth
  dashboard_port: DEFAULT_PORT
};

/* ------------------ utils ------------------ */
function now() { return new Date().toISOString(); }
function sha256Hex(s) { return crypto.createHash('sha256').update(s).digest('hex'); }
function isValidHexKey(hex) { return typeof hex === 'string' && /^[0-9a-fA-F]{64}$/.test(hex); }

async function ensureDirs() {
  await fsp.mkdir(LOG_DIR, { recursive: true }).catch(()=>{});
  await fsp.mkdir(REPORTS_DIR, { recursive: true }).catch(()=>{});
  await fsp.mkdir(KEYS_DIR, { recursive: true }).catch(()=>{});
}

/* logging */
let logBuffer = [];
async function appendLog(line) {
  const entry = `[${now()}] ${line}\n`;
  logBuffer.push(entry);
  if (logBuffer.length > 5000) logBuffer.shift();
  try { await fsp.appendFile(LOG_FILE, entry); } catch(e) { /* ignore */ }
  // also print to console for Render logs
  try { process.stdout.write(entry); } catch(e) {}
}

/* ------------------ config management ------------------ */
async function loadConfig() {
  try {
    const raw = await fsp.readFile(CONFIG_PATH, 'utf8');
    const loaded = JSON.parse(raw);
    Object.assign(config, loaded);
  } catch (err) {
    if (err && err.code === 'ENOENT') {
      await ensureDirs();
      await fsp.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8');
      console.log(`[INIT] config.json created at ${CONFIG_PATH}. Please set bot_token and admin_chat_id (or set BOT_TOKEN env).`);
      process.exit(0);
    } else {
      console.error('[ERR] loading config:', err);
      process.exit(1);
    }
  }
}
async function saveConfig() {
  try { await fsp.writeFile(CONFIG_PATH, JSON.stringify(config, null, 2), 'utf8'); } catch(e) { await appendLog(`[ERROR] saveConfig: ${e.message}`); }
}

/* ------------------ encryption helpers (AES-256-GCM) ------------------ */
function encryptGCM(buffer, hexKey) {
  if (!isValidHexKey(hexKey)) throw new Error('Invalid encryption key (must be 64 hex chars)');
  const key = Buffer.from(hexKey, 'hex');
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]); // iv(12) + tag(16) + ct
}
function decryptGCM(buf, hexKey) {
  if (!isValidHexKey(hexKey)) throw new Error('Invalid encryption key (must be 64 hex chars)');
  const key = Buffer.from(hexKey, 'hex');
  const iv = buf.slice(0,12);
  const tag = buf.slice(12,28);
  const ct = buf.slice(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]);
}

/* ------------------ sanitize input ------------------ */
function sanitizeTarget(t) {
  if (!t || typeof t !== 'string') return '';
  const s = t.trim();
  if (s.length > 256) return '';
  if (/[`;$|&<>]/.test(s)) return '';
  return s;
}

/* ------------------ job/scan system (simulated safe scans) ------------------ */
let jobCounter = 0;
const jobs = new Map();
const runningJobs = new Set();

function queueJob(target, userId) {
  const id = ++jobCounter;
  const job = {
    id, target, userId,
    status: 'queued',
    createdAt: now(),
    startedAt: null,
    finishedAt: null,
    exitCode: null,
    reportDir: null,
    procPid: null
  };
  jobs.set(id, job);
  appendLog(`[JOB] Queued job ${id} target=${target} user=${userId}`);
  process.nextTick(scheduleJobs);
  return job;
}

async function scheduleJobs() {
  try {
    if (runningJobs.size >= config.max_scan_concurrency) return;
    for (const job of jobs.values()) {
      if (runningJobs.size >= config.max_scan_concurrency) break;
      if (job.status === 'queued') await runJob(job);
    }
  } catch (e) {
    await appendLog(`[ERROR] scheduleJobs: ${e.message}`);
  }
}

async function runJob(job) {
  const target = sanitizeTarget(job.target);
  if (!target) {
    job.status = 'failed';
    job.finishedAt = now();
    job.exitCode = 1;
    appendLog(`[JOB] Invalid target for job ${job.id}`);
    return;
  }
  job.status = 'running';
  job.startedAt = now();
  runningJobs.add(job.id);
  appendLog(`[JOB] Starting job ${job.id} target=${target}`);

  const rptDir = path.join(REPORTS_DIR, `report_${Date.now()}_${job.id}`);
  await fsp.mkdir(rptDir, { recursive: true }).catch(()=>{});

  // If a local, user-provided scanner exists (legal and safe), call it. Otherwise, simulated scan.
  if (config.lombaohsint_path && fsExistsSync(path.join(config.lombaohsint_path, 'main.py'))) {
    // Run in SAFE mode: user is responsible for local scanner legality. We just spawn it.
    const args = ['main.py', '--target', target, '--export', 'json'];
    try {
      const proc = spawn('python3', args, { cwd: config.lombaohsint_path, timeout: config.scan_timeout_minutes * 60 * 1000 });
      job.procPid = proc.pid;
      proc.stdout.on('data', d => appendLog(`[JOB ${job.id}] STDOUT ${String(d).slice(0,1000)}`));
      proc.stderr.on('data', d => appendLog(`[JOB ${job.id}] STDERR ${String(d).slice(0,1000)}`));
      proc.on('close', async (code) => {
        job.exitCode = code;
        job.finishedAt = now();
        job.reportDir = rptDir;
        job.status = 'finished';
        runningJobs.delete(job.id);
        appendLog(`[JOB] External scanner finished job ${job.id} code=${code}`);
      });
      proc.on('error', async (err) => {
        job.status = 'failed';
        job.finishedAt = now();
        runningJobs.delete(job.id);
        appendLog(`[JOB] External scanner error job ${job.id}: ${err.message}`);
      });
    } catch (e) {
      job.status = 'failed';
      job.finishedAt = now();
      runningJobs.delete(job.id);
      appendLog(`[JOB] Spawn failed job ${job.id}: ${e.message}`);
    }
  } else {
    // Simulated safe scan
    const summary = {
      target,
      note: 'Simulated SAFE scan. No external scraping, harvesting, or illegal activity performed by this bot skeleton.',
      generatedAt: now(),
      simulatedFindings: [
        { type: 'public-domain', source: 'rdap', note: 'example simulated RDAP result' }
      ]
    };
    await fsp.writeFile(path.join(rptDir, 'summary.json'), JSON.stringify(summary, null, 2)).catch(()=>{});
    const md = `# Simulated Report for ${target}\n\nGenerated: ${now()}\n\nThis is a simulated, safe report.\n`;
    await fsp.writeFile(path.join(rptDir, 'report.md'), md, 'utf8').catch(()=>{});
    job.reportDir = rptDir;
    job.exitCode = 0;
    job.finishedAt = now();
    job.status = 'finished';
    runningJobs.delete(job.id);
    appendLog(`[JOB] Simulated job ${job.id} finished`);
  }
}

/* ------------------ pack report (JSON bundle, optional encryption) ------------------ */
async function packReport(reportDir, encrypt=false) {
  // If system tar available, try to use it; else bundle JSON
  const outBundlePath = path.join(os.tmpdir(), `report_bundle_${Date.now()}.json`);
  try {
    const files = await fsp.readdir(reportDir);
    const bundle = {};
    for (const f of files) {
      const p = path.join(reportDir, f);
      try {
        const buf = await fsp.readFile(p);
        bundle[f] = buf.toString('base64'); // base64 to preserve binary safely
      } catch(e) { bundle[f] = null; }
    }
    await fsp.writeFile(outBundlePath, JSON.stringify(bundle, null, 2));
    if (encrypt && isValidHexKey(config.encryption_key)) {
      const buf = await fsp.readFile(outBundlePath);
      const enc = encryptGCM(buf, config.encryption_key);
      const encPath = outBundlePath + '.enc';
      await fsp.writeFile(encPath, enc);
      await fsp.unlink(outBundlePath).catch(()=>{});
      return encPath;
    }
    return outBundlePath;
  } catch (e) {
    throw new Error('packReport failed: ' + e.message);
  }
}

/* ------------------ helper: sync fs exists ------------------ */
function fsExistsSync(p) {
  try { return fs.existsSync(p); } catch (e) { return false; }
}

/* ------------------ admin dashboard (minimal) ------------------ */
function checkBasicAuth(authHeader) {
  if (!authHeader || !authHeader.startsWith('Basic ')) return false;
  const creds = Buffer.from(authHeader.slice(6), 'base64').toString('utf8');
  const [user, pass] = creds.split(':');
  if (!user || !pass) return false;
  if (user !== config.admin_basic_user) return false;
  if (!config.admin_basic_pass_hash) return false;
  return sha256Hex(pass) === config.admin_basic_pass_hash;
}

function startAdminServer(port) {
  const server = http.createServer(async (req, res) => {
    const parsed = new URL(req.url, `http://${req.headers.host}`);
    const pathn = parsed.pathname;
    const auth = req.headers['authorization'] || '';
    if (!checkBasicAuth(auth)) {
      res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Lombaohsint"' });
      res.end('Unauthorized');
      return;
    }
    if (pathn === '/status') {
      const jobsArr = Array.from(jobs.values()).map(j => ({
        id: j.id, target: j.target, status: j.status, createdAt: j.createdAt
      }));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ uptime: process.uptime(), jobs: jobsArr }, null, 2));
      return;
    }
    if (pathn === '/logs') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      try {
        const tail = logBuffer.slice(-500).join('');
        res.end(tail);
      } catch (e) {
        res.end('No logs');
      }
      return;
    }
    // simple UI
    res.writeHead(200, { 'Content-Type': 'text/html' });
    res.end(`<html><body>
      <h2>Lombaohsint Admin</h2>
      <p><a href="/status">/status</a> | <a href="/logs">/logs</a></p>
      <pre id="logs" style="background:#111;color:#eee;padding:10px;height:60vh;overflow:auto;"></pre>
      <script>
        async function fetchLogs(){ const r=await fetch('/logs', {headers: { 'Authorization': '${'Basic ' + Buffer.from(config.admin_basic_user + ':<hidden>').toString('base64')}'}); const t=await r.text(); document.getElementById('logs').textContent = t; }
        fetchLogs(); setInterval(fetchLogs, 3000);
      </script>
    </body></html>`);
  });
  server.listen(port, () => appendLog(`[ADMIN] Dashboard listening on port ${port}`));
}

/* ------------------ Telegram bot setup & handlers ------------------ */
let bot = null;
let usingWebhook = false;

async function startTelegram() {
  // determine token (env overrides config)
  const token = (process.env.BOT_TOKEN && process.env.BOT_TOKEN.trim()) ? process.env.BOT_TOKEN.trim() : (config.bot_token || '').trim();
  if (!token) {
    appendLog('[FATAL] BOT_TOKEN missing. Set BOT_TOKEN env or config.json');
    console.error('FATAL: BOT_TOKEN missing. Set BOT_TOKEN env or config.json');
    process.exit(1);
  }
  const appUrl = (process.env.APP_URL && process.env.APP_URL.trim()) ? process.env.APP_URL.trim() : '';
  const port = process.env.PORT ? Number(process.env.PORT) : (config.dashboard_port || DEFAULT_PORT);
  const webhookPath = `/bot${token}`;

  if (appUrl) {
    // webhook mode: we will create an HTTP server that serves webhookPath and also admin endpoints
    usingWebhook = true;
    bot = new TelegramBot(token, { polling: false });
    const webhookUrl = (appUrl.endsWith('/')) ? appUrl.slice(0,-1) + webhookPath : appUrl + webhookPath;
    try {
      await bot.setWebHook(webhookUrl);
      appendLog(`[BOT] Webhook set to ${webhookUrl}`);
    } catch (e) {
      appendLog(`[BOT] setWebHook failed: ${e.message}`);
    }

    // create HTTP server that handles webhook POST to webhookPath and admin endpoints
    const server = http.createServer(async (req, res) => {
      const parsed = new URL(req.url, `http://${req.headers.host}`);
      if (req.method === 'POST' && parsed.pathname === webhookPath) {
        // receive body
        let chunks = [];
        req.on('data', c => chunks.push(c));
        req.on('end', async () => {
          try {
            const body = Buffer.concat(chunks).toString();
            const json = JSON.parse(body);
            await bot.processUpdate(json);
            res.writeHead(200); res.end('OK');
          } catch (e) {
            appendLog(`[BOT] webhook processing error: ${e.message}`);
            res.writeHead(500); res.end('ERR');
          }
        });
        return;
      }
      // other paths: admin dashboard (basic auth)
      if (parsed.pathname.startsWith('/admin')) {
        // map /admin/* to admin endpoints
        const sub = parsed.pathname.slice(6) || '/';
        // delegate to admin server handler logic: simple approach: return minimal page or /status
        if (!checkBasicAuth(req.headers['authorization'] || '')) {
          res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="Lombaohsint"' });
          res.end('Unauthorized');
          return;
        }
        if (sub === '/status' || sub === '/status/') {
          const jobsArr = Array.from(jobs.values()).map(j => ({ id: j.id, target: j.target, status: j.status, createdAt: j.createdAt }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ uptime: process.uptime(), jobs: jobsArr }, null, 2));
          return;
        }
        if (sub === '/logs' || sub === '/logs/') {
          res.writeHead(200, { 'Content-Type': 'text/plain' });
          res.end(logBuffer.slice(-500).join(''));
          return;
        }
        // default admin page
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body><h2>Admin</h2><p>/admin/status /admin/logs</p></body></html>`);
        return;
      }

      // default
      res.writeHead(200); res.end('OK');
    });

    server.listen(port, () => appendLog(`[WEB] Webhook & admin server listening on port ${port}`));
  } else {
    // polling fallback
    bot = new TelegramBot(token, { polling: true, onlyFirstMatch: true });
    appendLog('[BOT] Started in polling mode (set APP_URL env to enable webhook mode)');
  }

  registerHandlers();
}

/* ------------------ handlers & commands ------------------ */
function isAuthorized(chatId) {
  if (!chatId) return false;
  if (config.admin_chat_id && Number(chatId) === Number(config.admin_chat_id)) return true;
  if (Array.isArray(config.authorized_users) && config.authorized_users.map(Number).includes(Number(chatId))) return true;
  return false;
}

function registerHandlers() {
  if (!bot) throw new Error('Bot not initialized');

  // register commands displayed to users
  bot.setMyCommands([
    { command: 'start', description: 'Start bot' },
    { command: 'help', description: 'Show help' },
    { command: 'ping', description: 'Ping bot' },
    { command: 'scan', description: 'Start safe scan: /scan <target>' },
    { command: 'status', description: 'List jobs' },
    { command: 'reports', description: 'List report folders' },
    { command: 'setkey', description: 'Set AES-256-GCM key (64 hex)' },
    { command: 'setapi', description: 'Set API metadata: /setapi name value' },
    { command: 'checkapi', description: 'Show saved API metadata (hashes)' },
    { command: 'ban', description: 'Ban user (admin)' },
    { command: 'unban', description: 'Unban user (admin)' },
    { command: 'kill', description: 'Kill job (admin)' },
    { command: 'info', description: 'Bot info' }
  ]);

  bot.onText(/\/start/, async (msg) => {
    const chatId = msg.chat.id;
    await appendLog(`[CMD] /start from ${chatId}`);
    if (!isAuthorized(chatId)) {
      await bot.sendMessage(chatId, '❌ ACCESS DENIED. Contact admin.');
      return;
    }
    await bot.sendMessage(chatId, `✅ Lombaohsint — ready. Type /help`);
  });

  bot.onText(/\/help/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const help = `Commands:
/start /help
/ping - check bot
/scan <target> - simulated safe scan
/status - list jobs
/reports - list report folders
/setapi <name> <value> - store api metadata hash
/checkapi - list saved api metadata
/setkey <64hex> - enable encryption
/ban <userId> (admin)
/unban <userId> (admin)
/kill <jobId> (admin)
/info - bot info`;
    await bot.sendMessage(chatId, help);
  });

  bot.onText(/\/ping/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    await bot.sendMessage(chatId, `🏓 Pong — ${usingWebhook ? 'webhook' : 'polling'} mode. Uptime: ${Math.floor(process.uptime())}s`);
  });

  bot.onText(/\/info/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const info = `Lombaohsint skeleton\nMode: ${usingWebhook ? 'webhook' : 'polling'}\nReports dir: ${REPORTS_DIR}\nEncryption: ${config.use_encryption ? 'enabled' : 'disabled'}`;
    await bot.sendMessage(chatId, info);
  });

  bot.onText(/\/setkey (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const hex = (match && match[1]) ? match[1].trim() : '';
    if (!isValidHexKey(hex)) {
      await bot.sendMessage(chatId, '❌ Invalid key. Provide 64 hex chars (32 bytes).');
      return;
    }
    config.encryption_key = hex;
    config.use_encryption = true;
    await saveConfig();
    await bot.sendMessage(chatId, '✅ Encryption key set and enabled.');
    await appendLog(`[CONFIG] Encryption key set by ${chatId} (sha256:${sha256Hex(hex).slice(0,12)}...)`);
  });

  bot.onText(/\/setapi (.+?) (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const name = match[1].trim();
    const value = match[2].trim();
    const rec = { name, hash: sha256Hex(value), addedAt: now(), source: 'user' };
    let arr = [];
    try { arr = JSON.parse(await fsp.readFile(HARV_METADATA, 'utf8')); } catch(e){ arr = []; }
    arr.push(rec);
    await fsp.writeFile(HARV_METADATA, JSON.stringify(arr, null, 2)).catch(()=>{});
    config.api_keys[name] = 'user_meta';
    await saveConfig();
    await bot.sendMessage(chatId, `✅ API metadata saved for ${name} (value hash stored).`);
    await appendLog(`[CONFIG] API metadata ${name} saved by ${chatId}`);
  });

  bot.onText(/\/checkapi/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    let text = '🔍 API metadata stored:\n';
    try {
      const arr = JSON.parse(await fsp.readFile(HARV_METADATA, 'utf8'));
      for (const a of arr) text += `- ${a.name} (hash:${a.hash.slice(0,12)}...) added:${a.addedAt}\n`;
    } catch (e) { text += 'No API metadata stored.\n'; }
    await bot.sendMessage(chatId, text);
  });

  bot.onText(/\/scan (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) { await bot.sendMessage(chatId, '❌ Unauthorized.'); return; }
    if (config.banned_users.includes(Number(chatId))) { await bot.sendMessage(chatId, '❌ You are banned.'); return; }
    const target = (match && match[1]) ? match[1].trim() : '';
    if (!target) { await bot.sendMessage(chatId, 'Usage: /scan <target>'); return; }
    await appendLog(`[CMD] /scan ${target} by ${chatId}`);
    const job = queueJob(target, chatId);
    await bot.sendMessage(chatId, `✅ Scan queued. Job ID: ${job.id}`);
    // wait for job to finish (poll)
    const checkInterval = setInterval(async () => {
      const j = jobs.get(job.id);
      if (!j) { clearInterval(checkInterval); return; }
      if (j.status === 'finished' || j.status === 'failed' || j.status === 'killed') {
        clearInterval(checkInterval);
        if (j.status === 'finished' && j.reportDir) {
          try {
            const pack = await packReport(j.reportDir, config.use_encryption);
            await bot.sendMessage(chatId, `✅ Job ${j.id} finished. Sending report...`);
            await bot.sendDocument(chatId, pack).catch(async (e) => {
              await appendLog(`[SEND] Failed to send report ${j.id}: ${e.message}`);
              await bot.sendMessage(chatId, `❌ Failed to send report: ${e.message}`);
            });
            try { await fsp.unlink(pack).catch(()=>{}); } catch(e){}
          } catch (e) {
            await bot.sendMessage(chatId, `❌ Failed to prepare report: ${e.message}`);
          }
        } else {
          await bot.sendMessage(chatId, `Job ${j.id} ended with status: ${j.status}`);
        }
      }
    }, 3000);
  });

  bot.onText(/\/status/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const arr = Array.from(jobs.values()).map(j => `#${j.id} ${j.target} — ${j.status}`).join('\n') || 'No jobs';
    await bot.sendMessage(chatId, `Jobs:\n${arr}`);
  });

  bot.onText(/\/reports/, async (msg) => {
    const chatId = msg.chat.id;
    if (!isAuthorized(chatId)) return;
    const list = await fsp.readdir(REPORTS_DIR).catch(()=>[]);
    const text = list.length ? list.join('\n') : 'No reports available';
    await bot.sendMessage(chatId, `📂 Reports:\n${text}`);
  });

  bot.onText(/\/ban (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (Number(chatId) !== Number(config.admin_chat_id)) return;
    const u = Number(match[1].trim());
    if (!u) { await bot.sendMessage(chatId, 'Invalid userId'); return; }
    if (!config.banned_users.includes(u)) config.banned_users.push(u);
    await saveConfig();
    await bot.sendMessage(chatId, `✅ Banned ${u}`);
    await appendLog(`[ADMIN] ${chatId} banned ${u}`);
  });

  bot.onText(/\/unban (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (Number(chatId) !== Number(config.admin_chat_id)) return;
    const u = Number(match[1].trim());
    config.banned_users = config.banned_users.filter(x => x !== u);
    await saveConfig();
    await bot.sendMessage(chatId, `✅ Unbanned ${u}`);
    await appendLog(`[ADMIN] ${chatId} unbanned ${u}`);
  });

  bot.onText(/\/kill (.+)/, async (msg, match) => {
    const chatId = msg.chat.id;
    if (Number(chatId) !== Number(config.admin_chat_id)) return;
    const id = Number(match[1].trim());
    const job = jobs.get(id);
    if (!job) { await bot.sendMessage(chatId, 'Job not found'); return; }
    if (job.procPid) {
      try {
        process.kill(job.procPid, 'SIGTERM');
        job.status = 'killed';
        await bot.sendMessage(chatId, `✅ Sent SIGTERM to job ${id}`);
        await appendLog(`[ADMIN] ${chatId} killed job ${id}`);
      } catch (e) {
        await bot.sendMessage(chatId, `❌ Kill failed: ${e.message}`);
      }
    } else {
      job.status = 'killed';
      await bot.sendMessage(chatId, `✅ Job ${id} marked killed`);
      await appendLog(`[ADMIN] ${chatId} marked job ${id} killed`);
    }
  });

  // minimal other message handler
  bot.on('message', async (msg) => {
    // do not log message content for privacy; just note message received from authorized user
    const chatId = msg.chat && msg.chat.id;
    if (!chatId) return;
    if (!isAuthorized(chatId)) return;
    // ignore non-command text
  });

  appendLog('[BOT] Handlers registered');
}

/* ------------------ bootstrap ------------------ */
(async () => {
  try {
    await ensureDirs();
    await loadConfig();

    // env BOT_TOKEN override if present
    if (process.env.BOT_TOKEN && !config.bot_token) {
      config.bot_token = process.env.BOT_TOKEN;
      await saveConfig();
    }

    // ensure admin basic password exists for admin endpoints
    if (!config.admin_basic_pass_hash) {
      const rand = crypto.randomBytes(8).toString('hex');
      config.admin_basic_pass_hash = sha256Hex(rand);
      await saveConfig();
      appendLog('[INIT] Admin basic pass hash auto-generated. Please set admin_basic_user/admin_basic_pass_hash in config.json to secure admin endpoints.');
      console.log('[INIT] Admin basic pass hash auto-generated. Edit config.json to set your own.');
    }

    // start admin server on same port (webhook uses same port)
    const adminPort = process.env.PORT ? Number(process.env.PORT) : (config.dashboard_port || DEFAULT_PORT);
    startAdminServer(adminPort);

    // If APP_URL provided, webhook mode will start its own server inside startTelegram
    await startTelegram();

    appendLog('[BOOT] Bot started successfully');
    console.log('✅ Lombaohsint bot running');
  } catch (e) {
    console.error('[BOOT ERR]', e);
    await appendLog(`[BOOT ERROR] ${e && e.message ? e.message : String(e)}`);
    process.exit(1);
  }
})();
