const path = require('path');
const fs = require('fs').promises;

module.exports = {
  name: 'scan',
  description: 'Start a safe simulated scan: /scan <target>',
  exec: async ({ bot, msg, arg, log }) => {
    if (!arg) {
      await bot.sendMessage(msg.chat.id, 'Usage: /scan <email|domain|username|ip>');
      return;
    }
    const target = arg.trim();
    const rptDir = path.join(__dirname, '..', 'data', 'reports', `scan_${Date.now()}`);
    await fs.mkdir(rptDir, { recursive: true });
    const summary = { target, note: 'Simulated SAFE scan. No illicit data fetched.', generatedAt: new Date().toISOString() };
    await fs.writeFile(path.join(rptDir, 'summary.json'), JSON.stringify(summary, null, 2));
    await bot.sendMessage(msg.chat.id, `✅ Scan completed (simulated). Report saved.`);
    try { await bot.sendDocument(msg.chat.id, path.join(rptDir, 'summary.json')); } catch(e) { log('Send doc failed: '+e.message); }
  }
};
