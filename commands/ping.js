module.exports = {
  name: 'ping',
  description: 'Check bot status',
  exec: async ({ bot, msg }) => {
    await bot.sendMessage(msg.chat.id, '🏓 Pong — bot is alive.');
  }
};
