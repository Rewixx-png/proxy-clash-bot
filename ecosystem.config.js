// pm2 ecosystem: pm2 start ecosystem.config.js
module.exports = {
  apps: [
    {
      name: "proxy-clash-bot",
      cwd: __dirname,
      script: "main.py",
      interpreter: `${__dirname}/.venv/bin/python`,
      interpreter_args: "-u",
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
      exp_backoff_restart_delay: 100,
      out_file: `${__dirname}/logs/pm2-out.log`,
      error_file: `${__dirname}/logs/pm2-error.log`,
      merge_logs: true,
      time: true,
      env: { PYTHONUNBUFFERED: "1" },
    },
  ],
};
