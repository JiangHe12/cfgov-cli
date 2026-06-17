#!/usr/bin/env node

const { spawn } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');

function getBinaryPath() {
  const binaryName = os.platform() === 'win32' ? 'cfgov.exe' : 'cfgov';
  return path.join(__dirname, binaryName);
}

function main() {
  const binaryPath = getBinaryPath();
  if (!fs.existsSync(binaryPath)) {
    console.error('cfgov binary not found. Please reinstall:');
    console.error('  npm install -g cfgov-cli');
    process.exit(1);
  }

  const child = spawn(binaryPath, process.argv.slice(2), { stdio: 'inherit' });
  child.on('error', (err) => {
    console.error('Failed to run cfgov:', err.message);
    process.exit(1);
  });
  child.on('exit', (code, signal) => {
    if (signal) {
      process.kill(process.pid, signal);
      return;
    }
    process.exit(code == null ? 1 : code);
  });
}

main();
