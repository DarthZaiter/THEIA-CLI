#!/usr/bin/env node

// THEIA CLI - Red Team Host Monitor
// Usage: node theia-cli.js -c -p
// Or: node theia-cli.js -c (connections only)
// Or: node theia-cli.js -p (processes only)

const { exec } = require('child_process');
const os = require('os');
const path = require('path');

// Check if running in spawned window
const isSpawnedWindow = process.env.THEIA_SPAWNED === 'true';

// ANSI color codes for terminal styling
const colors = {
  reset: '\x1b[0m',
  bright: '\x1b[1m',
  cyan: '\x1b[36m',
  yellow: '\x1b[33m',
  green: '\x1b[32m',
  red: '\x1b[31m',
  gray: '\x1b[90m',
  blue: '\x1b[34m',
  bgYellow: '\x1b[43m\x1b[30m',
  bgCyan: '\x1b[46m\x1b[30m'
};

// Parse command line arguments
const parseArgs = () => {
  const args = process.argv.slice(2);
  const flags = {
    connections: false,
    processes: false
  };
  
  args.forEach(arg => {
    if (arg === '-c') flags.connections = true;
    if (arg === '-p') flags.processes = true;
  });
  
  return flags;
};

// Store previous state for change detection
let previousConnections = new Set();
let previousProcesses = new Set();
let newConnectionTimestamps = new Map();
let newProcessTimestamps = new Map();

// Auto-detect OS
const detectOS = () => {
  const platform = os.platform();
  if (platform === 'win32') return 'windows';
  if (platform === 'darwin') return 'mac';
  return 'unix';
};

// Get appropriate commands based on OS
const getCommands = (osType) => {
  const commands = {
    windows: {
      connections: 'netstat -ano',
      processes: 'tasklist /v /fo csv'
    },
    unix: {
      connections: 'ss -tunap 2>/dev/null || netstat -tunap 2>/dev/null',
      processes: 'ps aux'
    },
    mac: {
      // Use lsof for better IPv4/IPv6 distinction and process info
      connections: 'lsof -iTCP -sTCP:ESTABLISHED -n -P',
      processes: 'ps aux'
    }
  };
  return commands[osType];
};

// Execute system command
const executeCommand = (command) => {
  return new Promise((resolve, reject) => {
    exec(command, { maxBuffer: 1024 * 1024 * 10 }, (error, stdout, stderr) => {
      if (error) {
        reject(error);
        return;
      }
      if (stderr && !stderr.includes('Permission denied')) { // lsof may warn on some sockets
        console.warn(`${colors.yellow}Warning: ${stderr.trim()}${colors.reset}`);
      }
      resolve(stdout);
    });
  });
};

// Parse network connections
const parseConnections = (output, osType) => {
  const connections = [];
  const lines = output.split('\n').filter(line => line.trim());

  if (osType === 'windows') {
    lines.forEach(line => {
      const parts = line.trim().split(/\s+/);
      if (parts[0] === 'TCP' || parts[0] === 'UDP') {
        const protocol = parts[0];
        const local = parts[1];
        const remote = parts[2];
        const state = parts[3] || 'N/A';
        
        if (remote && remote !== '0.0.0.0:0' && remote !== '*:*') {
          const connStr = `${protocol}|${local}|${remote}|${state}`;
          connections.push({ protocol, local, remote, state, process: 'Unknown', id: connStr });
        }
      }
    });
  } else if (osType === 'mac') {
    // Parse lsof output: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
    // Example: Chrome 12345 user 50u IPv6 0xabc123 0t0 TCP [2601::]:54321->ipv6.google.com:https (ESTABLISHED)
    lines.forEach(line => {
      if (!line.includes('TCP') || !line.includes('ESTABLISHED')) return;

      const parts = line.trim().split(/\s+/);
      if (parts.length < 9) return;

      const process = parts[0];
      const pid = parts[1];
      const type = parts[3]; // IPv4 or IPv6
      const namePart = parts.slice(8).join(' '); // Everything after NAME

      const match = namePart.match(/([^\->]+)->([^\(]+)\s*\(ESTABLISHED\)/);
      if (!match) return;

      const local = match[1].trim();
      const remote = match[2].trim();

      const protocol = 'TCP';
      const state = 'ESTABLISHED';
      const connStr = `${protocol}|${local}|${remote}|${state}|${process}|${pid}`;

      connections.push({
        protocol,
        local,
        remote,
        state,
        process: `${process} (${pid})`,
        family: type, // IPv4 or IPv6
        id: connStr
      });
    });
  } else {
    // Unix/Linux fallback (ss or netstat)
    lines.forEach((line, idx) => {
      if (idx === 0 || !line.includes(':')) return;
      
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 5) {
        const protocol = (parts[0] || 'TCP').toUpperCase();
        const state = parts[1] || 'ESTABLISHED';
        const local = parts[4] || parts[3];
        const remote = parts[5] || parts[4];
        const process = parts[6] || 'Unknown';
        
        if (local && remote && remote !== '*' && !remote.includes('*:*')) {
          const connStr = `${protocol}|${local}|${remote}|${state}`;
          connections.push({ protocol, local, remote, state, process, id: connStr });
        }
      }
    });
  }

  return connections;
};

// Parse processes (unchanged but improved Windows parsing)
const parseProcesses = (output, osType) => {
  const processes = [];
  const lines = output.split('\n').filter(line => line.trim());

  if (osType === 'windows') {
    lines.forEach((line, idx) => {
      if (idx < 1) return;
      
      const fields = [];
      let current = '';
      let inQuotes = false;
      for (let char of line + ',') { // Add trailing comma to flush last field
        if (char === '"' && !inQuotes) inQuotes = true;
        else if (char === '"' && inQuotes) inQuotes = false;
        else if (char === ',' && !inQuotes) {
          fields.push(current.trim());
          current = '';
        } else {
          current += char;
        }
      }
      
      if (fields.length >= 2) {
        const name = fields[0].replace(/^"/, '').replace(/"$/, '');
        const pid = fields[1].replace(/^"/, '').replace(/"$/, '');
        const user = fields[6] || 'N/A';
        const cpu = fields[7] || 'N/A';
        const mem = fields[4] || 'N/A';
        const procStr = `${name}|${pid}`;
        processes.push({ name, pid, user, cpu, mem, id: procStr });
      }
    });
  } else {
    lines.forEach((line, idx) => {
      if (idx === 0) return;
      
      const parts = line.trim().split(/\s+/);
      if (parts.length >= 11) {
        const user = parts[0];
        const pid = parts[1];
        const cpu = parts[2];
        const mem = parts[3];
        const command = parts.slice(10).join(' ');
        const procStr = `${command}|${pid}`;
        processes.push({ name: command, pid, user, cpu, mem, id: procStr });
      }
    });
  }

  return processes.slice(0, 50);
};

// Clear screen (cross-platform)
const clearScreen = () => {
  process.stdout.write('\x1b[2J\x1b[H');
};

// Display header
const displayHeader = (monitoringMode) => {
  console.log(`${colors.cyan}${colors.bright}`);
  console.log('        ___');
  console.log('      /     \\');
  console.log('     | () () |     ████████╗██╗  ██╗███████╗██╗ █████╗ ');
  console.log('      \\  ^  /      ╚══██╔══╝██║  ██║██╔════╝██║██╔══██╗');
  console.log('       |||||          ██║   ███████║█████╗  ██║███████║');
  console.log('       |||||          ██║   ██╔══██║██╔══╝  ██║██╔══██║');
  console.log('                      ██║   ██║  ██║███████╗██║██║  ██║');
  console.log('                      ╚═╝   ╚═╝  ╚═╝╚══════╝╚═╝╚═╝  ╚═╝');
  console.log(`${colors.reset}${colors.gray}              Red Team Host Monitoring System${colors.reset}\n`);
  console.log(`${colors.gray}Monitoring: ${colors.green}${monitoringMode}${colors.reset}\n`);
};

// Display connections (now shows process and IPv4/IPv6 on macOS)
const displayConnections = (connections, osType) => {
  console.log(`${colors.bright}${colors.blue}━━━ NETWORK CONNECTIONS (${connections.length}) ━━━${colors.reset}\n`);
  
  if (connections.length === 0) {
    console.log(`${colors.gray}  No active connections detected${colors.reset}\n`);
    return;
  }

  const now = Date.now();
  
  connections.forEach(conn => {
    const isNew = newConnectionTimestamps.has(conn.id) && 
                  (now - newConnectionTimestamps.get(conn.id)) < 30000;
    
    const highlight = isNew ? colors.bgYellow : '';
    const resetColor = isNew ? colors.reset : '';
    
    const familyTag = conn.family ? ` ${conn.family}` : '';
    
    console.log(`  ${highlight}${colors.cyan}${conn.protocol}${familyTag}${resetColor} ${conn.local} ${colors.gray}→${colors.reset} ${conn.remote}`);
    console.log(`  ${highlight}${colors.gray}State: ${colors.green}${conn.state}${resetColor} | Process: ${conn.process || 'Unknown'}${resetColor}\n`);
  });
};

// Display processes
const displayProcesses = (processes) => {
  console.log(`${colors.bright}${colors.blue}━━━ RUNNING PROCESSES (${processes.length}) ━━━${colors.reset}\n`);
  
  if (processes.length === 0) {
    console.log(`${colors.gray}  No processes detected${colors.reset}\n`);
    return;
  }

  const now = Date.now();
  
  processes.forEach(proc => {
    const isNew = newProcessTimestamps.has(proc.id) && 
                  (now - newProcessTimestamps.get(proc.id)) < 30000;
    
    const highlight = isNew ? colors.bgYellow : '';
    const resetColor = isNew ? colors.reset : '';
    
    console.log(`  ${highlight}${colors.bright}${proc.name}${colors.reset}${resetColor} ${colors.gray}(PID: ${proc.pid})${colors.reset}`);
    console.log(`  ${highlight}${colors.gray}User: ${proc.user} | CPU: ${proc.cpu} | MEM: ${proc.mem}${colors.reset}${resetColor}\n`);
  });
};

// Main monitoring function
const monitor = async (osType, flags) => {
  try {
    const commands = getCommands(osType);
    
    let connections = [];
    let processes = [];
    
    if (flags.connections) {
      const connOutput = await executeCommand(commands.connections);
      connections = parseConnections(connOutput, osType);
      
      const currentConnIds = new Set(connections.map(c => c.id));
      connections.forEach(conn => {
        if (!previousConnections.has(conn.id)) {
          newConnectionTimestamps.set(conn.id, Date.now());
        }
      });
      previousConnections = currentConnIds;
    }
    
    if (flags.processes) {
      const procOutput = await executeCommand(commands.processes);
      processes = parseProcesses(procOutput, osType);
      
      const currentProcIds = new Set(processes.map(p => p.id));
      processes.forEach(proc => {
        if (!previousProcesses.has(proc.id)) {
          newProcessTimestamps.set(proc.id, Date.now());
        }
      });
      previousProcesses = currentProcIds;
    }
    
    const now = Date.now();
    for (const [id, timestamp] of [...newConnectionTimestamps.entries()]) {
      if (now - timestamp > 30000) newConnectionTimestamps.delete(id);
    }
    for (const [id, timestamp] of [...newProcessTimestamps.entries()]) {
      if (now - timestamp > 30000) newProcessTimestamps.delete(id);
    }
    
    const modes = [];
    if (flags.connections) modes.push('Connections');
    if (flags.processes) modes.push('Processes');
    const monitoringMode = modes.join(' + ');
    
    clearScreen();
    displayHeader(monitoringMode);
    console.log(`${colors.gray}OS: ${colors.green}${osType}${colors.reset} | ${colors.gray}Mode: ${colors.green}Local${colors.reset} | ${colors.gray}Refresh: ${colors.green}10s${colors.reset}`);
    console.log(`${colors.yellow}New items highlighted for 30 seconds${colors.reset}\n`);
    
    if (flags.connections) displayConnections(connections, osType);
    if (flags.processes) displayProcesses(processes);
    
    console.log(`${colors.gray}Press Ctrl+C to exit${colors.reset}`);
    
  } catch (error) {
    console.error(`${colors.red}Error during monitoring: ${error.message}${colors.reset}`);
  }
};

// Start monitoring
const startMonitoring = () => {
  const flags = parseArgs();
  
  if (!flags.connections && !flags.processes) {
    console.log(`${colors.cyan}${colors.bright}THEIA - Red Team Host Monitor${colors.reset}`);
    console.log(`\n${colors.red}Error: You must select at least one monitoring option.${colors.reset}`);
    console.log(`\nUsage: node theia-cli.js [OPTIONS]`);
    console.log(`\nOptions:`);
    console.log(`  -c    Monitor network connections`);
    console.log(`  -p    Monitor running processes`);
    console.log(`\nExamples:`);
    console.log(`  node theia-cli.js -c          ${colors.gray}# Connections only${colors.reset}`);
    console.log(`  node theia-cli.js -p          ${colors.gray}# Processes only${colors.reset}`);
    console.log(`  node theia-cli.js -c -p       ${colors.gray}# Both${colors.reset}\n`);
    process.exit(1);
  }
  
  const osType = detectOS();
  console.log(`${colors.cyan}Starting THEIA...${colors.reset}`);
  console.log(`${colors.gray}Detected OS: ${osType}${colors.reset}\n`);
  
  monitor(osType, flags);
  setInterval(() => monitor(osType, flags), 10000);
  
  process.on('SIGINT', () => {
    console.log(`\n\n${colors.cyan}THEIA monitoring stopped.${colors.reset}`);
    process.exit(0);
  });
};

// Spawning logic (unchanged from previous robust version)
if (!isSpawnedWindow) {
  const args = process.argv.slice(2);
  const platform = os.platform();
  const scriptPath = process.argv[1];
  const nodeCmd = `node "${scriptPath}" ${args.join(' ')}`;
  let terminalCmd = null;

  if (platform === 'darwin') {
    const cwd = process.cwd();
    const fullCmd = `export THEIA_SPAWNED=true && cd "${cwd}" && ${nodeCmd}`;
    terminalCmd = `osascript -e 'tell application "Terminal" to activate' -e 'tell application "Terminal" to do script ${JSON.stringify(fullCmd)} in window 1'`;
  } else if (platform === 'win32') {
    const cwd = process.cwd();
    terminalCmd = `start cmd /k "cd /d "${cwd}" && set THEIA_SPAWNED=true && ${nodeCmd}"`;
  } else {
    const terminals = ['gnome-terminal', 'konsole', 'xfce4-terminal', 'kitty', 'alacritty', 'xterm'];
    for (const term of terminals) {
      try {
        exec(`which ${term}`, { stdio: 'ignore' });
        if (term === 'gnome-terminal') {
          terminalCmd = `${term} -- bash -c "cd '${process.cwd()}' && export THEIA_SPAWNED=true && ${nodeCmd}; exec bash"`;
        } else if (term === 'kitty') {
          terminalCmd = `${term} bash -c "cd '${process.cwd()}' && export THEIA_SPAWNED=true && ${nodeCmd}"`;
        } else {
          terminalCmd = `${term} -e "bash -c 'cd \\"${process.cwd()}\\" && export THEIA_SPAWNED=true && ${nodeCmd}; exec bash'"`;
        }
        break;
      } catch {}
    }
    if (!terminalCmd) {
      console.log('No suitable terminal found. Running in current terminal...');
      process.env.THEIA_SPAWNED = 'true';
      startMonitoring();
      return;
    }
  }

  if (terminalCmd) {
    exec(terminalCmd, (error, stdout, stderr) => {
      if (error || stderr) {
        console.error('Failed to spawn new terminal:', error?.message || stderr);
        console.log('Running in current terminal...');
        process.env.THEIA_SPAWNED = 'true';
        startMonitoring();
      }
    });
  }
} else {
  startMonitoring();
}