# THEIA-CLI
Simple command line tool to monitor connections and processes during operations

# THEIA - Red Team Host Monitoring Tool

**THEIA** is a lightweight, cross-platform CLI tool for real-time local host monitoring. It displays active network connections and running processes in a clean, colorful terminal interface with change highlighting — perfect for red team engagements, quick threat hunting, or general system awareness.

## Features

- Real-time monitoring of **established network connections** (TCP/UDP)
- Clear **IPv4 vs IPv6** distinction (especially accurate on macOS)
- Shows **process names/PIDs** associated with connections (macOS & Linux)
- Top **running processes** with CPU/MEM usage
- **New item highlighting** (yellow background for 30 seconds)
- Cross-platform: **macOS**, **Windows**, **Linux**
- Attempts to **spawn in a new terminal window** for clean viewing
- Refresh every **10 seconds**
- Beautiful ASCII banner and ANSI colors

## Requirements

- **Node.js** v14 or higher (recommended: latest LTS)

No additional dependencies required!

## Installation

1. Save the script as `theia-cli.js`.

2. (Optional but recommended on macOS/Linux) Make it executable:

   ```bash
   chmod +x theia-cli.js

## Usage

Run tool with node.js

# Monitor both connections and processes (recommended)
node theia-cli.js -c -p

# Monitor only network connections
node theia-cli.js -c

# Monitor only running processes
node theia-cli.js -p


