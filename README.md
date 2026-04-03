# SecOps - Rust Port Scanner

A high-performance, asynchronous TCP/UDP port scanner built with Rust. Designed for security operations, it supports various scanning techniques and output formats.

## 🚀 Features

- **Asynchronous Execution:** Powered by `tokio` for massive concurrency.
- **Multiple Scan Types:**
  - **TCP Connect Scan:** Standard 3-way handshake (No special privileges required).
  - **TCP SYN Scan:** Half-open scanning (Stealthier, requires Admin/Root).
  - **UDP Scan:** Identifies open UDP ports.
- **Reporting:** Export results in **Markdown (Table)** or **JSON** formats.
- **Customizable:** Control port ranges, timeouts, and target resolution.

## 🛠️ Prerequisites

- **Rust:** Installed via [rustup](https://rustup.rs/).
- **Windows Users:** Requires [Npcap](https://nmap.org/npcap/) or WinPcap for SYN scanning (Raw Sockets).
- **Linux/macOS Users:** SYN scanning requires `sudo` or equivalent capabilities.

## 📦 Installation

```bash
git clone <repository-url>
cd "Port Scanner"
cargo build --release
```

## 📖 Usage Examples

Run the scanner using `cargo run --` followed by the command arguments.

### 1. Basic TCP Connect Scan
Scan the first 1024 ports of a target (Default).
```bash
# TCP Connect Scan (Default)
cargo run -- pentest port-scan 127.0.0.1 --range 1-1000

# JSON Output
cargo run -- pentest port-scan google.com --range 80,443 --format json
```

## Running the Web UI 🌐

For a modern, interactive experience, you can start the built-in web server:

```bash
cargo run -- web
```

By default, the UI will be available at [http://localhost:3000](http://localhost:3000).

### Web UI Features
- **Real-time Scanning**: Trigger scans directly from your browser.
- **Visual Analytics**: Interactive dashboard with port status breakdown.
- **Glassmorphism Design**: High-end user interface with dark mode support.
- **Protocols Supported**: TCP Connect, TCP SYN (requires admin), and UDP.

### 3. Stealthy SYN Scan (Requires Admin)
```powershell
# Run terminal as Administrator
cargo run -- pentest port-scan 192.168.1.1 --syn
```

### 4. UDP Port Scan
```powershell
cargo run -- pentest port-scan 192.168.1.1 --udp
```

### 5. Export results as JSON
```powershell
cargo run -- pentest port-scan localhost --format json
```

## ⚙️ Command Arguments

| Argument | Description | Default |
| :--- | :--- | :--- |
| `<target>` | IP Address or Hostname | (Required) |
| `--range` | Port range (e.g., `1-65535` or `80`) | `1-1024` |
| `--tcp` | Standard TCP Connect Scan | **Default** |
| `--syn` | TCP Half-Open (SYN) Scan | - |
| `--udp` | UDP Protocol Scan | - |
| `--timeout` | Timeout per port in milliseconds | `1000` |
| `--format` | Output format (`md` or `json`) | `md` |

## 🛡️ Educational Purpose
This tool is created for educational and security testing purposes only. **Only use it on networks you own or have explicit permission to test.**
