# LDE PolyMonitor

PolyMonitor is a next-generation, **ptrace-based process tracer** built for modern Linux. It offers real-time anomaly detection, system telemetry, SQLite logging, webhook alerts, ZeroMQ remote control, and a live Ncurses dashboard. Designed for both security researchers and sysadmins, it combines deep telemetry with a simple, readable UI.

---

## Features

- **Syscall Tracing**: Uses Linux `ptrace` to collect live syscall activity for traced child processes.
- **Anomaly Detection**: Built-in lightweight Perceptron machine learning detects abnormal syscall patterns live.
- **SQLite3 Logging**: All metrics and anomalies logged to a persistent database for reporting and offline forensics.
- **ZeroMQ API**: Query process stats from other tools or scripts (`tcp://localhost:5555`).
- **Webhook Alerts**: Sends Discord/Slack notifications for anomaly events (via environment variable).
- **System Telemetry**: Measures CPU cycles via `perf_event_open`, energy via RAPL, system memory and load.
- **Thread-Safe**: State updated/queried safely via POSIX mutex and atomic operations.
- **Ncurses UI**: Scrollable TUI built for clarity and rapid navigation.
- **Configurable**: Tune alerting thresholds, DB paths, and webhook settings via environment variables.
- **POSIX Threads**: Robust threading for UI, tracking, and API.
- **Portable Single File**: Ships in a single C++ source file—easy to audit, easy to build.

---

## Build Instructions

> **Supported OS:** Modern ArchLinux, Ubuntu, and other distros with kernel 4.x+.

Install dependencies:
```sh
sudo pacman -Sy ncurses sqlite zeromq curl jansson openssl seccomp
# or on Ubuntu:
sudo apt-get install libncurses-dev libsqlite3-dev libzmq3-dev libcurl4-openssl-dev libjansson-dev libssl-dev libseccomp-dev
```

Compile:
```sh
g++ -std=gnu++17 polymonitor.cpp -o polymonitor \
    -pthread -lncurses -lsqlite3 -lzmq -lcurl -ljansson -lcrypto -lssl -lseccomp -lm
```

---

## How to Run

PolyMonitor traces **child processes you launch**. Always provide at least one program that runs for a while.

### Examples

Monitor a process for 30 seconds:
```sh
./polymonitor sleep 30
```

Monitor a busy bash script:
```sh
./polymonitor bash -c 'for((i=0;i<1000;i++)); do sleep 0.05; done'
```

Monitor multiple processes:
```sh
./polymonitor ping 127.0.0.1 sleep 10
```

**Pro Tip:**  
If you see a blank UI, your process exited too quickly or you didn't provide one! Always use a "long-lived" process.

---

## Ncurses UI Controls

- `q`: **Quit**
- `r`: **Refresh**
- `↑ / ↓`: Navigate table rows
- `Enter`: [Future] Details (not yet implemented)

Columns:
- **PID**: Process ID
- **CMDLINE**: Command line / executable
- **SYSCALLS**: Syscalls traced so far
- **LATENCY**: Average latency per syscall
- **ANOMALY**: AI-detected anomaly score (0-100)
- **CPU CYCLES**: Hardware cycles sampled

Status panel shows Merkle root of all stats, system memory, CPU load, uptime, and recent alerts.

## ZeroMQ API

PolyMonitor serves live stats over ZeroMQ (`tcp://*:5555`).

Example Python query:
```python
import zmq, json
ctx = zmq.Context()
sock = ctx.socket(zmq.REQ)
sock.connect("tcp://localhost:5555")
sock.send_json({"cmd":"stats"})
print(sock.recv_json())
```

---

## Security & Sandbox Notes

- **Requires ptrace on child processes**: Can run as non-root for your own processes, but may need root/CAP_SYS_PTRACE for full access.
- **Seccomp sandbox**: Traced children are protected via seccomp, but enough syscalls are allowed for most binaries.
- **RAPL (CPU energy telemetry)**: Works only on Intel CPUs with sysfs RAPL support.

---

## Troubleshooting

- **Blank UI**: The process you asked to trace exited instantly—try tracing a loop, `sleep`, or a shell.
- **Permission errors (ptrace/seccomp)**: Try running as root: `sudo ./polymonitor ...`
- **No RAPL/energy data**: Not supported on non-Intel CPUs.
- **SQLite issues**: Make sure you have write permission to `$HOME/.polymonitor` or set a custom location.
- **ZMQ API not responding**: Port `5555` must be available.

---

## Extending and Customizing

- To add more syscall metrics, extend `trace_thread`.
- To add dashboard features, edit `draw_table()` and `draw_status()`.
- For additional child process sandboxing, modify seccomp rules in `main()`.
