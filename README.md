```markdown
# ShadowDNS

## Advanced DNS Monitoring Tool for Security Professionals

I developed ShadowDNS as a comprehensive DNS tracking solution designed for security professionals, penetration testers, and cybersecurity researchers who require complete visibility into network DNS activity.

### Overview

ShadowDNS employs multiple capture methodologies to provide complete DNS traffic visibility with minimal configuration. The tool records all DNS queries in a local database for analysis, visualization, and threat detection.

### Key Features

- **Multiple Capture Methods**: Implements several concurrent DNS monitoring techniques to ensure 100% coverage
- **Real-Time Threat Detection**: Identifies potentially suspicious domains using pattern matching and entropy analysis
- **Website Attribution**: Intelligently groups DNS requests by parent websites for clear traffic analysis
- **Interactive Analysis**: Provides comprehensive command interface for exploring captured DNS data
- **Visualization**: Generates plots of DNS activity for time-based and statistical analysis
- **Data Export**: Facilitates integration with other security tools via CSV export functionality

### Professional Applications

I created this tool specifically for legitimate security applications including:

- Advanced threat hunting and network monitoring
- Malware communication pattern analysis
- Red team operation DNS tracking
- Security research and DNS exfiltration detection
- Forensic analysis of DNS activity

### Technical Requirements

- Python 3.7+
- Administrative privileges (required for network capture)
- Core dependencies: scapy, matplotlib, sqlite3

Optional components for enhanced capture capabilities:
- dpkt (for packet processing)
- pydivert (for Windows packet capture)

### Installation

```bash
git clone https://github.com/echohollow/ShadowDNS
cd ShadowDNS
pip install -r requirements.txt
python main.py
```

### Usage

Launch with administrator/root privileges:

```bash
python main.py
```

#### Command Reference

| Command | Description |
|---------|-------------|
| `start` | Begin DNS capture using all available methods |
| `stop` | Halt DNS capture |
| `stats` | Display DNS query statistics |
| `website [filter]` | Group DNS queries by parent website |
| `plot [type]` | Generate visualizations (domains, timeline, suspicious) |
| `search [domain]` | Find specific domains in history |
| `export [filename]` | Export DNS history to CSV |
| `clear` | Remove all DNS history from database |
| `help` | Show available commands |
| `exit` | Close ShadowDNS |

### Security Notice

I designed this tool for authorized security testing, research, and defensive monitoring only. Users are responsible for ensuring all usage complies with applicable laws and regulations.

### License

This project is released under the MIT License.
```
