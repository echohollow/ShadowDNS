import socket
import sqlite3
import datetime
import cmd
import threading
import os
import matplotlib.pyplot as plt
from collections import Counter
import json
import re
import sys
import time
import traceback
import subprocess
import platform
import signal

# Try multiple packet capture libraries
try:
    from scapy.all import sniff, DNS
    HAVE_SCAPY = True
except ImportError:
    HAVE_SCAPY = False
    print("Scapy not available. Will use alternative capture methods.")

try:
    import dpkt
    HAVE_DPKT = True
except ImportError:
    HAVE_DPKT = False

try:
    import pydivert
    HAVE_PYDIVERT = True
except ImportError:
    HAVE_PYDIVERT = False

# Check if running as admin
def is_admin():
    try:
        if platform.system() == 'Windows':
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0  # Unix-based systems
    except:
        return False

if not is_admin():
    print("WARNING: ShadowDNS requires administrative privileges to capture DNS traffic.")
    print("Please restart as administrator/root.")
    if platform.system() == 'Windows':
        print("Right-click on PowerShell/CMD and select 'Run as administrator'")

class DNSTracker(cmd.Cmd):
    prompt = 'DNS-Track> '
    intro = '''
    ███████╗██╗  ██╗ █████╗ ██████╗  ██████╗ ██╗    ██╗██████╗ ███╗   ██╗███████╗
    ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔═══██╗██║    ██║██╔══██╗████╗  ██║██╔════╝
    ███████╗███████║███████║██║  ██║██║   ██║██║ █╗ ██║██║  ██║██╔██╗ ██║███████╗
    ╚════██║██╔══██║██╔══██║██║  ██║██║   ██║██║███╗██║██║  ██║██║╚██╗██║╚════██║
    ███████║██║  ██║██║  ██║██████╔╝╚██████╔╝╚███╔███╔╝██████╔╝██║ ╚████║███████║
    ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝  ╚═════╝  ╚══╝╚══╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    
    OPSEC-ready DNS tracking shell - Version 1.0
    Type 'help' for available commands.
    '''
    
    def __init__(self):
        super().__init__()
        self.db_path = 'shadowdns.db'
        self.db_conn = sqlite3.connect(self.db_path)
        self.setup_database()
        self.capturing = False
        self.capture_threads = []
        self.capture_methods = []
        self.suspicious_domains = self.load_suspicious_domains()
        self.whitelist = self.load_whitelist()
        self.dns_cache = {}  # Cache to avoid duplicate entries
        self.last_backup = datetime.datetime.now()
        self.backup_interval = datetime.timedelta(minutes=5)
        self.dns_server_ips = set()  # Track DNS server IPs
        
        # Detect the system's DNS servers
        self.detect_dns_servers()
        
        # Print capture capability status
        print(f"Capture capabilities:")
        print(f"- Scapy packet capture: {'✓' if HAVE_SCAPY else '✗'}")
        print(f"- DPKT packet processing: {'✓' if HAVE_DPKT else '✗'}")
        print(f"- WinDivert packet capture: {'✓' if HAVE_PYDIVERT else '✗'}")
        print(f"- Running as admin: {'✓' if is_admin() else '✗'}")
        print()
        
    def detect_dns_servers(self):
        """Detect system DNS servers"""
        try:
            if platform.system() == 'Windows':
                output = subprocess.check_output('ipconfig /all', shell=True).decode('utf-8')
                dns_servers = re.findall(r'DNS Servers[\s.]+:\s+([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)', output)
                if dns_servers:
                    self.dns_server_ips = set(dns_servers)
            else:
                # Linux/Mac
                with open('/etc/resolv.conf', 'r') as f:
                    for line in f:
                        if line.startswith('nameserver'):
                            self.dns_server_ips.add(line.split()[1])
                            
            if self.dns_server_ips:
                print(f"Detected DNS servers: {', '.join(self.dns_server_ips)}")
            else:
                print("No DNS servers detected. Using common DNS servers.")
                # Add common DNS servers
                self.dns_server_ips = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9'}
        except Exception as e:
            print(f"Error detecting DNS servers: {e}")
            # Fallback to common DNS servers
            self.dns_server_ips = {'8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9'}
        
    def setup_database(self):
        cursor = self.db_conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dns_queries (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                source_ip TEXT,
                domain TEXT,
                query_type TEXT,
                is_suspicious INTEGER DEFAULT 0,
                capture_method TEXT
            )
        ''')
        # Add index for faster queries
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_domain ON dns_queries(domain)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON dns_queries(timestamp)')
        self.db_conn.commit()
        
    def load_suspicious_domains(self):
        try:
            with open('suspicious_domains.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            # Default suspicious patterns - expanded list
            return [
                # TLDs commonly associated with malicious activity
                r'\.ru$', r'\.cn$', r'\.tk$', r'\.top$', r'\.xyz$', r'\.pw$',
                # URL shorteners
                r'bit\.ly', r'goo\.gl', r'tinyurl\.com', r't\.co', r'is\.gd',
                # Tor related
                r'.*\.tor\..*', r'.*\.onion\..*',
                # Common exfiltration channels
                r'pastebin\.com', r'paste\.ee', r'ghostbin\.co',
                # IP address directly in domain (suspicious)
                r'\d+\.\d+\.\d+\.\d+',
                # Extremely long domain names (potential DGA or exfil)
                r'^.{50,}$',
                # Unusual character distribution (potential DGA)
                r'[bcdfghjklmnpqrstvwxz]{8}',  # Many consonants in a row
                # Fast flux indicators
                r'.*\.[a-z0-9]{6,}\..*'
            ]
    
    def load_whitelist(self):
        try:
            with open('whitelist.json', 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            return [
                r'.*\.google\.com$', r'.*\.googleapis\.com$',
                r'.*\.microsoft\.com$', r'.*\.windows\.com$', r'.*\.office\.com$',
                r'.*\.github\.com$', r'.*\.githubusercontent\.com$',
                r'.*\.cloudflare\.com$', r'.*\.akamai\.net$',
                r'.*\.apple\.com$'
            ]
    
    def is_suspicious(self, domain):
        # Check if domain is whitelisted
        for pattern in self.whitelist:
            if re.match(pattern, domain):
                return False
                
        # Check against suspicious patterns
        for pattern in self.suspicious_domains:
            if re.match(pattern, domain):
                return True
                
        # Check entropy (randomness) of domain name
        parts = domain.split('.')
        if len(parts) > 0:
            main_part = parts[0]
            if len(main_part) > 10:
                # Calculate entropy
                import math
                char_count = {}
                for char in main_part:
                    if char in char_count:
                        char_count[char] += 1
                    else:
                        char_count[char] = 1
                
                entropy = 0
                for count in char_count.values():
                    freq = count / len(main_part)
                    entropy -= freq * math.log2(freq)
                
                # High entropy often indicates DGA (Domain Generation Algorithm)
                if entropy > 4.0 and len(main_part) > 12:
                    return True
        
        return False
        
    def do_start(self, arg):
        """Start capturing DNS traffic using all available methods"""
        if not self.capturing:
            if not is_admin():
                print("WARNING: Not running as administrator. Capture may be limited.")
                
            self.capturing = True
            self.capture_methods = []
            self.capture_threads = []
            
            print("Starting DNS capture using all available methods...")
            
            # Method 1: Scapy capture (if available)
            if HAVE_SCAPY:
                try:
                    thread = threading.Thread(target=self._capture_dns_scapy)
                    thread.daemon = True
                    thread.start()
                    self.capture_threads.append(thread)
                    self.capture_methods.append("scapy")
                    print("✓ Started Scapy packet capture")
                except Exception as e:
                    print(f"✗ Failed to start Scapy capture: {e}")
            
            # Method 2: Socket-based DNS capture
            try:
                thread = threading.Thread(target=self._capture_dns_socket)
                thread.daemon = True
                thread.start()
                self.capture_threads.append(thread)
                self.capture_methods.append("socket")
                print("✓ Started Socket DNS capture")
            except Exception as e:
                print(f"✗ Failed to start Socket capture: {e}")
                
            # Method 3: WinDivert capture (Windows only)
            if HAVE_PYDIVERT and platform.system() == 'Windows':
                try:
                    thread = threading.Thread(target=self._capture_dns_windivert)
                    thread.daemon = True
                    thread.start()
                    self.capture_threads.append(thread)
                    self.capture_methods.append("windivert")
                    print("✓ Started WinDivert packet capture")
                except Exception as e:
                    print(f"✗ Failed to start WinDivert capture: {e}")
            
            # Method 4: DNS log parsing (Windows only)
            if platform.system() == 'Windows':
                try:
                    thread = threading.Thread(target=self._capture_dns_etl)
                    thread.daemon = True
                    thread.start()
                    self.capture_threads.append(thread)
                    self.capture_methods.append("etl")
                    print("✓ Started Windows ETL DNS logging")
                except Exception as e:
                    print(f"✗ Failed to start ETL logging: {e}")
            
            # Backup thread
            backup_thread = threading.Thread(target=self._backup_thread)
            backup_thread.daemon = True
            backup_thread.start()
            
            # Start DNS cache resolver to catch missed domains
            resolver_thread = threading.Thread(target=self._dns_resolver_thread)
            resolver_thread.daemon = True
            resolver_thread.start()
            
            if not self.capture_methods:
                print("⚠️ Failed to start any capture methods. Check your permissions and dependencies.")
                self.capturing = False
            else:
                print(f"DNS capture started using {len(self.capture_methods)} methods. Use 'stop' command to halt capture.")
                print("Waiting for DNS traffic... browse some websites to generate activity.")
    
    def _capture_dns_scapy(self):
        """Capture DNS using Scapy"""
        try:
            # Filter for both UDP and TCP DNS traffic
            sniff(filter="udp port 53 or tcp port 53", prn=self._process_packet_scapy, store=0)
        except Exception as e:
            print(f"Scapy capture error: {e}")
            traceback.print_exc()
    
    def _process_packet_scapy(self, packet):
        """Process packets captured by Scapy"""
        if not self.capturing:
            return
            
        try:
            if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # DNS query
                query = packet.getlayer(DNS)
                domain = query.qd.qname.decode('utf-8').rstrip('.')
                timestamp = datetime.datetime.now().isoformat()
                src_ip = packet[0][1].src
                query_type = "A"  # Default
                
                # Skip if we've seen this domain recently (deduplication)
                cache_key = f"{domain}_{src_ip}"
                current_time = time.time()
                if cache_key in self.dns_cache and current_time - self.dns_cache[cache_key] < 5:
                    return
                self.dns_cache[cache_key] = current_time
                
                is_suspicious = 1 if self.is_suspicious(domain) else 0
                
                # Connect for each query to avoid thread issues
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, is_suspicious, capture_method)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (timestamp, src_ip, domain, query_type, is_suspicious, "scapy"))
                conn.commit()
                conn.close()
                
                status = "⚠️ SUSPICIOUS" if is_suspicious else "✓"
                print(f"[{status}] {domain} (scapy)")
        except Exception as e:
            print(f"Error processing Scapy packet: {e}")
            
    def _capture_dns_socket(self):
        """Capture DNS using raw sockets"""
        if platform.system() != 'Windows':
            # On Unix, we can use a raw socket
            try:
                raw_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
                raw_socket.bind(('0.0.0.0', 0))
                
                # Set socket options
                raw_socket.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                
                while self.capturing:
                    packet_data, addr = raw_socket.recvfrom(65535)
                    self._process_packet_socket(packet_data, addr)
                    
                raw_socket.close()
            except Exception as e:
                print(f"Socket capture error: {e}")
        else:
            # On Windows, we'll use a different approach - monitor DNS resolver cache
            try:
                while self.capturing:
                    # Use ipconfig /displaydns to get DNS cache
                    output = subprocess.check_output('ipconfig /displaydns', shell=True).decode('utf-8', errors='ignore')
                    domains = re.findall(r'Record Name[\s.]+:\s+([^\s]+)', output)
                    
                    for domain in domains:
                        if domain not in self.dns_cache:
                            # This is a new domain in the DNS cache
                            timestamp = datetime.datetime.now().isoformat()
                            is_suspicious = 1 if self.is_suspicious(domain) else 0
                            
                            # Add to our cache
                            self.dns_cache[domain] = time.time()
                            
                            # Add to database
                            conn = sqlite3.connect(self.db_path)
                            cursor = conn.cursor()
                            cursor.execute('''
                                INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, is_suspicious, capture_method)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (timestamp, 'local', domain, 'A', is_suspicious, "cache"))
                            conn.commit()
                            conn.close()
                            
                            status = "⚠️ SUSPICIOUS" if is_suspicious else "✓"
                            print(f"[{status}] {domain} (cache)")
                    
                    time.sleep(2)  # Check every 2 seconds
            except Exception as e:
                print(f"DNS cache monitoring error: {e}")
    
    def _process_packet_socket(self, packet_data, addr):
        """Process packets captured by raw socket"""
        if not self.capturing or not HAVE_DPKT:
            return
            
        try:
            # Parse the packet with dpkt
            ip_packet = dpkt.ip.IP(packet_data)
            
            # Check if it's UDP and port 53 (DNS)
            if isinstance(ip_packet.data, dpkt.udp.UDP) and (ip_packet.data.dport == 53 or ip_packet.data.sport == 53):
                udp_packet = ip_packet.data
                
                # Try to parse as DNS
                dns_packet = dpkt.dns.DNS(udp_packet.data)
                
                # Check if it's a query
                if dns_packet.qr == 0 and len(dns_packet.qd) > 0:
                    domain = dns_packet.qd[0].name.decode('utf-8')
                    timestamp = datetime.datetime.now().isoformat()
                    src_ip = socket.inet_ntoa(ip_packet.src)
                    
                    # Skip if we've seen this domain recently
                    cache_key = f"{domain}_{src_ip}"
                    current_time = time.time()
                    if cache_key in self.dns_cache and current_time - self.dns_cache[cache_key] < 5:
                        return
                    self.dns_cache[cache_key] = current_time
                    
                    is_suspicious = 1 if self.is_suspicious(domain) else 0
                    
                    # Add to database
                    conn = sqlite3.connect(self.db_path)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, is_suspicious, capture_method)
                        VALUES (?, ?, ?, ?, ?, ?)
                    ''', (timestamp, src_ip, domain, 'A', is_suspicious, "socket"))
                    conn.commit()
                    conn.close()
                    
                    status = "⚠️ SUSPICIOUS" if is_suspicious else "✓"
                    print(f"[{status}] {domain} (socket)")
        except Exception as e:
            # Silently ignore packet parsing errors
            pass
            
    def _capture_dns_windivert(self):
        """Capture DNS using WinDivert (Windows only)"""
        try:
            # Create a WinDivert handle
            with pydivert.WinDivert("udp.DstPort == 53 or tcp.DstPort == 53") as w:
                # Set up the packet filter
                for packet in w:
                    if not self.capturing:
                        break
                        
                    try:
                        # Check if it's a DNS packet
                        if packet.dst_port == 53:
                            # Extract the raw packet
                            raw_packet = packet.raw
                            
                            # Try to find the domain name in the DNS query
                            # This is a simple approach, not a full DNS parser
                            if len(raw_packet) > 60:  # Minimum size for DNS
                                dns_data = raw_packet[packet.payload_offset:]
                                
                                # DNS header is 12 bytes, then comes the query
                                # Skip to the query section and look for domain name
                                offset = 12
                                domain_parts = []
                                
                                while offset < len(dns_data):
                                    length = dns_data[offset]
                                    if length == 0:
                                        break
                                    
                                    # Extract domain part
                                    offset += 1
                                    if offset + length <= len(dns_data):
                                        part = dns_data[offset:offset+length]
                                        domain_parts.append(part.decode('utf-8', errors='ignore'))
                                        offset += length
                                    else:
                                        break
                                
                                if domain_parts:
                                    domain = '.'.join(domain_parts)
                                    timestamp = datetime.datetime.now().isoformat()
                                    src_ip = packet.src_addr
                                    
                                    # Skip if we've seen this domain recently
                                    cache_key = f"{domain}_{src_ip}"
                                    current_time = time.time()
                                    if cache_key in self.dns_cache and current_time - self.dns_cache[cache_key] < 5:
                                        continue
                                    self.dns_cache[cache_key] = current_time
                                    
                                    is_suspicious = 1 if self.is_suspicious(domain) else 0
                                    
                                    # Add to database
                                    conn = sqlite3.connect(self.db_path)
                                    cursor = conn.cursor()
                                    cursor.execute('''
                                        INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, is_suspicious, capture_method)
                                        VALUES (?, ?, ?, ?, ?, ?)
                                    ''', (timestamp, src_ip, domain, 'A', is_suspicious, "windivert"))
                                    conn.commit()
                                    conn.close()
                                    
                                    status = "⚠️ SUSPICIOUS" if is_suspicious else "✓"
                                    print(f"[{status}] {domain} (windivert)")
                    except Exception as e:
                        # Silently ignore packet parsing errors
                        pass
                        
                    # Re-inject the packet
                    w.send(packet)
        except Exception as e:
            print(f"WinDivert capture error: {e}")
    
    def _capture_dns_etl(self):
        """Capture DNS using Windows ETL (Event Tracing for Windows)"""
        if platform.system() != 'Windows':
            return
            
        try:
            # Use PowerShell to enable DNS client logging
            subprocess.run(['powershell', '-Command', 'Set-DnsClientGlobalSetting -UseDnsSuffixSearchList $true'], capture_output=True, text=True)
            
            # Start DNS client event logging
            etl_path = os.path.join(os.environ['TEMP'], 'dns_trace.etl')
            start_cmd = f'netsh trace start capture=yes tracefile="{etl_path}" maxsize=50 overwrite=yes report=no correlation=no provider=Microsoft-Windows-DNS-Client'
            subprocess.run(start_cmd, shell=True, capture_output=True, text=True)
            
            print(f"Started ETL DNS logging to {etl_path}")
            
            try:
                while self.capturing:
                    time.sleep(5)  # Check every 5 seconds
                    
                    # Use PowerShell to get DNS client events
                    ps_cmd = f'Get-WinEvent -FilterHashtable @{{ProviderName="Microsoft-Windows-DNS-Client"; StartTime=(Get-Date).AddMinutes(-1)}} -ErrorAction SilentlyContinue | Select-Object TimeCreated, Message'
                    result = subprocess.run(['powershell', '-Command', ps_cmd], capture_output=True, text=True)
                    
                    if result.stdout:
                        # Parse the output to extract domain names
                        for line in result.stdout.split('\n'):
                            match = re.search(r'QueryRequest.*?NAME:\s*([^\s]+)', line)
                            if match:
                                domain = match.group(1).rstrip('.')
                                timestamp = datetime.datetime.now().isoformat()
                                is_suspicious = 1 if self.is_suspicious(domain) else 0
                                
                                # Skip if we've seen this domain recently
                                if domain in self.dns_cache and time.time() - self.dns_cache[domain] < 5:
                                    continue
                                self.dns_cache[domain] = time.time()
                                
                                # Add to database
                                conn = sqlite3.connect(self.db_path)
                                cursor = conn.cursor()
                                cursor.execute('''
                                    INSERT INTO dns_queries (timestamp, source_ip, domain, query_type, is_suspicious, capture_method)
                                    VALUES (?, ?, ?, ?, ?, ?)
                                ''', (timestamp, 'local', domain, 'A', is_suspicious, "etl"))
                                conn.commit()
                                conn.close()
                                
                                status = "⚠️ SUSPICIOUS" if is_suspicious else "✓"
                                print(f"[{status}] {domain} (etl)")
            finally:
                # Stop the trace
                stop_cmd = 'netsh trace stop'
                subprocess.run(stop_cmd, shell=True, capture_output=True, text=True)
                
                # Clean up the ETL file
                try:
                    if os.path.exists(etl_path):
                        os.remove(etl_path)
                except:
                    pass
        except Exception as e:
            print(f"ETL logging error: {e}")
    
    def _dns_resolver_thread(self):
        """Actively resolve domains from browser history to catch missed DNS queries"""
        browsers_history = []
        
        # Try to find browser history files
        try:
            # Chrome history
            chrome_path = os.path.join(os.environ['LOCALAPPDATA'], 'Google', 'Chrome', 'User Data', 'Default', 'History')
            if os.path.exists(chrome_path):
                browsers_history.append(('chrome', chrome_path))
                
            # Firefox history
            firefox_profile = os.path.join(os.environ['APPDATA'], 'Mozilla', 'Firefox', 'Profiles')
            if os.path.exists(firefox_profile):
                for profile in os.listdir(firefox_profile):
                    places_path = os.path.join(firefox_profile, profile, 'places.sqlite')
                    if os.path.exists(places_path):
                        browsers_history.append(('firefox', places_path))
                        break
        except Exception as e:
            print(f"Error finding browser history: {e}")
        
        # If we found browser history, periodically check for new domains
        if browsers_history:
            print(f"Found {len(browsers_history)} browser history files to monitor")
            
            # Dictionary to keep track of last seen timestamps
            last_timestamps = {}
            
            while self.capturing:
                try:
                    for browser, path in browsers_history:
                        # Copy the database to avoid locks
                        temp_path = f"{path}.temp"
                        try:
                            # Copy the file
                            with open(path, 'rb') as src:
                                with open(temp_path, 'wb') as dst:
                                    dst.write(src.read())
                                    
                            # Open the copy
                            conn = sqlite3.connect(temp_path)
                            cursor = conn.cursor()
                            
                            # Get the last timestamp we checked
                            last_time = last_timestamps.get((browser, path), 0)
                            
                            # Query for new URLs
                            if browser == 'chrome':
                                cursor.execute("SELECT url, last_visit_time FROM urls WHERE last_visit_time > ? ORDER BY last_visit_time DESC LIMIT 50", (last_time,))
                            elif browser == 'firefox':
                                cursor.execute("SELECT url, last_visit_date FROM moz_places WHERE last_visit_date > ? ORDER BY last_visit_date DESC LIMIT 50", (last_time,))
                                
                            rows = cursor.fetchall()
                            
                            if rows:
                                # Update the last timestamp
                                last_timestamps[(browser, path)] = rows[0][1]
                                
                                # Process the URLs
                                for url, _ in rows:
                                    try:
                                        # Extract domain from URL
                                        domain = None
                                        if url.startswith('http'):
                                            domain = url.split('/')[2]
                                        
                                        if domain and domain not in self.dns_cache:
                                            # Add to our cache
                                            self.dns_cache[domain] = time.time()
                                            
                                            # Resolve the domain to trigger DNS
                                            threading.Thread(target=lambda: socket.gethostbyname(domain), daemon=True).start()
                                    except:
                                        pass
                                        
                            conn.close()
                            
                            # Remove the temp file
                            os.remove(temp_path)
                        except:
                            # Ignore errors with individual browser histories
                            pass
                except Exception as e:
                    print(f"Error in browser history monitoring: {e}")
                
                # Sleep before checking again
                time.sleep(30)
    
    def _backup_thread(self):
        """Periodically backup the database"""
        while self.capturing:
            try:
                now = datetime.datetime.now()
                if now - self.last_backup >= self.backup_interval:
                    # Create backup in same directory
                    backup_name = f"shadowdns_backup_{now.strftime('%Y%m%d_%H%M%S')}.db"
                    conn = sqlite3.connect(self.db_path)
                    backup_conn = sqlite3.connect(backup_name)
                    conn.backup(backup_conn)
                    backup_conn.close()
                    conn.close()
                    print(f"Created database backup: {backup_name}")
                    
                    # Clean up old backups (keep last 5)
                    backups = [f for f in os.listdir('.') if f.startswith('shadowdns_backup_') and f.endswith('.db')]
                    if len(backups) > 5:
                        backups.sort()
                        for old_backup in backups[:-5]:
                            try:
                                os.remove(old_backup)
                            except:
                                pass
                    
                    self.last_backup = now
            except Exception as e:
                print(f"Backup error: {e}")
                
            time.sleep(60)  # Check every minute
                
    def do_stop(self, arg):
        """Stop DNS capture"""
        if self.capturing:
            self.capturing = False
            print("Stopping DNS capture...")
            
            # Wait for threads to finish
            time.sleep(2)
            
            print(f"DNS capture stopped. Captured methods: {', '.join(self.capture_methods)}")
            
            # Clean up any ETL logging if it was used
            if "etl" in self.capture_methods and platform.system() == 'Windows':
                try:
                    stop_cmd = 'netsh trace stop'
                    subprocess.run(stop_cmd, shell=True, capture_output=True, text=True)
                except:
                    pass
            
            # Clear the threads list
            self.capture_threads = []
            self.capture_methods = []
    
    def do_stats(self, arg):
        """Show DNS query statistics"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Total queries
        cursor.execute("SELECT COUNT(*) FROM dns_queries")
        total = cursor.fetchone()[0]
        
        if total == 0:
            print("No DNS queries captured yet. Use 'start' to begin capturing.")
            conn.close()
            return
        
        # Suspicious queries
        cursor.execute("SELECT COUNT(*) FROM dns_queries WHERE is_suspicious = 1")
        suspicious = cursor.fetchone()[0]
        
        # Unique domains
        cursor.execute("SELECT COUNT(DISTINCT domain) FROM dns_queries")
        unique_domains = cursor.fetchone()[0]
        
        # By capture method
        cursor.execute("SELECT capture_method, COUNT(*) FROM dns_queries GROUP BY capture_method")
        methods = cursor.fetchall()
        
        # Top domains
        cursor.execute("""
            SELECT domain, COUNT(*) as count FROM dns_queries 
            GROUP BY domain ORDER BY count DESC LIMIT 10
        """)
        top_domains = cursor.fetchall()
        
        # Recent suspicious domains
        cursor.execute("""
            SELECT timestamp, domain FROM dns_queries 
            WHERE is_suspicious = 1 
            ORDER BY timestamp DESC LIMIT 5
        """)
        recent_suspicious = cursor.fetchall()
        
        # Print stats
        print("\n===== DNS TRACKING STATISTICS =====")
        print(f"Total DNS queries: {total}")
        print(f"Unique domains: {unique_domains}")
        print(f"Suspicious queries: {suspicious} ({suspicious/total*100:.1f}% of total)")
        
        print("\nCapture methods:")
        for method, count in methods:
            print(f"  {method}: {count} queries ({count/total*100:.1f}%)")
        
        print("\nTop 10 domains:")
        for domain, count in top_domains:
            print(f"  {domain}: {count}")
        
        if recent_suspicious:
            print("\nRecent suspicious domains:")
            for timestamp, domain in recent_suspicious:
                print(f"  [{timestamp}] {domain}")
                
        # Get time range
        cursor.execute("SELECT MIN(timestamp), MAX(timestamp) FROM dns_queries")
        min_time, max_time = cursor.fetchone()
        if min_time and max_time:
            try:
                min_dt = datetime.datetime.fromisoformat(min_time)
                max_dt = datetime.datetime.fromisoformat(max_time)
                duration = max_dt - min_dt
                print(f"\nCapture duration: {duration}")
            except:
                pass
            
        conn.close()

    def do_plot(self, arg):
        """Generate a plot of DNS activity
        Usage: plot [type]
        Types: domains (default), timeline, suspicious"""
        plot_type = "domains"
        if arg and arg in ["domains", "timeline", "suspicious"]:
            plot_type = arg
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if we have data
        cursor.execute("SELECT COUNT(*) FROM dns_queries")
        total = cursor.fetchone()[0]
        
        if total == 0:
            print("No DNS data available for plotting")
            conn.close()
            return
            
        if plot_type == "domains":
            # Get most frequent domains
            cursor.execute("""
                SELECT domain FROM dns_queries 
                GROUP BY domain ORDER BY COUNT(*) DESC LIMIT 15
            """)
            domains = [row[0] for row in cursor.fetchall()]
            
            if not domains:
                print("No domain data available for plotting")
                conn.close()
                return
                
            # Count domain frequency
            domain_counts = []
            for domain in domains:
                cursor.execute("SELECT COUNT(*) FROM dns_queries WHERE domain = ?", (domain,))
                count = cursor.fetchone()[0]
                domain_counts.append((domain, count))
                
            # Create plot
            plt.figure(figsize=(12, 8))
            plt.bar(
                [d[0][:20] + '...' if len(d[0]) > 20 else d[0] for d in domain_counts], 
                [d[1] for d in domain_counts]
            )
            plt.xticks(rotation=45, ha='right')
            plt.title('Most Frequent Domains')
            plt.tight_layout()
            
        elif plot_type == "timeline":
            # Get data over time
            cursor.execute("""
                SELECT timestamp FROM dns_queries ORDER BY timestamp
            """)
            timestamps = [datetime.datetime.fromisoformat(row[0]) for row in cursor.fetchall()]
            
            if not timestamps:
                print("No timeline data available for plotting")
                conn.close()
                return
                
            # Group by hour
            hours = {}
            for ts in timestamps:
                hour_key = ts.replace(minute=0, second=0, microsecond=0)
                if hour_key in hours:
                    hours[hour_key] += 1
                else:
                    hours[hour_key] = 1
                    
            # Sort by time
            sorted_hours = sorted(hours.items())
            
            # Create plot
            plt.figure(figsize=(12, 8))
            plt.plot(
                [h[0].strftime('%Y-%m-%d %H:%M') for h in sorted_hours],
                [h[1] for h in sorted_hours],
                marker='o'
            )
            plt.xticks(rotation=45, ha='right')
            plt.title('DNS Query Timeline')
            plt.ylabel('Number of Queries')
            plt.tight_layout()
            
        elif plot_type == "suspicious":
            # Get suspicious vs normal
            cursor.execute("""
                SELECT is_suspicious, COUNT(*) FROM dns_queries
                GROUP BY is_suspicious
            """)
            results = dict(cursor.fetchall())
            
            if not results:
                print("No suspicious data available for plotting")
                conn.close()
                return
                
            # Create plot
            plt.figure(figsize=(10, 8))
            labels = ['Normal', 'Suspicious']
            sizes = [results.get(0, 0), results.get(1, 0)]
            plt.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=['green', 'red'])
            plt.axis('equal')
            plt.title('Normal vs Suspicious DNS Queries')
            
        # Save plot
        plot_path = f'dns_{plot_type}_activity.png'
        plt.savefig(plot_path)
        plt.close()
        print(f"Plot saved to {plot_path}")
        conn.close()

    def do_export(self, arg):
        """Export DNS history to CSV
        Usage: export [filename.csv]"""
        if not arg:
            arg = 'dns_history.csv'
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Check if we have data
        cursor.execute("SELECT COUNT(*) FROM dns_queries")
        total = cursor.fetchone()[0]
        
        if total == 0:
            print("No DNS data available for export")
            conn.close()
            return
            
        cursor.execute("""
            SELECT timestamp, source_ip, domain, query_type, is_suspicious, capture_method
            FROM dns_queries ORDER BY timestamp
        """)
        
        try:
            with open(arg, 'w') as f:
                f.write("timestamp,source_ip,domain,query_type,is_suspicious,capture_method\n")
                for row in cursor:
                    f.write(','.join([str(item) for item in row]) + '\n')
            
            print(f"DNS history exported to {arg}")
            print(f"Exported {total} records")
        except Exception as e:
            print(f"Error exporting to CSV: {e}")
        
        conn.close()
    
    def do_search(self, arg):
        """Search for specific domains in history
        Usage: search [domain]"""
        if not arg:
            print("Please provide a search term")
            return
            
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Try to detect if searching for IP or domain
        is_ip = re.match(r'^\d+\.\d+\.\d+\.\d+$', arg)
        
        if is_ip:
            cursor.execute("""
                SELECT timestamp, domain, source_ip, is_suspicious FROM dns_queries 
                WHERE source_ip LIKE ? ORDER BY timestamp DESC LIMIT 50
            """, (f'%{arg}%',))
        else:
            cursor.execute("""
                SELECT timestamp, domain, source_ip, is_suspicious FROM dns_queries 
                WHERE domain LIKE ? ORDER BY timestamp DESC LIMIT 50
            """, (f'%{arg}%',))
        
        results = cursor.fetchall()
        if results:
            print(f"\nFound {len(results)} matches for '{arg}':")
            for timestamp, domain, source_ip, is_suspicious in results:
                status = "⚠️ " if is_suspicious else "  "
                print(f"  {status}[{timestamp}] {domain} (from {source_ip})")
        else:
            print(f"No matches found for '{arg}'")
        
        conn.close()
    
    def do_clear(self, arg):
        """Clear all DNS history from database"""
        confirm = input("⚠️  Are you sure you want to clear all DNS history? (y/N): ")
        if confirm.lower() == 'y':
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM dns_queries")
            conn.commit()
            conn.close()
            print("DNS history cleared")
        else:
            print("Operation cancelled")
    
    def do_help(self, arg):
        """Show available commands"""
        print("\n===== ShadowDNS - OPSEC-ready DNS tracking tool =====")
        print("Available commands:")
        print("  start      - Start capturing DNS traffic using all available methods")
        print("  stop       - Stop DNS capture")
        print("  stats      - Show DNS query statistics")
        print("  plot       - Generate a plot of DNS activity (types: domains, timeline, suspicious)")
        print("  export     - Export DNS history to CSV")
        print("  search     - Search for specific domains in history")
        print("  website    - Group DNS queries by parent website")
        print("  clear      - Clear all DNS history from database")
        print("  exit       - Exit ShadowDNS")
    def do_website(self, arg):
        """Group DNS queries by parent website
        Usage: website [filter]"""
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # First, extract all domains
        cursor.execute("SELECT DISTINCT domain FROM dns_queries")
        all_domains = [row[0] for row in cursor.fetchall()]
        
        # Extract root domains (example.com from sub.example.com)
        def get_root_domain(domain):
            parts = domain.split('.')
            if len(parts) > 2:
                # Handle special cases like co.uk
                if parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu'] and parts[-1] in ['uk', 'au', 'jp', 'br', 'in']:
                    if len(parts) > 3:
                        return f"{parts[-3]}.{parts[-2]}.{parts[-1]}"
                return f"{parts[-2]}.{parts[-1]}"
            return domain
        
        # Group domains by their root domain
        domain_groups = {}
        for domain in all_domains:
            try:
                # Skip IP addresses and other non-standard domains
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', domain) or not '.' in domain:
                    continue
                    
                root = get_root_domain(domain)
                
                # For CDN domains, try to infer the actual service
                if root in ['cloudfront.net', 'akamaiedge.net', 'edgekey.net', 'edgesuite.net', 
                        'azureedge.net', 'akadns.net', 'cloudapp.azure.com', 'googleusercontent.com',
                        'googlevideo.com', 'akamai.net', 'cdn.cloudflare.net']:
                    
                    # Try to find the service name in the domain
                    service_match = re.search(r'([a-zA-Z0-9-]+)\.[^.]+\.' + re.escape(root), domain)
                    if service_match:
                        service_name = service_match.group(1)
                        if service_name not in ['www', 'api', 'cdn', 'static']:
                            root = f"{service_name} ({root})"
                
                if root not in domain_groups:
                    domain_groups[root] = []
                domain_groups[root].append(domain)
            except:
                # Skip any domains that cause parsing errors
                continue
        
        # Count queries for each domain
        for root, domains in domain_groups.items():
            domain_patterns = []
            for domain in domains:
                domain_patterns.append(f"domain = '{domain}'")
            
            where_clause = " OR ".join(domain_patterns)
            cursor.execute(f"""
                SELECT COUNT(*) FROM dns_queries 
                WHERE {where_clause}
            """)
            
            count = cursor.fetchone()[0]
            domain_groups[root] = {
                'domains': domains,
                'count': count
            }
        
        # Filter by argument if provided
        if arg:
            filtered_groups = {}
            for root, data in domain_groups.items():
                if arg.lower() in root.lower():
                    filtered_groups[root] = data
            display_groups = filtered_groups
        else:
            # Sort by query count and take top 20
            sorted_groups = sorted(domain_groups.items(), key=lambda x: x[1]['count'], reverse=True)
            display_groups = dict(sorted_groups[:20])
        
        # Display results
        if display_groups:
            print("\nWebsites by DNS activity:")
            for root, data in display_groups.items():
                print(f"\n{root}: {data['count']} queries, {len(data['domains'])} domains")
                
                # Show top 5 domains by default
                top_domains = {}
                for domain in data['domains'][:5]:
                    cursor.execute(f"SELECT COUNT(*) FROM dns_queries WHERE domain = ?", (domain,))
                    count = cursor.fetchone()[0]
                    top_domains[domain] = count
                    
                sorted_domains = sorted(top_domains.items(), key=lambda x: x[1], reverse=True)
                for domain, count in sorted_domains:
                    print(f"  {domain}: {count}")
                    
                if len(data['domains']) > 5:
                    print(f"  ... and {len(data['domains']) - 5} more domains")
        else:
            print(f"No domains matching '{arg}' found")
        
        # Option to see all domains for a specific website
        if arg and len(display_groups) == 1:
            root = list(display_groups.keys())[0]
            show_all = input(f"\nShow all {len(display_groups[root]['domains'])} domains for {root}? (y/N): ")
            if show_all.lower() == 'y':
                print(f"\nAll domains for {root}:")
                for domain in display_groups[root]['domains']:
                    cursor.execute(f"SELECT COUNT(*) FROM dns_queries WHERE domain = ?", (domain,))
                    count = cursor.fetchone()[0]
                    print(f"  {domain}: {count}")
        
        conn.close()

    def do_exit(self, arg):
        """Exit the DNS tracker"""
        confirm = input("Are you sure you want to exit ShadowDNS? (y/N): ")
        if confirm.lower() == 'y':
            print("Closing ShadowDNS...")
            
            # Stop any active capturing
            if self.capturing:
                self.do_stop(None)
                
            # Close database connection
            if self.db_conn:
                self.db_conn.close()
                
            return True
        else:
            print("Operation cancelled")
            return False

if __name__ == '__main__':
    # Print a warning if not running as admin
    if not is_admin():
        print("=" * 80)
        print("WARNING: ShadowDNS requires administrative privileges for full functionality.")
        print("Please restart as administrator/root.")
        print("=" * 80)
        print()
    
    # Register signal handlers for clean exit
    def signal_handler(sig, frame):
        print("\nReceived interrupt signal. Shutting down...")
        tracker = DNSTracker()
        if tracker.capturing:
            tracker.do_stop(None)
        if tracker.db_conn:
            tracker.db_conn.close()
        sys.exit(0)
        
    signal.signal(signal.SIGINT, signal_handler)
    
    # Create and start tracker
    tracker = DNSTracker()
    
    # Run the command loop
    try:
        tracker.cmdloop()
    except KeyboardInterrupt:
        print("\nExiting ShadowDNS...")
        if tracker.capturing:
            tracker.do_stop(None)
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
    finally:
        if tracker.db_conn:
            tracker.db_conn.close()
