import subprocess
import json
import threading
import signal
import argparse
import os
import time
import random
import sys
# Queue removed - not used in this module
from concurrent.futures import ThreadPoolExecutor
from mcstatus import JavaServer
import geoip2.database
from rich.console import Console
from rich.live import Live
from rich.table import Table
import base64
from datetime import datetime, timezone
from sqlalchemy import create_engine, Column, Integer, String, Text, Boolean, DateTime, UniqueConstraint
from sqlalchemy.orm import declarative_base, sessionmaker
# IntegrityError removed - not used in this module

# ==============================
# CONFIGURATION
# ==============================
DEFAULT_THREADS = 100
BATCH_SIZE = 50
FLUSH_INTERVAL_SEC = 10

DATABASE_PATH = "instance/minecraft_scanner.db"
MASSCAN_OUTPUT_FILE = "masscan_live_results.json"
EXCLUDE_FILE = "exclude.conf"

# Create "static/server_icons" if needed for icon saving
os.makedirs("static/server_icons", exist_ok=True)

os.makedirs("instance", exist_ok=True)

# Old default ports if user doesn't specify --ports
COMMON_PORTS = [25565]

log_lock = threading.Lock()
console = Console()

mc_servers_found = 0
mc_ips_checked = 0

# GeoIP setup
GEOIP_DB_PATH = "GeoLite2-Country.mmdb"
geoip_available = os.path.exists(GEOIP_DB_PATH)
if not geoip_available:
    console.print("[WARNING] GeoLite2 database not found. Country detection is disabled.",
                  style="bold yellow")

child_processes = []
shutdown_event = threading.Event()

# ==============================
# DATABASE SETUP
# ==============================
Base = declarative_base()

class MinecraftServer(Base):
    __tablename__ = 'minecraft_servers'
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), nullable=False, index=True)
    port = Column(Integer, nullable=False, index=True)
    motd = Column(Text)
    version = Column(String(50))
    players = Column(Integer)
    country = Column(String(100))
    players_list = Column(Text)  # JSON-encoded list of player names
    server_icon = Column(String(255), default='server_icons/server-icon.png')
    last_updated = Column(DateTime, default=lambda: datetime.now(timezone.utc),
                          onupdate=lambda: datetime.now(timezone.utc))
    date_added = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)  # When server was first discovered
    reachable = Column(Boolean, default=True)

    __table_args__ = (
        UniqueConstraint('ip', 'port', name='unique_ip_port'),
    )

engine = create_engine(
    f"sqlite:///{DATABASE_PATH}",
    connect_args={'check_same_thread': False},
    pool_size=20,
    max_overflow=0
)
Session = sessionmaker(bind=engine)
Base.metadata.create_all(engine)

def log_message(message, error=False, silent=True):
    formatted_message = f"[LOG] {message}"
    if not silent:
        style = "bold red" if error else "bold green"
        console.print(formatted_message, style=style)
    with log_lock:
        with open("log.txt", "a") as f:
            f.write(formatted_message + "\n")

def create_dashboard():
    table = Table(title="Masscan & Minecraft Scan Status")
    table.add_column("Task", justify="left", style="cyan", no_wrap=True)
    table.add_column("Status", justify="right", style="green")
    table.add_row("============================================", "")
    table.add_row("        MASSCAN SCANNING STATUS            ", "")
    table.add_row("--------------------------------------------", "")
    table.add_row("Masscan Progress", "Initializing...")
    table.add_row("--------------------------------------------", "")
    table.add_row("        MINECRAFT SERVER SCAN STATS        ", "")
    table.add_row("--------------------------------------------", "")
    table.add_row("IPs Checked for MC", "0")
    table.add_row("Minecraft Servers Found", "0")
    table.add_row("============================================", "")
    return table

def update_dashboard(live, masscan_progress=None):
    """
    Rebuilds the dashboard table and updates the live display.
    Only updates the progress field if a non-None value is provided.
    """
    global mc_servers_found, mc_ips_checked
    table = create_dashboard()
    if masscan_progress is not None:
        table.columns[1]._cells[3] = masscan_progress
    table.columns[1]._cells[7] = str(mc_ips_checked)
    table.columns[1]._cells[8] = str(mc_servers_found)
    live.update(table)

def fix_adapter_port_in_paused_conf(paused_file_path):
    if not os.path.exists(paused_file_path):
        return
    with open(paused_file_path, "r") as f:
        lines = f.readlines()
    new_lines = []
    for line in lines:
        if line.strip().startswith("adapter-port"):
            parts = line.split("=")
            if len(parts) != 2:
                continue
            adapter_line = parts[1].strip()
            if "-" in adapter_line:
                start_str, end_str = adapter_line.split("-")
                try:
                    start_port = int(start_str)
                    end_port = int(end_str)
                    count = end_port - start_port + 1
                    if (count & (count - 1)) != 0:
                        single_port = start_port
                        new_lines.append(f"adapter-port = {single_port}-{single_port}\n")
                        continue
                    else:
                        new_lines.append(line)
                        continue
                except ValueError:
                    continue
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)
    with open(paused_file_path, "w") as f:
        f.writelines(new_lines)

def run_masscan(ports, rate=None, seed=None, target_file="targets.txt", resume_file=None):
    if os.path.exists(target_file):
        log_message(f"Using {target_file} as the scan target.")
        cmd = [
            "masscan", "-iL", target_file,
            f"-p{ports}",
            "-oJ", MASSCAN_OUTPUT_FILE,
            "--exclude-file", EXCLUDE_FILE
        ]
    else:
        log_message("Target file not found. Scanning entire IPv4 range.")
        cmd = [
            "masscan", "0.0.0.0/0",
            f"-p{ports}",
            "-oJ", MASSCAN_OUTPUT_FILE,
            "--exclude-file", EXCLUDE_FILE
        ]
    if rate:
        cmd.extend(["--rate", str(rate)])
    if seed:
        cmd.extend(["--seed", str(seed)])
        log_message(f"Using random seed: {seed}")
    if resume_file:
        fix_adapter_port_in_paused_conf(resume_file)
        cmd.extend(["--resume", resume_file])
        log_message(f"Resuming Masscan from {resume_file}")
    try:
        process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        log_message(f"Masscan started with PID {process.pid} (rate={rate if rate else 'default'})")
        child_processes.append(process)
        return process
    except Exception as e:
        log_message(f"Failed to start Masscan: {e}", error=True)
        return None

def process_masscan_output(process, live):
    """
    Continuously reads masscan's stderr and updates the dashboard with its output.
    Once masscan produces output, that remains as the latest progress.
    """
    while process.poll() is None:
        line = process.stderr.readline().strip()
        if line:
            update_dashboard(live, masscan_progress=line)
        time.sleep(0.5)

def parse_motd(motd_obj):
    if hasattr(motd_obj, 'parsed'):
        return " ".join(str(part) for part in motd_obj.parsed if isinstance(part, str))
    return str(motd_obj)

def get_country(ip):
    if not geoip_available:
        return "Unknown"
    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.country(ip)
            return response.country.name
    except Exception as e:
        log_message(f"GeoIP lookup failed for {ip}: {e}", error=True)
        return "Unknown"

def check_minecraft_server(ip, port, live):
    global mc_servers_found
    session = Session()
    try:
        java_server = JavaServer.lookup(f"{ip}:{port}", timeout=5)
        status = java_server.status()
        
        # Validate that we actually got a valid Minecraft server response
        if not hasattr(status, 'version') or not status.version:
            raise ValueError("Invalid Minecraft server response - no version info")
        
        # Check if server already exists
        existing_server = session.query(MinecraftServer).filter_by(ip=ip, port=port).first()
        if existing_server:
            # Update existing server instead of creating new one
            server = existing_server
            server.reachable = True
        else:
            # Create new server with current timestamp
            current_time = datetime.now(timezone.utc)
            server = MinecraftServer(ip=ip, port=port, reachable=True, date_added=current_time)
            session.add(server)
        session.flush()  # Retrieve server.id

        motd = parse_motd(status.motd) if status.motd else "No MOTD"
        version = status.version.name if status.version else "Unknown"
        players = status.players.online if status.players else 0
        players_list = [p.name for p in status.players.sample] if status.players and status.players.sample else []
        country = get_country(ip)
        favicon = getattr(status, 'icon', None)

        server_icon_path = "server_icons/server-icon.png"
        if favicon and favicon.startswith("data:image/"):
            try:
                # Extract the base64 data after the comma
                icon_data = base64.b64decode(favicon.split(",", 1)[1])
                icon_filename = f"{server.id}.png"
                icon_path = os.path.join("static", "server_icons", icon_filename)
                with open(icon_path, 'wb') as f:
                    f.write(icon_data)
                server_icon_path = f"server_icons/{icon_filename}"
                log_message(f"Saved favicon for {ip}:{port}", error=False, silent=True)
            except Exception as ex:
                log_message(f"Error saving icon for {ip}:{port}: {ex}", error=True, silent=True)

        server.motd = motd
        server.version = version
        server.players = players
        server.country = country
        server.players_list = json.dumps(players_list)
        server.server_icon = server_icon_path
        server.last_updated = datetime.now(timezone.utc)

        session.commit()
        mc_servers_found += 1
        
        # Log successful detection (useful for debugging)
        log_message(f"Minecraft server found: {ip}:{port} - {version} - {motd[:50]}...", 
                   error=False, silent=True)
        
    except Exception as e:
        session.rollback()
        error_msg = str(e).lower()
        
        # Categorize errors for better debugging
        network_errors = [
            "timed out", "broken pipe", "connection reset",
            "no route to host", "network is unreachable",
            "refused", "connection aborted", "host unreachable",
            "server did not respond with any information",
            "[errno 32]", "[errno 104]"
        ]
        
        protocol_errors = [
            "invalid minecraft server response", "no version info",
            "connection closed", "invalid packet", "bad packet",
            "received invalid status response packet"
        ]
        
        # Determine if error should be silent based on type
        is_network_error = any(pattern in error_msg for pattern in network_errors)
        is_protocol_error = any(pattern in error_msg for pattern in protocol_errors)
        
        # Silent network and protocol errors, only show truly unknown errors
        should_be_silent = is_network_error or is_protocol_error
        
        if not is_network_error:
            error_type = "PROTOCOL" if is_protocol_error else "OTHER"
            log_message(f"[{error_type}] Server {ip}:{port} - {str(e)}", error=True, silent=should_be_silent)
        else:
            log_message(f"Server {ip}:{port} - {error_msg}", error=True, silent=True)
    finally:
        session.close()

def handle_masscan_line(line, processed_ips, executor, live):
    global mc_ips_checked
    try:
        data = json.loads(line)
        ip = data.get("ip")
        if not ip:
            return
        for port_obj in data.get("ports", []):
            port_number = port_obj["port"]
            if (ip, port_number) not in processed_ips:
                processed_ips.add((ip, port_number))
                mc_ips_checked += 1
                executor.submit(check_minecraft_server, ip, port_number, live)
    except json.JSONDecodeError:
        pass

def process_masscan_results(live, minecraft_threads, process):
    processed_ips = set()
    with ThreadPoolExecutor(max_workers=minecraft_threads) as executor:
        fpos = 0
        while True:
            if process.poll() is not None:
                if os.path.exists(MASSCAN_OUTPUT_FILE):
                    with open(MASSCAN_OUTPUT_FILE, "r") as f:
                        f.seek(fpos)
                        for line in f:
                            fpos += len(line)
                            handle_masscan_line(line, processed_ips, executor, live)
                break
            if not os.path.exists(MASSCAN_OUTPUT_FILE):
                time.sleep(1)
                continue
            with open(MASSCAN_OUTPUT_FILE, "r") as f:
                f.seek(fpos)
                for line in f:
                    fpos += len(line)
                    handle_masscan_line(line, processed_ips, executor, live)
            time.sleep(0.5)

def signal_handler(sig, frame):
    log_message("Interrupt received. Shutting down gracefully...", error=False, silent=False)
    shutdown_event.set()
    for process in child_processes:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
            except Exception as e:
                log_message(f"Error terminating process: {e}", error=True)
    sys.exit(0)

def main():
    parser = argparse.ArgumentParser(description="Masscan-based Minecraft Server Scanner")
    parser.add_argument("--random", nargs="?", const=random.randint(1, 999999), type=int,
                        help="Use a random seed for Masscan (optional).")
    parser.add_argument("--threads", type=int, default=DEFAULT_THREADS,
                        help=f"Threads for MC scanning (default: {DEFAULT_THREADS}).")
    parser.add_argument("--rate", "-r", type=int, help="Packet rate for Masscan (optional).")
    parser.add_argument("--resume", type=str, help="Resume from paused file (optional).")
    parser.add_argument("--ports", type=str,
                        help="Comma-separated ports or port-ranges (e.g. '25565,27015-27020,1-65535'). "
                             "If omitted, uses the built-in COMMON_PORTS list.")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if args.ports:
        ports_arg = args.ports
    else:
        ports_arg = ",".join(str(p) for p in COMMON_PORTS)

    masscan_proc = run_masscan(
        ports=ports_arg,
        rate=args.rate,
        seed=args.random,
        target_file="targets.txt",
        resume_file=args.resume
    )
    if not masscan_proc:
        return

    with Live(create_dashboard(), refresh_per_second=1) as live:
        # Set the initial message only once (this will be overwritten as soon as masscan produces output)
        update_dashboard(live, masscan_progress="Scanning...")

        t1 = threading.Thread(target=process_masscan_output, args=(masscan_proc, live), daemon=True)
        t1.start()

        t2 = threading.Thread(target=process_masscan_results, args=(live, args.threads, masscan_proc), daemon=True)
        t2.start()

        masscan_proc.wait()
        t2.join()

if __name__ == "__main__":
    main()

