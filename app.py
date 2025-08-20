# app.py
from flask import Flask, render_template, request, jsonify
from flask_sqlalchemy import SQLAlchemy
# IntegrityError removed - not used in this module
from sqlalchemy import or_
from flask_cors import CORS
import logging
import os
import sys  # Ensure sys is imported
import json
from datetime import datetime
from mcstatus import JavaServer  # Import mcstatus
import base64
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from sqlalchemy import event
from sqlalchemy.engine import Engine
import sqlalchemy  # Added import for sqlalchemy
import atexit  # For graceful shutdown
from whitelist_probe import WhitelistProbe

# ==============================
# CONFIGURATION
# ==============================
app = Flask(__name__)
CORS(app)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app_web.log"),
        logging.StreamHandler()
    ]
)

def log_message(message, error=False):
    if error:
        logging.error(message)
    else:
        logging.info(message)

def check_and_cleanup_wal_files():
    """
    Check if WAL/SHM files are compatible with the main database.
    If not compatible (e.g., after replacing the main DB file), remove them.
    If database is corrupted, attempt recovery from backup.
    """
    db_path = DATABASE_PATH
    wal_path = db_path + "-wal"
    shm_path = db_path + "-shm"
    backup_path = db_path.replace('.db', '_backup_20250731_142351.db')
    
    # If main database doesn't exist, no need to check
    if not os.path.exists(db_path):
        return
    
    # Check if WAL or SHM files exist
    wal_exists = os.path.exists(wal_path)
    shm_exists = os.path.exists(shm_path)
    
    if not wal_exists and not shm_exists:
        # No WAL files to check, but still verify database integrity
        if not verify_database_integrity(db_path):
            attempt_database_recovery(db_path, backup_path)
        return
    
    try:
        # Try a simple connectivity test first
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Quick connectivity check - try to read schema
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
        result = cursor.fetchone()
        
        # If we can read the schema, try a more comprehensive test
        if result:
            # Test actual table access instead of just PRAGMA integrity_check
            cursor.execute("SELECT COUNT(*) FROM minecraft_servers LIMIT 1")
            count_result = cursor.fetchone()
            
            if count_result is None:
                raise sqlite3.DatabaseError("Unable to access main table")
                
        conn.close()
        
    except (sqlite3.DatabaseError, sqlite3.OperationalError) as e:
        log_message(f"Database access issue detected: {e}", error=True)
        log_message("Cleaning up potentially incompatible WAL/SHM files...", error=False)
        
        # Close any existing connections
        try:
            if 'conn' in locals():
                conn.close()
        except:
            pass
        
        # Remove WAL and SHM files
        files_removed = []
        if wal_exists:
            try:
                os.remove(wal_path)
                files_removed.append("WAL")
                log_message(f"Removed incompatible WAL file: {wal_path}", error=False)
            except OSError as e:
                log_message(f"Failed to remove WAL file: {e}", error=True)
        
        if shm_exists:
            try:
                os.remove(shm_path)
                files_removed.append("SHM")
                log_message(f"Removed incompatible SHM file: {shm_path}", error=False)
            except OSError as e:
                log_message(f"Failed to remove SHM file: {e}", error=True)
        
        if files_removed:
            log_message(f"Successfully cleaned up {', '.join(files_removed)} files.", error=False)
            
        # After cleanup, verify database is still accessible
        if not verify_database_integrity(db_path):
            attempt_database_recovery(db_path, backup_path)
    
    except Exception as e:
        log_message(f"Error during WAL/SHM compatibility check: {e}", error=True)
        # Try database recovery as last resort
        attempt_database_recovery(db_path, backup_path)

def verify_database_integrity(db_path):
    """
    Verify that the database is accessible and not corrupted.
    Returns True if database is OK, False if corrupted.
    """
    try:
        import sqlite3
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Test basic connectivity
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' LIMIT 1")
        result = cursor.fetchone()
        
        if result:
            # Test table access
            cursor.execute("SELECT COUNT(*) FROM minecraft_servers LIMIT 1")
            cursor.fetchone()
            
        # Run a quick integrity check
        cursor.execute("PRAGMA quick_check")
        integrity_result = cursor.fetchone()
        
        conn.close()
        
        return integrity_result and integrity_result[0] == 'ok'
        
    except Exception as e:
        log_message(f"Database integrity verification failed: {e}", error=True)
        return False

def attempt_database_recovery(db_path, backup_path):
    """
    Attempt to recover from database corruption using backup.
    """
    if not os.path.exists(backup_path):
        log_message(f"No backup database found at {backup_path}. Cannot recover.", error=True)
        return False
        
    try:
        # First, verify the backup is good
        if not verify_database_integrity(backup_path):
            log_message("Backup database is also corrupted. Cannot recover.", error=True)
            return False
            
        # Create a timestamp backup of the corrupted database
        import time
        corrupted_backup = db_path.replace('.db', f'_corrupted_{int(time.time())}.db')
        os.rename(db_path, corrupted_backup)
        log_message(f"Moved corrupted database to {corrupted_backup}", error=False)
        
        # Copy backup to main database location
        import shutil
        shutil.copy2(backup_path, db_path)
        log_message(f"Restored database from backup: {backup_path}", error=False)
        
        # Verify the restored database
        if verify_database_integrity(db_path):
            log_message("Database recovery successful!", error=False)
            return True
        else:
            log_message("Database recovery failed - restored database is still corrupted", error=True)
            return False
            
    except Exception as e:
        log_message(f"Database recovery failed: {e}", error=True)
        return False

# Determine the absolute path to the directory containing app.py
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
STATIC_DIR = os.path.join(BASE_DIR, "static", "server_icons")
AUTH_SETTINGS_PATH = os.path.join(INSTANCE_DIR, "auth_settings.json")

# Create necessary directories if they don't exist
os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(STATIC_DIR, exist_ok=True)

# Configure SQLite Database URI
DATABASE_PATH = os.path.join(INSTANCE_DIR, "minecraft_scanner.db")
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DATABASE_PATH}?check_same_thread=False'  # Added check_same_thread=False
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
whitelist_probe = WhitelistProbe(AUTH_SETTINGS_PATH)

# ==============================
# DATABASE MODEL
# ==============================
class MinecraftServer(db.Model):
    __tablename__ = 'minecraft_servers'
    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(45), nullable=False, index=True)
    port = db.Column(db.Integer, nullable=False, index=True)
    motd = db.Column(db.Text)
    version = db.Column(db.String(50))
    players = db.Column(db.Integer)
    country = db.Column(db.String(100))
    players_list = db.Column(db.Text)  # JSON-encoded list of player names
    server_icon = db.Column(db.String(255), default='server_icons/server-icon.png')  # Path to the server icon image
    last_updated = db.Column(db.DateTime, default=lambda: datetime.utcnow(), onupdate=lambda: datetime.utcnow(), index=True)
    date_added = db.Column(db.DateTime, default=lambda: datetime.utcnow(), index=True)  # When server was first discovered
    reachable = db.Column(db.Boolean, default=True)  # Reachability status

    __table_args__ = (
        db.UniqueConstraint('ip', 'port', name='unique_ip_port'),
    )

# ==============================
# SET UP WAL MODE FOR SQLITE
# ==============================
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if isinstance(db.engine.dialect, sqlalchemy.dialects.sqlite.dialect):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.close()
        log_message("SQLite set to WAL mode.", error=False)

# ==============================
# FLASK ROUTES
# ==============================
@app.route('/')
def index():
    # Get query parameters
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'asc')
    search_query = request.args.get('search', '')

    # Define allowed sort columns
    allowed_sort_by = {
        'id': MinecraftServer.id,
        'ip': MinecraftServer.ip,
        'motd': MinecraftServer.motd,
        'version': MinecraftServer.version,
        'players': MinecraftServer.players,
        'country': MinecraftServer.country,
        'date_added': MinecraftServer.date_added,
        'reachable': MinecraftServer.reachable
    }
    sort_column = allowed_sort_by.get(sort_by, MinecraftServer.id)
    
    # Build the base query with ordering
    if sort_order == 'asc':
        query = MinecraftServer.query.order_by(sort_column.asc())
    else:
        query = MinecraftServer.query.order_by(sort_column.desc())
    
    # Apply search filter if provided
    if search_query:
        query = query.filter(
            or_(
                MinecraftServer.ip.ilike(f'%{search_query}%'),
                MinecraftServer.port.cast(db.String).ilike(f'%{search_query}%'),
                MinecraftServer.motd.ilike(f'%{search_query}%'),
                MinecraftServer.version.ilike(f'%{search_query}%'),
                MinecraftServer.players.cast(db.String).ilike(f'%{search_query}%'),
                MinecraftServer.country.ilike(f'%{search_query}%')
            )
        )
    
    # Paginate the query using the per_page value from the URL
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    total_entries = MinecraftServer.query.count()
    filtered_entries = pagination.total
    last_entry = db.session.query(MinecraftServer).order_by(MinecraftServer.last_updated.desc()).first()
    last_updated = (last_entry.last_updated.strftime('%Y-%m-%d %H:%M:%S')
                    if last_entry and last_entry.last_updated else 'N/A')
    
    return render_template('index.html',
                           pagination=pagination,
                           search_query=search_query,
                           sort_by=sort_by,
                           sort_order=sort_order,
                           total_entries=total_entries,
                           filtered_entries=filtered_entries,
                           last_updated=last_updated)



@app.route('/api/servers', methods=['GET'])
def get_servers():
    search_query = request.args.get('search', '')
    sort_by = request.args.get('sort_by', 'id')
    sort_order = request.args.get('sort_order', 'asc')
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 50, type=int)  # Return 50 servers per page

    # Define allowed sort columns
    allowed_sort_by = {
        'id': MinecraftServer.id,
        'ip': MinecraftServer.ip,
        'motd': MinecraftServer.motd,
        'version': MinecraftServer.version,
        'players': MinecraftServer.players,
        'country': MinecraftServer.country,
        'date_added': MinecraftServer.date_added,
        'reachable': MinecraftServer.reachable
    }
    sort_column = allowed_sort_by.get(sort_by, MinecraftServer.id)

    # Apply sorting
    if sort_order == 'asc':
        query = MinecraftServer.query.order_by(sort_column.asc())
    else:
        query = MinecraftServer.query.order_by(sort_column.desc())

    # Apply search filtering if needed
    if search_query:
        query = query.filter(
            or_(
                MinecraftServer.ip.ilike(f'%{search_query}%'),
                MinecraftServer.port.cast(db.String).ilike(f'%{search_query}%'),
                MinecraftServer.motd.ilike(f'%{search_query}%'),
                MinecraftServer.version.ilike(f'%{search_query}%'),
                MinecraftServer.players.cast(db.String).ilike(f'%{search_query}%'),
                MinecraftServer.country.ilike(f'%{search_query}%')
            )
        )

    # Paginate the results
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    servers = pagination.items

    server_list = []
    for server in servers:
        server_list.append({
            'id': server.id,
            'ip': server.ip,
            'port': server.port,
            'motd': server.motd,
            'version': server.version,
            'players': server.players,
            'country': server.country,
            'server_icon': server.server_icon,
            'last_updated': server.last_updated.strftime('%Y-%m-%d %H:%M:%S') if server.last_updated else 'N/A',
            'date_added': server.date_added.strftime('%Y-%m-%d %H:%M:%S') if server.date_added else 'N/A',
            'reachable': server.reachable
        })

    return jsonify({
        "servers": server_list,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": pagination.page
    }), 200

@app.route('/api/players/<int:server_id>', methods=['GET'])
def get_players(server_id):
    try:
        server = MinecraftServer.query.get_or_404(server_id)
        if server.players_list:
            players = json.loads(server.players_list)
        else:
            players = []
        return jsonify({'players': players}), 200
    except Exception as e:
        log_message(f"Error fetching players for server {server_id}: {e}", error=True)
        return jsonify({'message': 'Internal server error.'}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    try:
        total_entries = MinecraftServer.query.count()
        last_entry = db.session.query(MinecraftServer).order_by(MinecraftServer.last_updated.desc()).first()
        last_updated = last_entry.last_updated.strftime('%Y-%m-%d %H:%M:%S') if last_entry and last_entry.last_updated else 'N/A'
        return jsonify({
            'total_entries': total_entries,
            'last_updated': last_updated
        }), 200
    except Exception as e:
        log_message(f"Database error during get_stats: {e}", error=True)
        return jsonify({'message': 'Internal server error.'}), 500

@app.route('/api/delete/<int:server_id>', methods=['DELETE'])
def delete_server(server_id):
    try:
        server = MinecraftServer.query.get(server_id)
        if not server:
            return jsonify({'status': 'error', 'message': 'Server not found.'}), 404

        # Optionally, delete the server icon file if it's not the default
        if server.server_icon != 'server_icons/server-icon.png':
            icon_path = os.path.join(STATIC_DIR, server.server_icon)
            if os.path.exists(icon_path):
                try:
                    os.remove(icon_path)
                    log_message(f"Deleted icon file at {icon_path}", error=False)
                except Exception as e:
                    log_message(f"Failed to delete icon file at {icon_path}: {e}", error=True)

        db.session.delete(server)
        db.session.commit()
        return jsonify({'status': 'success', 'message': 'Server deleted successfully.'}), 200
    except Exception as e:
        log_message(f"Error deleting server {server_id}: {e}", error=True)
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500

@app.route('/api/servers/favorites', methods=['POST'])
def favorites_servers():
    data = request.get_json()
    favs = data.get('favorites', [])
    if not favs:
        return jsonify({"servers": []}), 200
    try:
        servers = MinecraftServer.query.filter(MinecraftServer.id.in_(favs)).all()
        server_list = []
        for server in servers:
            server_list.append({
                'id': server.id,
                'ip': server.ip,
                'port': server.port,
                'motd': server.motd,
                'version': server.version,
                'players': server.players,
                'country': server.country,
                'server_icon': server.server_icon,
                'last_updated': server.last_updated.strftime('%Y-%m-%d %H:%M:%S') if server.last_updated else 'N/A',
                'date_added': server.date_added.strftime('%Y-%m-%d %H:%M:%S') if server.date_added else 'N/A',
                'reachable': server.reachable
            })
        return jsonify({"servers": server_list}), 200
    except Exception as e:
        log_message(f"Error fetching favorites: {e}", error=True)
        return jsonify({"message": "Internal server error."}), 500


# ==============================
# NEW: Refresh Server Function
# ==============================
def refresh_server_task(server_id):
    """
    Refreshes the status of a single server.
    This function is intended to be run in a separate thread.
    """
    try:
        with app.app_context():
            server = MinecraftServer.query.get(server_id)
            if not server:
                log_message(f"Server ID {server_id} not found.", error=True)
                return {'id': server_id, 'status': 'failed', 'message': 'Server not found.'}
            ip = server.ip
            port = server.port

            # Check if the server is reachable
            server_obj = JavaServer.lookup(f"{ip}:{port}", timeout=5)
            try:
                status = server_obj.status()
                
                # Validate that we actually got a valid Minecraft server response
                if not hasattr(status, 'version') or not status.version:
                    raise ValueError("Invalid Minecraft server response - no version info")
                    
            except Exception as e:
                log_message(f"Error obtaining status for server {ip}:{port} - {e}", error=True)
                server.reachable = False
                server.players = 0  # Reset player count
                server.players_list = json.dumps([])  # Reset players list
                db.session.commit()
                return {'id': server_id, 'status': 'failed', 'message': 'Server not reachable.'}

            # Update server details
            server.reachable = True
            server.players = status.players.online if status.players else 0
            server.motd = parse_motd(status.description)
            server.version = status.version.name if status.version else "Unknown"
            server.players_list = json.dumps([player.name for player in status.players.sample]) if status.players and status.players.sample else json.dumps([])
            server.last_updated = datetime.utcnow()

            # Handle favicon (server icon)
            favicon = getattr(status, 'icon', None)  # e.g., "data:image/png;base64,<data>"
            if favicon and favicon.startswith("data:image/"):
                favicon_data = favicon.split(",", 1)[1]
                try:
                    image_data = base64.b64decode(favicon_data)
                    # Save the server icon
                    icon_filename = f"{server.id}.png"
                    icon_path = os.path.join(STATIC_DIR, icon_filename)
                    with open(icon_path, 'wb') as img_file:
                        img_file.write(image_data)
                    server.server_icon = f"server_icons/{icon_filename}"
                    # log_message(f"Saved icon for server {ip}:{port} at {icon_path}", error=False)
                except base64.binascii.Error:
                    log_message(f"Invalid favicon data for server {ip}:{port}. Using default icon.", error=True, silent=True)
                    server.server_icon = "server_icons/server-icon.png"  # Fallback to default
            else:
                # Assign a default icon if favicon is not available
                server.server_icon = "server_icons/server-icon.png"  # Ensure this file exists

            db.session.commit()
            log_message(f"Refreshed server {ip}:{port} successfully.", error=False)

            # Prepare the updated server data to send back to the frontend
            updated_server = {
                'id': server.id,
                'ip': server.ip,
                'port': server.port,
                'motd': server.motd,
                'version': server.version,
                'players': server.players,
                'country': server.country,
                'server_icon': server.server_icon,
                'last_updated': server.last_updated.strftime('%Y-%m-%d %H:%M:%S') if server.last_updated else 'N/A',
                'date_added': server.date_added.strftime('%Y-%m-%d %H:%M:%S') if server.date_added else 'N/A',
                'reachable': server.reachable
            }

            return {'id': server_id, 'status': 'success', 'message': 'Server refreshed successfully.', 'server': updated_server}

    except Exception as e:
        log_message(f"Error refreshing server {server_id}: {e}", error=True)
        return {'id': server_id, 'status': 'error', 'message': 'An unexpected error occurred.'}

def minecraft_motd_format(motd):
    """
    Converts a Minecraft MOTD string with formatting codes (using §)
    into HTML with inline styles.
    """
    # Define a mapping of Minecraft color codes to HTML color values.
    color_map = {
        '0': '#000000',  # Black
        '1': '#0000AA',  # Dark Blue
        '2': '#00AA00',  # Dark Green
        '3': '#00AAAA',  # Dark Aqua
        '4': '#AA0000',  # Dark Red
        '5': '#AA00AA',  # Dark Purple
        '6': '#FFAA00',  # Gold
        '7': '#AAAAAA',  # Gray
        '8': '#555555',  # Dark Gray
        '9': '#5555FF',  # Blue
        'a': '#55FF55',  # Green
        'b': '#55FFFF',  # Aqua
        'c': '#FF5555',  # Red
        'd': '#FF55FF',  # Light Purple
        'e': '#FFFF55',  # Yellow
        'f': '#FFFFFF'   # White
    }
    
    # Handle formatting codes (bold, italic, etc.)
    format_map = {
        'l': 'font-weight: bold;',
        'o': 'font-style: italic;',
        'n': 'text-decoration: underline;',
        'm': 'text-decoration: line-through;',
        'k': 'text-decoration: blink;'  # Obfuscated text
    }
    
    # Split the string on the formatting code marker.
    parts = motd.split("§")
    # Start with the first part (which has no formatting)
    result = parts[0]
    # Process each subsequent part: first character is the code, rest is the text.
    for part in parts[1:]:
        if part:
            code = part[0].lower()
            text = part[1:]
            
            styles = ''
            if code in color_map:
                styles += f'color:{color_map[code]};'
            if code in format_map:
                styles += format_map[code]
            
            if styles:
                result += f'<span style="{styles}">{text}</span>'
            else:
                result += text  # Unknown code, just add the text
    return result

# Register the filter with Jinja.
app.jinja_env.filters['motd_format'] = minecraft_motd_format

def favicon_exists():
    """
    Check if any favicon file exists and return the filename and mime type.
    Checks for server-icon.png, server-icon.ico, and server-icon.svg.
    Returns tuple: (exists, filename, mime_type)
    """
    favicon_files = [
        ("server-icon.png", "image/png"),
        ("server-icon.ico", "image/x-icon"),
        ("server-icon.svg", "image/svg+xml")
    ]
    
    for filename, mime_type in favicon_files:
        favicon_path = os.path.join(STATIC_DIR, filename)
        if os.path.exists(favicon_path):
            return True, filename, mime_type
    
    return False, None, None

# Register context processor to make favicon_exists available in templates
@app.context_processor
def inject_favicon_check():
    exists, filename, mime_type = favicon_exists()
    return dict(
        favicon_exists=exists,
        favicon_filename=filename,
        favicon_mime_type=mime_type
    )


# ==============================
# NEW: Refresh Server Endpoint
# ==============================
@app.route('/api/refresh/<int:server_id>', methods=['POST'])
def refresh_server(server_id):
    """
    Endpoint to refresh an individual server.
    """
    try:
        # Submit the refresh task to the thread pool
        future = executor.submit(refresh_server_task, server_id)
        result = future.result()  # Wait for the task to complete

        # Determine the appropriate HTTP status code based on the result
        if result['status'] == 'success':
            return jsonify(result), 200
        elif result['status'] == 'failed':
            return jsonify(result), 200  # Server not reachable is not a client error
        else:
            return jsonify(result), 500  # Unexpected error
    except Exception as e:
        log_message(f"Error in /api/refresh/{server_id}: {e}", error=True)
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500

# ==============================
# OPTIONAL: Refresh All Servers Endpoint
# ==============================
@app.route('/api/refresh_all', methods=['POST'])
def refresh_all_servers():
    try:
        data = request.get_json()
        server_ids = data.get('server_ids', [])

        if not isinstance(server_ids, list):
            return jsonify({'status': 'error', 'message': 'Invalid server_ids format.'}), 400

        results = []

        # Submit all refresh tasks to the thread pool
        futures = {executor.submit(refresh_server_task, server_id): server_id for server_id in server_ids}

        for future in as_completed(futures):
            result = future.result()
            results.append(result)

        return jsonify({'status': 'success', 'results': results}), 200

    except Exception as e:
        log_message(f"Error in refresh_all_servers: {e}", error=True)
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500

@app.route('/api/refresh_all_batches', methods=['POST'])
def refresh_all_batches():
    try:
        data = request.get_json()
        start_index = data.get('start_index')
        limit = data.get('limit')
        sort_by = data.get('sort_by', 'id')
        sort_order = data.get('sort_order', 'asc')
        search = data.get('search', '')

        # Define allowed sort columns.
        allowed_sort_by = {
            'id': MinecraftServer.id,
            'ip': MinecraftServer.ip,
            'motd': MinecraftServer.motd,
            'version': MinecraftServer.version,
            'players': MinecraftServer.players,
            'country': MinecraftServer.country,
            'reachable': MinecraftServer.reachable
        }
        sort_column = allowed_sort_by.get(sort_by, MinecraftServer.id)

        # Build the base query with ordering.
        if sort_order == 'asc':
            query = MinecraftServer.query.order_by(sort_column.asc())
        else:
            query = MinecraftServer.query.order_by(sort_column.desc())

        # Apply search filter if needed.
        if search:
            query = query.filter(
                or_(
                    MinecraftServer.ip.ilike(f'%{search}%'),
                    MinecraftServer.port.cast(db.String).ilike(f'%{search}%'),
                    MinecraftServer.motd.ilike(f'%{search}%'),
                    MinecraftServer.version.ilike(f'%{search}%'),
                    MinecraftServer.players.cast(db.String).ilike(f'%{search}%'),
                    MinecraftServer.country.ilike(f'%{search}%')
                )
            )

        # Get the subset of servers to refresh.
        servers = query.offset(start_index).limit(limit).all()

        # Process each server (synchronously). You can also use a thread pool if desired.
        for server in servers:
            # Call the existing refresh logic. This should update the server in the database.
            refresh_server_task(server.id)

        return jsonify({'status': 'success', 'message': f"Refreshed {len(servers)} servers."}), 200

    except Exception as e:
        log_message(f"Error in refresh_all_batches: {e}", error=True)
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred during batch refresh.'}), 500


# ==============================
# UTILITY FUNCTIONS
# ==============================
def parse_motd(motd_obj):
    """
    Parses the MOTD object returned by mcstatus into a readable string.
    """
    if hasattr(motd_obj, 'parsed'):
        return " ".join(str(part) for part in motd_obj.parsed if isinstance(part, str))
    return str(motd_obj)

@app.route('/api/auth/status', methods=['GET'])
def get_auth_status():
    try:
        return jsonify(whitelist_probe.get_public_status()), 200
    except Exception as e:
        log_message(f"Auth status error: {e}", error=True)
        return jsonify({'configured': False}), 200


@app.route('/api/auth/update', methods=['POST'])
def update_auth():
    try:
        data = request.get_json() or {}
        result = whitelist_probe.update_auth_settings(data)
        return jsonify(result), 200 if result['status'] == 'success' else 400
    except Exception as e:
        log_message(f"Auth update error: {e}", error=True)
        return jsonify({'status': 'error', 'message': f'Auth update failed: {str(e)}'}), 500


@app.route('/api/whitelist_check/<int:server_id>', methods=['POST'])
def whitelist_check(server_id):
    try:
        server = MinecraftServer.query.get_or_404(server_id)
        # Pass the known server version to optimize protocol detection
        result = whitelist_probe.check_whitelist(
            server.ip, 
            server.port, 
            server_version=server.version
        )
        return jsonify(result), 200
    except Exception as e:
        log_message(f"Whitelist check error for {server_id}: {e}", error=True)
        return jsonify({'status': 'error', 'message': 'Unexpected error during whitelist check'}), 500

# ==============================
# MAIN ENTRY POINT
# ==============================
if __name__ == "__main__":
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Minecraft Server Scanner Flask App")
    parser.add_argument('--threads', type=int, default=20, help='Number of threads for refreshing servers (default: 20)')
    args = parser.parse_args()
    thread_count = args.threads

    # Initialize the ThreadPoolExecutor
    executor = ThreadPoolExecutor(max_workers=thread_count)
    log_message(f"ThreadPoolExecutor initialized with {thread_count} threads.", error=False)

    # Check and cleanup incompatible WAL/SHM files before database operations
    check_and_cleanup_wal_files()

    # Ensure the database exists and tables are created within an application context
    try:
        with app.app_context():
            db.create_all()
            log_message("Database tables ensured.", error=False)
    except Exception as e:
        log_message(f"Error creating database tables: {e}", error=True)
        sys.exit(1)  # Now 'sys' is defined

    # Register executor shutdown to ensure threads are cleaned up on exit
    atexit.register(executor.shutdown, wait=True)

    # Run the Flask app
    try:
        app.run(host='0.0.0.0', port=5000, threaded=True, debug=False)
    except Exception as e:
        log_message(f"Failed to start Flask server: {e}", error=True)


