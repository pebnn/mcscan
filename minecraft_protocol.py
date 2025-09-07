import socket
import struct
import json
import uuid
from typing import Dict, Any, Optional, Tuple, List
from datetime import datetime, timezone
import logging
import hashlib
import zlib
import os
import time
try:
	from Crypto.Cipher import AES, PKCS1_v1_5
	from Crypto.PublicKey import RSA
except ImportError:
	from Cryptodome.Cipher import AES, PKCS1_v1_5
	from Cryptodome.PublicKey import RSA

# Optional: requests for remote protocol loading
try:
	import requests  # type: ignore
except Exception:
	requests = None  # Fallback if unavailable

# ===============================
# Built-in protocol definitions
# ===============================
DEFAULT_SUPPORTED_PROTOCOL_VERSIONS: List[Tuple[int, str]] = [
    (772, "1.21.7/1.21.8"),
    (771, "1.21.6"),
    (770, "1.21.5"),
    (767, "1.21.1"),
    (766, "1.20.5/1.20.6"), 
    (765, "1.20.3/1.20.4"),
    (764, "1.20.2"),
    (763, "1.20/1.20.1"),
    (762, "1.19.4"),
    (761, "1.19.3"),
    (760, "1.19.1/1.19.2"),
    (759, "1.19"),
    (758, "1.18.2"),
    (757, "1.18/1.18.1"),
    (756, "1.17.1"),
    (755, "1.17"),
    (754, "1.16.5/1.16.4"),
    (404, "1.13.2"),
    (401, "1.13.1"),
    (393, "1.13"),
    (340, "1.12.2"),
    (338, "1.12.1"),
    (335, "1.12"),
]

DEFAULT_VERSION_TO_PROTOCOL: Dict[str, int] = {
    # 1.21.x series
    "1.21.8": 772, "1.21.7": 772, "1.21.6": 771, "1.21.5": 770,
    "1.21.4": 769, "1.21.3": 768, "1.21.2": 768, "1.21.1": 767, "1.21": 767,
    # 1.20.x series
    "1.20.6": 766, "1.20.5": 766, "1.20.4": 765, "1.20.3": 765, "1.20.2": 764, "1.20.1": 763, "1.20": 763,
    # 1.19.x series
    "1.19.4": 762, "1.19.3": 761, "1.19.2": 760, "1.19.1": 760, "1.19": 759,
    # 1.18.x series
    "1.18.2": 758, "1.18.1": 757, "1.18": 757,
    # 1.17.x series
    "1.17.1": 756, "1.17": 755,
    # 1.16.x series
    "1.16.5": 754, "1.16.4": 754, "1.16.3": 753, "1.16.2": 751, "1.16.1": 736, "1.16": 735,
    # 1.15.x series
    "1.15.2": 578, "1.15.1": 575, "1.15": 573,
    # 1.14.x series
    "1.14.4": 498, "1.14.3": 490, "1.14.2": 485, "1.14.1": 480, "1.14": 477,
    # 1.13.x series
    "1.13.2": 404, "1.13.1": 401, "1.13": 393,
    # 1.12.x series
    "1.12.2": 340, "1.12.1": 338, "1.12": 335,
}

# Runtime variables (may be updated by remote mapping)
SUPPORTED_PROTOCOL_VERSIONS: List[Tuple[int, str]] = list(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS)
VERSION_TO_PROTOCOL: Dict[str, int] = dict(DEFAULT_VERSION_TO_PROTOCOL)

# Default to latest stable version
DEFAULT_PROTOCOL_VERSION = 772  # 1.21.7/1.21.8

# Remote mapping sources (PrismarineJS)
REMOTE_PROTOCOL_URLS = [
    "https://raw.githubusercontent.com/PrismarineJS/minecraft-data/master/data/pc/common/versions.json",
    # Fallback
    "https://raw.githubusercontent.com/PrismarineJS/minecraft-data/master/data/pc/common/protocolVersions.json",
]

CACHE_DIR = os.path.join(os.path.dirname(__file__), "instance")
os.makedirs(CACHE_DIR, exist_ok=True)
CACHE_PATH = os.path.join(CACHE_DIR, "protocol_cache.json")
MIN_PROTOCOL = 335  # don't auto-add very old protocols

AUTO_UPDATE = os.environ.get("PROTOCOL_AUTO_UPDATE", "1") not in ("0", "false", "False")
CACHE_TTL_SECONDS = 7 * 24 * 3600  # 7 days


def _load_cache() -> Optional[dict]:
	try:
		if os.path.exists(CACHE_PATH):
			st = os.stat(CACHE_PATH)
			with open(CACHE_PATH, "r") as f:
				data = json.load(f)
			data["_mtime"] = st.st_mtime
			return data
	except Exception:
		return None
	return None


def _save_cache(mapping: dict) -> None:
	try:
		with open(CACHE_PATH, "w") as f:
			json.dump(mapping, f)
	except Exception:
		pass


def _fetch_remote_versions(timeout: float = 2.0) -> Optional[List[dict]]:
	if not requests:
		return None
	for url in REMOTE_PROTOCOL_URLS:
		try:
			resp = requests.get(url, timeout=timeout)
			if resp.status_code == 200:
				return resp.json()
		except Exception:
			continue
	return None


def _merge_protocols(built_supported: List[Tuple[int, str]], built_map: Dict[str, int], remote_items: Optional[List[dict]]) -> Tuple[List[Tuple[int, str]], Dict[str, int]]:
	"""Merge built-ins with remote list into (supported_list, version_to_protocol)."""
	version_to_protocol = dict(built_map)
	supported = list(built_supported)
	seen_protocols = {proto for proto, _ in supported}
	if not remote_items:
		return supported, version_to_protocol
	# Prismarine versions.json entries have 'version' and 'protocol'
	for item in remote_items:
		try:
			proto = int(item.get("protocol")) if "protocol" in item else None
			ver = str(item.get("version")) if "version" in item else None
			if proto is None or not ver:
				continue
			# Guardrails
			if proto < MIN_PROTOCOL:
				continue
			version_to_protocol[ver] = proto
			# Build a simple label using version string
			label = ver
			if proto not in seen_protocols:
				supported.append((proto, label))
				seen_protocols.add(proto)
		except Exception:
			continue
	# Sort supported by protocol desc
	supported = sorted(supported, key=lambda x: x[0], reverse=True)
	return supported, version_to_protocol


def _initialize_protocols() -> None:
	global SUPPORTED_PROTOCOL_VERSIONS, VERSION_TO_PROTOCOL
	# Try cache first if recent
	cache = _load_cache()
	if cache and (time.time() - cache.get("_mtime", 0) < CACHE_TTL_SECONDS):
		try:
			SUPPORTED_PROTOCOL_VERSIONS = [(int(p), str(lbl)) for p, lbl in cache.get("SUPPORTED_PROTOCOL_VERSIONS", [])]
			VERSION_TO_PROTOCOL = {str(k): int(v) for k, v in cache.get("VERSION_TO_PROTOCOL", {}).items()}
			return
		except Exception:
			pass
	if AUTO_UPDATE:
		remote = _fetch_remote_versions()
		supported, vmap = _merge_protocols(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS, DEFAULT_VERSION_TO_PROTOCOL, remote)
		SUPPORTED_PROTOCOL_VERSIONS = supported
		VERSION_TO_PROTOCOL = vmap
		# Save cache
		try:
			_save_cache({
				"SUPPORTED_PROTOCOL_VERSIONS": SUPPORTED_PROTOCOL_VERSIONS,
				"VERSION_TO_PROTOCOL": VERSION_TO_PROTOCOL,
			})
		except Exception:
			pass
	else:
		SUPPORTED_PROTOCOL_VERSIONS = list(DEFAULT_SUPPORTED_PROTOCOL_VERSIONS)
		VERSION_TO_PROTOCOL = dict(DEFAULT_VERSION_TO_PROTOCOL)


# Initialize on import
_initialize_protocols()

# ===============================
# Protocol constants used below
# ===============================
HANDSHAKE_PACKET_ID = 0x00
LOGIN_START_PACKET_ID = 0x00
ENCRYPTION_REQUEST_PACKET_ID = 0x01
ENCRYPTION_RESPONSE_PACKET_ID = 0x01
LOGIN_SUCCESS_PACKET_ID = 0x02
DISCONNECT_PACKET_ID = 0x00
SET_COMPRESSION_PACKET_ID = 0x03
LOGIN_PLUGIN_REQUEST_PACKET_ID = 0x04

# Protocol states
STATE_HANDSHAKING = 0
STATE_STATUS = 1
STATE_LOGIN = 2
STATE_PLAY = 3

class ProtocolError(Exception):
    pass

def get_protocol_from_version(version_string: str) -> Optional[int]:
    """
    Extract protocol version from Minecraft version string.
    
    Args:
        version_string: Version string from mcstatus (e.g., "1.21.6", "1.20.4 (Paper)", etc.)
        
    Returns:
        Protocol version number or None if not found
    """
    if not version_string:
        return None
        
    # Clean up the version string - remove extra info like (Paper), (Forge), etc.
    version_clean = version_string.strip()
    
    # Remove common suffixes
    for suffix in [" (Paper)", " (Forge)", " (Spigot)", " (Bukkit)", " (Fabric)", " (Quilt)"]:
        if version_clean.endswith(suffix):
            version_clean = version_clean[:-len(suffix)]
            break
    
    # Try exact match first
    if version_clean in VERSION_TO_PROTOCOL:
        return VERSION_TO_PROTOCOL[version_clean]
    
    # Try partial matches for complex version strings
    for known_version, protocol in VERSION_TO_PROTOCOL.items():
        if version_clean.startswith(known_version):
            return protocol
    
    # Try to extract version number from anywhere in the string (e.g., "Paper 1.21.6")
    import re
    match = re.search(r'(\d+\.\d+(?:\.\d+)?)', version_clean)
    if match:
        extracted_version = match.group(1)
        if extracted_version in VERSION_TO_PROTOCOL:
            return VERSION_TO_PROTOCOL[extracted_version]
    
    return None

class MinecraftProtocolClient:
    """
    Minimal Minecraft protocol client for testing whitelist status.
    Based on protocol documentation from wiki.vg and reference implementations.
    Supports multiple Minecraft versions with automatic fallback.
    """
    
    def __init__(self, logger: Optional[logging.Logger] = None, protocol_version: Optional[int] = None):
        self.socket = None
        self.logger = logger or logging.getLogger(__name__)
        self.protocol_version = protocol_version or DEFAULT_PROTOCOL_VERSION
        self.server_version_detected = None
        self._cipher_enc = None
        self._cipher_dec = None
        self._compression_threshold = None
        self._server_pubkey = None
        self._server_id = ""
        self._force_legacy_login_start = False
        
    def _pack_varint(self, value: int) -> bytes:
        """Pack an integer as a VarInt."""
        data = bytearray()
        while True:
            byte = value & 0x7F
            value >>= 7
            if value != 0:
                byte |= 0x80
            data.append(byte)
            if value == 0:
                break
        return bytes(data)
    
    def _unpack_varint(self, data: bytes, offset: int = 0) -> Tuple[int, int]:
        """Unpack a VarInt and return (value, bytes_read)."""
        value = 0
        position = 0
        bytes_read = 0
        
        while offset + bytes_read < len(data):
            byte = data[offset + bytes_read]
            bytes_read += 1
            
            value |= (byte & 0x7F) << position
            
            if (byte & 0x80) == 0:
                break
                
            position += 7
            
            if position >= 32:
                raise ProtocolError("VarInt is too big")
                
        return value, bytes_read
    
    def _pack_string(self, text: str) -> bytes:
        """Pack a string with length prefix."""
        encoded = text.encode('utf-8')
        return self._pack_varint(len(encoded)) + encoded
    
    def _unpack_string(self, data: bytes, offset: int = 0) -> Tuple[str, int]:
        """Unpack a string and return (string, bytes_read)."""
        length, bytes_read = self._unpack_varint(data, offset)
        start = offset + bytes_read
        end = start + length
        
        if end > len(data):
            raise ProtocolError("String length exceeds available data")
            
        text = data[start:end].decode('utf-8')
        return text, bytes_read + length
    
    def _pack_uuid(self, uuid_str: str) -> bytes:
        """Pack a UUID as bytes."""
        try:
            # Remove dashes and convert to UUID object
            clean_uuid = uuid_str.replace('-', '')
            uuid_obj = uuid.UUID(clean_uuid)
            return uuid_obj.bytes
        except ValueError as e:
            raise ProtocolError(f"Invalid UUID format: {uuid_str}") from e
    
    def _enable_encryption(self, shared_secret: bytes) -> None:
        # AES/CFB8 like vanilla client
        self._cipher_enc = AES.new(shared_secret, AES.MODE_CFB, iv=shared_secret, segment_size=8)
        self._cipher_dec = AES.new(shared_secret, AES.MODE_CFB, iv=shared_secret, segment_size=8)

    def _encrypt_rsa(self, public_key_der: bytes, data: bytes) -> bytes:
        key = RSA.import_key(public_key_der)
        cipher = PKCS1_v1_5.new(key)
        return cipher.encrypt(data)

    def _session_join(self, username: str, uuid_str: str, access_token: str, server_hash: str) -> tuple[bool, int, str]:
        import requests
        uuid_nodash = uuid_str.replace('-', '').lower()
        uuid_dashed = str(uuid.UUID(uuid_nodash))
        headers = {"Content-Type": "application/json"}

        def try_join(url_base: str) -> tuple[bool, int, str]:
            url = f"{url_base}/session/minecraft/join"
            # 1) nodash
            payload = {"accessToken": access_token, "selectedProfile": uuid_nodash, "serverId": server_hash}
            r = requests.post(url, json=payload, headers=headers, timeout=10)
            if r.status_code == 204:
                return True, 204, ""
            self.logger.warning(f"Session join failed via {url} (nodash): {r.status_code} {r.text}")
            # 2) dashed
            payload = {"accessToken": access_token, "selectedProfile": uuid_dashed, "serverId": server_hash}
            r2 = requests.post(url, json=payload, headers=headers, timeout=10)
            if r2.status_code == 204:
                return True, 204, ""
            self.logger.warning(f"Session join failed via {url} (dashed): {r2.status_code} {r2.text}")
            return False, r2.status_code, r2.text

        # Prefer the modern services API first
        ok, code, text = try_join("https://api.minecraftservices.com")
        if ok:
            return True, code, text
        # Fallback to legacy Mojang endpoint
        ok2, code2, text2 = try_join("https://sessionserver.mojang.com")
        return (ok2, code2, text2)

    def _compute_server_hash(self, server_id: str, public_key_der: bytes, shared_secret: bytes) -> str:
        # Java-style signed hash hex (two's complement) per wiki.vg
        digest = hashlib.sha1()
        digest.update(server_id.encode('ISO-8859-1'))
        digest.update(shared_secret)
        digest.update(public_key_der)
        value = int.from_bytes(digest.digest(), byteorder='big', signed=True)
        return format(value, 'x')

    def _send_encryption_response(self, encrypted_secret: bytes, encrypted_token: bytes) -> None:
        data = (
            self._pack_varint(len(encrypted_secret)) + encrypted_secret +
            self._pack_varint(len(encrypted_token)) + encrypted_token
        )
        self._send_packet(ENCRYPTION_RESPONSE_PACKET_ID, data)

    def _send_packet(self, packet_id: int, data: bytes = b'') -> None:
        """Send a packet with proper framing."""
        if not self.socket:
            raise ProtocolError("Socket not connected")
            
        # Packet payload = VarInt(packet_id) + data
        payload = self._pack_varint(packet_id) + data
        
        # Apply compression wrapper if enabled
        if self._compression_threshold is not None:
            threshold = self._compression_threshold or 0
            if threshold > 0 and len(payload) >= threshold:
                # compress
                try:
                    compressed = zlib.compress(payload)
                except Exception as e:
                    raise ProtocolError(f"Failed to compress packet: {e}")
                # VarInt of uncompressed length, then compressed bytes
                inner = self._pack_varint(len(payload)) + compressed
            else:
                # Uncompressed: VarInt 0 + raw payload
                inner = self._pack_varint(0) + payload
            frame_body = inner
        else:
            frame_body = payload
        
        # Frame = VarInt(length of frame_body) + frame_body
        frame = self._pack_varint(len(frame_body)) + frame_body
        if self._cipher_enc:
            frame = self._cipher_enc.encrypt(frame)
        self.socket.sendall(frame)
        self.logger.debug(f"Sent packet ID {packet_id}, {len(frame)} bytes")
    
    def _receive_packet(self) -> Tuple[int, bytes]:
        """Receive and parse a packet."""
        if not self.socket:
            raise ProtocolError("Socket not connected")
        
        # Read packet length (VarInt)
        def _read_exact(n: int) -> bytes:
            buf = b''
            while len(buf) < n:
                chunk = self.socket.recv(n - len(buf))
                if not chunk:
                    raise ConnectionError("Socket closed")
                buf += chunk
            return buf
        # Read VarInt length one byte at a time
        raw = b''
        while True:
            b1 = _read_exact(1)
            if self._cipher_dec:
                b1 = self._cipher_dec.decrypt(b1)
            raw += b1
            if b1[0] & 0x80 == 0:
                break
        packet_length, _ = self._unpack_varint(raw)
        body = _read_exact(packet_length)
        if self._cipher_dec:
            body = self._cipher_dec.decrypt(body)
        
        # Handle compression if enabled
        if self._compression_threshold is not None:
            # First VarInt in body is the uncompressed data length; 0 means not compressed
            uncompressed_len, read_a = self._unpack_varint(body, 0)
            if uncompressed_len == 0:
                data_bytes = body[read_a:]
            else:
                compressed_bytes = body[read_a:]
                try:
                    data_bytes = zlib.decompress(compressed_bytes)
                except Exception as e:
                    raise ProtocolError(f"Failed to decompress packet: {e}")
        else:
            data_bytes = body
        
        packet_id, read = self._unpack_varint(data_bytes, 0)
        return packet_id, data_bytes[read:]
    
    def _read_varint(self) -> int:
        """Read a VarInt directly from socket."""
        value = 0
        position = 0
        
        while True:
            byte_data = self._receive_exact(1)
            byte = byte_data[0]
            
            value |= (byte & 0x7F) << position
            
            if (byte & 0x80) == 0:
                break
                
            position += 7
            
            if position >= 32:
                raise ProtocolError("VarInt is too big")
                
        return value
    
    def _receive_exact(self, num_bytes: int) -> bytes:
        """Receive exactly num_bytes from socket."""
        data = b''
        while len(data) < num_bytes:
            chunk = self.socket.recv(num_bytes - len(data))
            if not chunk:
                raise ProtocolError("Connection closed")
            data += chunk
        return data
    
    def _send_handshake(self, host: str, port: int) -> None:
        """Send handshake packet."""
        data = (
            self._pack_varint(self.protocol_version) +
            self._pack_string(host) +
            struct.pack('>H', port) +  # Unsigned short, big endian
            self._pack_varint(STATE_LOGIN)
        )
        self._send_packet(HANDSHAKE_PACKET_ID, data)
    
    def _send_login_start(self, username: str, uuid_str: str) -> None:
        """Send login start packet: >=1.19 send fields per version; older send name only."""
        if self.protocol_version >= 764:
            # 1.20.2+ works with name + UUID (no chat-signing boolean here)
            if self._force_legacy_login_start:
                data = (
                    self._pack_string(username)
                )
            else:
                data = (
                    self._pack_string(username) +
                    self._pack_uuid(uuid_str)
                )
        elif 759 <= self.protocol_version <= 763:
            # 1.19.x to 1.20.1 expect name + hasSignature(boolean). We send hasSignature=false
            if self._force_legacy_login_start:
                data = (
                    self._pack_string(username)
                )
            else:
                data = (
                    self._pack_string(username) +
                    b'\x00'  # hasSignature = false
                )
        else:
            data = (
                self._pack_string(username)
            )
        self._send_packet(LOGIN_START_PACKET_ID, data)
    
    def _parse_disconnect_message(self, payload: bytes) -> str:
        """Parse disconnect packet and extract a readable reason (supports translate/with/extra)."""
        def _flatten_chat_component(component: Any) -> str:
            # Recursively flatten Minecraft chat component JSON into plain text
            if isinstance(component, str):
                return component
            if isinstance(component, list):
                return "".join(_flatten_chat_component(part) for part in component)
            if isinstance(component, dict):
                parts: list[str] = []
                text = component.get('text')
                if isinstance(text, str):
                    parts.append(text)
                # Handle translated messages with parameters
                if 'translate' in component:
                    translate_key = component.get('translate')
                    with_args = component.get('with') or []
                    rendered_with = ", ".join(_flatten_chat_component(arg) for arg in with_args)
                    # Include translate key to help downstream classification
                    if rendered_with:
                        parts.append(f"{translate_key}: {rendered_with}")
                    else:
                        parts.append(f"{translate_key}")
                # Handle extra array
                if 'extra' in component:
                    parts.append(_flatten_chat_component(component.get('extra')))
                return "".join(parts) if parts else str(component)
            return str(component)
        reason_json = None
        try:
            reason_json, _ = self._unpack_string(payload)
            try:
                reason_data = json.loads(reason_json)
                return _flatten_chat_component(reason_data)
            except Exception:
                # Not JSON, return raw string
                return reason_json
        except Exception as e:
            self.logger.warning(f"Failed to parse disconnect message: {e}")
            return reason_json or "Unknown disconnect reason"
    
    def check_whitelist_with_smart_fallback(self, host: str, port: int, username: str, uuid_str: str, 
                                            access_token: str, timeout: int = 10, 
                                            server_version: Optional[str] = None) -> Dict[str, Any]:
        """
        Check whitelist status with smart protocol version detection.
        Uses known server version first, then falls back to version probing.
        
        Args:
            server_version: Known server version string from mcstatus (e.g., "1.21.6")
        """
        last_error = None
        versions_tried = []
        attempted_protocols: set[int] = set()
        attempted_legacy_protocols: set[int] = set()
        
        # statuses that are definitive and should end probing
        definitive_statuses = {
            'allowed', 'not_whitelisted', 'banned', 'server_full', 'modded_required',
            'join_forbidden', 'rate_limited'
        }
        
        # Step 1: Try to use the known server version first
        if server_version:
            target_protocol = get_protocol_from_version(server_version)
            if target_protocol:
                try:
                    self.protocol_version = target_protocol
                    version_name = next((name for proto, name in SUPPORTED_PROTOCOL_VERSIONS if proto == target_protocol), f"protocol {target_protocol}")
                    self.logger.info(f"Using known server version {server_version} -> protocol {target_protocol}")
                    versions_tried.append(f"{target_protocol} ({version_name}) [from server version]")
                    attempted_protocols.add(target_protocol)
                    
                    result = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                    
                    # Return only for definitive outcomes; keep probing on version mismatch/unknown
                    if result.get('status') in definitive_statuses:
                        result['protocol_version'] = target_protocol
                        result['version_name'] = version_name
                        result['versions_tried'] = versions_tried
                        result['used_known_version'] = True
                        return result
                    
                    # If not definitive, try server-provided version hint before generic fallback
                    last_error = result
                    # 1.19.x adaptive login start: if same-version mismatch or decoder exception, retry once with legacy name-only
                    try:
                        current_proto = target_protocol
                        msg = (result.get('message') or '').lower()
                        same_version_mismatch = (result.get('status') == 'version_mismatch' and result.get('hint_protocol') == current_proto)
                        decoder_or_outdated = ('decoderexception' in msg) or ('outdated_client' in msg)
                        if 759 <= current_proto <= 762 and (same_version_mismatch or decoder_or_outdated) and current_proto not in attempted_legacy_protocols:
                            self._force_legacy_login_start = True
                            self.logger.info("Retrying with legacy Login Start (name-only) for 1.19.x")
                            versions_tried.append(f"{current_proto} ({version_name}) [legacy login start]")
                            attempted_legacy_protocols.add(current_proto)
                            result_legacy = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                            self._force_legacy_login_start = False
                            if result_legacy.get('status') in definitive_statuses:
                                result_legacy['protocol_version'] = current_proto
                                result_legacy['version_name'] = version_name
                                result_legacy['versions_tried'] = versions_tried
                                result_legacy['used_known_version'] = True
                                return result_legacy
                            last_error = result_legacy
                    except Exception:
                        self._force_legacy_login_start = False
                    # If server hints a protocol we've already used, stop probing
                    if result.get('status') == 'version_mismatch':
                        _hp = result.get('hint_protocol')
                        if isinstance(_hp, int) and _hp in attempted_protocols:
                            result['protocol_version'] = target_protocol
                            result['version_name'] = version_name
                            result['versions_tried'] = versions_tried
                            result['used_known_version'] = True
                            return result
                    try:
                        _hint_proto = result.get('hint_protocol')
                        _hint_ver = result.get('hint_version')
                        if isinstance(_hint_proto, int) and _hint_proto not in attempted_protocols:
                            self.protocol_version = _hint_proto
                            version_name = next((name for proto, name in SUPPORTED_PROTOCOL_VERSIONS if proto == _hint_proto), f"protocol {_hint_proto}")
                            self.logger.info(f"Retrying using server-provided version hint {_hint_ver} -> protocol {_hint_proto}")
                            versions_tried.append(f"{_hint_proto} ({version_name}) [from hint]")
                            attempted_protocols.add(_hint_proto)
                            result2 = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                            if result2.get('status') in definitive_statuses:
                                result2['protocol_version'] = _hint_proto
                                result2['version_name'] = version_name
                                result2['versions_tried'] = versions_tried
                                result2['used_known_version'] = True
                                return result2
                            last_error = result2
                    except Exception:
                        pass
                    self.logger.warning(f"Known version {server_version} protocol {target_protocol} not definitive ({result.get('status')}), trying fallback")
                    
                except Exception as e:
                    self.logger.debug(f"Known protocol {target_protocol} failed: {e}")
                    last_error = {
                        'status': 'error',
                        'message': f'Known protocol {target_protocol} error: {str(e)}'
                    }
        
        # Step 2: Fall back to trying all supported versions
        self.logger.info("Falling back to version probing")
        for protocol_version, version_name in SUPPORTED_PROTOCOL_VERSIONS:
            # Skip the version we already tried
            if server_version and protocol_version == get_protocol_from_version(server_version):
                continue
            if protocol_version in attempted_protocols:
                continue
                
            try:
                self.protocol_version = protocol_version
                self.logger.debug(f"Attempting whitelist check with protocol {protocol_version} ({version_name})")
                versions_tried.append(f"{protocol_version} ({version_name})")
                attempted_protocols.add(protocol_version)
                
                result = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                
                # Return only for definitive outcomes; keep probing on version mismatch/unknown
                if result.get('status') in definitive_statuses:
                    result['protocol_version'] = protocol_version
                    result['version_name'] = version_name
                    result['versions_tried'] = versions_tried
                    result['used_known_version'] = False
                    return result
                
                # Otherwise, try server-provided hint before trying next protocol
                last_error = result
                # 1.19.x adaptive login start: if same-version mismatch or decoder exception, retry once with legacy name-only
                try:
                    current_proto = protocol_version
                    msg = (result.get('message') or '').lower()
                    same_version_mismatch = (result.get('status') == 'version_mismatch' and result.get('hint_protocol') == current_proto)
                    decoder_or_outdated = ('decoderexception' in msg) or ('outdated_client' in msg)
                    if 759 <= current_proto <= 762 and (same_version_mismatch or decoder_or_outdated) and current_proto not in attempted_legacy_protocols:
                        self._force_legacy_login_start = True
                        self.logger.info("Retrying with legacy Login Start (name-only) for 1.19.x")
                        versions_tried.append(f"{current_proto} ({version_name}) [legacy login start]")
                        attempted_legacy_protocols.add(current_proto)
                        result_legacy = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                        self._force_legacy_login_start = False
                        if result_legacy.get('status') in definitive_statuses:
                            result_legacy['protocol_version'] = current_proto
                            result_legacy['version_name'] = version_name
                            result_legacy['versions_tried'] = versions_tried
                            result_legacy['used_known_version'] = False
                            return result_legacy
                        last_error = result_legacy
                except Exception:
                    self._force_legacy_login_start = False
                # If server hints a protocol we've already used, stop probing to avoid thrashing
                if result.get('status') == 'version_mismatch':
                    _hp = result.get('hint_protocol')
                    if isinstance(_hp, int) and _hp in attempted_protocols:
                        result['versions_tried'] = versions_tried
                        result['used_known_version'] = bool(server_version and get_protocol_from_version(server_version))
                        return result
                try:
                    _hint_proto = result.get('hint_protocol')
                    _hint_ver = result.get('hint_version')
                    if isinstance(_hint_proto, int) and _hint_proto not in attempted_protocols:
                        self.protocol_version = _hint_proto
                        vname2 = next((name for proto, name in SUPPORTED_PROTOCOL_VERSIONS if proto == _hint_proto), f"protocol {_hint_proto}")
                        self.logger.info(f"Retrying using server-provided version hint {_hint_ver} -> protocol {_hint_proto}")
                        versions_tried.append(f"{_hint_proto} ({vname2}) [from hint]")
                        attempted_protocols.add(_hint_proto)
                        result2 = self.check_whitelist(host, port, username, uuid_str, access_token, timeout)
                        if result2.get('status') in definitive_statuses:
                            result2['protocol_version'] = _hint_proto
                            result2['version_name'] = vname2
                            result2['versions_tried'] = versions_tried
                            result2['used_known_version'] = False
                            return result2
                        last_error = result2
                except Exception:
                    pass
                continue
                    
            except Exception as e:
                self.logger.debug(f"Protocol {protocol_version} failed: {e}")
                last_error = {
                    'status': 'error',
                    'message': f'Protocol {protocol_version} error: {str(e)}'
                }
                continue
        
        # All versions failed or non-definitive; return the last observed result
        if last_error:
            last_error['versions_tried'] = versions_tried
            last_error['used_known_version'] = bool(server_version and get_protocol_from_version(server_version))
            return last_error
        
        return {
            'status': 'error',
            'message': 'All supported protocol versions failed',
            'versions_tried': versions_tried,
            'used_known_version': bool(server_version and get_protocol_from_version(server_version)),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    def check_whitelist_with_fallback(self, host: str, port: int, username: str, uuid_str: str, 
                                      access_token: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Check whitelist status with automatic protocol version fallback.
        Tries multiple protocol versions starting with the latest.
        
        Deprecated: Use check_whitelist_with_smart_fallback instead for better performance.
        """
        return self.check_whitelist_with_smart_fallback(host, port, username, uuid_str, access_token, timeout)

    def check_whitelist(self, host: str, port: int, username: str, uuid_str: str, 
                       access_token: str, timeout: int = 10) -> Dict[str, Any]:
        """
        Attempt to connect to a Minecraft server and determine whitelist status.
        
        Returns:
            Dict with 'status' and 'message' keys.
            Status can be: 'allowed', 'not_whitelisted', 'timeout', 'error'
        """
        self.socket = None
        
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(timeout)
            self.logger.info(f"Connecting to {host}:{port} as {username}")
            self.socket.connect((host, port))
            self._cipher_enc = self._cipher_dec = None
            self._compression_threshold = None
            
            self._send_handshake(host, port)
            self._send_login_start(username, uuid_str)

            packet_count = 0
            max_packets = 20

            while packet_count < max_packets:
                packet_count += 1
                try:
                    packet_id, payload = self._receive_packet()
                except socket.timeout:
                    break

                if packet_id == DISCONNECT_PACKET_ID:
                    disconnect_reason = self._parse_disconnect_message(payload)
                    self.logger.info(f"Disconnected: {disconnect_reason}")
                    return self._analyze_disconnect_reason(disconnect_reason)

                elif packet_id == ENCRYPTION_REQUEST_PACKET_ID:
                    # Parse: serverId(String), publicKey(byte array), verifyToken(byte array)
                    server_id, read = self._unpack_string(payload, 0)
                    pk_len, r2 = self._unpack_varint(payload, read)
                    read = read + r2
                    server_pubkey = payload[read:read+pk_len]
                    read += pk_len
                    token_len, r3 = self._unpack_varint(payload, read)
                    read += r3
                    verify_token = payload[read:read+token_len]
                    self._server_pubkey = server_pubkey
                    self._server_id = server_id

                    # Generate shared secret
                    from os import urandom
                    shared_secret = urandom(16)
                    encrypted_secret = self._encrypt_rsa(server_pubkey, shared_secret)
                    encrypted_token = self._encrypt_rsa(server_pubkey, verify_token)

                    # Compute server hash and join session
                    server_hash = self._compute_server_hash(server_id, server_pubkey, shared_secret)
                    ok, join_code, join_text = self._session_join(username, uuid_str, access_token, server_hash)
                    if not ok:
                        if join_code == 403:
                            return {
                                'status': 'join_forbidden',
                                'message': 'Session join forbidden (403) by session server'
                            }
                        if join_code == 429:
                            return {
                                'status': 'rate_limited',
                                'message': 'Session server rate-limited the request (429). Please slow down and retry later.'
                            }
                        return {
                            'status': 'error',
                            'message': f'Session join failed ({join_code})'
                        }

                    # Send encryption response and enable encryption
                    self._send_encryption_response(encrypted_secret, encrypted_token)
                    self._enable_encryption(shared_secret)
                    continue

                elif packet_id == SET_COMPRESSION_PACKET_ID:
                    # Read threshold
                    threshold, _ = self._unpack_varint(payload, 0)
                    self._compression_threshold = threshold
                    continue

                elif packet_id == LOGIN_PLUGIN_REQUEST_PACKET_ID:
                    # Decline plugin request (send empty response) to continue
                    message_id, r = self._unpack_varint(payload, 0)
                    # Respond with: messageId VarInt, successful Boolean=false
                    resp = self._pack_varint(message_id) + b'\x00'
                    # Packet ID for Login Plugin Response is 0x02 on modern versions? Keep consistent: use 0x02 when LOGIN_SUCCESS is 0x02; response id is 0x02 as well in login phase
                    # For simplicity, ignore when mismatch; declining is acceptable
                    try:
                        self._send_packet(0x02, resp)
                    except Exception:
                        pass
                    continue

                elif packet_id == LOGIN_SUCCESS_PACKET_ID:
                    self.logger.info("Login successful - whitelisted")
                    return {
                        'status': 'allowed',
                        'message': 'Login successful'
                    }
                else:
                    self.logger.warning(f"Unexpected packet ID during login: {packet_id}")
                    continue

            self.logger.warning(f"Login process incomplete after {packet_count} packets")
            return {
                'status': 'error',
                'message': 'Login process incomplete - no clear response from server'
            }
        except socket.timeout:
            self.logger.warning("Connection timed out")
            return {
                'status': 'timeout',
                'message': 'Connection timed out'
            }
        except ConnectionRefusedError:
            self.logger.warning("Connection refused")
            return {
                'status': 'error',
                'message': 'Connection refused - server may be offline'
            }
        except Exception as e:
            self.logger.error(f"Error during whitelist check: {e}")
            return {
                'status': 'error',
                'message': f'Connection error: {str(e)}'
            }
        finally:
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
                self.socket = None
    
    def _analyze_disconnect_reason(self, reason: str) -> Dict[str, Any]:
        """
        Analyze disconnect reason to determine if it's whitelist-related.
        """
        reason_lower = reason.lower()
        
        # Map common translate keys (if present in flattened text)
        if 'multiplayer.disconnect.not_whitelisted' in reason_lower:
            return {
                'status': 'not_whitelisted',
                'message': f'Not whitelisted: {reason}'
            }
        if 'multiplayer.disconnect.banned' in reason_lower:
            return {
                'status': 'banned',
                'message': f'Banned: {reason}'
            }
        if 'multiplayer.disconnect.server_full' in reason_lower:
            return {
                'status': 'server_full',
                'message': f'Server full: {reason}'
            }
        if 'multiplayer.disconnect.incompatible' in reason_lower or 'outdated' in reason_lower:
            # Provide a protocol hint if the server includes a version string
            try:
                import re
                m = re.search(r'(\d+\.\d+(?:\.\d+)?)', reason)
                if m:
                    hint_ver = m.group(1)
                    proto = get_protocol_from_version(hint_ver)
                    if proto:
                        return {
                            'status': 'version_mismatch',
                            'message': f'Version mismatch: server indicates {hint_ver}',
                            'hint_version': hint_ver,
                            'hint_protocol': proto
                        }
            except Exception:
                pass
            return {
                'status': 'version_mismatch',
                'message': f'Version mismatch: {reason}'
            }
        
        # Handshake/proxy/mod-related failures that are not simple version mismatches
        if 'handshake failure' in reason_lower or 'incompatible client' in reason_lower:
            return {
                'status': 'modded_required',
                'message': reason
            }
        if 'badly compressed packet' in reason_lower:
            return {
                'status': 'error',
                'message': reason
            }
        
        # Common whitelist messages
        whitelist_indicators = [
            'not white-listed',
            'not whitelisted', 
            'whitelist',
            'not on the whitelist',
            'you are not whitelisted',
            'not allowed to join',
            'not permitted',
            'access denied'
        ]
        for indicator in whitelist_indicators:
            if indicator in reason_lower:
                return {
                    'status': 'not_whitelisted',
                    'message': f'Not whitelisted: {reason}'
                }
        
        # Modded servers requiring client mods/Forge/Fabric
        if any(term in reason_lower for term in ['forge', 'fml', 'fabric', 'quilt', 'mods required', 'requires fml']):
            return {
                'status': 'modded_required',
                'message': reason
            }

        # Velocity proxy required
        if 'velocity' in reason_lower or 'requires you to connect with velocity' in reason_lower:
            return {
                'status': 'velocity_required',
                'message': 'Proxy required (Velocity): ' + reason
            }
        
        # Other common rejection reasons
        if 'server starting' in reason_lower or 'please reconnect' in reason_lower:
            return {
                'status': 'server_starting',
                'message': reason
            }
        if any(term in reason_lower for term in ['banned', 'ban']):
            return {
                'status': 'banned',
                'message': f'Banned: {reason}'
            }
        if 'full' in reason_lower or 'server is full' in reason_lower:
            return {
                'status': 'server_full',
                'message': f'Server full: {reason}'
            }
        if any(term in reason_lower for term in ['version', 'protocol']):
            # Provide a protocol hint if detectable
            try:
                import re
                m = re.search(r'(\d+\.\d+(?:\.\d+)?)', reason)
                if m:
                    hint_ver = m.group(1)
                    proto = get_protocol_from_version(hint_ver)
                    if proto:
                        return {
                            'status': 'version_mismatch',
                            'message': f'Version mismatch: server indicates {hint_ver}',
                            'hint_version': hint_ver,
                            'hint_protocol': proto
                        }
            except Exception:
                pass
            return {
                'status': 'version_mismatch',
                'message': f'Version mismatch: {reason}'
            }
        
        # Unknown disconnect reason
        return {
            'status': 'unknown_disconnect',
            'message': f'Disconnected: {reason}'
        } 
