import json
import os
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import logging

import requests
from minecraft_protocol import MinecraftProtocolClient


# Minecraft API endpoints (no Microsoft/Azure endpoints)
MC_PROFILE_URL = "https://api.minecraftservices.com/minecraft/profile"
MC_ENTITLEMENTS_URL = "https://api.minecraftservices.com/entitlements/mcstore"


class WhitelistProbe:
	"""
	Simple whitelist checker that uses stored profile (UUID+name) fetched
	from a Minecraft access token. Manual profile path removed.
	"""
	def __init__(self, auth_settings_path: str):
		self.auth_settings_path = auth_settings_path
		self._auth: Dict[str, Any] = {}
		self._load_auth_settings()
		
		# Set up logger for protocol client
		self.logger = logging.getLogger(f"{__name__}.WhitelistProbe")
		
		# Initialize protocol client
		self.protocol_client = MinecraftProtocolClient(self.logger)

	def _load_auth_settings(self) -> None:
		try:
			if os.path.exists(self.auth_settings_path):
				with open(self.auth_settings_path, 'r') as f:
					self._auth = json.load(f)
			else:
				self._auth = {}
		except Exception:
			self._auth = {}

	def _save_auth_settings(self) -> None:
		os.makedirs(os.path.dirname(self.auth_settings_path), exist_ok=True)
		with open(self.auth_settings_path, 'w') as f:
			json.dump(self._auth, f, indent=2)

	# ==============================
	# Public status & configuration
	# ==============================
	def is_configured(self) -> bool:
		"""Configured when we have an access token and a fetched profile."""
		profile = self._auth.get('profile') or {}
		return bool(self._auth.get('access_token')) and bool(profile.get('id')) and bool(profile.get('name'))

	def get_public_status(self) -> Dict[str, Any]:
		profile = self._auth.get('profile') or {}
		return {
			'configured': self.is_configured(),
			'auth_type': 'token',
			'owns_game': self._auth.get('owns_game'),
			'username': profile.get('name'),
			'uuid': profile.get('id')
		}

	def _fetch_profile_from_token(self, access_token: str) -> Dict[str, Any]:
		"""Fetch Minecraft profile using access token"""
		try:
			headers = {'Authorization': f'Bearer {access_token}'}
			
			# Get profile
			profile_resp = requests.get(MC_PROFILE_URL, headers=headers, timeout=15)
			if profile_resp.status_code != 200:
				return {
					'status': 'error', 
					'message': f'Profile fetch failed: {profile_resp.status_code} {profile_resp.text}'
				}
			
			profile_data = profile_resp.json()
			profile = {
				'id': profile_data.get('id'),
				'name': profile_data.get('name')
			}
			
			# Check game ownership (optional)
			owns_game = None
			try:
				entitlements_resp = requests.get(MC_ENTITLEMENTS_URL, headers=headers, timeout=15)
				if entitlements_resp.status_code == 200:
					entitlements = entitlements_resp.json()
					items = entitlements.get('items', [])
					owns_game = any(item.get('name') in ['product_minecraft', 'game_minecraft'] for item in items)
			except Exception:
				pass  # Game ownership check is optional
			
			return {
				'status': 'success',
				'profile': profile,
				'owns_game': owns_game
			}
			
		except Exception as e:
			return {
				'status': 'error',
				'message': f'Profile fetch error: {str(e)}'
			}

	def update_auth_settings(self, data: Dict[str, Any]) -> Dict[str, Any]:
		"""Update authentication settings with token only."""
		access_token = data.get('access_token', '').strip()
		
		self._auth.update({
			'auth_type': 'token',
			'updated_at': datetime.now(timezone.utc).isoformat()
		})
		
		if not access_token:
			return {'status': 'error', 'message': 'Provide access_token'}
		
		result = self._fetch_profile_from_token(access_token)
		if result['status'] == 'success':
			self._auth['access_token'] = access_token
			self._auth['profile'] = result['profile']
			if result.get('owns_game') is not None:
				self._auth['owns_game'] = result['owns_game']
			self._save_auth_settings()
			return {'status': 'success', 'message': 'Profile fetched and saved successfully'}
		else:
			return result

	def check_whitelist(self, ip: str, port: int, timeout_seconds: int = 10, server_version: str = None) -> Dict[str, Any]:
		"""
		Check if player is whitelisted on server using stored profile and token.
		"""
		if not self.is_configured():
			return {'status': 'error', 'message': 'No token/profile configured. Open Settings and save a Minecraft token first.'}
		
		profile = self._auth.get('profile', {})
		username = profile.get('name')
		uuid_str = profile.get('id')
		access_token = self._auth.get('access_token')
		
		try:
			result = self.protocol_client.check_whitelist_with_smart_fallback(
				host=ip,
				port=port,
				username=username,
				uuid_str=uuid_str,
				access_token=access_token or "",
				timeout=timeout_seconds,
				server_version=server_version
			)
			return result
		except Exception as e:
			self.logger.error(f"Whitelist check failed: {e}")
			return {'status': 'error', 'message': f'Whitelist check failed: {str(e)}'} 