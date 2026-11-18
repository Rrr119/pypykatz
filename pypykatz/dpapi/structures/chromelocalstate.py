#!/usr/bin/env python3
#
# Chrome Local State support for offline DPAPI forensics.
#

import base64
import copy
import json

from pypykatz.dpapi.structures.blob import DPAPI_BLOB


class ChromeLocalState:
	"""
	Parses Chrome's Local State JSON document and decrypts the DPAPI-protected
	key stored in os_crypt.encrypted_key.
	"""

	DPAPI_PREFIX = b'DPAPI'

	def __init__(self, data = None, path = None):
		self.data = data if data is not None else {}
		self.path = path
		self.encrypted_key = None
		self.encrypted_key_b64 = None
		self.masterkey_guid = None
		self.masterkey_scope = None
		self.key = None

	@staticmethod
	def from_bytes(data, path = None):
		return ChromeLocalState.from_buffer(data, path = path)

	@staticmethod
	def from_buffer(data, path = None):
		if isinstance(data, str):
			data = data.encode('utf-8')

		try:
			local_state = json.loads(data.decode('utf-8-sig'))
		except Exception as e:
			raise ValueError('Failed to parse Chrome Local State JSON: %s' % e)

		if not isinstance(local_state, dict):
			raise ValueError('Chrome Local State must contain a JSON object')

		os_crypt = local_state.get('os_crypt')
		if not isinstance(os_crypt, dict) or os_crypt.get('encrypted_key') is None:
			raise ValueError('Chrome Local State does not contain os_crypt.encrypted_key')
		if not isinstance(os_crypt['encrypted_key'], str):
			raise ValueError('os_crypt.encrypted_key must be a base64 string')

		res = ChromeLocalState(local_state, path = path)
		res.encrypted_key_b64 = os_crypt['encrypted_key'].strip()
		try:
			res.encrypted_key = base64.b64decode(res.encrypted_key_b64, validate = True)
		except Exception:
			try:
				padding = '=' * (-len(res.encrypted_key_b64) % 4)
				res.encrypted_key = base64.b64decode(res.encrypted_key_b64 + padding, validate = True)
			except Exception as e:
				raise ValueError('Failed to base64-decode os_crypt.encrypted_key: %s' % e)

		if not res.encrypted_key.startswith(ChromeLocalState.DPAPI_PREFIX):
			raise ValueError('os_crypt.encrypted_key is not a DPAPI blob')

		res.encrypted_key = res.encrypted_key[len(ChromeLocalState.DPAPI_PREFIX):]
		if len(res.encrypted_key) == 0:
			raise ValueError('os_crypt.encrypted_key contains an empty DPAPI blob')

		return res

	@staticmethod
	def from_file(path):
		with open(path, 'rb') as f:
			return ChromeLocalState.from_bytes(f.read(), path = path)

	def decrypt(self, dpapi, key = None):
		"""
		Decrypts the Local State's DPAPI-protected AES key.

		dpapi: DPAPI instance containing user and/or system masterkeys
		key: optional raw masterkey. When omitted the DPAPI key store is used.
		"""
		blob = DPAPI_BLOB.from_bytes(self.encrypted_key)
		self.masterkey_guid = blob.masterkey_guid

		if key is None:
			try:
				key, self.masterkey_scope = dpapi.get_key_for_blob(blob, return_scope = True)
			except Exception:
				plaintext = dpapi.decrypt_blob(blob)
				if plaintext is None:
					raise
				self.masterkey_scope = 'unbound'
				self.key = plaintext
				return plaintext

		plaintext = dpapi.decrypt_blob(blob, key = key)
		if plaintext is None:
			raise ValueError(
				'DPAPI authentication failed for Chrome Local State key (masterkey GUID %s)'
				% self.masterkey_guid
			)

		if len(plaintext) not in (16, 32):
			raise ValueError(
				'Unexpected Chrome Local State key length: %d bytes (expected 16 or 32)'
				% len(plaintext)
			)

		self.key = plaintext
		return plaintext

	def to_dict(self, include_key = True):
		"""
		Returns the original Local State structure with the decrypted key added
		under os_crypt.decrypted_key (hex) while retaining encrypted_key.
		"""
		res = copy.deepcopy(self.data)
		os_crypt = res.setdefault('os_crypt', {})
		os_crypt['encrypted_key'] = self.encrypted_key_b64

		if include_key and self.key is not None:
			os_crypt['decrypted_key'] = self.key.hex()
			os_crypt['decrypted_key_b64'] = base64.b64encode(self.key).decode('ascii')
			if self.masterkey_guid is not None:
				os_crypt['masterkey_guid'] = str(self.masterkey_guid)
			if self.masterkey_scope is not None:
				os_crypt['masterkey_scope'] = self.masterkey_scope

		return res
