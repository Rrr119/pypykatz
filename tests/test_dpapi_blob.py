import base64
import hashlib
import hmac
import json
import os
import sqlite3
import struct
import uuid

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from pypykatz.dpapi.constants import ALGORITHMS
from pypykatz.dpapi.dpapi import DPAPI


MASTERKEY_GUID = '00112233-4455-6677-8899-aabbccddeeff'


def build_dpapi_blob(masterkey, plaintext, masterkey_guid=MASTERKEY_GUID, flags=0):
    """Builds an AES-256/SHA-512 DPAPI blob without using pypykatz's crypto."""
    salt = os.urandom(16)
    hmac_field = os.urandom(64)
    description = 'Chrome\0'.encode('utf-16le')

    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()

    key_hash = hashlib.sha1(masterkey).digest()
    session_key = hmac.new(key_hash, salt, hashlib.sha512).digest()
    encryptor = Cipher(
        algorithms.AES(session_key[:32]),
        modes.CBC(b'\x00' * 16),
    ).encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    to_sign = (
        struct.pack('<I', 1)
        + uuid.UUID(masterkey_guid).bytes_le
        + struct.pack('<I', flags)
        + struct.pack('<I', len(description))
        + description
        + struct.pack('<I', int(ALGORITHMS.CALG_AES_256))
        + struct.pack('<I', 192)
        + struct.pack('<I', len(salt))
        + salt
        + struct.pack('<I', 0)
        + struct.pack('<I', int(ALGORITHMS.CALG_SHA_512))
        + struct.pack('<I', 512)
        + struct.pack('<I', len(hmac_field))
        + hmac_field
        + struct.pack('<I', len(encrypted))
        + encrypted
    )
    signature = hmac.new(key_hash, hmac_field + to_sign, hashlib.sha512).digest()

    credential_guid = uuid.UUID('aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee').bytes_le
    return (
        struct.pack('<I', 1)
        + credential_guid
        + to_sign
        + struct.pack('<I', len(signature))
        + signature
    )


def build_local_state(masterkey, local_state_key, flags=0):
    encrypted_key = b'DPAPI' + build_dpapi_blob(masterkey, local_state_key, flags=flags)
    return {
        'os_crypt': {
            'encrypted_key': base64.b64encode(encrypted_key).decode('ascii'),
        },
        'profile': {
            'info_cache': {},
        },
    }


def encrypt_chrome_v10(local_state_key, plaintext):
    nonce = os.urandom(12)
    return b'v10' + nonce + AESGCM(local_state_key).encrypt(nonce, plaintext, None)


def test_dpapi_blob_user_and_system_masterkey_selection():
    user_masterkey = b'U' * 32
    system_masterkey = b'S' * 32
    user_plaintext = b'user scoped secret'
    system_plaintext = b'system scoped secret'

    user_blob = build_dpapi_blob(user_masterkey, user_plaintext)
    system_blob = build_dpapi_blob(
        system_masterkey,
        system_plaintext,
        flags=int(0x20000000),
    )

    dpapi = DPAPI()
    dpapi.add_masterkey(MASTERKEY_GUID, user_masterkey, scope='user')
    dpapi.add_masterkey(MASTERKEY_GUID, system_masterkey, scope='system')

    assert dpapi.decrypt_blob_bytes(user_blob) == user_plaintext
    assert dpapi.decrypt_blob_bytes(system_blob) == system_plaintext


def test_dpapi_blob_backupkey_fallback():
    masterkey = b'B' * 32
    plaintext = b'backup key secret'
    blob = build_dpapi_blob(masterkey, plaintext)

    dpapi = DPAPI()
    dpapi.add_masterkey(MASTERKEY_GUID, masterkey, scope='system', backup=True)

    assert dpapi.decrypt_blob_bytes(blob) == plaintext


def test_decrypt_chrome_local_state():
    masterkey = b'M' * 32
    local_state_key = os.urandom(32)
    local_state = build_local_state(masterkey, local_state_key, flags=int(0x20000000))

    dpapi = DPAPI()
    dpapi.add_masterkey(MASTERKEY_GUID, masterkey, scope='system')
    decrypted = dpapi.decrypt_chrome_local_state_bytes(json.dumps(local_state).encode('utf-8'))

    assert decrypted['os_crypt']['decrypted_key'] == local_state_key.hex()
    assert decrypted['os_crypt']['masterkey_guid'] == MASTERKEY_GUID
    assert decrypted['os_crypt']['masterkey_scope'] == 'system'
    assert decrypted['profile'] == {'info_cache': {}}


def test_decrypt_chrome_local_state_with_unbound_masterkey():
    masterkey = b'U' * 32
    local_state_key = os.urandom(32)
    local_state = build_local_state(masterkey, local_state_key)

    dpapi = DPAPI()
    dpapi.add_unbound_masterkey(masterkey)
    decrypted = dpapi.decrypt_chrome_local_state_bytes(json.dumps(local_state).encode('utf-8'))

    assert decrypted['os_crypt']['decrypted_key'] == local_state_key.hex()
    assert decrypted['os_crypt']['masterkey_scope'] == 'unbound'


def test_decrypt_chrome_database_with_local_state(tmp_path):
    masterkey = b'M' * 32
    local_state_key = os.urandom(32)

    local_state_path = tmp_path / 'Local State'
    local_state_path.write_text(
        json.dumps(build_local_state(masterkey, local_state_key, flags=int(0x20000000))),
        encoding='utf-8',
    )

    cookies_path = tmp_path / 'Cookies'
    conn = sqlite3.connect(str(cookies_path))
    conn.execute(
        'CREATE TABLE cookies(host_key TEXT, name TEXT, path TEXT, encrypted_value BLOB)'
    )
    conn.execute(
        'INSERT INTO cookies VALUES (?, ?, ?, ?)',
        ('.example.com', 'session', '/', encrypt_chrome_v10(local_state_key, b'cookie-value')),
    )
    conn.commit()
    conn.close()

    logins_path = tmp_path / 'Login Data'
    conn = sqlite3.connect(str(logins_path))
    conn.execute(
        'CREATE TABLE logins(action_url TEXT, username_value TEXT, password_value BLOB)'
    )
    conn.execute(
        'INSERT INTO logins VALUES (?, ?, ?)',
        ('https://example.com', 'alice', encrypt_chrome_v10(local_state_key, b'password-value')),
    )
    conn.commit()
    conn.close()

    dpapi = DPAPI()
    dpapi.add_masterkey(MASTERKEY_GUID, masterkey, scope='system')
    result = dpapi.decrypt_all_chrome(
        {
            'alice': {
                'localstate': str(local_state_path),
                'cookies': str(cookies_path),
                'logindata': str(logins_path),
            }
        },
        throw=True,
    )

    assert result['localstate'][str(local_state_path)]['os_crypt']['decrypted_key'] == local_state_key.hex()
    assert result['logins'][0][3] == b'password-value'
    assert result['cookies'][0][4] == b'cookie-value'
    assert result['errors'] == []
