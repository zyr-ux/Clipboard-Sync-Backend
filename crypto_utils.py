from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import os

# Server-side secret key (store this securely in prod)
SECRET_KEY = os.getenv("REFRESH_TOKEN_AES_KEY", "zyruxclipboardcrypt").encode('utf-8').ljust(32, b'\0')

def encrypt_clipboard(plaintext: str, key: bytes) -> (bytes, bytes):
    cipher = AES.new(key, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode())
    return cipher.nonce + tag + ciphertext, cipher.nonce  # Return full blob and nonce

def decrypt_clipboard(encrypted_blob: bytes, key: bytes) -> str:
    nonce = encrypted_blob[:16]
    tag = encrypted_blob[16:32]
    ciphertext = encrypted_blob[32:]
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag).decode()


def encrypt_token(token: str) -> str:
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(token.encode('utf-8'), AES.block_size))
    iv = base64.b64encode(cipher.iv).decode('utf-8')
    ct = base64.b64encode(ct_bytes).decode('utf-8')
    return f"{iv}:{ct}"

def decrypt_token(enc_token: str) -> str:
    iv, ct = enc_token.split(":")
    iv = base64.b64decode(iv)
    ct = base64.b64decode(ct)
    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode('utf-8')
