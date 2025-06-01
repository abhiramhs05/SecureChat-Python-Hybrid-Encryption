from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Random import get_random_bytes
import base64

# Generate RSA key pair
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    print("[KEY GENERATION] RSA Key Pair Generated")
    return private_key, public_key

# Save and load keys
def save_key(path, key_data):
    with open(path, 'wb') as f:
        f.write(key_data)
    print(f"[KEY SAVED] Key saved to {path}")

def load_key(path):
    with open(path, 'rb') as f:
        key_data = f.read()
    print(f"[KEY LOADED] Key loaded from {path}")
    return key_data

# Encrypt AES key with RSA public key
def encrypt_aes_key(aes_key, public_key_bytes):
    public_key = RSA.import_key(public_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(public_key)
    encrypted_key = cipher_rsa.encrypt(aes_key)
    print(f"[ENCRYPT] AES key encrypted with RSA public key: {base64.b64encode(encrypted_key).decode()}")
    return encrypted_key

def decrypt_aes_key(encrypted_key, private_key_bytes):
    private_key = RSA.import_key(private_key_bytes)
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_key = cipher_rsa.decrypt(encrypted_key)
    print(f"[DECRYPT] AES key decrypted with RSA private key.")
    return decrypted_key

# AES encryption/decryption
def aes_encrypt(message, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode())
    print(f"[AES ENCRYPT] Message: '{message}'")
    print(f"[AES ENCRYPT] Ciphertext: {base64.b64encode(ciphertext).decode()}")
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag).decode()
    print(f"[AES DECRYPT] Decrypted message: '{plaintext}'")
    return plaintext
