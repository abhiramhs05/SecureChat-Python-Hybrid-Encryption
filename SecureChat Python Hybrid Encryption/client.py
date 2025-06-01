import socket
import threading
from encryption import *
from Crypto.Random import get_random_bytes

HOST = '127.0.0.1'
PORT = 5055

# Load or generate keys
try:
    private_key = load_key("keys/private.pem")
    public_key = load_key("keys/public.pem")
except:
    private_key, public_key = generate_keys()
    save_key("keys/private.pem", private_key)
    save_key("keys/public.pem", public_key)

# Connect to server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# Receive messages
def receive():
    while True:
        try:
            data = client.recv(4096)
            if data:
                encrypted_key, nonce, ciphertext, tag = data.split(b'||')
                aes_key = decrypt_aes_key(encrypted_key, private_key)
                message = aes_decrypt(nonce, ciphertext, tag, aes_key)
                print("\n[Received]:", message)
        except Exception as e:
            print("[ERROR receiving]:", e)
            break

# Send messages
def send():
    while True:
        msg = input("[You]: ")
        aes_key = get_random_bytes(16)
        nonce, ciphertext, tag = aes_encrypt(msg, aes_key)

        # Encrypt AES key with RSA
        encrypted_key = encrypt_aes_key(aes_key, public_key)

        # For demo: print encrypted AES key and message
        print(f"\n🔐 [DEBUG] Encrypted AES key: {encrypted_key.hex()}")
        print(f"🔐 [DEBUG] AES Encrypted Message: {ciphertext.hex()}\n")

        # Combine data and send
        final_data = encrypted_key + b'||' + nonce + b'||' + ciphertext + b'||' + tag
        client.send(final_data)

# Start threads
threading.Thread(target=receive, daemon=True).start()
send()
