import socket
import threading

HOST = '127.0.0.1'
PORT = 5055
clients = {}

def handle_client(client, addr):
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break

            # Extract and show encrypted message part (for debug/demo)
            try:
                parts = data.split(b'||')
                if len(parts) == 4:
                    encrypted_key, nonce, ciphertext, tag = parts
                    print(f"\n📥 [SERVER] Encrypted AES key received: {encrypted_key.hex()}")
                    print(f"📥 [SERVER] Ciphertext received: {ciphertext.hex()}\n")
            except Exception as e:
                print("[DEBUG PARSE ERROR]", e)

            for c in clients:
                if c != client:
                    c.send(data)
        except:
            break

    client.close()
    del clients[client]
    print(f"[DISCONNECTED] {addr}")

def start_server():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((HOST, PORT))
    s.listen()
    print("[SERVER STARTED]")
    while True:
        client, addr = s.accept()
        clients[client] = addr
        print(f"[CONNECTED] {addr}")
        threading.Thread(target=handle_client, args=(client, addr), daemon=True).start()

start_server()
