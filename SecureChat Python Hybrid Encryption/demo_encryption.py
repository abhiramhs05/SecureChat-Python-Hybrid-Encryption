from encryption import (
    generate_keys,
    encrypt_aes_key,
    decrypt_aes_key,
    aes_encrypt,
    aes_decrypt
)
from Crypto.Random import get_random_bytes

def demo_encryption_process():
    print("\n🔐 Hybrid Encryption Demo: RSA + AES\n")

    # Step 1: Generate RSA key pair
    private_key, public_key = generate_keys()

    # Step 2: Generate AES key (symmetric key)
    aes_key = get_random_bytes(16)
    print(f"[INFO] AES key (generated): {aes_key.hex()}")

    # Step 3: Encrypt AES key with RSA public key
    encrypted_aes_key = encrypt_aes_key(aes_key, public_key)

    # Step 4: Decrypt AES key with RSA private key
    decrypted_aes_key = decrypt_aes_key(encrypted_aes_key, private_key)
    print(f"[INFO] AES key (after decryption): {decrypted_aes_key.hex()}\n")

    # Step 5: Encrypt a message using AES
    message = "This is a secret message!"
    nonce, ciphertext, tag = aes_encrypt(message, aes_key)

    # Step 6: Decrypt the message using AES
    decrypted_message = aes_decrypt(nonce, ciphertext, tag, aes_key)

    # Final result
    print(f"\n✅ Final Output:")
    print(f"Original Message: {message}")
    print(f"Decrypted Message: {decrypted_message}")
    print("\n🎉 Encryption demo completed successfully.")

if __name__ == "__main__":
    demo_encryption_process()
