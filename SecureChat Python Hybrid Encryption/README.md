 SecureChat Python Hybrid Encryption

A secure chat application using hybrid encryption (RSA + AES), developed as part of the Cryptography and Network Security course at SRM University.

 👨‍💻 Project Info

 Name: ABHIRAM H S  
 Institution: SRM University  
 Semester: 4th Semester  
 Subject: Cryptography and Network Security  
 Course: B.Tech Computer Science Engineering with Specialisation Cybersecurity

 🔐 Features

 End-to-end encrypted communication.
 Hybrid encryption with:
   RSA (2048bit) for key exchange.
   AES (128bit, EAX mode) for message encryption.
 Modular encryption logic usingencryption.py`.
 Easy to extend to GUI, web sockets, or secure file sharing.
 Built using real cryptographic standards (no base64 or hashing).

 🧪 Technologies Used

 Python 3
 Libraries: pycryptodome`,socket`
 Platform:  Cross platform (tested on macOS)
 Virtual Environment: Pythonvenv`

 🚀 How to Run

1. Clone the repository:
bash
   git clone https://github.com/abhiramhs05/SecureChatPythonHybridEncryption.git
   cd SecureChatPythonHybridEncryption


2. Set up and activate a virtual environment:
bash
   python3 m venv venv
   source venv/bin/activate   Windows: venv\Scripts\activate


3. Install dependencies:
bash
   pip install r requirements.txt


4. Run the server:
bash
   python3 server.py


5. In a new terminal, run the client:
bash
   python3 client.py


6. (Optional) To test encryption separately:
bash
   python3 demo_encryption.py


 📁 File Structure

client.py` – Connects to server and sends AESencrypted messages.
server.py` – Listens for clients and decrypts incoming messages.
encryption.py` – Contains RSA/AES key generation, encryption & decryption.
demo_encryption.py` – A demo of how hybrid encryption works.
requirements.txt` – Python dependencies.
.gitignore` – Files to be ignored by Git (e.g.,venv/`,__pycache__/`).

 🔐 Cryptographic Overview

 RSA (2048bit): Used to securely share AES keys.
 AES (128bit, EAX Mode): Used for encrypting message data.
 Hybrid Encryption: Combines asymmetric and symmetric cryptography to get the best of both.

 🔐 Security Considerations

 Keys are not hardcoded; RSA keys are generated per user or securely loaded.
 AES keys are randomly generated and exchanged securely using RSA.
 Each message is encrypted with AES using a nonce to ensure uniqueness.
 Error handling prevents crashes from corrupt or modified ciphertext.
 Ready to be extended with SSL, digital signatures, or certificate verification.

 ✅ Conclusion

This project successfully demonstrates a secure, encrypted chat using hybrid cryptography. It provides a strong foundation in both networking and security — essential for careers in cybersecurity.
