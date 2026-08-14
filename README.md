Information Assurance and Security - ALM-TASK-1

A Python-based client-server cryptography project implementing Caesar Cipher, Playfair Cipher, and Simple Data Encryption Standard (SDES) with two-way communication, encryption/decryption, and SDES file transfer.

Project Structure
IAS-ALM-TASK-
├── crypto.py
│
├── client.py
│
├── server.py
│
├── sample_1MB.txt
│
├── server_received_sample_1MB.txt
│
├── sample_10KB.txt
│
└── client_received_sample_10KB.txt
Algorithms
Caesar Cipher – Message encryption and decryption.
Playfair Cipher – Message encryption and decryption.
SDES – Message encryption/decryption and file transfer.
ALM-1 File Transfer
1 MB file: Client → Server using SDES.
10 KB file: Server → Client using SDES.
Both sides display ciphertext and plaintext.
Execution
python server.py
python client.py

Run the server first, then the client.
