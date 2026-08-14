# server.py

import socket
import struct
import json
import os

from crypto import (
    caesar_decrypt,
    caesar_encrypt,
    playfair_decrypt,
    playfair_encrypt,
    sdes_encrypt,
    sdes_decrypt
)


HOST = "0.0.0.0"
PORT = 5000

SDES_KEY = "1010000010"


# ============================================================
# SOCKET FUNCTIONS
# ============================================================

def send_data(sock, data):

    data = json.dumps(data).encode()

    sock.sendall(struct.pack("!I", len(data)))
    sock.sendall(data)


def receive_data(sock):

    size_data = sock.recv(4)

    if not size_data:
        return None

    size = struct.unpack("!I", size_data)[0]

    data = b""

    while len(data) < size:
        packet = sock.recv(min(4096, size - len(data)))

        if not packet:
            break

        data += packet

    return json.loads(data.decode())


# ============================================================
# MAIN SERVER
# ============================================================

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

server.bind((HOST, PORT))
server.listen(1)

print("=" * 60)
print("        CRYPTOGRAPHY CLIENT-SERVER SERVER")
print("=" * 60)

print(f"Server started on port {PORT}")
print("Waiting for client...")

conn, address = server.accept()

print(f"\nClient connected from: {address}")


while True:

    try:

        data = receive_data(conn)

        if data is None:
            break

        operation = data.get("operation")

        # ====================================================
        # CHAT MESSAGE FROM CLIENT
        # ====================================================

        if operation == "CHAT":

            algorithm = data["algorithm"]
            cipher_text = data["ciphertext"]

            print("\n" + "=" * 50)
            print("MESSAGE RECEIVED FROM CLIENT")
            print("=" * 50)

            print("Algorithm :", algorithm)
            print("Ciphertext:", cipher_text)

            if algorithm == "CAESAR":

                shift = data["key"]

                plaintext = caesar_decrypt(
                    cipher_text,
                    shift
                )

            elif algorithm == "PLAYFAIR":

                key = data["key"]

                plaintext = playfair_decrypt(
                    cipher_text,
                    key
                )

            elif algorithm == "SDES":

                encrypted = bytes.fromhex(cipher_text)

                decrypted = sdes_decrypt(
                    encrypted,
                    SDES_KEY
                )

                plaintext = decrypted.decode(
                    "utf-8",
                    errors="replace"
                )

            else:

                plaintext = "Unknown Algorithm"

            print("Plaintext :", plaintext)

            # ------------------------------------------------
            # SERVER SENDS MESSAGE TO CLIENT
            # ------------------------------------------------

            print("\nSERVER → CLIENT")

            server_message = input(
                "Enter message for client: "
            )

            if algorithm == "CAESAR":

                server_cipher = caesar_encrypt(
                    server_message,
                    data["key"]
                )

            elif algorithm == "PLAYFAIR":

                server_cipher = playfair_encrypt(
                    server_message,
                    data["key"]
                )

            elif algorithm == "SDES":

                encrypted = sdes_encrypt(
                    server_message.encode(),
                    SDES_KEY
                )

                server_cipher = encrypted.hex()

            send_data(
                conn,
                {
                    "operation": "SERVER_REPLY",
                    "algorithm": algorithm,
                    "ciphertext": server_cipher
                }
            )

            print("Ciphertext sent:", server_cipher)

        # ====================================================
        # FILE FROM CLIENT → SERVER
        # ====================================================

        elif operation == "FILE_C2S":

            print("\n" + "=" * 50)
            print("FILE RECEIVED FROM CLIENT")
            print("=" * 50)

            filename = data["filename"]

            encrypted = bytes.fromhex(
                data["ciphertext"]
            )

            print("Filename :", filename)
            print("Ciphertext size:", len(encrypted), "bytes")

            plaintext = sdes_decrypt(
                encrypted,
                SDES_KEY
            )

            received_file = "server_received_" + filename

            with open(
                received_file,
                "wb"
            ) as f:

                f.write(plaintext)

            print(
                "Plaintext size:",
                len(plaintext),
                "bytes"
            )

            print(
                "Ciphertext preview:",
                encrypted[:100].hex()
            )

            print(
                "Plaintext preview:",
                plaintext[:200].decode(
                    "utf-8",
                    errors="replace"
                )
            )

            print(
                "Saved as:",
                received_file
            )

            send_data(
                conn,
                {
                    "operation": "FILE_ACK",
                    "message": "1 MB file received successfully"
                }
            )

        # ====================================================
        # FILE FROM SERVER → CLIENT
        # ====================================================

        elif operation == "REQUEST_10KB":

            filename = "sample_10KB.txt"

            if not os.path.exists(filename):

                text = (
                    "This is a 10 KB SDES test file.\n"
                    * 500
                )

                text = text[:10240]

                with open(
                    filename,
                    "w",
                    encoding="utf-8"
                ) as f:

                    f.write(text)

            with open(
                filename,
                "rb"
            ) as f:

                plaintext = f.read()

            plaintext = plaintext[:10240]

            encrypted = sdes_encrypt(
                plaintext,
                SDES_KEY
            )

            print("\n" + "=" * 50)
            print("SENDING 10 KB FILE TO CLIENT")
            print("=" * 50)

            print("Plaintext size :", len(plaintext))
            print("Ciphertext size:", len(encrypted))

            print(
                "Plaintext preview:",
                plaintext[:200].decode(
                    "utf-8",
                    errors="replace"
                )
            )

            print(
                "Ciphertext preview:",
                encrypted[:100].hex()
            )

            send_data(
                conn,
                {
                    "operation": "FILE_S2C",
                    "filename": filename,
                    "ciphertext": encrypted.hex()
                }
            )

            print("10 KB file sent to client.")

        # ====================================================
        # EXIT
        # ====================================================

        elif operation == "EXIT":

            print("Client disconnected.")
            break

    except Exception as e:

        print("Error:", e)
        break


conn.close()
server.close()

print("\nServer stopped.")