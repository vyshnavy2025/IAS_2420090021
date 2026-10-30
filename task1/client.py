# client.py

import socket
import struct
import json
import os

from crypto import (
    caesar_encrypt,
    caesar_decrypt,
    playfair_encrypt,
    playfair_decrypt,
    sdes_encrypt,
    sdes_decrypt
)


SERVER_IP = "127.0.0.1"
PORT = 5000

SDES_KEY = "1010000010"


# ============================================================
# SOCKET FUNCTIONS
# ============================================================

def send_data(sock, data):

    data = json.dumps(data).encode()

    sock.sendall(
        struct.pack("!I", len(data))
    )

    sock.sendall(data)


def receive_data(sock):

    size_data = sock.recv(4)

    if not size_data:
        return None

    size = struct.unpack(
        "!I",
        size_data
    )[0]

    data = b""

    while len(data) < size:

        packet = sock.recv(
            min(4096, size - len(data))
        )

        if not packet:
            break

        data += packet

    return json.loads(
        data.decode()
    )


# ============================================================
# CREATE 1 MB TEST FILE
# ============================================================

def create_1mb_file():

    filename = "sample_1MB.txt"

    if not os.path.exists(filename):

        text = (
            "This is a 1 MB SDES file transfer test.\n"
            "Client sends encrypted file to server.\n"
        )

        target_size = 1024 * 1024

        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as f:

            while f.tell() < target_size:

                remaining = target_size - f.tell()

                f.write(
                    text[:remaining]
                )

    return filename


# ============================================================
# CHAT
# ============================================================

def chat(sock):

    print("\nSelect Algorithm")
    print("----------------------------")
    print("1. Caesar Cipher")
    print("2. Playfair Cipher")
    print("3. SDES")
    print("----------------------------")

    choice = input(
        "Enter your choice: "
    )

    # ========================================================
    # CAESAR
    # ========================================================

    if choice == "1":

        algorithm = "CAESAR"

        plaintext = input(
            "Enter message: "
        )

        shift = int(
            input(
                "Enter Caesar key/shift: "
            )
        )

        ciphertext = caesar_encrypt(
            plaintext,
            shift
        )

        print(
            "\nClient Plaintext :",
            plaintext
        )

        print(
            "Client Ciphertext:",
            ciphertext
        )

        send_data(
            sock,
            {
                "operation": "CHAT",
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "key": shift
            }
        )

    # ========================================================
    # PLAYFAIR
    # ========================================================

    elif choice == "2":

        algorithm = "PLAYFAIR"

        plaintext = input(
            "Enter message: "
        )

        key = input(
            "Enter Playfair key: "
        )

        ciphertext = playfair_encrypt(
            plaintext,
            key
        )

        print(
            "\nClient Plaintext :",
            plaintext
        )

        print(
            "Client Ciphertext:",
            ciphertext
        )

        send_data(
            sock,
            {
                "operation": "CHAT",
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "key": key
            }
        )

    # ========================================================
    # SDES
    # ========================================================

    elif choice == "3":

        algorithm = "SDES"

        plaintext = input(
            "Enter message: "
        )

        encrypted = sdes_encrypt(
            plaintext.encode(),
            SDES_KEY
        )

        ciphertext = encrypted.hex()

        print(
            "\nClient Plaintext :",
            plaintext
        )

        print(
            "Client Ciphertext:",
            ciphertext
        )

        send_data(
            sock,
            {
                "operation": "CHAT",
                "algorithm": algorithm,
                "ciphertext": ciphertext,
                "key": SDES_KEY
            }
        )

    else:

        print("Invalid choice.")
        return

    # ========================================================
    # RECEIVE SERVER MESSAGE
    # ========================================================

    response = receive_data(sock)

    if response is None:
        return

    if response["operation"] == "SERVER_REPLY":

        algorithm = response["algorithm"]
        ciphertext = response["ciphertext"]

        print("\n" + "=" * 50)
        print("MESSAGE RECEIVED FROM SERVER")
        print("=" * 50)

        print(
            "Server Ciphertext:",
            ciphertext
        )

        if algorithm == "CAESAR":

            plaintext = caesar_decrypt(
                ciphertext,
                shift
            )

        elif algorithm == "PLAYFAIR":

            plaintext = playfair_decrypt(
                ciphertext,
                key
            )

        elif algorithm == "SDES":

            encrypted = bytes.fromhex(
                ciphertext
            )

            decrypted = sdes_decrypt(
                encrypted,
                SDES_KEY
            )

            plaintext = decrypted.decode(
                "utf-8",
                errors="replace"
            )

        print(
            "Server Plaintext :",
            plaintext
        )


# ============================================================
# 1 MB FILE CLIENT → SERVER
# ============================================================

def send_1mb_file(sock):

    filename = create_1mb_file()

    with open(
        filename,
        "rb"
    ) as f:

        plaintext = f.read()

    print("\n" + "=" * 50)
    print("CLIENT → SERVER : 1 MB FILE")
    print("=" * 50)

    print(
        "Plaintext size:",
        len(plaintext),
        "bytes"
    )

    encrypted = sdes_encrypt(
        plaintext,
        SDES_KEY
    )

    print(
        "Ciphertext size:",
        len(encrypted),
        "bytes"
    )

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
        sock,
        {
            "operation": "FILE_C2S",
            "filename": filename,
            "ciphertext": encrypted.hex()
        }
    )

    response = receive_data(sock)

    print(
        "\nServer:",
        response["message"]
    )


# ============================================================
# 10 KB FILE SERVER → CLIENT
# ============================================================

def receive_10kb_file(sock):

    print("\nRequesting 10 KB file from server...")

    send_data(
        sock,
        {
            "operation": "REQUEST_10KB"
        }
    )

    response = receive_data(sock)

    if response["operation"] != "FILE_S2C":
        return

    filename = response["filename"]

    encrypted = bytes.fromhex(
        response["ciphertext"]
    )

    print("\n" + "=" * 50)
    print("SERVER → CLIENT : 10 KB FILE")
    print("=" * 50)

    print(
        "Ciphertext size:",
        len(encrypted),
        "bytes"
    )

    plaintext = sdes_decrypt(
        encrypted,
        SDES_KEY
    )

    print(
        "Plaintext size:",
        len(plaintext),
        "bytes"
    )

    print(
        "\nCiphertext preview:"
    )

    print(
        encrypted[:100].hex()
    )

    print(
        "\nPlaintext preview:"
    )

    print(
        plaintext[:200].decode(
            "utf-8",
            errors="replace"
        )
    )

    output_filename = (
        "client_received_" + filename
    )

    with open(
        output_filename,
        "wb"
    ) as f:

        f.write(plaintext)

    print(
        "\nFile saved as:",
        output_filename
    )


# ============================================================
# MAIN CLIENT
# ============================================================

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

client.connect(
    (SERVER_IP, PORT)
)

print("=" * 60)
print("        CRYPTOGRAPHY CLIENT")
print("=" * 60)

print(
    "Connected to server:",
    SERVER_IP,
    PORT
)


while True:

    print("\n")
    print("=" * 50)
    print("MAIN MENU")
    print("=" * 50)

    print("1. Send encrypted message")
    print("2. Send 1 MB file to server using SDES")
    print("3. Receive 10 KB file from server using SDES")
    print("4. Exit")

    choice = input(
        "\nEnter choice: "
    )

    if choice == "1":

        chat(client)

    elif choice == "2":

        send_1mb_file(client)

    elif choice == "3":

        receive_10kb_file(client)

    elif choice == "4":

        send_data(
            client,
            {
                "operation": "EXIT"
            }
        )

        break

    else:

        print("Invalid choice.")


client.close()

print("Client stopped.")