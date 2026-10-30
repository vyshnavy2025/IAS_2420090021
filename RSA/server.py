import socket
import json
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


HOST = "0.0.0.0"
PORT = 5005


# ============================================================
# SEND DATA
# ============================================================

def send_data(sock, data):

    message = json.dumps(data).encode()

    sock.sendall(
        struct.pack("!I", len(message))
    )

    sock.sendall(message)


# ============================================================
# RECEIVE DATA
# ============================================================

def receive_data(sock):

    size_data = receive_exact(sock, 4)

    if not size_data:
        return None

    size = struct.unpack(
        "!I",
        size_data
    )[0]

    data = receive_exact(
        sock,
        size
    )

    if not data:
        return None

    return json.loads(
        data.decode()
    )


# ============================================================
# RECEIVE EXACT DATA
# ============================================================

def receive_exact(sock, size):

    data = b""

    while len(data) < size:

        packet = sock.recv(
            size - len(data)
        )

        if not packet:
            return None

        data += packet

    return data


# ============================================================
# GENERATE RSA KEYS
# ============================================================

print("=" * 70)
print("                       RSA SERVER")
print("                     PyCryptodome")
print("=" * 70)

print("\nGenerating RSA 2048-bit key pair...")

key = RSA.generate(2048)

private_key = key
public_key = key.publickey()

print("✓ RSA key pair generated.")


# ============================================================
# START SERVER
# ============================================================

server = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

server.setsockopt(
    socket.SOL_SOCKET,
    socket.SO_REUSEADDR,
    1
)

server.bind(
    (HOST, PORT)
)

server.listen(1)

print("\nWaiting for client...")

conn, address = server.accept()

print(
    "\n✓ Client connected:",
    address
)


# ============================================================
# SEND PUBLIC KEY TO CLIENT
# ============================================================

public_key_pem = public_key.export_key().decode()

send_data(
    conn,
    {
        "operation": "PUBLIC_KEY",
        "public_key": public_key_pem
    }
)

print(
    "\n✓ Public key sent to client."
)


# ============================================================
# SERVER MENU
# ============================================================

while True:

    print("\n")
    print("=" * 55)
    print("SERVER MENU")
    print("=" * 55)

    print("1. Receive Encrypted Message")
    print("2. Send Encrypted Message")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # ========================================================
    # RECEIVE MESSAGE FROM CLIENT
    # ========================================================

    if choice == "1":

        print(
            "\nWaiting for encrypted message from client..."
        )

        data = receive_data(
            conn
        )

        if data is None:
            break

        if data["operation"] == "CLIENT_SEND":

            ciphertext = bytes.fromhex(
                data["ciphertext"]
            )

            print("\n")
            print("=" * 70)
            print("CLIENT → SERVER")
            print("=" * 70)

            print("\nRSA Ciphertext:")
            print(ciphertext.hex())

            # Decrypt using PRIVATE KEY
            cipher = PKCS1_OAEP.new(
                private_key
            )

            try:

                plaintext = cipher.decrypt(
                    ciphertext
                ).decode(
                    "utf-8"
                )

                print("\nPlaintext:")
                print(plaintext)

                print(
                    "\n✓ RSA decryption successful."
                )

            except Exception as e:

                print(
                    "\n✗ RSA decryption failed:",
                    e
                )

        elif data["operation"] == "EXIT":

            break

    # ========================================================
    # SEND MESSAGE TO CLIENT
    # ========================================================

    elif choice == "2":

        plaintext = input(
            "\nEnter plaintext to send: "
        )

        print(
            "\nWaiting for client to select Receive..."
        )

        request = receive_data(
            conn
        )

        if request is None:
            break

        if request["operation"] == "REQUEST":

            # Client public key
            client_public_key = RSA.import_key(
                request["public_key"]
            )

            # Encrypt using CLIENT public key
            cipher = PKCS1_OAEP.new(
                client_public_key
            )

            ciphertext = cipher.encrypt(
                plaintext.encode(
                    "utf-8"
                )
            )

            print("\n")
            print("=" * 70)
            print("SERVER → CLIENT")
            print("=" * 70)

            print("\nPlaintext:")
            print(plaintext)

            print("\nRSA Ciphertext:")
            print(ciphertext.hex())

            send_data(
                conn,
                {
                    "operation": "SERVER_SEND",
                    "ciphertext": ciphertext.hex()
                }
            )

            print(
                "\n✓ RSA ciphertext sent to client."
            )

        elif request["operation"] == "EXIT":

            break

    # ========================================================
    # EXIT
    # ========================================================

    elif choice == "3":

        try:

            send_data(
                conn,
                {
                    "operation": "EXIT"
                }
            )

        except:
            pass

        break

    else:

        print(
            "\nInvalid choice!"
        )


conn.close()
server.close()

print("\nServer closed.")