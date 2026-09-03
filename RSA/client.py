import socket
import json
import struct

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP


HOST = "127.0.0.1"
PORT = 5005


# ============================================================
# SEND DATA
# ============================================================

def send_data(sock, data):

    message = json.dumps(
        data
    ).encode()

    sock.sendall(
        struct.pack(
            "!I",
            len(message)
        )
    )

    sock.sendall(message)


# ============================================================
# RECEIVE DATA
# ============================================================

def receive_data(sock):

    size_data = receive_exact(
        sock,
        4
    )

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
# CLIENT
# ============================================================

print("=" * 70)
print("                       RSA CLIENT")
print("                     PyCryptodome")
print("=" * 70)


client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:

    client.connect(
        (HOST, PORT)
    )

    print(
        "\n✓ Connected to server."
    )

except Exception as e:

    print(
        "\nConnection error:",
        e
    )

    exit()


# ============================================================
# RECEIVE SERVER PUBLIC KEY
# ============================================================

data = receive_data(
    client
)

if data is None:

    print(
        "\nServer disconnected."
    )

    client.close()
    exit()


server_public_key = RSA.import_key(
    data["public_key"]
)

print(
    "\n✓ Server public key received."
)


# ============================================================
# GENERATE CLIENT RSA KEY PAIR
# ============================================================

print(
    "\nGenerating client RSA key pair..."
)

client_private_key = RSA.generate(
    2048
)

client_public_key = (
    client_private_key.publickey()
)

print(
    "✓ Client RSA key pair generated."
)


# ============================================================
# CLIENT MENU
# ============================================================

while True:

    print("\n")
    print("=" * 55)
    print("CLIENT MENU")
    print("=" * 55)

    print("1. Encrypt and Send Message")
    print("2. Receive and Decrypt Message")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # ========================================================
    # SEND MESSAGE
    # ========================================================

    if choice == "1":

        plaintext = input(
            "\nEnter plaintext: "
        )

        # Encrypt using SERVER PUBLIC KEY
        cipher = PKCS1_OAEP.new(
            server_public_key
        )

        ciphertext = cipher.encrypt(
            plaintext.encode(
                "utf-8"
            )
        )

        print("\n")
        print("=" * 70)
        print("CLIENT → SERVER")
        print("=" * 70)

        print("\nPlaintext:")
        print(plaintext)

        print("\nRSA Ciphertext:")
        print(
            ciphertext.hex()
        )

        send_data(
            client,
            {
                "operation": "CLIENT_SEND",
                "ciphertext": ciphertext.hex()
            }
        )

        print(
            "\n✓ RSA ciphertext sent to server."
        )

    # ========================================================
    # RECEIVE MESSAGE
    # ========================================================

    elif choice == "2":

        # Tell server we are ready
        send_data(
            client,
            {
                "operation": "REQUEST",
                "public_key":
                    client_public_key.export_key().decode()
            }
        )

        print(
            "\nWaiting for server message..."
        )

        data = receive_data(
            client
        )

        if data is None:

            print(
                "\nServer disconnected."
            )

            break

        if data["operation"] == "SERVER_SEND":

            ciphertext = bytes.fromhex(
                data["ciphertext"]
            )

            print("\n")
            print("=" * 70)
            print("SERVER → CLIENT")
            print("=" * 70)

            print("\nRSA Ciphertext:")
            print(
                ciphertext.hex()
            )

            # Decrypt using CLIENT PRIVATE KEY
            cipher = PKCS1_OAEP.new(
                client_private_key
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
    # EXIT
    # ========================================================

    elif choice == "3":

        send_data(
            client,
            {
                "operation": "EXIT"
            }
        )

        break

    else:

        print(
            "\nInvalid choice!"
        )


client.close()

print(
    "\nClient closed."
)