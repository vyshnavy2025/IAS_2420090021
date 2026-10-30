import socket
import json
import struct

HOST = "0.0.0.0"
PORT = 5003

KEY = "SECURITY"


# ============================================================
# RC4
# ============================================================

def rc4(data, key):

    key = key.encode("utf-8")

    S = list(range(256))
    j = 0

    # KSA
    for i in range(256):

        j = (
            j +
            S[i] +
            key[i % len(key)]
        ) % 256

        S[i], S[j] = S[j], S[i]

    # PRGA
    i = 0
    j = 0

    result = bytearray()

    for byte in data:

        i = (i + 1) % 256

        j = (
            j +
            S[i]
        ) % 256

        S[i], S[j] = S[j], S[i]

        keystream = S[
            (S[i] + S[j]) % 256
        ]

        result.append(
            byte ^ keystream
        )

    return bytes(result)


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
# RECEIVE EXACT
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
# SERVER
# ============================================================

print("=" * 60)
print("                 RC4 SERVER")
print("=" * 60)

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

print(
    "\nWaiting for client..."
)

conn, address = server.accept()

print(
    "\n✓ Client connected:",
    address
)


# ============================================================
# SERVER MENU
# ============================================================

while True:

    print("\n")
    print("=" * 50)
    print("SERVER MENU")
    print("=" * 50)

    print("1. Receive Message from Client")
    print("2. Send Message to Client")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # --------------------------------------------------------
    # RECEIVE FROM CLIENT
    # --------------------------------------------------------

    if choice == "1":

        print(
            "\nWaiting for client message..."
        )

        data = receive_data(
            conn
        )

        if data is None:
            break

        if data["operation"] == "SEND":

            plaintext = data["plaintext"]

            ciphertext = bytes.fromhex(
                data["ciphertext"]
            )

            key = data["key"]

            print("\n")
            print("=" * 60)
            print("CLIENT → SERVER")
            print("=" * 60)

            print("\nPlaintext:")
            print(plaintext)

            print("\nKey:")
            print(key)

            print("\nRC4 Ciphertext:")
            print(
                ciphertext.hex()
            )

            # RC4 decrypt = RC4 encrypt
            decrypted = rc4(
                ciphertext,
                key
            ).decode(
                "utf-8",
                errors="replace"
            )

            print("\nDecrypted Plaintext:")
            print(decrypted)

            print(
                "\n✓ RC4 decryption successful."
            )

    # --------------------------------------------------------
    # SEND TO CLIENT
    # --------------------------------------------------------

    elif choice == "2":

        plaintext = input(
            "\nEnter plaintext to send: "
        )

        key = input(
            "Enter key (Enter = SECURITY): "
        ).strip()

        if not key:
            key = KEY

        plaintext_bytes = plaintext.encode(
            "utf-8"
        )

        ciphertext = rc4(
            plaintext_bytes,
            key
        )

        print("\nPlaintext:")
        print(plaintext)

        print("\nKey:")
        print(key)

        print("\nRC4 Ciphertext:")
        print(
            ciphertext.hex()
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

            send_data(
                conn,
                {
                    "operation": "SERVER_SEND",
                    "ciphertext": ciphertext.hex(),
                    "key": key
                }
            )

            print(
                "\n✓ Ciphertext sent to client."
            )

        elif request["operation"] == "EXIT":

            break

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

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

print(
    "\nServer closed."
)