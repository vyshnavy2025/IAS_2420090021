import socket
import json
import struct

HOST = "127.0.0.1"
PORT = 5003

KEY = "SECURITY"


# ============================================================
# RC4 KEY-SCHEDULING ALGORITHM
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

    message = json.dumps(data).encode()

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

print("=" * 60)
print("                 RC4 CLIENT")
print("=" * 60)

client = socket.socket(
    socket.AF_INET,
    socket.SOCK_STREAM
)

try:

    client.connect(
        (HOST, PORT)
    )

    print("\n✓ Connected to server.")

except Exception as e:

    print("\nConnection error:", e)
    exit()


# ============================================================
# CLIENT MENU
# ============================================================

while True:

    print("\n")
    print("=" * 50)
    print("CLIENT MENU")
    print("=" * 50)

    print("1. Encrypt and Send Message")
    print("2. Receive and Decrypt Message")
    print("3. Exit")

    choice = input(
        "\nEnter choice: "
    )

    # --------------------------------------------------------
    # SEND
    # --------------------------------------------------------

    if choice == "1":

        plaintext = input(
            "\nEnter plaintext: "
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
        print(ciphertext.hex())

        send_data(
            client,
            {
                "operation": "SEND",
                "plaintext": plaintext,
                "ciphertext": ciphertext.hex(),
                "key": key
            }
        )

        print(
            "\n✓ Ciphertext sent to server."
        )

    # --------------------------------------------------------
    # RECEIVE
    # --------------------------------------------------------

    elif choice == "2":

        send_data(
            client,
            {
                "operation": "REQUEST"
            }
        )

        data = receive_data(
            client
        )

        if data is None:

            print(
                "\nServer disconnected."
            )

            break

        if data["operation"] == "NO_MESSAGE":

            print(
                "\nNo message available."
            )

        elif data["operation"] == "SERVER_SEND":

            ciphertext = bytes.fromhex(
                data["ciphertext"]
            )

            key = data["key"]

            plaintext = rc4(
                ciphertext,
                key
            ).decode(
                "utf-8",
                errors="replace"
            )

            print("\n")
            print("=" * 60)
            print("SERVER → CLIENT")
            print("=" * 60)

            print("\nRC4 Ciphertext:")
            print(
                ciphertext.hex()
            )

            print("\nKey:")
            print(key)

            print("\nPlaintext:")
            print(plaintext)

            print(
                "\n✓ RC4 decryption successful."
            )

        elif data["operation"] == "EXIT":

            break

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

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

print("\nClient closed.")