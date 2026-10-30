import socket

from Crypto.Random import random


HOST = "127.0.0.1"
PORT = 5004


# ============================================================
# SEND INTEGER
# ============================================================

def send_number(sock, number):

    data = str(number).encode()

    size = len(data).to_bytes(
        4,
        "big"
    )

    sock.sendall(size)
    sock.sendall(data)


# ============================================================
# RECEIVE INTEGER
# ============================================================

def receive_number(sock):

    size_data = receive_exact(
        sock,
        4
    )

    if not size_data:
        return None

    size = int.from_bytes(
        size_data,
        "big"
    )

    data = receive_exact(
        sock,
        size
    )

    if not data:
        return None

    return int(
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
# CLIENT
# ============================================================

print("=" * 65)
print("                 DIFFIE-HELLMAN CLIENT")
print("=" * 65)

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

    print(
        "\nConnection error:",
        e
    )

    exit()


# ============================================================
# RECEIVE P
# ============================================================

P = receive_number(
    client
)


# ============================================================
# RECEIVE G
# ============================================================

G = receive_number(
    client
)


# ============================================================
# RECEIVE SERVER PUBLIC KEY
# ============================================================

server_public_key = receive_number(
    client
)


print("\n")
print("=" * 65)
print("DIFFIE-HELLMAN PARAMETERS")
print("=" * 65)

print("\nPrime P:")
print(P)

print("\nGenerator G:")
print(G)

print("\nServer Public Key:")
print(server_public_key)


# ============================================================
# GENERATE CLIENT PRIVATE KEY
# ============================================================

client_private_key = random.randint(
    2,
    P - 2
)


# ============================================================
# CALCULATE CLIENT PUBLIC KEY
# ============================================================

client_public_key = pow(
    G,
    client_private_key,
    P
)


print("\nClient Private Key:")
print(client_private_key)

print("\nClient Public Key:")
print(client_public_key)


# ============================================================
# SEND CLIENT PUBLIC KEY
# ============================================================

send_number(
    client,
    client_public_key
)


# ============================================================
# CALCULATE SHARED SECRET
# ============================================================

shared_secret = pow(
    server_public_key,
    client_private_key,
    P
)


print("\n")
print("=" * 65)
print("CLIENT SHARED SECRET")
print("=" * 65)

print("\nShared Secret:")
print(shared_secret)


# ============================================================
# RECEIVE SERVER SHARED SECRET
# ============================================================

server_shared_secret = receive_number(
    client
)


print("\nServer Shared Secret:")
print(server_shared_secret)


# ============================================================
# VERIFY
# ============================================================

if shared_secret == server_shared_secret:

    print(
        "\n✓ SUCCESS: Both sides generated the SAME shared key!"
    )

else:

    print(
        "\n✗ ERROR: Shared keys do not match."
    )


client.close()

print("\nClient closed.")