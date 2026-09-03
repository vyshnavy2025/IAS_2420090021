import socket

from Crypto.Random import random
from Crypto.Util.number import getPrime


HOST = "0.0.0.0"
PORT = 5004


# ============================================================
# DIFFIE-HELLMAN PARAMETERS
# ============================================================

# Large prime number
P = getPrime(2048)

# Generator
G = 2


# ============================================================
# SEND INTEGER
# ============================================================

def send_number(sock, number):

    data = str(number).encode()

    size = len(data).to_bytes(4, "big")

    sock.sendall(size)
    sock.sendall(data)


# ============================================================
# RECEIVE INTEGER
# ============================================================

def receive_number(sock):

    size_data = receive_exact(sock, 4)

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
# SERVER
# ============================================================

print("=" * 65)
print("                 DIFFIE-HELLMAN SERVER")
print("=" * 65)

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
# GENERATE SERVER PRIVATE KEY
# ============================================================

server_private_key = random.randint(
    2,
    P - 2
)

server_public_key = pow(
    G,
    server_private_key,
    P
)


# ============================================================
# SEND P, G AND SERVER PUBLIC KEY
# ============================================================

send_number(
    conn,
    P
)

send_number(
    conn,
    G
)

send_number(
    conn,
    server_public_key
)


print("\n")
print("=" * 65)
print("SERVER PARAMETERS")
print("=" * 65)

print("\nPrime P:")
print(P)

print("\nGenerator G:")
print(G)

print("\nServer Private Key:")
print(server_private_key)

print("\nServer Public Key:")
print(server_public_key)


# ============================================================
# RECEIVE CLIENT PUBLIC KEY
# ============================================================

client_public_key = receive_number(
    conn
)

print("\nClient Public Key:")
print(client_public_key)


# ============================================================
# CALCULATE SHARED SECRET
# ============================================================

shared_secret = pow(
    client_public_key,
    server_private_key,
    P
)


print("\n")
print("=" * 65)
print("DIFFIE-HELLMAN SHARED SECRET")
print("=" * 65)

print("\nShared Secret:")
print(shared_secret)

print(
    "\n✓ Shared secret generated successfully."
)


# ============================================================
# VERIFY WITH CLIENT
# ============================================================

send_number(
    conn,
    shared_secret
)

print(
    "\n✓ Shared secret sent to client for demonstration."
)


conn.close()
server.close()

print("\nServer closed.")
