
from flask import Flask, jsonify
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# Educational TLS handshake steps
TLS_STEPS = [
    {
        "step": 1,
        "title": "Client Hello",
        "description": "The client sends supported TLS versions, cipher suites, and a random value."
    },
    {
        "step": 2,
        "title": "Server Hello",
        "description": "The server selects the TLS parameters and sends its random value."
    },
    {
        "step": 3,
        "title": "Server Certificate",
        "description": "The server provides its certificate so the client can authenticate its identity."
    },
    {
        "step": 4,
        "title": "Key Exchange",
        "description": "The client and server establish shared session secrets using key exchange."
    },
    {
        "step": 5,
        "title": "Finished",
        "description": "Both sides verify the handshake transcript and begin protected communication."
    }
]

# Educational SSH connection steps
SSH_STEPS = [
    {
        "step": 1,
        "title": "Protocol Version Exchange",
        "description": "Client and server announce their SSH protocol versions."
    },
    {
        "step": 2,
        "title": "Key Exchange",
        "description": "Both sides establish shared session keys."
    },
    {
        "step": 3,
        "title": "Server Authentication",
        "description": "The client verifies the server's host key."
    },
    {
        "step": 4,
        "title": "User Authentication",
        "description": "The server checks the user's password or public-key credentials."
    },
    {
        "step": 5,
        "title": "Secure Channel",
        "description": "An authenticated session can carry encrypted SSH traffic."
    }
]

IPSEC_MODES = {
    "transport": {
        "name": "Transport Mode",
        "description": (
            "IPsec protects the IP packet payload while retaining "
            "the original IP header. Commonly used for host-to-host communication."
        )
    },
    "tunnel": {
        "name": "Tunnel Mode",
        "description": (
            "IPsec protects the entire original IP packet and adds a new "
            "outer IP header. Commonly used in VPN gateways."
        )
    }
}


@app.route("/")
def home():
    return jsonify({
        "message": "SecureTunnel API is running",
        "features": ["TLS", "SSH", "IPsec"]
    })


@app.route("/api/tls")
def tls():
    return jsonify({
        "title": "TLS Handshake",
        "steps": TLS_STEPS
    })


@app.route("/api/ssh")
def ssh():
    return jsonify({
        "title": "SSH Connection",
        "steps": SSH_STEPS
    })


@app.route("/api/ipsec")
def ipsec():
    return jsonify(IPSEC_MODES)


if __name__ == "__main__":
    app.run(port=5001, debug=True)
