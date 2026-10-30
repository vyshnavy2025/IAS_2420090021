
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta, timezone
import base64

app = Flask(__name__)
CORS(app)

# Generate RSA key pair for demonstration
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()


@app.route("/")
def home():
    return jsonify({"message": "CryptoVault API is running"})


# RSA ENCRYPTION
@app.route("/rsa/encrypt", methods=["POST"])
def rsa_encrypt():
    data = request.get_json()
    message = data.get("message", "").encode()

    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return jsonify({
        "ciphertext": base64.b64encode(ciphertext).decode()
    })


# RSA DECRYPTION
@app.route("/rsa/decrypt", methods=["POST"])
def rsa_decrypt():
    data = request.get_json()

    try:
        ciphertext = base64.b64decode(data["ciphertext"], validate=True)
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({"plaintext": plaintext.decode("utf-8")})
    except Exception:
        return jsonify({"error": "Decryption failed"}), 400


# SHA-512 HASHING
@app.route("/hash", methods=["POST"])
def make_hash():
    message = request.get_json().get("message", "").encode()
    digest = hashes.Hash(hashes.SHA512())
    digest.update(message)

    return jsonify({"hash": digest.finalize().hex()})


# DIGITAL SIGNATURE
@app.route("/signature/sign", methods=["POST"])
def sign_message():
    message = request.get_json().get("message", "").encode()

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return jsonify({
        "signature": base64.b64encode(signature).decode()
    })


@app.route("/signature/verify", methods=["POST"])
def verify_signature():
    data = request.get_json()

    try:
        signature = base64.b64decode(data["signature"], validate=True)
        public_key.verify(
            signature,
            data["message"].encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return jsonify({"valid": True, "message": "Signature verified"})
    except Exception:
        return jsonify({"valid": False, "message": "Invalid signature"}), 400


# DIFFIE-HELLMAN KEY EXCHANGE DEMONSTRATION
@app.route("/dh/exchange", methods=["GET"])
def dh_exchange():
    parameters = dh.generate_parameters(generator=2, key_size=2048)
    alice = parameters.generate_private_key()
    bob = parameters.generate_private_key()

    alice_secret = alice.exchange(bob.public_key())
    bob_secret = bob.exchange(alice.public_key())

    return jsonify({
        "alice_public_key": base64.b64encode(
            alice.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode(),
        "bob_public_key": base64.b64encode(
            bob.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            )
        ).decode(),
        "shared_secret_match": alice_secret == bob_secret,
        "message": "Both parties generated the same shared secret"
    })


# SELF-SIGNED X.509 CERTIFICATE DEMONSTRATION
@app.route("/certificate", methods=["GET"])
def generate_certificate():
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "CryptoVault Demo")
    ])

    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=30))
        .sign(private_key, hashes.SHA256())
    )

    pem = certificate.public_bytes(serialization.Encoding.PEM).decode()

    return jsonify({"certificate": pem})


if __name__ == "__main__":
    app.run(debug=True, port=5000)
