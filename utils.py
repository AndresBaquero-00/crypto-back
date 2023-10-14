import json
import random
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from secretpy import alphabets as al

def generate_polybius_conf():
    alpha = list(al.SPANISH_SQUARE)
    random.shuffle(alpha)
    file = open('keys/polybius.key', 'w')
    file.write(json.dumps(alpha))
    file.close()

def generate_playfair_conf():
    alpha = list(al.SPANISH_SQUARE)
    random.shuffle(alpha)
    file = open('keys/playfair.key', 'w')
    file.write(json.dumps(alpha))
    file.close()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    file = open('keys/rsa_private_key.pem', 'wb')
    file.write(pem)
    file.close()

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    file = open('keys/rsa_public_key.pem', 'wb')
    file.write(pem)
    file.close()

def generate_ec_keys():
    private_key = ec.generate_private_key(ec.SECP384R1())
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    file = open('keys/ec_private_key.pem', 'wb')
    file.write(pem)
    file.close()

    public_key = private_key.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    file = open('keys/ec_public_key.pem', 'wb')
    file.write(pem)
    file.close()

def load_polybius_conf() -> list:
    file = open('keys/polybius.key', 'r')
    return json.loads(file.read())

def load_playfair_conf() -> list:
    file = open('keys/polybius.key', 'r')
    return json.loads(file.read())

def load_rsa_keys() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    file = open('keys/rsa_private_key.pem', 'rb')
    private_key = serialization.load_pem_private_key(file.read(), password=None)

    file = open('keys/rsa_public_key.pem', 'rb')
    public_key = serialization.load_pem_public_key(file.read())

    return private_key, public_key

def load_ec_keys() -> tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    file = open('keys/ec_private_key.pem', 'rb')
    private_key = serialization.load_pem_private_key(file.read(), password=None)

    file = open('keys/ec_public_key.pem', 'rb')
    public_key = serialization.load_pem_public_key(file.read())

    return private_key, public_key