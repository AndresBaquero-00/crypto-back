import codecs
from flask import request, jsonify, Flask
from flask_cors import CORS
from os import environ

# Algoritmos clásicos
from secretpy import Caesar, Polybius, Playfair, alphabets as al

# Algoritmos modernos simétricos
from Crypto.Cipher import DES3, AES
from Crypto.Util import Padding

# Algoritmos modernos asimétricos
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding

from utils import (
    generate_polybius_conf,
    generate_playfair_conf,
    generate_rsa_keys,
    generate_ec_keys,
    load_polybius_conf,
    load_playfair_conf,
    load_rsa_keys,
    load_ec_keys
)

app = Flask(__name__)
CORS(app)

codecs.register_error('handler', lambda e: ('*', e.end))
generate_polybius_conf()
generate_playfair_conf()
generate_rsa_keys()
generate_ec_keys()

@app.route('/')
def home():
    return jsonify({'ok': True, 'status': 200, 'message': 'Hello World!'})

@app.route('/caesar', methods=['POST'])
def caesar_cipher():
    cipher = Caesar()
    raw: str = request.form.get('raw')
    
    if raw:
        encrypted = cipher.encrypt(raw.lower(), int(environ.get('CAESAR_KEY')), al.SPANISH)
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'Caesar',
            'raw': raw,
            'encrypted': encrypted
        }), 200
    
    encode: str = request.form.get('encode')
    decrypted = cipher.decrypt(encode.lower(), int(environ.get('CAESAR_KEY')), al.SPANISH)
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'Caesar',
        'raw': decrypted,
        'encrypted': encode
    }), 200

@app.route('/polybius', methods=['POST'])
def polybius_cipher():
    cipher = Polybius()
    raw: str = request.form.get('raw')

    if raw:
        encrypted = cipher.encrypt(raw.lower(), environ.get('POLYBIUS_KEY'), load_polybius_conf())
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'Polybius',
            'raw': raw,
            'encrypted': encrypted
        }), 200

    encode: str = request.form.get('encode')
    decrypted = cipher.decrypt(encode.lower(), environ.get('POLYBIUS_KEY'), load_polybius_conf())
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'Polybius',
        'raw': decrypted,
        'encrypted': encode
    }), 200

@app.route('/playfair', methods=['POST'])
def playfair_cipher():
    cipher = Playfair()
    raw: str = request.form.get('raw')

    if raw:
        encrypted = cipher.encrypt(raw.lower(), environ.get('PLAYFAIR_KEY'), load_playfair_conf())
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'Playfair',
            'raw': raw,
            'encrypted': encrypted
        }), 200

    encode: str = request.form.get('encode')
    decrypted = cipher.decrypt(encode.lower(), environ.get('PLAYFAIR_KEY'), load_playfair_conf())
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'Playfair',
        'raw': decrypted,
        'encrypted': encode
    }), 200

@app.route('/des3', methods=['POST'])
def des3_cipher():
    key = environ.get('DES3_KEY')
    cipher = DES3.new(bytes.fromhex(key), DES3.MODE_ECB)
    raw: str = request.form.get('raw')

    if raw:
        encrypted: bytes = cipher.encrypt(Padding.pad(raw.encode(), 16))
        # return jsonify({'ok': True, 'status': 200, 'message': encrypted.hex()})
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'DES3',
            'raw': raw,
            'encrypted': encrypted.hex()
        }), 200 

    encode: str = request.form.get('encode')
    decrypted: bytes = Padding.unpad(cipher.decrypt(bytes.fromhex(encode)), 16).decode(errors='handler')
    # return jsonify({'ok': True, 'status': 200, 'message': decrypted})
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'DES3',
        'raw': decrypted,
        'encrypted': encode
    }), 200 

@app.route('/aes', methods=['POST'])
def aes_cipher():
    key = environ.get('AES_KEY')
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)
    raw: str = request.form.get('raw')

    if raw:
        encrypted: bytes = cipher.encrypt(Padding.pad(raw.encode(), 16))
        # return jsonify({'ok': True, 'status': 200, 'message': encrypted.hex()})
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'AES',
            'raw': raw,
            'encrypted': encrypted.hex()
        }), 200 

    encode: str = request.form.get('encode')
    decrypted: bytes = Padding.unpad(cipher.decrypt(bytes.fromhex(encode)), 16).decode(errors='handler')
    # return jsonify({'ok': True, 'status': 200, 'message': decrypted})
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'AES',
        'raw': decrypted,
        'encrypted': encode
    }), 200 

@app.route('/rsa', methods=['POST'])
def rsa_cipher():
    private_key, public_key = load_rsa_keys()
    raw: str = request.form.get('raw')

    if raw:
        encrypted: bytes = public_key.encrypt(
            raw.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # return jsonify({'ok': True, 'status': 200, 'message': encrypted.hex()})
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'RSA',
            'raw': raw,
            'encrypted': encrypted.hex()
        }), 200 

    encode: str = request.form.get('encode')
    decrypted: bytes = private_key.decrypt(
        bytes.fromhex(encode),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    # return jsonify({'ok': True, 'status': 200, 'message': decrypted.decode(errors='handler')})
    return jsonify({
        'ok': True,
        'status': 200,
        'cipher': 'RSA',
        'raw': decrypted.decode(errors='handler'),
        'encrypted': encode
    }), 200 

@app.route('/ec', methods=['POST'])
def elliptic_curve_cipher():
    private_key, public_key = load_ec_keys()
    raw: str = request.form.get('raw')
    signature: str = request.form.get('encode')

    if raw and not signature:
        encrypted: bytes = private_key.sign(raw.encode(), ec.ECDSA(hashes.SHA256()))
        # return jsonify({'ok': True, 'status': 200, 'message': encrypted.hex()})
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'EC',
            'raw': raw,
            'encrypted': encrypted.hex()
        }), 200

    try:
        public_key.verify(bytes.fromhex(signature), raw.encode(), ec.ECDSA(hashes.SHA256()))
        # return jsonify({'ok': True, 'status': 200, 'message': True})
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'EC',
            'raw': str(True),
            'encrypted': signature
        }), 200 
    except:
        # return jsonify({'ok': True, 'status': 400, 'message': False}), 400
        return jsonify({
            'ok': True,
            'status': 200,
            'cipher': 'EC',
            'raw': str(False),
            'encrypted': signature
        }), 200 

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7500, debug=True)
