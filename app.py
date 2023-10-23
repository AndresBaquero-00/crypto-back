import codecs
from flask import request, jsonify, Flask
from flask_cors import CORS
from os import environ
from werkzeug.datastructures.file_storage import FileStorage

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
    raw: str = request.get_json().get('raw')
    
    if raw:
        encoded = cipher.encrypt(raw.lower(), int(environ.get('CAESAR_KEY')), al.SPANISH)
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded
        }), 200
    
    encoded: str = request.get_json().get('encoded')
    raw = cipher.decrypt(encoded.lower(), int(environ.get('CAESAR_KEY')), al.SPANISH)
    return jsonify({
        'ok': True,
        'status': 200,
        'raw': raw,
    }), 200

@app.route('/polybius', methods=['POST'])
def polybius_cipher():
    cipher = Polybius()
    raw: str = request.get_json().get('raw')
    
    if raw:
        encoded = cipher.encrypt(raw.lower(), environ.get('POLYBIUS_KEY'), load_polybius_conf())
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded
        }), 200
    
    encoded: str = request.get_json().get('encoded')
    raw = cipher.decrypt(encoded.lower(), environ.get('POLYBIUS_KEY'), load_polybius_conf())
    return jsonify({
        'ok': True,
        'status': 200,
        'raw': raw,
    }), 200

@app.route('/playfair', methods=['POST'])
def playfair_cipher():
    cipher = Playfair()
    raw: str = request.get_json().get('raw')
    
    if raw:
        encoded = cipher.encrypt(raw.lower(), environ.get('PLAYFAIR_KEY'), load_playfair_conf())
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded
        }), 200
    
    encoded: str = request.get_json().get('encoded')
    raw = cipher.decrypt(encoded.lower(), environ.get('PLAYFAIR_KEY'), load_playfair_conf())
    return jsonify({
        'ok': True,
        'status': 200,
        'raw': raw,
    }), 200

@app.route('/des3', methods=['POST'])
def des3_cipher():
    key = environ.get('DES3_KEY')
    cipher = DES3.new(bytes.fromhex(key), DES3.MODE_ECB)

    file: FileStorage = request.files.get('file')
    if file:
        encoded: bytes = cipher.encrypt(Padding.pad(file.stream.read(), 16))
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 
    
    raw: str = request.get_json().get('raw')
    if raw:
        encoded: bytes = cipher.encrypt(Padding.pad(raw.encode(), 16))
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 

    encoded: str = request.get_json().get('encoded')
    raw = Padding.unpad(cipher.decrypt(bytes.fromhex(encoded)), 16).decode(errors='handler')
    return jsonify({
        'ok': True,
        'status': 200,
        'raw': raw,
    }), 200 

@app.route('/aes', methods=['POST'])
def aes_cipher():
    key = environ.get('AES_KEY')
    cipher = AES.new(bytes.fromhex(key), AES.MODE_ECB)

    file: FileStorage = request.files.get('file')
    if file:
        encoded: bytes = cipher.encrypt(Padding.pad(file.stream.read(), 16))
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 

    raw: str = request.get_json().get('raw')
    if raw:
        encoded: bytes = cipher.encrypt(Padding.pad(raw.encode(), 16))
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200

    encoded: str = request.get_json().get('encoded')
    raw = Padding.unpad(cipher.decrypt(bytes.fromhex(encoded)), 16).decode(errors='handler')
    return jsonify({
        'ok': True,
        'status': 200,
        'raw': raw
    }), 200 

@app.route('/rsa', methods=['POST'])
def rsa_cipher():
    private_key, public_key = load_rsa_keys()

    file: FileStorage = request.files.get('file')
    if file:
        encoded: bytes = public_key.encrypt(
            file.stream.read(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 

    raw: str = request.get_json().get('raw')
    if raw:
        encoded: bytes = public_key.encrypt(
            raw.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 

    return jsonify({
        'ok': False,
        'status': 400,
    }), 400 

@app.route('/ec', methods=['POST'])
def elliptic_curve_cipher():
    private_key, public_key = load_ec_keys()

    file: FileStorage = request.files.get('file')
    if file:
        encoded: bytes = private_key.sign(file.stream.read(), ec.ECDSA(hashes.SHA256()))

        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200 

    raw: str = request.get_json().get('raw')
    if raw:
        encoded: bytes = private_key.sign(raw.encode(), ec.ECDSA(hashes.SHA256()))
        return jsonify({
            'ok': True,
            'status': 200,
            'encoded': encoded.hex()
        }), 200

    return jsonify({
        'ok': False,
        'status': 400,
    }), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=7500, debug=True)
