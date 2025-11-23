import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

# --- CONSTANTS ---
AES_KEY = b'sixteen_byte_key' # 16 bytes
DEMO_IV = b'sixteen_byte_iv_' # 16 bytes

app = Flask(__name__)
CORS(app) 

@app.route("/encrypt", methods=['POST'])
def get_encrypted_message():
    """Encrypts a message for the attacker to decrypt."""
    try:
        data = request.json
        # Get plaintext from user, or use default
        plaintext_str = data.get('plaintext', "This is the top secret message!")
        plaintext = plaintext_str.encode('utf-8')

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(plaintext) + padder.finalize()

        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(DEMO_IV), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext_raw = encryptor.update(padded_data) + encryptor.finalize()

        full_payload_hex = DEMO_IV.hex() + ciphertext_raw.hex()
        
        return jsonify({
            "message": "Payload acquired.",
            "full_payload_for_attack": full_payload_hex,
            "plaintext_encrypted": plaintext_str # Send back what we encrypted
        })

    except Exception as e:
        return jsonify({"status": "ERROR", "message": str(e)}), 500

@app.route("/decrypt-vulnerable", methods=['POST'])
def decrypt_vulnerable():
    """Tries to decrypt data and LEAKS padding status."""
    try:
        data = request.json
        full_ciphertext_hex = data['ciphertext']
        full_ciphertext = bytes.fromhex(full_ciphertext_hex)
        
        iv = full_ciphertext[:16]
        ciphertext = full_ciphertext[16:] 

        cipher = Cipher(algorithms.AES(AES_KEY), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unpadder.update(padded_plaintext)
        plaintext += unpadder.finalize()
        
        # If we get here, padding was GOOD!
        return jsonify({"status": "OK", "oracle_response": "PADDING_VALID"}), 200

    except ValueError as e:
        # --- THE LEAK ---
        if "Invalid padding" in str(e):
            return jsonify({"status": "ERROR", "oracle_response": "PADDING_INVALID"}), 500
        else:
            return jsonify({"status": "ERROR", "oracle_response": "DECRYPTION_ERROR"}), 400
    except Exception as e:
        return jsonify({"status": "ERROR", "oracle_response": str(e)}), 400

if __name__ == '__main__':
    # --- RENDER DEPLOYMENT CHANGE ---
    # Read the port from the environment variable 'PORT' (set by Render)
    # Default to 5000 for local testing if the environment variable is not set.
    port = int(os.environ.get('PORT', 5000))
    
    print("--- [ Vulnerable Oracle Server ] ---")
    print(f"AES Key: {AES_KEY.hex()}")
    print(f"Demo IV: {DEMO_IV.hex()}")
    print(f"STATUS: ONLINE. Listening on http://0.0.0.0:{port}")
    print("Endpoint: /encrypt (POST) - Acquire target payload (JSON: {\"plaintext\": \"...\"})")
    print("Endpoint: /decrypt-vulnerable (POST) - Oracle entry point")
    
    # Use host='0.0.0.0' to listen on all public interfaces (required for Render)
    app.run(host='0.0.0.0', port=port, debug=False)
