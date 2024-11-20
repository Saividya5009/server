from flask import Flask, request, jsonify
from pymongo import MongoClient
from flask_cors import CORS
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
from dotenv import load_dotenv
import os
import json

# Load .env file
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/": {"origins": "*"}})  # Enable CORS for all origins

# MongoDB setup
mongo_client = MongoClient('mongodb://localhost:27017/')
db = mongo_client['Recognition']
collection = db['Embeddings']

# AES encryption settings
AES_KEY_SIZE = 32  # 256-bit AES key
AES_MODE = AES.MODE_GCM

# Load AES key from environment variable
aes_key = os.getenv("AES_SECRET_KEY", None)

# Validate AES key
if aes_key is None:
    raise ValueError("AES_SECRET_KEY not found in environment variables.")
try:
    aes_key = bytes.fromhex(aes_key)
except ValueError:
    raise ValueError("AES_SECRET_KEY must be a valid 64-character hexadecimal string.")
if len(aes_key) != AES_KEY_SIZE:
    raise ValueError(f"AES key must be 32 bytes. Current key length: {len(aes_key)}")

# Utility functions
def encrypt_data(data):
    """Encrypt data using AES-GCM."""
    cipher = AES.new(aes_key, AES_MODE)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'ciphertext': b64encode(ciphertext).decode('utf-8'),
        'tag': b64encode(tag).decode('utf-8'),
        'nonce': b64encode(cipher.nonce).decode('utf-8')
    }

def decrypt_data(encrypted_data):
    """Decrypt data using AES-GCM."""
    try:
        cipher = AES.new(aes_key, AES_MODE, nonce=b64decode(encrypted_data['nonce']))
        return cipher.decrypt_and_verify(
            b64decode(encrypted_data['ciphertext']),
            b64decode(encrypted_data['tag'])
        )
    except (ValueError, KeyError) as e:
        raise ValueError("Decryption failed. Ensure the key and data are valid.") from e

# Flask routes
@app.route('/upload_embeddings', methods=['POST'])
def upload_embeddings():
    """Endpoint to upload embeddings."""
    data = request.json  # Expecting JSON format with embeddings
    if isinstance(data, list):
        try:
            for embedding in data:
                # Check if the name already exists in the database
                existing_record = collection.find_one({'name': embedding['name']})
                if existing_record:
                    return jsonify({
                        "status": "failed",
                        "message": f"Name '{embedding['name']}' already exists in the database."
                    }), 400
                
                # Serialize and encrypt the embedding
                embedding_json = json.dumps(embedding['embedding']).encode('utf-8')
                encrypted_embedding = encrypt_data(embedding_json)
                
                # Prepare data for insertion
                encrypted_data = {
                    'name': embedding['name'],
                    'embedding': encrypted_embedding
                }
                
                # Insert the data into the database
                collection.insert_one(encrypted_data)

            return jsonify({"status": "success"}), 200
        except Exception as e:
            return jsonify({"status": "failed", "error": str(e)}), 500
    else:
        return jsonify({"status": "failed", "error": "Invalid data format"}), 400

@app.route('/get_embeddings', methods=['GET'])
def get_embeddings():
    """Endpoint to get all embeddings."""
    try:
        # Retrieve and decrypt embeddings from MongoDB
        encrypted_embeddings = list(collection.find({}, {"_id": 0}))
        decrypted_embeddings = []
        for item in encrypted_embeddings:
            decrypted_embedding = decrypt_data(item['embedding']).decode('utf-8')
            decrypted_embeddings.append({
                'name': item['name'],
                'embedding': json.loads(decrypted_embedding)  # Safely deserialize JSON
            })
        return jsonify(decrypted_embeddings), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)