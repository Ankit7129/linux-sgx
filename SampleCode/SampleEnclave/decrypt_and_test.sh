#!/bin/bash
set -euo pipefail

DATA_DIR="/home/ankit/data"
VECTOR_ENC="${DATA_DIR}/vector1.enc"
VECTOR_DEC="${DATA_DIR}/vector1.dec.txt"
KEY_FILE="${DATA_DIR}/aesgcm_key.bin"
CHUNK_SIZE=5000000

if [[ ! -f "$VECTOR_ENC" ]]; then
  echo "❌ Encrypted vector file not found: $VECTOR_ENC"
  exit 1
fi
if [[ ! -f "$KEY_FILE" ]]; then
  echo "❌ Key file not found: $KEY_FILE"
  exit 1
fi

echo "🔓 Starting decryption..."

python3 - <<EOF
from Crypto.Cipher import AES

VECTOR_ENC = "$VECTOR_ENC"
VECTOR_DEC = "$VECTOR_DEC"
KEY_FILE = "$KEY_FILE"

NONCE_SIZE = 12
TAG_SIZE = 16

def human_readable_size(size):
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"

def decrypt_file():
    with open(KEY_FILE, "rb") as kf:
        key = kf.read()
    if len(key) != 16:
        raise ValueError("Key length invalid, expected 16 bytes")

    with open(VECTOR_ENC, "rb") as ef, open(VECTOR_DEC, "w") as df:
        total_bytes = 0
        chunk_num = 0

        while True:
            # Read nonce
            nonce = ef.read(NONCE_SIZE)
            if len(nonce) == 0:
                # EOF
                break
            if len(nonce) < NONCE_SIZE:
                raise ValueError("Incomplete nonce read")

            # Read chunk ciphertext + tag, chunk size unknown
            # We'll read next CHUNK_SIZE + TAG_SIZE bytes - 12 nonce bytes
            # but since you wrote chunks with (nonce + ciphertext + tag), 
            # and ciphertext size = chunk size

            # Here, read ciphertext + tag of unknown size, so let's try reading in loop
            
            # But you know original chunk size from encryption; here we assume you want to read fixed chunk ciphertext size

            # To simplify: read next CHUNK_SIZE bytes + TAG_SIZE
            ciphertext_and_tag = ef.read($CHUNK_SIZE + TAG_SIZE)
            if len(ciphertext_and_tag) < TAG_SIZE:
                raise ValueError("Incomplete tag read")

            ciphertext = ciphertext_and_tag[:-TAG_SIZE]
            tag = ciphertext_and_tag[-TAG_SIZE:]

            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)

            # Write decrypted bytes as space-separated integers
            df.write(" ".join(str(b) for b in plaintext) + "\n")

            chunk_num += 1
            total_bytes += len(plaintext)

            print(f"✅ Decrypted chunk {chunk_num}: {human_readable_size(len(plaintext))}")

    print(f"🎉 Decryption complete, total plaintext bytes: {human_readable_size(total_bytes)}")

if __name__ == "__main__":
    decrypt_file()
EOF

echo "✅ Decryption finished, output at: $VECTOR_DEC"
