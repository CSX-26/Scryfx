import argparse
import os
import sys

def xor_encrypt(data, key):
    """
    Encrypt data using XOR with the provided key
    """
    encrypted_data = bytearray()
    for i in range(len(data)):
        encrypted_data.append(data[i] ^ key[i % len(key)])
    return bytes(encrypted_data)

def main():
    parser = argparse.ArgumentParser(description='Encrypt shellcode using XOR encryption')
    parser.add_argument('input_file', help='Path to the shellcode file to encrypt')
    parser.add_argument('output_file', help='Path to save the encrypted shellcode')
    parser.add_argument('-k', '--key', help='Encryption key as hex string (e.g., 1a2b3c4d...)', default=None)
    
    args = parser.parse_args()
    
    # Generate or use provided key
    if args.key:
        try:
            key = bytes.fromhex(args.key)
            if len(key) < 16:
                print("Error: Key should be at least 16 bytes (32 hex characters)")
                sys.exit(1)
        except ValueError:
            print("Error: Invalid hex string for key")
            sys.exit(1)
    else:
        # Generate a random 32-byte key
        key = os.urandom(32)
        print(f"Generated key: {key.hex()}")
        print("Save this key for decryption!")
    
    # Read the shellcode
    try:
        with open(args.input_file, 'rb') as f:
            shellcode = f.read()
    except Exception as e:
        print(f"Error reading input file: {e}")
        sys.exit(1)
    
    # Encrypt the shellcode
    encrypted_data = xor_encrypt(shellcode, key)
    
    # Write the encrypted data
    try:
        with open(args.output_file, 'wb') as f:
            f.write(encrypted_data)
        print(f"Shellcode encrypted successfully and saved to {args.output_file}")
        if not args.key:
            print(f"Key: {key.hex()}")
    except Exception as e:
        print(f"Error writing output file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()