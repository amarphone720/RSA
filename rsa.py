import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend

def generate_keys():
    # Generate private and public keys
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Save the private key to a file
    with open("private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save the public key to a file
    with open("public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("RSA key pair generated and saved as 'private_key.pem' and 'public_key.pem'.")

def encrypt_file(filename):
  #if public key file exist then run the code in this function
  try:
    # Load the public key
    with open("public_key.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(f.read(), backend=default_backend())
    
    # Read the file content
    with open(filename, "rb") as f:
        file_data = f.read()
    
    # Encrypt the file data
    encrypted_data = public_key.encrypt(
        file_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Save the encrypted data
    encrypted_filename = filename + ".encrypted"
    with open(encrypted_filename, "wb") as f:
        f.write(encrypted_data)
    
    print(f"File '{filename}' encrypted and saved as '{encrypted_filename}'.")
  #if the public key file doesn't exist show this 
  except:
     print("generate a public key first")
def decrypt_file(filename):
  try:
    # Load the private key
    with open("private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())
    
    # Read the encrypted file content
    with open(filename, "rb") as f:
        encrypted_data = f.read()
    
    # Decrypt the data
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    
    # Save the decrypted data
    decrypted_filename = filename.replace(".encrypted", "")
    with open(decrypted_filename, "wb") as f:
        f.write(decrypted_data)
    
    print(f"File '{filename}' decrypted and saved as '{decrypted_filename}'.")
  except:
     print("the private key is missing or incorrect or corrupt")
if __name__ == "__main__":
    print("1. Generate RSA Keys")
    print("2. Encrypt a File")
    print("3. Decrypt a File")
    print("4. Exit")
    
    choice = input("Select an option: ")
    
    if choice == "1":
        generate_keys()
    elif choice == "2":
        filename = input("Enter the filename to encrypt: ")
        if os.path.exists(filename):
            encrypt_file(filename)
        else:
            print("File not found.")
    elif choice == "3":
        filename = input("Enter the filename to decrypt (must be .encrypted file): ")
        if os.path.exists(filename):
            decrypt_file(filename)
        else:
            print("File not found.")
    elif choice == "4":
        print("Exiting.")
    else:
        print("Invalid option.")
