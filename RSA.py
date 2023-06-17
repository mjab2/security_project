import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
import cryptography.exceptions


class App:
    def __init__(self, master):
        self.master = master
        master.title("RSA Encryption and Signing Tool")

        # Key Generation
        self.key_label = tk.Label(master, text="RSA Key Pair:")
        self.key_label.pack()

        self.generate_key_button = tk.Button(
            master, text="Generate Key Pair", command=self.generate_key_pair)
        self.generate_key_button.pack()

        self.public_key_label = tk.Label(master, text="Public Key:")
        self.public_key_label.pack()

        self.public_key_entry = tk.Entry(master, width=50)
        self.public_key_entry.pack()

        self.private_key_label = tk.Label(master, text="Private Key:")
        self.private_key_label.pack()

        self.private_key_entry = tk.Entry(master, width=50)
        self.private_key_entry.pack()

        # File Selection
        self.file_label = tk.Label(master, text="File:")
        self.file_label.pack()

        self.file_entry = tk.Entry(master, width=50)
        self.file_entry.pack()

        self.browse_button = tk.Button(
            master, text="Browse", command=self.browse_file)
        self.browse_button.pack()

        # Encryption
        self.encrypt_button = tk.Button(
            master, text="Encrypt", command=self.encrypt_file)
        self.encrypt_button.pack()

        # Decryption
        self.decrypt_button = tk.Button(
            master, text="Decrypt", command=self.decrypt_file)
        self.decrypt_button.pack()

        # Signing
        self.sign_button = tk.Button(
            master, text="Sign", command=self.sign_file)
        self.sign_button.pack()

        # Verification
        self.verify_button = tk.Button(
            master, text="Verify", command=self.verify_file)
        self.verify_button.pack()

        # Status Label
        self.status_label = tk.Label(master, text="")
        self.status_label.pack()

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,  # Co-prime
            key_size=2048
        )
        public_key = private_key.public_key()

        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

        self.public_key_entry.delete(0, tk.END)
        self.public_key_entry.insert(0, public_key_pem)
        self.private_key_entry.delete(0, tk.END)
        self.private_key_entry.insert(0, private_key_pem)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def encrypt_file(self):
        public_key_pem = self.public_key_entry.get()
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        in_filename = self.file_entry.get()
        out_filename = in_filename + '.enc'

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(190)
                    if len(chunk) == 0:
                        break
                    encrypted_chunk = public_key.encrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    outfile.write(encrypted_chunk)

        self.status_label.config(text="File encrypted successfully.")

    def decrypt_file(self):
        private_key_pem = self.private_key_entry.get()
        private_key = load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None)

        in_filename = self.file_entry.get()
        out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(256)
                    if len(chunk) == 0:
                        break
                    decrypted_chunk = private_key.decrypt(
                        chunk,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )
                    outfile.write(decrypted_chunk)

        self.status_label.config(text="File decrypted successfully.")

    def sign_file(self):
        private_key_pem = self.private_key_entry.get()
        private_key = load_pem_private_key(
            private_key_pem.encode('utf-8'), password=None)

        in_filename = self.file_entry.get()
        out_filename = in_filename + '.sig'

        with open(in_filename, 'rb') as infile:
            data = infile.read()

        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        with open(out_filename, 'wb') as outfile:
            outfile.write(signature)

        self.status_label.config(text="File signed successfully.")

    def verify_file(self):
        public_key_pem = self.public_key_entry.get()
        public_key = load_pem_public_key(public_key_pem.encode('utf-8'))

        in_filename = self.file_entry.get()
        sig_filename = in_filename + '.sig'

        with open(in_filename, 'rb') as infile:
            data = infile.read()

        with open(sig_filename, 'rb') as sigfile:
            signature = sigfile.read()

        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            self.status_label.config(text="File signature is valid.")
        except cryptography.exceptions.InvalidSignature:
            self.status_label.config(text="File signature is invalid.")


root = tk.Tk()
app = App(root)
root.mainloop()
