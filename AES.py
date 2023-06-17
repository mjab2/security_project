import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding


class App:
    def __init__(self, master):
        self.master = master
        master.title("AES Encryption Tool")

        # Symmetric Key Generation
        self.key_label = tk.Label(master, text="Symmetric Key (32 bytes):")
        self.key_label.pack()

        self.key_entry = tk.Entry(master, width=50)
        self.key_entry.pack()

        self.generate_key_button = tk.Button(
            master, text="Generate Key", command=self.generate_key)
        self.generate_key_button.pack()

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

        # Status Label
        self.status_label = tk.Label(master, text="")
        self.status_label.pack()

    def generate_key(self):
        key = os.urandom(32)
        self.key_entry.delete(0, tk.END)
        self.key_entry.insert(0, key.hex())

    def browse_file(self):
        filename = filedialog.askopenfilename()
        self.file_entry.delete(0, tk.END)
        self.file_entry.insert(0, filename)

    def pad_data(self, data):
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(data) + padder.finalize()
        return padded_data

    def unpad_data(self, padded_data):
        unpadder = padding.PKCS7(128).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()
        return data

    def encrypt_file(self):
        key = bytes.fromhex(self.key_entry.get())
        in_filename = self.file_entry.get()
        out_filename = in_filename + '.enc'
        iv = os.urandom(16)

        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                while True:
                    chunk = infile.read(64 * 1024)
                    if not chunk:
                        break
                    padded_chunk = self.pad_data(chunk)
                    ciphertext = encryptor.update(padded_chunk)
                    outfile.write(ciphertext)

        self.status_label.config(text="File encrypted successfully.")

    def decrypt_file(self):
        key = bytes.fromhex(self.key_entry.get())
        in_filename = self.file_entry.get()
        out_filename = os.path.splitext(in_filename)[0]

        with open(in_filename, 'rb') as infile:
            with open(out_filename, 'wb') as outfile:
                iv = infile.read(16)

                cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
                decryptor = cipher.decryptor()

                while True:
                    ciphertext = infile.read(64 * 1024)
                    if not ciphertext:
                        break
                    padded_chunk = decryptor.update(ciphertext)
                    chunk = self.unpad_data(padded_chunk)
                    outfile.write(chunk)

        self.status_label.config(text="File decrypted successfully.")


root = tk.Tk()
app = App(root)
root.mainloop()
