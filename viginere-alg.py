import tkinter as tk
from tkinter import ttk

def caesar_cipher(text, shift, decrypt=False):
    result = ""
    for char in text:
        if char.isalpha():
            if decrypt:
                shifted = ord(char) - shift
            else:
                shifted = ord(char) + shift
                
            if char.islower():
                if shifted < ord('a'):
                    shifted += 26
                elif shifted > ord('z'):
                    shifted -= 26
            elif char.isupper():
                if shifted < ord('A'):
                    shifted += 26
                elif shifted > ord('Z'):
                    shifted -= 26
            
            result += chr(shifted)
        else:
            result += char
    return result

def vigenere_encrypt(plain_text, key):
    encrypted_text = ""
    key_index = 0
    
    for char in plain_text:
        if char.isalpha():
            shift = ord(key[key_index].upper()) - ord('A')
            if char.isupper():
                encrypted_text += chr((ord(char) + shift - ord('A')) % 26 + ord('A'))
            else:
                encrypted_text += chr((ord(char) + shift - ord('a')) % 26 + ord('a'))
            key_index = (key_index + 1) % len(key)
        else:
            encrypted_text += char
    
    return encrypted_text

def vigenere_decrypt(encrypted_text, key):
    decrypted_text = ""
    key_index = 0
    
    for char in encrypted_text:
        if char.isalpha():
            shift = ord(key[key_index].upper()) - ord('A')
            if char.isupper():
                decrypted_text += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))
            else:
                decrypted_text += chr((ord(char) - shift - ord('a')) % 26 + ord('a'))
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_text += char
    
    return decrypted_text

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Text Cipher App")

        self.input_label = tk.Label(root, text="Enter text:")
        self.input_label.grid(row=0, column=0, padx=10, pady=5, sticky=tk.W)

        self.input_text = tk.Text(root, height=5, width=40)
        self.input_text.grid(row=0, column=1, columnspan=3, padx=10, pady=5)

        self.key_label = tk.Label(root, text="Enter key:")
        self.key_label.grid(row=1, column=0, padx=10, pady=5, sticky=tk.W)

        self.key_entry = tk.Entry(root)
        self.key_entry.grid(row=1, column=1, padx=10, pady=5)

        self.algorithm_label = tk.Label(root, text="Select Algorithm:")
        self.algorithm_label.grid(row=2, column=0, padx=10, pady=5, sticky=tk.W)

        self.algorithm_var = tk.StringVar()
        self.algorithm_dropdown = ttk.Combobox(root, textvariable=self.algorithm_var, values=["Caesar", "Vigenere", "Playfair", "DES"])
        self.algorithm_dropdown.grid(row=2, column=1, padx=10, pady=5)

        self.encrypt_button = tk.Button(root, text="Encrypt", command=self.encrypt_text)
        self.encrypt_button.grid(row=2, column=2, padx=10, pady=5)

        self.decrypt_button = tk.Button(root, text="Decrypt", command=self.decrypt_text)
        self.decrypt_button.grid(row=2, column=3, padx=10, pady=5)

        self.output_label = tk.Label(root, text="Converted Text:")
        self.output_label.grid(row=3, column=0, padx=10, pady=5, sticky=tk.W)

        self.output_text = tk.Text(root, height=5, width=40)
        self.output_text.grid(row=3, column=1, columnspan=3, padx=10, pady=5)

    def encrypt_text(self):
        algorithm = self.algorithm_var.get()
        text = self.input_text.get("1.0", "end-1c")
        key = self.key_entry.get()
        if algorithm == "Caesar":
            key = int(key)
            encrypted_text = caesar_cipher(text, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted_text)
        elif algorithm == "Vigenere":
            encrypted_text = vigenere_encrypt(text, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, encrypted_text)
        else:
            # Implement encryption for other algorithms
            pass

    def decrypt_text(self):
        algorithm = self.algorithm_var.get()
        text = self.input_text.get("1.0", "end-1c")
        key = self.key_entry.get()
        if algorithm == "Caesar":
            key = int(key)
            decrypted_text = caesar_cipher(text, key, decrypt=True)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
        elif algorithm == "Vigenere":
            decrypted_text = vigenere_decrypt(text, key)
            self.output_text.delete("1.0", tk.END)
            self.output_text.insert(tk.END, decrypted_text)
        else:
            # Implement decryption for other algorithms
            pass

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
