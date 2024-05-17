from Crypto.Cipher import DES  # Importing the DES cipher from the Crypto library
from Crypto.Random import get_random_bytes  # Importing a function to generate random bytes
import tkinter as tk  # Importing the tkinter module for building GUI applications
############################
#############playfair-cipher##############################
#############################

# Create a 5x5 matrix using a secret key
# Function to create a 5x5 matrix for the Playfair cipher using a secret key
def create_matrix(key):
    key = key.upper()  # Convert the key to uppercase
    matrix = [[0 for i in range(5)] for j in range(5)]  # Initialize a 5x5 matrix with zeros
    letters_added = []  # List to keep track of letters added to the matrix
    row = 0
    col = 0
    # Add the key to the matrix
    for letter in key:
        if letter not in letters_added:
            matrix[row][col] = letter
            letters_added.append(letter)
        else:
            continue
        if col == 4:  # If the column index reaches 4, reset it to 0 and increment the row index
            col = 0
            row += 1
        else:
            col += 1
    # Add the rest of the alphabet to the matrix
    for letter in range(65, 91):  # ASCII codes for A to Z
        if letter == 74:  # Skip 'J' (it shares the same position with 'I' in the matrix)
            continue
        if chr(letter) not in letters_added:  # Add letters that are not already in the matrix
            letters_added.append(chr(letter))
    # Fill the matrix with the remaining letters of the alphabet
    index = 0
    for i in range(5):
        for j in range(5):
            matrix[i][j] = letters_added[index]
            index += 1
    return matrix
#Code to separate same letters.

#Add fillers if the same letter is in a pair
# Function to separate same letters in a message by adding a filler character ('X')
def separate_same_letters(message, encrypt=True):
    index = 0
    while index < len(message):
        l1 = message[index]
        if index == len(message) - 1:
            if encrypt:  # Add 'X' during encryption
                message = message + 'X'
            break
        l2 = message[index + 1]
        if l1 == l2:
            message = message[:index + 1] + ("X" if encrypt else "") + message[index + 1:]
            index += 2
        else:
            index += 2
    return message
#Code to encrypt and decrypt a message

#Return the index of a letter in the matrix
#This will be used to know what rule (1-4) to apply
# Function to find the index of a letter in the Playfair matrix
def indexOf(letter, matrix):
    for i in range(5):
        try:
            index = matrix[i].index(letter)
            return (i, index)
        except:
            continue
#Implementation of the playfair cipher
#If encrypt=True the method will encrypt the message
# otherwise the method will decrypt
# Function to perform encryption or decryption using the Playfair cipher
def playfair(key, message, encrypt=True):
    inc = 1 if encrypt else -1  # Increment for encryption or decryption
    matrix = create_matrix(key)  # Create the Playfair matrix
    message = message.upper().replace(' ', '')  # Convert the message to uppercase and remove spaces
    message = separate_same_letters(message, encrypt)  # Handle same letters in the message
    cipher_text = ''  # Initialize the result variable
    # Iterate through pairs of letters in the message
    for (l1, l2) in zip(message[0::2], message[1::2]):
        row1, col1 = indexOf(l1, matrix)  # Get indices of first letter
        row2, col2 = indexOf(l2, matrix)  # Get indices of second letter
        # Apply Playfair rules
        if row1 == row2:  # Rule 2: letters are in the same row
            cipher_text += matrix[row1][(col1 + inc) % 5] + matrix[row2][(col2 + inc) % 5]
        elif col1 == col2:  # Rule 3: letters are in the same column
            cipher_text += matrix[(row1 + inc) % 5][col1] + matrix[(row2 + inc) % 5][col2]
        else:  # Rule 4: letters are in different rows and columns
            cipher_text += matrix[row1][col2] + matrix[row2][col1]
    if not encrypt:  # If decrypting, remove filler characters ('X')
        cipher_text = cipher_text.replace('X', '')
    return cipher_text

##################################
######################Viginere-cipher##################################
############################################

# Vigenere cipher encryption function
def vigenere_encrypt(plain_text, key):
    encrypted_text = ""  # Initialize the result variable
    key_index = 0  # Initialize index for key traversal
    for char in plain_text:
        if char.isalpha():  # Check if the character is an alphabet
            shift = ord(key[key_index].upper()) - ord('A')  # Calculate shift amount
            if char.isupper():
                encrypted_text += chr((ord(char) + shift - ord('A')) % 26 + ord('A'))  # Encrypt uppercase letter
            else:
                encrypted_text += chr((ord(char) + shift - ord('a')) % 26 + ord('a'))  # Encrypt lowercase letter
            key_index = (key_index + 1) % len(key)  # Move to the next key character
        else:
            encrypted_text += char  # Keep non-alphabetic characters unchanged
    return encrypted_text

# Vigenere cipher decryption function
def vigenere_decrypt(encrypted_text, key):
    decrypted_text = ""  # Initialize the result variable
    key_index = 0  # Initialize index for key traversal
    for char in encrypted_text:
        if char.isalpha():  # Check if the character is an alphabet
            shift = ord(key[key_index].upper()) - ord('A')  # Calculate shift amount
            if char.isupper():
                decrypted_text += chr((ord(char) - shift - ord('A')) % 26 + ord('A'))  # Decrypt uppercase letter
            else:
                decrypted_text += chr((ord(char) - shift - ord('a')) % 26 + ord('a'))  # Decrypt lowercase letter
            key_index = (key_index + 1) % len(key)  # Move to the next key character
        else:
            decrypted_text += char  # Keep non-alphabetic characters unchanged
    return decrypted_text
###############################################

####################    GUI  ##############################

root = tk.Tk()  # Create the main tkinter window
root.geometry('500x500')  # Set window dimensions
root.title('Security Algorithms')  # Set window title

# Function to switch between different cipher options
def switch(indicator_lb, page):
    for child in option_fm.winfo_children():
        if isinstance(child, tk.Label):
            child['bg'] = 'SystemButtonFace'
    indicator_lb['bg'] = '#8294C4'  # Change background color of selected option indicator
    for fm in main_fm.winfo_children():
        fm.destroy()  # Destroy current page frame
        root.update()  # Update the main window
    page()  # Switch to the selected cipher page


option_fm = tk.Frame(root)

# Creating buttons for different cipher options
caeser_btn = tk.Button(option_fm, text='Caesar', font=('Sagona ExtraLight', 13),
                       bd=0, fg='#8294C4', activeforeground='#8294C4',
                       command=lambda: switch(indicator_lb=caeser_indicator_lb,
                                               page=caeser_page))
caeser_btn.place(x=0, y=0, width=125)

caeser_indicator_lb = tk.Label(option_fm)  # Indicator for the Caesar cipher option
caeser_indicator_lb.place(x=22, y=30, width=80, height=2)

playfair_btn = tk.Button(option_fm, text='Playfair' , font=('Sagona ExtraLight', 13),
                    bd=0, fg='#8294C4', activeforeground='#8294C4',
                    command=lambda: switch(indicator_lb=playfair_indicator_lb,
                                        page=playfair_page) )
playfair_btn.place(x=125, y=0, width=125)

playfair_indicator_lb = tk.Label(option_fm)
playfair_indicator_lb.place(x=147, y=30, width=80, height=2)

viginere_btn = tk.Button(option_fm, text='Viginere' , font=('Sagona ExtraLight', 13),
                    bd=0, fg='#8294C4', activeforeground='#8294C4',
                    command=lambda: switch(indicator_lb=viginere_indicator_lb,
                                        page=viginere_page) )
viginere_btn.place(x=250, y=0, width=125)

viginere_indicator_lb = tk.Label(option_fm)
viginere_indicator_lb.place(x=272, y=30, width=80, height=2)

des_btn = tk.Button(option_fm, text='DES' , font=('Sagona ExtraLight', 13),
                    bd=0, fg='#8294C4', activeforeground='#8294C4',
                    command=lambda: switch(indicator_lb=des_indicator_lb,
                                        page=des_page) )
des_btn.place(x=375, y=0, width=125)

des_indicator_lb = tk.Label(option_fm)
des_indicator_lb.place(x=397, y=30, width=80, height=2)

option_fm.pack(pady=5)  # Pack the frame containing cipher options
option_fm.pack_propagate(False)  # Prevent the frame from resizing based on its contents
option_fm.configure(width=500, height=35)  # Configure the size of the frame


def caeser_page():
    caeser_page_fm = tk.Frame(main_fm, bg='#EEF5FF')

    caeser_page_lb = tk.Label(caeser_page_fm, text='Caeser Cipher',
                            font=('French Script MT', 35), fg='#8294C4', bg='#EEF5FF')
    caeser_page_lb.pack(pady=20)

    text_label = tk.Label(caeser_page_fm, text='Enter text:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    text_label.pack(pady=10)
    text_entry = tk.Entry(caeser_page_fm, font=('Arial', 12), width=30)
    text_entry.pack()

    key_label = tk.Label(caeser_page_fm, text='Enter key (shift amount):', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    key_label.pack(pady=10)
    key_entry = tk.Entry(caeser_page_fm, font=('Arial', 12), width=5)
    key_entry.pack()

    result_label = tk.Label(caeser_page_fm, text='Result:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    result_label.pack(pady=(20, 5))  # Adding vertical padding only to the top of the label

    result_text = tk.Text(caeser_page_fm, font=('Arial', 12), width=30, height=3.5, bd=1)
    result_text.pack(pady=(0, 10))  # Adding vertical padding only to the bottom of the text widget

    button_frame = tk.Frame(caeser_page_fm)
    button_frame.pack()

    def encrypt_text():
        text = text_entry.get().upper()
        key = int(key_entry.get())
        encrypted_text = caesar_cipher(text, key)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, encrypted_text)

    def decrypt_text():
        text = text_entry.get()
        key = int(key_entry.get())
        decrypted_text = caesar_cipher(text, -key)  # Negative key for decryption
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, decrypted_text)

    encrypt_btn = tk.Button(button_frame, text='Encrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=encrypt_text)
    encrypt_btn.grid(row=0, column=0, padx=10)

    decrypt_btn = tk.Button(button_frame, text='Decrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=decrypt_text)
    decrypt_btn.grid(row=0, column=1, padx=10)

    caeser_page_fm.pack(fill=tk.BOTH, expand=True)


def caesar_cipher(text, key):
    result = ''
    for char in text:
        if char.isalpha():
            shifted = ord(char) + key
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            result += chr(shifted)
        else:
            result += char
    return result



def playfair_page():
    playfair_page_fm = tk.Frame(main_fm, bg='#EEF5FF')

    playfair_page_lb = tk.Label(playfair_page_fm, text='Playfair Cipher',
                            font=('French Script MT', 35), fg='#8294C4', bg='#EEF5FF' )
    playfair_page_lb.pack(pady=20)

    text_label = tk.Label(playfair_page_fm, text='Enter text:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    text_label.pack(pady=10)
    text_entry = tk.Entry(playfair_page_fm, font=('Arial', 12), width=30)
    text_entry.pack()

    key_label = tk.Label(playfair_page_fm, text='Enter key (Word):', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    key_label.pack(pady=10)
    key_entry = tk.Entry(playfair_page_fm, font=('Arial', 12), width=15)
    key_entry.pack()

    result_label = tk.Label(playfair_page_fm, text='Result:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    result_label.pack(pady=(10, 5))  # Adding vertical padding only to the top of the label

    result_text = tk.Text(playfair_page_fm, font=('Arial', 12), width=30, height=3.5, bd=1)
    result_text.pack(pady=(0, 10))  # Adding vertical padding only to the bottom of the text widget

    button_frame = tk.Frame(playfair_page_fm)
    button_frame.pack()

    def encrypt_text():
        text = text_entry.get().replace(' ', '').upper()
        key = key_entry.get().upper()
        encrypted_text = playfair(key, text)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, encrypted_text)

    def decrypt_text():
        text = text_entry.get().replace(' ', '').upper()
        key = key_entry.get().upper()
        decrypted_text = playfair(key, text, encrypt=False)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, decrypted_text)

    encrypt_btn = tk.Button(button_frame, text='Encrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=encrypt_text)
    encrypt_btn.grid(row=0, column=0, padx=10)

    decrypt_btn = tk.Button(button_frame, text='Decrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=decrypt_text)
    decrypt_btn.grid(row=0, column=1, padx=10)

    playfair_page_fm.pack(fill=tk.BOTH, expand=True)

def viginere_page():
    vigenere_page_fm = tk.Frame(main_fm, bg='#EEF5FF')

    vigenere_page_lb = tk.Label(vigenere_page_fm, text='Vigenere Cipher',
                                font=('French Script MT', 35), fg='#8294C4', bg='#EEF5FF')
    vigenere_page_lb.pack(pady=20)

    text_label = tk.Label(vigenere_page_fm, text='Enter text:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    text_label.pack(pady=10)
    text_entry = tk.Entry(vigenere_page_fm, font=('Arial', 12), width=30)
    text_entry.pack()

    key_label = tk.Label(vigenere_page_fm, text='Enter key (Word):', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    key_label.pack(pady=10)
    key_entry = tk.Entry(vigenere_page_fm, font=('Arial', 12), width=15)
    key_entry.pack()

    result_label = tk.Label(vigenere_page_fm, text='Result:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    result_label.pack(pady=(10, 5))  # Adding vertical padding only to the top of the label

    result_text = tk.Text(vigenere_page_fm, font=('Arial', 12), width=30, height=3.5, bd=1)
    result_text.pack(pady=(0, 10))  # Adding vertical padding only to the bottom of the text widget

    button_frame = tk.Frame(vigenere_page_fm)
    button_frame.pack()

    def encrypt_text():
        text = text_entry.get().replace(' ', '').upper()
        key = key_entry.get().upper()
        encrypted_text = vigenere_encrypt(text, key)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, encrypted_text)

    def decrypt_text():
        text = text_entry.get().replace(' ', '').upper()
        key = key_entry.get().upper()
        decrypted_text = vigenere_decrypt(text, key)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, decrypted_text)

    encrypt_btn = tk.Button(button_frame, text='Encrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2' , command=encrypt_text)
    encrypt_btn.grid(row=0, column=0, padx=10)

    decrypt_btn = tk.Button(button_frame, text='Decrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=decrypt_text)
    decrypt_btn.grid(row=0, column=1, padx=10)

    vigenere_page_fm.pack(fill=tk.BOTH, expand=True)


def des_page():
    des_page_fm = tk.Frame(main_fm, bg='#EEF5FF')  # Set background color of the page frame

    des_page_lb = tk.Label(des_page_fm, text='DES Cipher', font=('French Script MT', 35), fg='#8294C4', bg='#EEF5FF')
    des_page_lb.pack(pady=20)

    text_label = tk.Label(des_page_fm, text='Enter text:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    text_label.pack(pady=10)
    text_entry = tk.Entry(des_page_fm, font=('Arial', 12), width=30)
    text_entry.pack()

    key_label = tk.Label(des_page_fm, text='Enter key:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    key_label.pack(pady=10)
    key_entry = tk.Entry(des_page_fm, font=('Arial', 12), width=30)
    key_entry.pack()

    result_label = tk.Label(des_page_fm, text='Result:', font=('French Script MT', 20), fg='#8294C4', bg='#EEF5FF')
    result_label.pack(pady=(10, 5))  # Adding vertical padding only to the top of the label

    result_text = tk.Text(des_page_fm, font=('Arial', 12), width=30, height=3.5, bd=1)
    result_text.pack(pady=(0, 10))  # Adding vertical padding only to the bottom of the text widget

    button_frame = tk.Frame(des_page_fm)
    button_frame.pack()

    def encrypt_text():
        text = text_entry.get()
        key = key_entry.get()
        encrypted_text = des_encrypt(text, key)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, encrypted_text)

    def decrypt_text():
        text = text_entry.get()
        key = key_entry.get()
        decrypted_text = des_decrypt(text, key)
        result_text.delete('1.0', tk.END)
        result_text.insert(tk.END, decrypted_text)

    encrypt_btn = tk.Button(button_frame, text='Encrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=encrypt_text)
    encrypt_btn.grid(row=0, column=0, padx=10)

    decrypt_btn = tk.Button(button_frame, text='Decrypt', font=('French Script MT', 15),
                            bd=2, bg='#4A55A2', fg='white', activeforeground='white',activebackground='#4A55A2', command=decrypt_text)
    decrypt_btn.grid(row=0, column=1, padx=10)

    des_page_fm.pack(fill=tk.BOTH, expand=True)

def des_encrypt(text, key):
    key = key[:8].encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = pad(text.encode('utf-8'))
    encrypted_text = cipher.encrypt(padded_text)
    return encrypted_text.hex()

def des_decrypt(text, key):
    key = key[:8].encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    decrypted_text = cipher.decrypt(bytes.fromhex(text))
    return unpad(decrypted_text).decode('utf-8')

def pad(data):
    padding_length = 8 - (len(data) % 8)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


main_fm = tk.Frame(root)  # Create a frame for the main content

main_fm.pack(fill=tk.BOTH, expand=True)

caeser_page()# Show the Caesar cipher page by default

root.mainloop()# Start the tkinter event loop , which handles user inputs and updates to the GUI.