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

while True:
    text = input("Enter the message: ")
    key = int(input("Enter the key (an integer): "))
    choice = input("Enter 'encrypt' or 'decrypt': ").lower()

    if choice == 'encrypt':
        encrypted_text = caesar_cipher(text, key)
        print("Encrypted:", encrypted_text)
    elif choice == 'decrypt':
        decrypted_text = caesar_cipher(text, key, decrypt=True)
        print("Decrypted:", decrypted_text)
    else:
        print("Invalid choice.")

    another = input("Do you want to enter another message? (yes/no): ").lower()
    if another != 'yes':
        break
