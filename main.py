from tkinter import *
from tkinter import messagebox
import base64

def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode(key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)

def save_and_encrypt_notes():
    title=title_input.get()
    message=secret_input.get("1.0",END)
    master_secret=masterkey_input.get()

    if len(title) == 0 or len(message) == 0 or len(master_secret) == 0 :
        messagebox.showinfo(title="Error!",message="Please enter all info.")
    else:
        message_encrypted=encode(master_secret,message)
        try:
            with open("mysecret.txt","a") as data_file:
                data_file.write(f"\n {title} \n {message_encrypted}")
        except FileNotFoundError:
            with open("mysecret.txt","w") as data_file:
                data_file.write(f"\n {title} \n {message_encrypted}")
        finally:
            title_input.delete(0,END)
            masterkey_input.delete(0,END)
            secret_input.delete("1.0",END)

def decrypt_notes():
    message_encrypted=secret_input.get("1.0",END)
    master_secret=masterkey_input.get()

    if len(message_encrypted)==0 or len(master_secret)==0:
        messagebox.showinfo(title="Error!",message="Please enter all info.")
    else:
        try:
            decrypted_message=decode(master_secret,message_encrypted)
            secret_input.delete("1.0",END)
            secret_input.insert("1.0",decrypted_message)
        except:
            messagebox.showinfo(title="Error!",message="Please enter encrypted text!")

window=Tk()
window.title("Secret Notes")
window.minsize(400,600)
window.config(padx=30,pady=30)
FONT=("Verdana",10,"bold")

photo=PhotoImage(file="topsecret.png")

'''
photo_label=Label(image=photo)
photo_label.pack()'''

canvas=Canvas(height=170,width=240)
canvas.create_image(120,85,image=photo)
canvas.pack()

title_label=Label(text="Enter your title",font=FONT)
title_label.pack()

title_input=Entry(width=40)
title_input.pack()

secret_label=Label(text="Enter your secret",font=FONT)
secret_label.pack()

secret_input=Text(width=40,height=20)
secret_input.pack()

masterkey_label=Label(text="Enter master key",font=FONT)
masterkey_label.pack()

masterkey_input=Entry(width=40)
masterkey_input.pack()

encrypt_button=Button(text="Save & Encrypt",font=FONT,command=save_and_encrypt_notes)
encrypt_button.config(padx=10,pady=10)
encrypt_button.pack()

decrypt_button=Button(text="Decrypt",font=FONT,command=decrypt_notes)
decrypt_button.config(padx=10,pady=10)
decrypt_button.pack()

window.mainloop()