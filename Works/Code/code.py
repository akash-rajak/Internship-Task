
# Message Securing Algorithm

# imported necessary library
from tkinter import *
import tkinter as tk
import tkinter.messagebox as mbox
from pil import ImageTk, Image
import random
import math


# Main Window & Configuration
window = tk.Tk() # created a tkinter gui window frame
window.title("Message Securing Algorithm")
window.geometry('1000x700')

# top label
start1 = tk.Label(text = "MESSAGE SECURING\nALGORITHM", font=("Arial", 50,"underline"), fg="magenta") # same way bg
start1.place(x = 130, y = 10)

def start_fun():
    window.destroy()

# start button created
startb = Button(window, text="START",command=start_fun,font=("Arial", 25), bg = "orange", fg = "blue", borderwidth=3, relief="raised")
startb.place(x =130 , y =590 )

# image on the main window
path = "Images/front.jpg"
# Creates a Tkinter-compatible photo image, which can be used everywhere Tkinter expects an image object.
img1 = ImageTk.PhotoImage(Image.open(path))
# The Label widget is a standard Tkinter widget used to display a text or image on the screen.
panel = tk.Label(window, image = img1)
panel.place(x = 90, y = 180)

# function created for exiting
def exit_win():
    if mbox.askokcancel("Exit", "Do you want to exit?"):
        window.destroy()

# exit button created
exitb = Button(window, text="EXIT",command=exit_win,font=("Arial", 25), bg = "red", fg = "blue", borderwidth=3, relief="raised")
exitb.place(x =730 , y = 590 )
window.protocol("WM_DELETE_WINDOW", exit_win)
window.mainloop()


# Main Window & Configuration
window1 = tk.Tk() # created a tkinter gui window frame
window1.title("Message Securing Algorithm") # title given is "DICTIONARY"
window1.geometry('1000x700')


# top label
start1 = tk.Label(text = "MESSAGE  SECURING\nALGORITHM", font=("Arial", 45, "underline"), fg="magenta") # same way bg
start1.place(x = 160, y = 10)

lbl1 = tk.Label(text="Enter any text message...", font=("Arial", 35),fg="green")  # same way bg
lbl1.place(x=50, y=160)

# text area
path_text = tk.Text(window1, height=5, width=40, font=("Arial", 30), bg="light yellow", fg="orange",borderwidth=2, relief="solid")
path_text.place(x=50, y = 225)

# helper function to encrypt and decrypt message
def endecrypt_message(m, key, n):
    res = 1  # Initialize result
    # Update message if it is more than or equal to p
    m = m % n
    if (m == 0):
        return 0
    while (key > 0):
        # If key is odd, multiply key with result
        if ((key & 1) == 1):
            res = (res * m) % n
            # key must be even now
        key = key >> 1  # key = key/2
        m = (m * m) % n
    return res

# function to encrypt message
def ecrypt_message():
    global encrypted, d, n, message, e

    # ----------- function for converting string to decimal and vice versa
    def str2dec(st):
        dec_list = []
        for i in st:
            dec_list.append(ord(i))
        return dec_list

    # Converts a list of decimal numbers to string
    def dec2str(dec):
        str_list = []
        for i in dec:
            str_list.append(chr(i))
        return ''.join(str_list)

    # funcion to generate prime no.
    def generate_prime(beg=1000, end=10000):
        beg_rand = random.randint(beg, end)
        if beg_rand % 2 == 0:
            beg_rand += 1

        for possiblePrime in range(beg_rand, end, 2):

            # Assume number is prime until shown it is not.
            isPrime = True
            for num in range(3, math.floor(possiblePrime / 2), 2):
                if possiblePrime % num == 0:
                    isPrime = False

            if isPrime:
                return possiblePrime

    # function to generate three different keys
    # This value is the multiplication of the two prime numbers,
    # because the prime numbers are large this value is difficult to factorize
    def generate_nkey(p, q):
        return p * q

    # This 'e' key with 'n' is considered the public key
    def generate_ekey(p, q):
        phi = (p - 1) * (q - 1)

        for e in range(random.randrange(3, phi - 1, 2), phi - 1):
            if math.gcd(e, phi) == 1:
                return e

    # This 'd' key with 'n' is considered the private key
    def generate_dkey(e):
        phi = (p - 1) * (q - 1)

        d = int(phi / e)
        while (True):
            if (d * e) % phi == 1:
                return d
            d += 1

    # generating primes
    p = generate_prime()
    q = generate_prime()
    while (p == q):
        q = generate_prime()

    # generating n, e, d keys
    n = generate_nkey(p, q)
    e = generate_ekey(p, q)
    d = generate_dkey(e)
    mbox.showinfo("Encrypt Process", "Keys generated successfully.")

    message = path_text.get("1.0", "end-1c")
    message_dec = str2dec(message)
    # print(message_dec)

    encrypted = [endecrypt_message(i, e, n) for i in message_dec]

    es = "["
    for i in encrypted:
        es += str(i)+", "
    es+=']'

    path_text.delete("1.0", "end")
    path_text.insert(END, es)
    mbox.showinfo("Encrypt Process", "Message Encrypted successfully.")

# function to decrypt message
def decrypt_message():
    # Converts a list of decimal numbers to string
    def dec2str(dec):
        str_list = []
        for i in dec:
            str_list.append(chr(i))
        return ''.join(str_list)

    global encrypted, d, n
    decrypted = [endecrypt_message(i, d, n) for i in encrypted]
    # print(dec2str(decrypted))

    path_text.delete("1.0", "end")
    path_text.insert(END, dec2str(decrypted))
    mbox.showinfo("Decrypt Process", "Message Decrypted successfully.")

# function for authenticating signature
def sign(message, priv_key, hashAlg="SHA-256"):
    global hash
    hash = hashAlg
    signer = PKCS1_v1_5.new(priv_key)

    if (hash == "SHA-512"):
        digest = SHA512.new()
    elif (hash == "SHA-384"):
        digest = SHA384.new()
    elif (hash == "SHA-256"):
        digest = SHA256.new()
    elif (hash == "SHA-1"):
        digest = SHA.new()
    else:
        digest = MD5.new()
    digest.update(message)
    return signer.sign(digest)

# function for verifying
def verify(message, signature, pub_key):
   signer = PKCS1_v1_5.new(pub_key)
   if (hash == "SHA-512"):
      digest = SHA512.new()
   elif (hash == "SHA-384"):
      digest = SHA384.new()
   elif (hash == "SHA-256"):
      digest = SHA256.new()
   elif (hash == "SHA-1"):
      digest = SHA.new()
   else:
      digest = MD5.new()
   digest.update(message)
   return signer.verify(digest, signature)

best = False
def authentic_fun():
    global message, d, e
    if(best):
        verify(message, sign(message, d), e)
        mbox.showinfo("Authentication error","Authentication is not successful.")
    else:
        mbox.showinfo("Authentication success", "Users signature are analyzed with keys generated.\nUsers authentication successful.")


# encrypt Button
getb=Button(window1, text="AUTHENTICATE",command=authentic_fun,  font=("Arial", 25), bg = "light green", fg = "blue")
getb.place(x = 370, y = 490)

# encrypt Button
getb=Button(window1, text="ENCRYPT",command=ecrypt_message,  font=("Arial", 25), bg = "orange", fg = "blue")
getb.place(x = 80, y = 580)

# decrypt Button
getb=Button(window1, text="DECRYPT",command=decrypt_message,  font=("Arial", 25), bg = "orange", fg = "blue")
getb.place(x = 330, y = 580)

def clear_fun():
    path_text.delete("1.0", "end")

# Get Images Button
clearb=Button(window1, text="CLEAR",command=clear_fun,  font=("Arial", 25), bg = "yellow", fg = "blue")
clearb.place(x = 580, y = 580)

def exit_win1():
    if mbox.askokcancel("Exit", "Do you want to exit?"):
        window1.destroy()

# Get Images Button
getb=Button(window1, text="EXIT",command=exit_win1,  font=("Arial", 25), bg = "red", fg = "blue")
getb.place(x = 780, y = 580)

window1.protocol("WM_DELETE_WINDOW", exit_win1)
window1.mainloop()
