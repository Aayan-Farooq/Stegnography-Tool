import customtkinter as ctk
from PIL import Image
import tkinter.filedialog as filedialog
from tkinter import *
from tkinter import ttk        # USED FOR CREATING GUI'S
from PIL import Image, ImageTk # USED FOR ADDING IMAGES 
from tkinter import filedialog # DIALOUGE BOXES FOR ADD IMAGES
import os
from stegano  import lsb
from tkinter import messagebox # FOR MESSAGES 
from tkinter import simpledialog # FOR DIALOUGE BOXES
from cryptography.fernet import Fernet # for one type of encryption, uses AES 128+ hashing
#ADD ENCRYPTION ACCORDING TO THE FUNCTION, MAKE IT 3D , MAKE IT RUN SMOOTHER, IMAGE DOWNLOADING TYPES, ADD IMAGE BACKGROUND.
import sqlite3 # for database

# -----------------  Color Scheme -----------------
BG_COLOR = "#1a1d1f"
FRAME_COLOR = "#2e3438"
TEXT_COLOR = "#dcdcdc"
BUTTON_COLOR = "#3b9c9c"
HOVER_COLOR = "#57b1b1"
ENTRY_COLOR = "#23272a"
SHADOW_COLOR = "#46bfbf"
CONTENT_FRAME="#5D7677"
# ----------------- App Setup -----------------
ctk.set_appearance_mode("system")
ctk.set_default_color_theme("blue")

root = ctk.CTk()
root.geometry("900x600")
root.title("🔐 Image Steganography Tool")
root.configure(fg_color=BG_COLOR)
#-----------------------------Database -------------------------------------
connector=sqlite3.connect('Image_information.db')
cursor=connector.cursor() # create a cursor object that lets me execute sql commands
#creating a table 
cursor.execute('''
 CREATE TABLE IF NOT EXISTS Image_Information (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        password TEXT,
        fernet_key TEXT
               )
               
''')
connector.commit()
#--------------------------------Globals ---------------------------------
global check_encrypted
global check_decrypt
check_decrypt=0
check_encrypted=0
global downloaded
downloaded=0
global encoded
encoded=0
global encrypted
encrypted=None
key_for_encryption=None
#------------------------- Shadow function ------------------------
def shadow_button(parent, text, command=None):
    shadow = ctk.CTkFrame(parent, fg_color=SHADOW_COLOR, corner_radius=8)
    shadow.pack(padx=10, pady=5, fill="x")

    btn = ctk.CTkButton(shadow, text=text, command=command,
                        fg_color=BUTTON_COLOR, hover_color=HOVER_COLOR,
                        text_color="white", corner_radius=8,
                        font=("San Francisco", 14))
    btn.pack( padx=2, pady=2,fill="x")

    def on_enter(event): btn.configure(font=("San Francisco", 16))
    def on_leave(event): btn.configure(font=("San Francisco", 14))

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

    return btn

def small_shadow_button(parent, text, command=None, width=125):
    shadow = ctk.CTkFrame(parent, fg_color=SHADOW_COLOR, corner_radius=8)
    btn = ctk.CTkButton(shadow, text=text, command=command,
                        fg_color=BUTTON_COLOR, hover_color=HOVER_COLOR,
                        text_color="white", corner_radius=8,
                        font=("San Francisco", 14), width=width)
    btn.pack(padx=2, pady=2, fill="both", expand=True)

    def on_enter(event): btn.configure(font=("San Francisco", 16))
    def on_leave(event): btn.configure(font=("San Francisco", 14))

    btn.bind("<Enter>", on_enter)
    btn.bind("<Leave>", on_leave)

    return shadow  # Return the frame to pack it externally

def on_option_change(choice):
    if choice == "With Password":
        password_entry.pack(padx=10, pady=(0, 20), fill="x")
    else:
        password_entry.pack_forget()


#-------------------------------- Functions -----------------------------

def upload_image():
    global open_file
    global duplicate_open_file
    global encoded
    global downloaded
    open_file = filedialog.askopenfilename(initialdir= os.getcwd(), title = "Select file type", filetypes = [("JPG file", "*.jpg"),("PNG file", "*.png")] )
    if not open_file:
        messagebox.showwarning("CANCELED","NO IMAGE SELECTED")
        del open_file
        return    
    try:
        hidden_data = lsb.reveal(open_file) # check if the image is encoded or not? 
        if hidden_data and (hidden_data.startswith("steg:1:") or hidden_data.startswith("steg:0:")):
            encoded = 1 # for further use in encode image function 
            downloaded = True # for decrypting function 
        else:
            encoded = 0  #same as above 
            downloaded = False
    except Exception:
        encoded = 0
        downloaded = False    
    duplicate_open_file = open_file
    img = Image.open(open_file)
    img = img.resize((250, 150), Image.Resampling.LANCZOS)  # Resize to fit the frame
    img = ctk.CTkImage(light_image=img, dark_image=img, size=(250, 150))
    output_box.delete(1.0,END)
    f1.configure(image=img, text="")  # remove text if any
    f1.image = img  # keep a reference

def download_encoded_image():
    global open_file, password_in_image, key_for_encryption, downloaded

    if 'open_file' not in globals():
        messagebox.showerror("Error", "Please upload an image before downloading.")
        return
    try:
        check_download = lsb.reveal(open_file)  # see if the image is already encoded or not
    except IndexError:
        check_download= None
    if check_download is not None:#and check_download.startswith("steg:0:") or check_download.startswith("steg:1:"):
        messagebox.showerror("AlERT","ALREADY ENCODED \nDOWNLOADING IS DISABLED")
        return
    elif 'encode_info' not in globals():
        messagebox.showerror("Error", "Please encode before downloading.")
        return
    if downloaded == 1 :
        messagebox.showwarning("ALERT", "IMAGE ALREADY DOWNLOADED")
        return
    file_path = filedialog.asksaveasfilename(
        initialfile="Encoded Image.png",
        defaultextension=".png",
        filetypes=[("PNG Image", "*.png*")],
        title="Save Image As"
    )

    if file_path:
        encode_info.save(file_path)
        messagebox.showinfo("ALERT", "IMAGE DOWNLOADED")

        # Clear image and text
        f1.configure(image='')
        f1.image = None
        text1.delete(1.0, END)

        # Save into database
        image_title = os.path.basename(file_path)
        if key_for_encryption is not None:
            add_into_database(image_title, password_in_image, key_for_encryption)
        else:
            add_into_database(image_title, password_in_image, key_for_encryption)

        downloaded = 1
        del open_file
    else:
        messagebox.showinfo("ALERT", "SAVE AS CANCELED")

def encrypt_text():
    global encrypted, cipher, key_for_encryption, check_encrypted, check_decrypt

    if 'open_file' not in globals():
        messagebox.showerror("Error", "Please upload an image before Encrypting.")
        return

    if check_encrypted == 1:
        messagebox.showerror("ALERT", "MESSAGE ALREADY ENCRYPTED")
        return

    if check_decrypt == 1:
        messagebox.showerror("ALERT", "DECRYPTED MESSAGE CANNOT BE ENCRYPTED AGAIN")
        return

    main_text = text1.get(1.0, END)
    if main_text.strip() == "":
        messagebox.showerror("Error", "Please enter a text to encrypt.")
        return

    try:
        message_hidden = lsb.reveal(open_file)
    except IndexError:
        message_hidden = None

    if message_hidden is not None:
        messagebox.showerror("ALERT", "ENCRYPTION DISABLED FOR ENCODED IMAGES")
        return  
    else:
        key_for_encryption = Fernet.generate_key()
        cipher = Fernet(key_for_encryption)
        encrypted = cipher.encrypt(main_text.encode())
        messagebox.showinfo("ALERT", "Your information has been encrypted.")
        text1.delete(1.0, END)
        check_encrypted = 1
        text1.insert(END, encrypted.decode())

def decrypt_text():
    global cipher
    global check_decrypt
    global key_for_encryption

    if 'open_file' not in globals():
        messagebox.showerror("Error", "Please upload an encoded image before decrypting.")
        return

    if output_box.get(1.0, END).strip() == "":
        messagebox.showerror("Error", "No text found for decryption.")
        return

    if check_decrypt == 1:
        messagebox.showerror("ALERT", "Message already decrypted.")
        return

    if encoded == 1 and not downloaded:
        messagebox.showwarning("Warning", "Please download the image before decrypting.")
        return

    required_fernet_key = get_key_by_imagename()
    
    if required_fernet_key is None:
        messagebox.showerror("ALERT", "Download the image first before decrypting.")
        return

    text_box_data = output_box.get(1.0, END).strip()

    if not text_box_data.endswith("=="):
        messagebox.showerror("ALERT", "Data doesn't appear to be encrypted.")
        return

    try:
        cipher = Fernet(required_fernet_key)
        decrypted = cipher.decrypt(text_box_data.encode())
        output_box.delete(1.0, END)
        output_box.insert(END, decrypted.decode())
        check_decrypt = 1
        messagebox.showinfo("ALERT", "Your information has been decrypted.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed\nData Redundancy: {str(e)}") #if 2 images have same name

def encode_image():
    global encode_info, open_file, encrypted, password_in_image, encoded, password
    global selected_option
    password_in_image = password_entry.get()

    # Check if image is uploaded or not 
    if 'open_file' not in globals():
        messagebox.showerror("Error", "Please upload an image before hiding text.")
        return
    # check if user wants the password but hasnt entered one 
    selected_option = encode_option.get()
    if selected_option in ["With Password"] and password_entry.get()=='':
        messagebox.showwarning("ALERT","ENTER PASSWORD BEFORE ENCODING")
        return
    # Check if image is already encoded
    if encoded == 1:
        messagebox.showwarning("ERROR", "IMAGE ALREADY ENCODED")
        return

    # Check: text field empty
    if text1.get(1.0, END).strip() == "":
        messagebox.showwarning("EMPTY BOX", "NO TEXT ENTERED")
        return

    # Check: not already secretly encoded
    try:
        hidden_data = lsb.reveal(open_file)
        if hidden_data and (hidden_data.startswith("steg:1:") or hidden_data.startswith("steg:0:")):
            messagebox.showerror("Error", "This image is already encoded.")
            return
    except Exception:
        pass  # proceed if image is not encoded

    # Validate encoding option
    selected_option = encode_option.get()
    if selected_option not in ["With Password", "Without Password"]:
        messagebox.showerror("Error", "Please select an encryption type before hiding text.")
        return

    # Set flag based on password presence
    flag = "steg:1:" if password_in_image else "steg:0:"
    info = text1.get(1.0, END)

    if encrypted is None:
        flagedinfo = flag + password_in_image + ":" + info
        encode_info = lsb.hide(str(open_file), flagedinfo)
    else:
        flagedinfo = flag + password_in_image + ":" + encrypted.decode()
        encode_info = lsb.hide(str(open_file), flagedinfo)

    encoded = 1
    password = password_entry.get()

    # Hide password entry since it's packed, not placed
    password_entry.pack_forget()
    password_entry.delete(0, END)

    # Reset the dropdown 
    encode_option.set("Without Password")

    messagebox.showinfo("Success", "Image Encoded. Proceed to Download.")

def decode_image():
    global open_file
    global useable_text

    if 'open_file' not in globals():
        messagebox.showerror("Error", "Please upload an encoded image before decoding.")
        return

    try:
        decode_Image_data = lsb.reveal(open_file)
    except IndexError:
        messagebox.showerror("Error", "This image is not encoded.")
        return

    if decode_Image_data is None:
        messagebox.showerror("Error", "No hidden message found in the image.")
        return

    message = decode_Image_data.split(":", 3)

    

    useable_text = message[3]
    current_flag = message[0] + ':' + message[1] + ':'
    match_password = message[2]

    output_box.delete(1.0, END)  # Clear output box first

    if current_flag == 'steg:1:':  # Password-protected
        while True:
            password_for_decoding = simpledialog.askstring("Password Required", "Enter password:")
            if password_for_decoding == match_password:
                messagebox.showinfo("ALERT", "Image Decoded")
                output_box.insert(END, useable_text)
                break
            elif password_for_decoding is None:
                messagebox.showinfo("ALERT", "Image decoding cancelled.")
                break
            else:
                messagebox.showerror("Error", "Incorrect password! Please try again.")
    else:
        messagebox.showinfo("ALERT", "Image decoded. No password used.")
        output_box.insert(END, useable_text)

def get_key_by_imagename():
    global open_file
    image_name=os.path.basename(open_file)
    cursor.execute("SELECT fernet_key FROM Image_Information WHERE name = ?", (image_name,))
    result = cursor.fetchone()
    # Return the result
    if result:
        return result[0]  # This is the fernet_key
    else:
        return None  # Name not found

def add_into_database(image_name,Password_of_image,Fernet_key):
    cursor.execute('''
    insert into Image_information(name,password,fernet_key)
                   values(?,?,?)
    ''',(image_name,Password_of_image,Fernet_key)
    )
    connector.commit()
# ----------------- Frames -----------------
main_frame = ctk.CTkFrame(root, fg_color=FRAME_COLOR, corner_radius=15) # this is the 1st rounded rectangle
main_frame.pack(padx=20, pady=20, fill="both", expand=True)

#title of the app 
title_label = ctk.CTkLabel(main_frame, text="Image Steganography Tool", text_color=TEXT_COLOR, font=("San Francisco", 26, "bold"))
title_label.pack(pady=(10, 5))

#second roudned rectangle 
content = ctk.CTkFrame(main_frame, fg_color=FRAME_COLOR)
content.pack(padx=20, pady=10, fill="both", expand=True)

# initalize left and right side 
left_frame = ctk.CTkFrame(content, fg_color=FRAME_COLOR)
left_frame.pack(side="left", fill="both", expand=True, padx=(0, 10))

right_frame = ctk.CTkFrame(content, fg_color=FRAME_COLOR)
right_frame.pack(side="right", fill="both", expand=True, padx=(10, 0))
#-------------left side of app ----------------------------------------------
# Image preview area
f1 = ctk.CTkLabel(left_frame, text="", width=250, height=150, fg_color=CONTENT_FRAME)
f1.pack(pady=(20, 20))

img_uplaod = shadow_button(left_frame, "📤 Upload Image", command=upload_image)

img_download = shadow_button(left_frame, "📥 Download Image",command=download_encoded_image)

text_label = ctk.CTkLabel(left_frame, text="Secret Message:", text_color=TEXT_COLOR)
text_label.pack(anchor="w", padx=10)

text1 = ctk.CTkTextbox(left_frame, height=120, fg_color=ENTRY_COLOR, text_color=TEXT_COLOR)
text1.pack(padx=10, pady=(0, 10), fill="x")

button_row = ctk.CTkFrame(left_frame, fg_color=FRAME_COLOR)
button_row.pack(padx=10, pady=(10, 5), fill="x")

# Add both buttons with equal space
encrypt_button = small_shadow_button(button_row, "🔒 Encrypt",command=encrypt_text)
encrypt_button.pack(side="left", expand=True, fill="x", padx=(0, 5))

decrypt_button = small_shadow_button(button_row, "🔓 Decrypt",command=decrypt_text)
decrypt_button.pack(side="left", expand=True, fill="x", padx=(5, 0))



# ----------------- Right Panel -----------------
option_label = ctk.CTkLabel(right_frame, text="Encoding Type:", text_color=TEXT_COLOR)
option_label.pack(anchor="w", padx=10, pady=(10, 0))

encode_option = ctk.CTkOptionMenu(right_frame, values=["Without Password", "With Password"],
                                  fg_color=BUTTON_COLOR, text_color="white", button_color=HOVER_COLOR,
                                  command=on_option_change)
encode_option.pack(padx=10, pady=(0, 10), fill="x")
encode_option.set("Without Password")

password_entry = ctk.CTkEntry(right_frame, placeholder_text="Enter Password", fg_color=ENTRY_COLOR,
                              text_color=TEXT_COLOR,show='*')
# Only shown if selected via dropdown

encode_button=shadow_button(right_frame, "🧬 Encode Image",command=encode_image)
decode_button=shadow_button(right_frame, "🔍 Decode Image",command=decode_image)

output_label = ctk.CTkLabel(right_frame, text="Decoded Output:", text_color=TEXT_COLOR)
output_label.pack(anchor="w", padx=10, pady=(15, 2))

output_box = ctk.CTkTextbox(right_frame, height=120, fg_color=ENTRY_COLOR, text_color=TEXT_COLOR)
output_box.pack(padx=10, pady=(0, 10), fill="both", expand=True)

encode_option.set("Without Password")



#--------------RUN ----------------
root.mainloop()