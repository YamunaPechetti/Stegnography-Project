import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from PIL import Image
import base64
import os
from cryptography.fernet import Fernet, InvalidToken

SUPPORTED_FORMATS = [".png", ".bmp"]
SECRET_END = "<<<END>>>"

# Helper: Convert text to bits
def text_to_bits(text):
    return ''.join(f'{ord(c):08b}' for c in text)

# Helper: Convert bits to text
def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

# Encrypt a message with password
def encrypt_message(message, password):
    key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    return Fernet(key).encrypt(message.encode()).decode()

# Decrypt a message with password
def decrypt_message(message, password):
    key = base64.urlsafe_b64encode(password.ljust(32)[:32].encode())
    return Fernet(key).decrypt(message.encode()).decode()

# Hide message into image
def hide_message(image_path, message, output_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    binary = text_to_bits(message + SECRET_END)
    pixels = list(img.getdata())

    if len(binary) > len(pixels) * 3:
        raise ValueError("Message too long for image.")

    new_pixels = []
    bit_idx = 0
    for r, g, b in pixels:
        if bit_idx < len(binary): r = (r & ~1) | int(binary[bit_idx]); bit_idx += 1
        if bit_idx < len(binary): g = (g & ~1) | int(binary[bit_idx]); bit_idx += 1
        if bit_idx < len(binary): b = (b & ~1) | int(binary[bit_idx]); bit_idx += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)

# Extract message from image
def show_message(image_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    bits = ''
    for pixel in img.getdata():
        for color in pixel:
            bits += str(color & 1)

    try:
        message = bits_to_text(bits)
        return message.split(SECRET_END)[0]
    except Exception:
        return ""

# GUI application for steganography
def start_app():
    def pick_image():
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if path:
            img_path.set(path)

    def embed_text():
        path = img_path.get()
        msg = msg_box.get("1.0", tk.END).strip()
        if not path or not msg:
            messagebox.showerror("Error", "Select image and enter message.")
            return
        password = simpledialog.askstring("Password", "Enter password (optional):", show='*')
        if password:
            try:
                msg = encrypt_message(msg, password)
            except Exception as e:
                messagebox.showerror("Encryption Error", str(e))
                return

        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if out:
            try:
                hide_message(path, msg, out)
                messagebox.showinfo("Done", "Message embedded and saved.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def extract_text():
        path = img_path.get()
        if not path:
            messagebox.showerror("Error", "Select an image first.")
            return
        try:
            extracted = show_message(path)
            if not extracted:
                raise Exception("No message found.")
            try:
                _ = decrypt_message(extracted, 'test')  # probe test
                password_required = True
            except InvalidToken:
                password_required = True
            except:
                password_required = False

            if password_required:
                password = simpledialog.askstring("Password", "Enter password:", show='*')
                try:
                    extracted = decrypt_message(extracted, password)
                except InvalidToken:
                    messagebox.showerror("Error", "Incorrect password or not encrypted properly.")
                    return

            msg_box.delete("1.0", tk.END)
            msg_box.insert(tk.END, extracted)
            messagebox.showinfo("Success", "Message extracted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def embed_plain():
        path = img_path.get()
        msg = msg_box.get("1.0", tk.END).strip()
        if not path or not msg:
            messagebox.showerror("Error", "Select image and enter message.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if out:
            try:
                hide_message(path, msg, out)
                messagebox.showinfo("Done", "Message embedded without password.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def extract_plain():
        path = img_path.get()
        if not path:
            messagebox.showerror("Error", "Select image first.")
            return
        try:
            extracted = show_message(path)
            if not extracted:
                raise Exception("No message found.")
            msg_box.delete("1.0", tk.END)
            msg_box.insert(tk.END, extracted)
            messagebox.showinfo("Success", "Message extracted.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def embed_file():
        path = img_path.get()
        file_path = filedialog.askopenfilename(title="Select file to hide")
        if not path or not file_path:
            messagebox.showerror("Error", "Select both image and file.")
            return
        with open(file_path, "rb") as f:
            data = base64.b64encode(f.read()).decode()
        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if out:
            try:
                hide_message(path, data, out)
                messagebox.showinfo("Done", "File hidden inside image.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def extract_file():
        path = img_path.get()
        if not path:
            messagebox.showerror("Error", "Select image first.")
            return
        try:
            extracted = show_message(path)
            out_path = filedialog.asksaveasfilename(title="Save extracted file")
            if out_path:
                with open(out_path, "wb") as f:
                    f.write(base64.b64decode(extracted))
                messagebox.showinfo("Done", "File extracted and saved.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    win = tk.Tk()
    win.title("Steganography Tool - Text & File Hider with Encryption")
    win.geometry("650x600")
    win.configure(bg="#2e2e2e")

    img_path = tk.StringVar()

    tk.Label(win, text="Image File", fg="white", bg="#2e2e2e").pack(pady=5)
    tk.Entry(win, textvariable=img_path, width=70).pack(pady=2)
    tk.Button(win, text="Browse", command=pick_image).pack(pady=2)

    tk.Label(win, text="Message Box", fg="white", bg="#2e2e2e").pack(pady=5)
    msg_box = tk.Text(win, width=80, height=10)
    msg_box.pack(pady=2)

    tk.Button(win, text="Hide Text with Password", command=embed_text).pack(pady=5)
    tk.Button(win, text="Extract Text with Password", command=extract_text).pack(pady=5)

    tk.Button(win, text="Hide Plain Text", command=embed_plain).pack(pady=5)
    tk.Button(win, text="Extract Plain Text", command=extract_plain).pack(pady=5)

    tk.Button(win, text="Hide a File in Image", command=embed_file).pack(pady=5)
    tk.Button(win, text="Extract Hidden File", command=extract_file).pack(pady=5)

    win.mainloop()

if __name__ == '__main__':
    start_app()
