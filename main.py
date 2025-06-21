import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image

SUPPORTED_FORMATS = [".png", ".bmp"]
SECRET_END = "<<<END>>>"

def text_to_bits(text):
    return ''.join(f'{ord(c):08b}' for c in text)

def bits_to_text(bits):
    chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
    return ''.join(chr(int(b, 2)) for b in chars)

def hide_message(image_path, message, output_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    message += SECRET_END
    binary = text_to_bits(message)
    pixels = list(img.getdata())

    if len(binary) > len(pixels) * 3:
        raise ValueError("Message is too long for this image.")

    new_pixels = []
    bit_idx = 0

    for pixel in pixels:
        r, g, b = pixel
        if bit_idx < len(binary):
            r = (r & ~1) | int(binary[bit_idx])
            bit_idx += 1
        if bit_idx < len(binary):
            g = (g & ~1) | int(binary[bit_idx])
            bit_idx += 1
        if bit_idx < len(binary):
            b = (b & ~1) | int(binary[bit_idx])
            bit_idx += 1
        new_pixels.append((r, g, b))

    img.putdata(new_pixels)
    img.save(output_path)

def show_message(image_path):
    img = Image.open(image_path)
    if img.mode != 'RGB':
        img = img.convert('RGB')

    pixels = list(img.getdata())
    bits = ''

    for pixel in pixels:
        for channel in pixel:
            bits += str(channel & 1)

    message = bits_to_text(bits)
    return message.split(SECRET_END)[0]

def start_app():
    def pick_image():
        path = filedialog.askopenfilename(filetypes=[("Image files", "*.png *.bmp")])
        if path:
            img_path.set(path)

    def embed():
        path = img_path.get()
        msg = msg_box.get("1.0", tk.END).strip()
        if not path or not msg:
            messagebox.showerror("Error", "Choose an image and write a message.")
            return
        out = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG", "*.png")])
        if out:
            try:
                hide_message(path, msg, out)
                messagebox.showinfo("Done", "Message hidden and saved.")
            except Exception as e:
                messagebox.showerror("Error", str(e))

    def extract():
        path = img_path.get()
        if not path:
            messagebox.showerror("Error", "Choose an image first.")
            return
        try:
            msg = show_message(path)
            msg_box.delete("1.0", tk.END)
            msg_box.insert(tk.END, msg)
            messagebox.showinfo("Done", "Message shown below.")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    win = tk.Tk()
    win.title("Simple Steganography Tool")
    win.geometry("500x400")

    img_path = tk.StringVar()

    tk.Label(win, text="Image File").pack()
    tk.Entry(win, textvariable=img_path, width=50).pack(pady=2)
    tk.Button(win, text="Browse", command=pick_image).pack(pady=2)

    tk.Label(win, text="Message").pack()
    msg_box = tk.Text(win, width=60, height=10)
    msg_box.pack(pady=2)

    tk.Button(win, text="Hide Message", command=embed).pack(pady=5)
    tk.Button(win, text="Show Message", command=extract).pack(pady=5)

    win.mainloop()

if __name__ == '__main__':
    start_app()
