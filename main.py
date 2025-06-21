from interface import start_app

if __name__ == '__main__':
    start_app()

# config.py
SUPPORTED_FORMATS = [".png", ".bmp"]
SECRET_END = "<<<END>>>"

# embedder.py
from PIL import Image
import stepic
import config

def hide_message(image_path, message, output_path):
    img = Image.open(image_path)
    message += config.SECRET_END
    new_img = stepic.encode(img, message.encode())
    new_img.save(output_path)

# extractor.py
from PIL import Image
import stepic
import config

def show_message(image_path):
    img = Image.open(image_path)
    message = stepic.decode(img).decode()
    return message.split(config.SECRET_END)[0]

# utils.py
def is_valid_file(filename):
    return filename.lower().endswith((".png", ".bmp"))

# interface.py
import tkinter as tk
from tkinter import filedialog, messagebox
from embedder import hide_message
from extractor import show_message

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
            hide_message(path, msg, out)
            messagebox.showinfo("Done", "Message hidden and saved.")

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
