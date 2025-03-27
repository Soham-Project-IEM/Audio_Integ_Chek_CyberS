import tkinter as tk
from tkinter import filedialog, messagebox
import hashlib

def compute_hash(filepath):
    """Compute SHA-256 hash of the given file."""
    try:
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        messagebox.showerror("Error", f"Error computing hash: {e}")
        return None

def select_file():
    """Open file dialog to select an audio file."""
    file_path = filedialog.askopenfilename(title="Select an Audio File", filetypes=[("Audio Files", "*.mp3;*.wav;*.flac")])
    if file_path:
        entry_file_path.delete(0, tk.END)
        entry_file_path.insert(0, file_path)

def generate_hash():
    """Generate and display the file hash."""
    file_path = entry_file_path.get()
    if not file_path:
        messagebox.showwarning("Warning", "Please select a file first.")
        return
    
    file_hash = compute_hash(file_path)
    if file_hash:
        entry_hash.delete(0, tk.END)
        entry_hash.insert(0, file_hash)

def save_hash():
    """Save the generated hash to a text file."""
    file_hash = entry_hash.get()
    if not file_hash:
        messagebox.showwarning("Warning", "Generate a hash first before saving.")
        return

    save_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if save_path:
        try:
            with open(save_path, "w") as f:
                f.write(file_hash)
            messagebox.showinfo("Success", "Hash saved successfully.")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving hash: {e}")

# GUI Setup
root = tk.Tk()
root.title("Audio Integrity Checker")
root.geometry("500x300")

# File Selection
tk.Label(root, text="Select Audio File:").pack(pady=5)
entry_file_path = tk.Entry(root, width=50)
entry_file_path.pack(pady=5)
tk.Button(root, text="Browse", command=select_file).pack(pady=5)

# Hash Display
tk.Label(root, text="Generated Hash:").pack(pady=5)
entry_hash = tk.Entry(root, width=50)
entry_hash.pack(pady=5)

# Buttons
tk.Button(root, text="Generate Hash", command=generate_hash).pack(pady=5)
tk.Button(root, text="Save Hash", command=save_hash).pack(pady=5)

# Run GUI
root.mainloop()
