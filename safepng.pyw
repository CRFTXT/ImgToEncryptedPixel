import tkinter
import customtkinter
from tkinter import filedialog
import threading
import os
import zlib
import base64
from PIL import Image, PngImagePlugin

# --- Cryptography components ---
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# --- Constants ---
METADATA_KEYWORD = "StegoSafeData"

# --- Backend Logic (modified to communicate with GUI) ---

def derive_key(password: str, salt: bytes) -> bytes:
    """Derives a Fernet-compatible key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
        backend=default_backend()
    )
    raw_key = kdf.derive(password.encode())
    return base64.urlsafe_b64encode(raw_key)

def hide_data_logic(input_path, output_path, password, pixel_level, status_callback):
    """The core logic for hiding data."""
    try:
        status_callback("Opening original image...")
        original_image = Image.open(input_path).convert('RGBA')
        width, height = original_image.size

        status_callback("Step 1/5: Creating pixelated base layer...")
        small_image = original_image.resize((width // pixel_level, height // pixel_level), resample=Image.NEAREST)
        base_layer = small_image.resize(original_image.size, Image.NEAREST)

        status_callback("Step 2/5: Calculating details layer...")
        original_pixels = original_image.tobytes()
        base_pixels = base_layer.tobytes()
        details_data = bytes([p1 ^ p2 for p1, p2 in zip(original_pixels, base_pixels)])

        status_callback("Step 3/5: Compressing and encrypting details...")
        compressed_details = zlib.compress(details_data, level=9)
        salt = os.urandom(16)
        key = derive_key(password, salt)
        fernet = Fernet(key)
        encrypted_data = fernet.encrypt(compressed_details)
        payload_bytes = salt + encrypted_data
        payload_text = base64.b64encode(payload_bytes).decode('utf-8')

        status_callback("Step 4/5: Building new PNG with secret metadata...")
        png_info = PngImagePlugin.PngInfo()
        png_info.add_text(METADATA_KEYWORD, payload_text)

        status_callback("Step 5/5: Saving final image...")
        base_layer.convert('RGBA').save(output_path, 'PNG', pnginfo=png_info)
        
        status_callback(f"Success! Hidden image saved to {os.path.basename(output_path)}", "green")
    except Exception as e:
        status_callback(f"Error: {e}", "red")

def reveal_data_logic(input_path, output_path, password, status_callback):
    """The core logic for revealing data."""
    try:
        status_callback("Opening secure PNG...")
        stego_image = Image.open(input_path)

        status_callback("Step 1/4: Searching for secret metadata...")
        payload_text = stego_image.text.get(METADATA_KEYWORD)

        if payload_text is None:
            status_callback("Error: No secret data found in this PNG file.", "red")
            return

        status_callback("Step 2/4: Decrypting details layer...")
        payload_bytes = base64.b64decode(payload_text)
        salt = payload_bytes[:16]
        encrypted_data = payload_bytes[16:]
        key = derive_key(password, salt)
        fernet = Fernet(key)
        decrypted_data = fernet.decrypt(encrypted_data)
        details_data = zlib.decompress(decrypted_data)

        status_callback("Step 3/4: Loading pixelated base layer...")
        base_layer = stego_image.convert('RGBA')
        base_pixels = base_layer.tobytes()

        status_callback("Step 4/4: Reconstructing original image...")
        if len(details_data) != len(base_pixels):
            status_callback("Error: Data size mismatch. File may be corrupt.", "red")
            return

        reconstructed_pixels = bytes([p1 ^ p2 for p1, p2 in zip(base_pixels, details_data)])
        reconstructed_image = Image.frombytes('RGBA', base_layer.size, reconstructed_pixels)
        reconstructed_image.save(output_path, 'PNG')

        status_callback(f"Success! Revealed image saved as {os.path.basename(output_path)}", "green")
    except Exception as e:
        status_callback(f"Error: Wrong password or corrupted file.", "red")

# --- GUI Application Class ---

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # Window setup
        self.title("Safe")
        self.geometry("500x400")
        self.resizable(False, False)
        customtkinter.set_appearance_mode("System")
        customtkinter.set_default_color_theme("blue")

        # Class variables
        self.hide_input_path = ""
        self.reveal_input_path = ""

        # Main container
        self.tabview = customtkinter.CTkTabview(self, width=480)
        self.tabview.pack(padx=10, pady=10)
        self.tabview.add("Hide Image")
        self.tabview.add("Reveal Image")
        
        # --- Hide Tab Widgets ---
        self.hide_tab = self.tabview.tab("Hide Image")
        
        self.hide_input_button = customtkinter.CTkButton(self.hide_tab, text="Select Original Image", command=self.select_hide_input)
        self.hide_input_button.pack(pady=10)
        self.hide_input_label = customtkinter.CTkLabel(self.hide_tab, text="No file selected")
        self.hide_input_label.pack(pady=5)

        self.slider_frame = customtkinter.CTkFrame(self.hide_tab, fg_color="transparent")
        self.slider_frame.pack(pady=10)
        self.slider_label = customtkinter.CTkLabel(self.slider_frame, text="Pixelation Level:")
        self.slider_label.pack(side="left", padx=5)
        self.slider = customtkinter.CTkSlider(self.slider_frame, from_=4, to=64, number_of_steps=15, command=self.update_slider_label)
        self.slider.set(16)
        self.slider.pack(side="left")
        self.slider_value_label = customtkinter.CTkLabel(self.slider_frame, text="16")
        self.slider_value_label.pack(side="left", padx=5)

        self.hide_password_entry = customtkinter.CTkEntry(self.hide_tab, placeholder_text="Enter Password", show="*")
        self.hide_password_entry.pack(pady=10)

        self.hide_button = customtkinter.CTkButton(self.hide_tab, text="Hide Image", command=self.start_hide_thread)
        self.hide_button.pack(pady=20, ipady=10)

        # --- Reveal Tab Widgets ---
        self.reveal_tab = self.tabview.tab("Reveal Image")
        
        self.reveal_input_button = customtkinter.CTkButton(self.reveal_tab, text="Select Secure PNG", command=self.select_reveal_input)
        self.reveal_input_button.pack(pady=10)
        self.reveal_input_label = customtkinter.CTkLabel(self.reveal_tab, text="No file selected")
        self.reveal_input_label.pack(pady=5)
        
        self.reveal_password_entry = customtkinter.CTkEntry(self.reveal_tab, placeholder_text="Enter Password", show="*")
        self.reveal_password_entry.pack(pady=10)
        
        self.reveal_button = customtkinter.CTkButton(self.reveal_tab, text="Reveal Image", command=self.start_reveal_thread)
        self.reveal_button.pack(pady=20, ipady=10)

        # --- Status Bar ---
        self.status_label = customtkinter.CTkLabel(self, text="made with ai", text_color="gray")
        self.status_label.pack(side="bottom", fill="x", padx=10, pady=5)

    # --- GUI Methods ---

    def update_status(self, message, color="gray"):
        self.status_label.configure(text=message, text_color=color)

    def update_slider_label(self, value):
        self.slider_value_label.configure(text=f"{int(value)}")
        
    def select_hide_input(self):
        path = filedialog.askopenfilename(title="Select original image", filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")])
        if path:
            self.hide_input_path = path
            self.hide_input_label.configure(text=os.path.basename(path))

    def select_reveal_input(self):
        path = filedialog.askopenfilename(title="Select secure PNG", filetypes=[("PNG Files", "*.png")])
        if path:
            self.reveal_input_path = path
            self.reveal_input_label.configure(text=os.path.basename(path))

    def start_hide_thread(self):
        input_path = self.hide_input_path
        password = self.hide_password_entry.get()
        pixel_level = int(self.slider.get())

        if not input_path:
            self.update_status("Error: Please select an input image.", "red")
            return
        if not password:
            self.update_status("Error: Please enter a password.", "red")
            return
            
        output_path = filedialog.asksaveasfilename(title="Save Secure PNG as...", defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if not output_path:
            self.update_status("Hide operation cancelled.", "gray")
            return

        # Run the backend logic in a separate thread to keep the GUI responsive
        thread = threading.Thread(target=hide_data_logic, args=(input_path, output_path, password, pixel_level, self.update_status))
        thread.daemon = True
        thread.start()

    def start_reveal_thread(self):
        input_path = self.reveal_input_path
        password = self.reveal_password_entry.get()

        if not input_path:
            self.update_status("Error: Please select a secure PNG to reveal.", "red")
            return
        if not password:
            self.update_status("Error: Please enter a password.", "red")
            return

        output_path = filedialog.asksaveasfilename(title="Save Revealed Image as...", defaultextension=".png", filetypes=[("PNG Files", "*.png")])
        if not output_path:
            self.update_status("Reveal operation cancelled.", "gray")
            return

        # Run the backend logic in a separate thread
        thread = threading.Thread(target=reveal_data_logic, args=(input_path, output_path, password, self.update_status))
        thread.daemon = True
        thread.start()

if __name__ == "__main__":
    app = App()
    app.mainloop()