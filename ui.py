import customtkinter as ctk

# Note: The appearance mode and theme are set in app.py
# before this class is even instantiated.

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configure the main window ---
        self.title("Crypto Tool - Encryption & Decryption")
        self.geometry("800x600") # Set a default size
        self.minsize(600, 400)   # Set a minimum size

        # --- Create a placeholder label ---
        # This is just to show the window is working.
        # We will replace this with our full UI layout.
        self.label = ctk.CTkLabel(
            self,
            text="Crypto Tool UI Scaffold - Ready to build!",
            font=ctk.CTkFont(size=20, weight="bold")
        )
        self.label.pack(pady=40, padx=40, expand=True)

# This allows you to run ui.py directly for testing/development if you want
if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = App()
    app.mainloop()