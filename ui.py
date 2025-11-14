import customtkinter as ctk
import crypto_logic  # Import our crypto functions
import traceback # To print detailed errors

class App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # --- Configure the main window ---
        self.title("Crypto Tool - Encryption, Decryption & Hashing")
        self.geometry("850x700") # Set a default size
        self.minsize(700, 550)   # Set a minimum size

        # --- Set up the main grid layout ---
        # Configure the grid to be responsive
        # 3 rows: settings (auto-fit), content (expands), execute (auto-fit)
        # 1 column that spans the whole width
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # --- Create widgets ---
        self._create_settings_frame()
        self._create_content_frame()
        self._create_execute_frame()
        
        # --- Set up event bindings ---
        self._setup_callbacks()
        
        # --- Set initial UI state ---
        # Trigger the callback once to set the correct UI for the default algorithm (AES)
        self._on_algorithm_change(self.algorithm_combobox.get())

    # ------------------------------------------------------------------
    #                   WIDGET CREATION METHODS
    # ------------------------------------------------------------------

    def _create_settings_frame(self):
        """Creates the top frame for algorithm and mode selection."""
        self.settings_frame = ctk.CTkFrame(self, corner_radius=0)
        self.settings_frame.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        self.settings_frame.grid_columnconfigure(1, weight=1)

        # Algorithm Selection
        self.algo_label = ctk.CTkLabel(self.settings_frame, text="Algorithm:")
        self.algo_label.grid(row=0, column=0, padx=(20, 10), pady=10)
        
        self.algorithm_combobox = ctk.CTkComboBox(
            self.settings_frame,
            values=["AES-256 (Symmetric)", "RSA (Asymmetric)", "SHA-256 (Hash)", "MD5 (Hash)"]
        )
        self.algorithm_combobox.grid(row=0, column=1, padx=10, pady=10, sticky="ew")

        # Mode Selection (Encrypt/Decrypt)
        self.mode_label = ctk.CTkLabel(self.settings_frame, text="Mode:")
        self.mode_label.grid(row=0, column=2, padx=(10, 10), pady=10)
        
        self.mode_segmented_button = ctk.CTkSegmentedButton(
            self.settings_frame,
            values=["Encrypt", "Decrypt"]
        )
        self.mode_segmented_button.grid(row=0, column=3, padx=(0, 20), pady=10)
        self.mode_segmented_button.set("Encrypt") # Default value

    def _create_content_frame(self):
        """Creates the central area for text boxes and key inputs."""
        self.content_frame = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.content_frame.grid(row=1, column=0, sticky="nsew", padx=10, pady=0)
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1) # Input box
        self.content_frame.grid_rowconfigure(1, weight=1) # Output box
        self.content_frame.grid_rowconfigure(2, weight=0) # Key frames (auto-size)

        # --- Input & Output Textboxes (in their own frames) ---
        self._create_io_frames()
        
        # --- Key Input Frames (will be shown/hidden) ---
        self._create_aes_key_frame()
        self._create_rsa_key_frame()
        
    def _create_io_frames(self):
        """Creates the Input and Output text areas."""
        # Input Frame
        self.input_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.input_frame.grid(row=0, column=0, sticky="nsew", pady=(0, 5))
        self.input_frame.grid_columnconfigure(0, weight=1)
        self.input_frame.grid_rowconfigure(1, weight=1)
        
        self.input_label = ctk.CTkLabel(self.input_frame, text="Input (Plaintext / Ciphertext):", font=ctk.CTkFont(weight="bold"))
        self.input_label.grid(row=0, column=0, sticky="w", padx=5)
        
        self.input_textbox = ctk.CTkTextbox(self.input_frame, wrap="word", border_width=0)
        self.input_textbox.grid(row=1, column=0, sticky="nsew")

        # Output Frame
        self.output_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.output_frame.grid(row=1, column=0, sticky="nsew", pady=(5, 10))
        self.output_frame.grid_columnconfigure(0, weight=1)
        self.output_frame.grid_rowconfigure(1, weight=1)

        self.output_label_frame = ctk.CTkFrame(self.output_frame, fg_color="transparent")
        self.output_label_frame.grid(row=0, column=0, sticky="ew")

        self.output_label = ctk.CTkLabel(self.output_label_frame, text="Output (Result):", font=ctk.CTkFont(weight="bold"))
        self.output_label.grid(row=0, column=0, sticky="w", padx=5)

        self.copy_button = ctk.CTkButton(self.output_label_frame, text="Copy to Clipboard", width=150, command=self._on_copy_to_clipboard)
        self.copy_button.grid(row=0, column=1, sticky="e", padx=5)
        
        self.output_textbox = ctk.CTkTextbox(self.output_frame, wrap="word", state="disabled", border_width=0, fg_color_disabled="gray14")
        self.output_textbox.grid(row=1, column=0, sticky="nsew")

    def _create_aes_key_frame(self):
        """Creates the input frame for the AES password."""
        self.aes_key_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.aes_key_frame.grid(row=2, column=0, sticky="ew") # Placed at row 2
        self.aes_key_frame.grid_columnconfigure(1, weight=1)

        self.aes_key_label = ctk.CTkLabel(self.aes_key_frame, text="AES Password:")
        self.aes_key_label.grid(row=0, column=0, padx=(5, 10), pady=10)
        
        self.aes_key_entry = ctk.CTkEntry(self.aes_key_frame, show="*")
        self.aes_key_entry.grid(row=0, column=1, sticky="ew", padx=(0, 5), pady=10)

    def _create_rsa_key_frame(self):
        """Creates the text boxes for RSA keys and the generate button."""
        self.rsa_key_frame = ctk.CTkFrame(self.content_frame, fg_color="transparent")
        self.rsa_key_frame.grid(row=2, column=0, sticky="ew") # Placed at row 2
        self.rsa_key_frame.grid_columnconfigure(0, weight=1)
        self.rsa_key_frame.grid_columnconfigure(1, weight=1)

        # Public Key
        self.rsa_public_label = ctk.CTkLabel(self.rsa_key_frame, text="RSA Public Key:")
        self.rsa_public_label.grid(row=0, column=0, padx=5, pady=(5,0), sticky="w")
        self.rsa_public_key_box = ctk.CTkTextbox(self.rsa_key_frame, height=100, wrap="word")
        self.rsa_public_key_box.grid(row=1, column=0, sticky="nsew", padx=(5, 2), pady=5)

        # Private Key
        self.rsa_private_label = ctk.CTkLabel(self.rsa_key_frame, text="RSA Private Key:")
        self.rsa_private_label.grid(row=0, column=1, padx=5, pady=(5,0), sticky="w")
        self.rsa_private_key_box = ctk.CTkTextbox(self.rsa_key_frame, height=100, wrap="word")
        self.rsa_private_key_box.grid(row=1, column=1, sticky="nsew", padx=(2, 5), pady=5)

        # Generate Button
        self.rsa_generate_button = ctk.CTkButton(self.rsa_key_frame, text="Generate New Key Pair", command=self._on_generate_rsa_keys)
        self.rsa_generate_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10)

        # Hide frame initially
        self.rsa_key_frame.grid_remove() 

    def _create_execute_frame(self):
        """Creates the bottom frame with the 'Execute' button."""
        self.execute_frame = ctk.CTkFrame(self, corner_radius=0)
        self.execute_frame.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        self.execute_frame.grid_columnconfigure(0, weight=1)
        
        self.execute_button = ctk.CTkButton(
            self.execute_frame,
            text="Execute",
            height=40,
            font=ctk.CTkFont(size=16, weight="bold"),
            command=self._on_execute_click
        )
        self.execute_button.grid(row=0, column=0, sticky="ew", padx=20, pady=10)
        
    # ------------------------------------------------------------------
    #                   CALLBACK & LOGIC METHODS
    # ------------------------------------------------------------------

    def _setup_callbacks(self):
        """Binds widget events to their handler functions."""
        # When the combobox value changes, call _on_algorithm_change
        self.algorithm_combobox.configure(command=self._on_algorithm_change)
        
    def _on_algorithm_change(self, choice: str):
        """Shows/hides UI elements based on the selected algorithm."""
        
        # Default state: show mode button, show AES key, hide RSA keys
        self.mode_segmented_button.grid()
        self.mode_label.grid()
        self.aes_key_frame.grid()
        self.rsa_key_frame.grid_remove() # Use grid_remove() to hide
        self.execute_button.configure(text="Execute") # Reset button text

        if choice.startswith("AES"):
            # This is the default state, already set.
            self.input_label.configure(text="Input (Plaintext / Base64 Ciphertext):")
            pass
            
        elif choice.startswith("RSA"):
            self.aes_key_frame.grid_remove()
            self.rsa_key_frame.grid()
            self.input_label.configure(text="Input (Plaintext / Base64 Ciphertext):")
            
        elif choice.endswith("(Hash)"):
            self.mode_segmented_button.grid_remove()
            self.mode_label.grid_remove()
            self.aes_key_frame.grid_remove()
            self.rsa_key_frame.grid_remove()
            self.input_label.configure(text="Input (Text to Hash):")
            self.execute_button.configure(text=f"Generate {choice.split()[0]} Hash")

    def _update_output_textbox(self, text: str):
        """Helper function to safely update the read-only output box."""
        self.output_textbox.configure(state="normal") # Enable
        self.output_textbox.delete("1.0", "end")       # Clear
        self.output_textbox.insert("1.0", text)        # Insert
        self.output_textbox.configure(state="disabled") # Disable

    def _on_generate_rsa_keys(self):
        """Calls crypto_logic to generate keys and puts them in the UI."""
        self._update_output_textbox("Generating RSA key pair...")
        try:
            public_key, private_key = crypto_logic.generate_rsa_keys()
            
            self.rsa_public_key_box.delete("1.0", "end")
            self.rsa_public_key_box.insert("1.0", public_key)
            
            self.rsa_private_key_box.delete("1.0", "end")
            self.rsa_private_key_box.insert("1.0", private_key)
            
            self._update_output_textbox("Successfully generated new RSA key pair.")
        except Exception as e:
            self._update_output_textbox(f"Error generating keys:\n\n{e}\n\n{traceback.format_exc()}")
            
    def _on_copy_to_clipboard(self):
        """Copies the content of the output textbox to the clipboard."""
        try:
            text_to_copy = self.output_textbox.get("1.0", "end-1c") # Get all text
            if text_to_copy:
                self.clipboard_clear()
                self.clipboard_append(text_to_copy)
                print("Copied to clipboard.") # For debugging
            else:
                print("Nothing to copy.")
        except Exception as e:
            print(f"Clipboard error: {e}") # Handle clipboard errors gracefully
            
    def _on_execute_click(self):
        """
        The main "controller" function.
        It reads all UI fields and calls the correct crypto_logic function.
        """
        try:
            # Get values from UI
            algorithm = self.algorithm_combobox.get()
            mode = self.mode_segmented_button.get()
            input_text = self.input_textbox.get("1.0", "end-1c")
            
            result = ""

            # --- Hashing Logic ---
            if "SHA-256" in algorithm:
                result = crypto_logic.hash_sha256(input_text)
            elif "MD5" in algorithm:
                result = crypto_logic.hash_md5(input_text)

            # --- AES Logic ---
            elif "AES" in algorithm:
                password = self.aes_key_entry.get()
                if not password:
                    result = "Error: Please enter an AES password."
                elif mode == "Encrypt":
                    result = crypto_logic.encrypt_aes(input_text, password)
                elif mode == "Decrypt":
                    result = crypto_logic.decrypt_aes(input_text, password)

            # --- RSA Logic ---
            elif "RSA" in algorithm:
                public_key = self.rsa_public_key_box.get("1.0", "end-1c")
                private_key = self.rsa_private_key_box.get("1.0", "end-1c")
                
                if mode == "Encrypt":
                    if not public_key:
                        result = "Error: Please provide a Public Key to encrypt."
                    else:
                        result = crypto_logic.encrypt_rsa(input_text, public_key)
                elif mode == "Decrypt":
                    if not private_key:
                        result = "Error: Please provide a Private Key to decrypt."
                    else:
                        result = crypto_logic.decrypt_rsa(input_text, private_key)
            
            # Update the output box with the result
            self._update_output_textbox(result)

        except Exception as e:
            # Show a detailed error in the output box
            error_message = f"An unexpected error occurred:\n\n{e}\n\n{traceback.format_exc()}"
            self._update_output_textbox(error_message)

# This allows you to run ui.py directly for testing/development if you want
if __name__ == "__main__":
    ctk.set_appearance_mode("Dark")
    ctk.set_default_color_theme("blue")
    app = App()
    app.mainloop()