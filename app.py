import ui  # Import the ui.py file
import customtkinter as ctk

if __name__ == "__main__":
    # Set the initial appearance mode
    # This is a good place to do it before the window is created
    ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
    ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"
    
    app = ui.App()  # Create an instance of the App class from ui.py
    app.mainloop()  # Start the main event loop