import ui  # Import the ui.py file
import customtkinter as ctk

if __name__ == "__main__":
    # Set the initial appearance mode and color theme for the entire app.
    # This is done here before the App window is created.
    ctk.set_appearance_mode("Dark")  # Options: "Light", "Dark", "System"
    ctk.set_default_color_theme("blue")  # Options: "blue", "green", "dark-blue"
    
    # Create the main application window from our ui.py file
    app = ui.App()  
    
    # Start the application's main event loop
    app.mainloop()