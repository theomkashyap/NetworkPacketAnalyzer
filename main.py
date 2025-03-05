import tkinter as tk
import subprocess  # For opening other Tkinter files (windows)

# Function to open the first Tkinter window (Packet Sniffer)
def open_file_1():
    subprocess.run(["python", "sniffer.py"])

# Function to open the second Tkinter window (Packet Analyzer)
def open_file_2():
    subprocess.run(["python", "analyzer.py"])

# Function to close the app
def close_app():
    root.quit()

# Creating the main window (Landing Page)
root = tk.Tk()
root.title("Landing Page")

# Set the window to full screen
root.attributes("-fullscreen", True)

# Create Close App Button with Text (No icon, using text "X")
close_button = tk.Button(root, text="X", command=close_app, font=("Arial", 16, "bold"), bg="red", fg="white", relief="flat", height=1, width=2)
close_button.pack(side=tk.TOP, anchor='ne', padx=20, pady=10)  # Position it at the top-right

# Add buttons to the landing page with uniform size and different colors
button_1 = tk.Button(root, text="Sniffer", command=open_file_1, width=15, height=2, bg='skyblue', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
button_1.pack(pady=10)

button_2 = tk.Button(root, text="Analyzer", command=open_file_2, width=15, height=2, bg='lightgreen', fg='black', font=('Arial', 12, 'bold'), relief='flat', borderwidth=2)
button_2.pack(pady=10)

# Start the Tkinter main loop
root.mainloop()
