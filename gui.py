import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff

class NetworkAnalyzerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Traffic Analyzer")

        self.start_button = tk.Button(root, text="Start Capture", command=self.start_capture)
        self.start_button.pack()

        self.stop_button = tk.Button(root, text="Stop Capture", command=self.stop_capture)
        self.stop_button.pack()

        self.status_label = tk.Label(root, text="Status: Idle")
        self.status_label.pack()

        self.capturing = False

    def start_capture(self):
        self.capturing = True
        self.status_label.config(text="Status: Capturing")
        sniff(prn=self.packet_callback, store=False, stop_filter=self.stop_filter)

    def stop_capture(self):
        self.capturing = False
        self.status_label.config(text="Status: Stopped")
        messagebox.showinfo("Info", "Capture stopped")

    def packet_callback(self, packet):
        print(packet.summary())

    def stop_filter(self, packet):
        return not self.capturing

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzerApp(root)
    root.mainloop()