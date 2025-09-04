#!/usr/bin/env python3
"""
Professional Mesh Network Desktop Application
Modern UI with enhanced features and better user experience
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import tkinter.font as tkFont
from typing import Optional, Dict, List
import threading
import time
import json
import os
from datetime import datetime
from pathlib import Path

# Import the mesh network core (assuming it's in the same directory)
# from mesh_network import MeshNode, PeerInfo, MeshNetworkFactory

class ModernStyle:
    """Modern UI styling constants"""
    
    # Colors
    PRIMARY_COLOR = "#2E3440"      # Dark blue-gray
    SECONDARY_COLOR = "#3B4252"    # Lighter blue-gray  
    ACCENT_COLOR = "#5E81AC"       # Blue accent
    SUCCESS_COLOR = "#A3BE8C"      # Green
    WARNING_COLOR = "#EBCB8B"      # Yellow
    ERROR_COLOR = "#BF616A"        # Red
    TEXT_COLOR = "#ECEFF4"         # Light text
    BG_COLOR = "#2E3440"           # Background
    CARD_COLOR = "#3B4252"         # Card background
    
    # Fonts
    TITLE_FONT = ("Segoe UI", 16, "bold")
    HEADER_FONT = ("Segoe UI", 12, "bold") 
    BODY_FONT = ("Segoe UI", 10)
    MONO_FONT = ("Consolas", 9)


class ConnectionDialog:
    """Dialog for initial connection setup"""
    
    def __init__(self, parent):
        self.result = None
        self.dialog = tk.Toplevel(parent)
        self.dialog.title("Connect to Mesh Network")
        self.dialog.geometry("400x300")
        self.dialog.transient(parent)
        self.dialog.grab_set()
        self.dialog.resizable(False, False)
        
        # Center the dialog
        self.dialog.geometry("+%d+%d" % (parent.winfo_rootx() + 50, parent.winfo_rooty() + 50))
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the connection dialog UI"""
        main_frame = ttk.Frame(self.dialog, padding="20")
        main_frame.pack(fill="both", expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Join Mesh Network", 
                               font=ModernStyle.TITLE_FONT)
        title_label.pack(pady=(0, 20))
        
        # Node name
        ttk.Label(main_frame, text="Your Display Name:").pack(anchor="w")
        self.name_var = tk.StringVar(value=f"User-{os.getlogin()}")
        name_entry = ttk.Entry(main_frame, textvariable=self.name_var, font=ModernStyle.BODY_FONT)
        name_entry.pack(fill="x", pady=(5, 15))
        
        # Port
        ttk.Label(main_frame, text="Port Number:").pack(anchor="w")
        self.port_var = tk.StringVar(value="9999")
        port_entry = ttk.Entry(main_frame, textvariable=self.port_var, font=ModernStyle.BODY_FONT)
        port_entry.pack(fill="x", pady=(5, 15))
        
        # Password (optional)
        ttk.Label(main_frame, text="Encryption Password (Optional):").pack(anchor="w")
        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(main_frame, textvariable=self.password_var, 
                                 show="*", font=ModernStyle.BODY_FONT)
        password_entry.pack(fill="x", pady=(5, 20))
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.pack(fill="x")
        
        ttk.Button(button_frame, text="Cancel", 
                  command=self.cancel).pack(side="right", padx=(10, 0))
        ttk.Button(button_frame, text="Connect", 
                  command=self.connect).pack(side="right")
        
        # Focus on name entry
        name_entry.focus_set()
        name_entry.select_range(0, tk.END)
        
    def connect(self):
        """Handle connect button"""
        try:
            port = int(self.port_var.get())
            if not (1024 <= port <= 65535):
                raise ValueError("Port must be between 1024 and 65535")
                
            self.result = {
                "name": self.name_var.get().strip(),
                "port": port,
                "password": self.password_var.get().strip() or None
            }
            
            if not self.result["name"]:
                messagebox.showerror("Error", "Please enter a display name")
                return
                
            self.dialog.destroy()
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid port number: {e}")
    
    def cancel(self):
        """Handle cancel button"""
        self.dialog.destroy()


class StatusBar(ttk.Frame):
    """Custom status bar widget"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.pack(side="bottom", fill="x")
        
        # Status text
        self.status_var = tk.StringVar(value="Disconnected")
        self.status_label = ttk.Label(self, textvariable=self.status_var)
        self.status_label.pack(side="left", padx=5)
        
        # Separator
        ttk.Separator(self, orient="vertical").pack(side="left", fill="y", padx=5)
        
        # Peer count
        self.peer_var = tk.StringVar(value="Peers: 0")
        self.peer_label = ttk.Label(self, textvariable=self.peer_var)
        self.peer_label.pack(side="left", padx=5)
        
        # Connection indicator
        self.indicator_canvas = tk.Canvas(self, width=20, height=20, highlightthickness=0)
        self.indicator_canvas.pack(side="right", padx=5)
        self.connection_indicator = self.indicator_canvas.create_oval(2, 2, 18, 18, 
                                                                    fill="red", outline="darkred")
    
    def set_status(self, status: str, connected: bool = False, peer_count: int = 0):
        """Update status bar"""
        self.status_var.set(status)
        self.peer_var.set(f"Peers: {peer_count}")
        
        color = "green" if connected else "red"
        outline_color = "darkgreen" if connected else "darkred"
        self.indicator_canvas.itemconfig(self.connection_indicator, fill=color, outline=outline_color)


class ChatWidget(ttk.Frame):
    """Enhanced chat widget with modern features"""
    
    def __init__(self, parent):
        super().__init__(parent)
        
        # Chat display with custom scrollbar
        self.setup_chat_display()
        
        # Input area
        self.setup_input_area()
        
        # Message callback
        self.on_send_message = None
    
    def setup_chat_display(self):
        """Setup the chat display area"""
        # Frame for chat display and scrollbar
        display_frame = ttk.Frame(self)
        display_frame.pack(fill="both", expand=True, pady=(0, 10))
        
        # Chat text widget
        self.chat_text = tk.Text(display_frame, state="disabled", wrap="word",
                                font=ModernStyle.BODY_FONT, height=20)
        self.chat_text.pack(side="left", fill="both", expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(display_frame, orient="vertical", 
                                 command=self.chat_text.yview)
        scrollbar.pack(side="right", fill="y")
        self.chat_text.configure(yscrollcommand=scrollbar.set)
        
        # Configure text tags for styling
        self.chat_text.tag_configure("timestamp", foreground="gray")
        self.chat_text.tag_configure("own_message", foreground="lightblue")
        self.chat_text.tag_configure("system", foreground="orange")
        self.chat_text.tag_configure("file", foreground="lightgreen")
    
    def setup_input_area(self):
        """Setup the message input area"""
        input_frame = ttk.Frame(self)
        input_frame.pack(fill="x")
        
        # Message entry
        self.message_var = tk.StringVar()
        self.message_entry = ttk.Entry(input_frame, textvariable=self.message_var,
                                     font=ModernStyle.BODY_FONT)
        self.message_entry.pack(side="left", fill="x", expand=True, padx=(0, 5))
        self.message_entry.bind("<Return>", self.send_message)
        
        # Send button
        self.send_button = ttk.Button(input_frame, text="Send", 
                                    command=self.send_message)
        self.send_button.pack(side="right")
        
        # Focus on entry
        self.message_entry.focus_set()
    
    def send_message(self, event=None):
        """Send message"""
        message = self.message_var.get().strip()
        if message and self.on_send_message:
            self.on_send_message(message)
            self.message_var.set("")
    
    def add_message(self, message: str, message_type: str = "normal"):
        """Add message to chat display"""
        self.chat_text.configure(state="normal")
        
        # Add timestamp
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.chat_text.insert("end", f"[{timestamp}] ", "timestamp")
        
        # Add message with appropriate styling
        if message_type == "own":
            self.chat_text.insert("end", message + "\n", "own_message")
        elif message_type == "system":
            self.chat_text.insert("end", message + "\n", "system")
        elif message_type == "file":
            self.chat_text.insert("end", message + "\n", "file")
        else:
            self.chat_text.insert("end", message + "\n")
        
        self.chat_text.configure(state="disabled")
        self.chat_text.see("end")


class PeersWidget(ttk.Frame):
    """Enhanced peers widget with context menu"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
        
    def setup_ui(self):
        """Setup peers widget UI"""
        # Header
        header_frame = ttk.Frame(self)
        header_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Label(header_frame, text="Network Peers", 
                 font=ModernStyle.HEADER_FONT).pack(side="left")
        
        ttk.Button(header_frame, text="Refresh", 
                  command=self.refresh_peers).pack(side="right")
        
        # Peers tree
        columns = ("name", "id", "address", "status")
        self.tree = ttk.Treeview(self, columns=columns, show="headings", height=10)
        
        # Column headings and widths
        self.tree.heading("name", text="Name")
        self.tree.heading("id", text="Node ID")  
        self.tree.heading("address", text="Address")
        self.tree.heading("status", text="Status")
        
        self.tree.column("name", width=120)
        self.tree.column("id", width=80)
        self.tree.column("address", width=120)
        self.tree.column("status", width=80)
        
        # Scrollbar for tree
        tree_scroll = ttk.Scrollbar(self, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_scroll.set)
        
        self.tree.pack(side="left", fill="both", expand=True)
        tree_scroll.pack(side="right", fill="y")
        
        # Context menu
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Send Direct Message", command=self.send_direct_message)
        self.context_menu.add_command(label="View Info", command=self.view_peer_info)
        
        self.tree.bind("<Button-3>", self.show_context_menu)
    
    def refresh_peers(self):
        """Refresh peers list"""
        # This would be called by the main application
        pass
    
    def update_peers(self, peers_list):
        """Update peers display"""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add peers
        for peer in peers_list:
            self.tree.insert("", "end", values=(
                peer.get("name", "Unknown"),
                peer.get("id", "")[:8],
                peer.get("address", ""),
                "Online"
            ))
    
    def show_context_menu(self, event):
        """Show context menu"""
        item = self.tree.selection()
        if item:
            self.context_menu.post(event.x_root, event.y_root)
    
    def send_direct_message(self):
        """Send direct message to selected peer"""
        selection = self.tree.selection()
        if selection:
            peer_name = self.tree.item(selection[0])["values"][0]
            messagebox.showinfo("Feature", f"Direct message to {peer_name}\n(Feature coming soon)")
    
    def view_peer_info(self):
        """View peer information"""
        selection = self.tree.selection()
        if selection:
            values = self.tree.item(selection[0])["values"]
            info = f"Name: {values[0]}\nNode ID: {values[1]}\nAddress: {values[2]}\nStatus: {values[3]}"
            messagebox.showinfo("Peer Information", info)


class FileTransferWidget(ttk.Frame):
    """Enhanced file transfer widget"""
    
    def __init__(self, parent):
        super().__init__(parent)
        self.setup_ui()
        self.on_send_file = None
        
    def setup_ui(self):
        """Setup file transfer UI"""
        # Send files section
        send_frame = ttk.LabelFrame(self, text="Send Files", padding=10)
        send_frame.pack(fill="x", pady=(0, 10))
        
        ttk.Button(send_frame, text="📁 Select File to Send", 
                  command=self.select_file).pack()
        
        # File history
        history_frame = ttk.LabelFrame(self, text="Transfer History", padding=10)
        history_frame.pack(fill="both", expand=True)
        
        # History list
        self.history_text = tk.Text(history_frame, height=15, state="disabled",
                                   font=ModernStyle.MONO_FONT)
        history_scroll = ttk.Scrollbar(history_frame, orient="vertical",
                                     command=self.history_text.yview)
        self.history_text.configure(yscrollcommand=history_scroll.set)
        
        self.history_text.pack(side="left", fill="both", expand=True)
        history_scroll.pack(side="right", fill="y")
        
        # Downloads folder button
        ttk.Button(history_frame, text="📂 Open Downloads Folder",
                  command=self.open_downloads).pack(pady=(10, 0))
    
    def select_file(self):
        """Select file to send"""
        file_path = filedialog.askopenfilename(
            title="Select file to send",
            filetypes=[
                ("All files", "*.*"),
                ("Documents", "*.pdf;*.doc;*.docx;*.txt"),
                ("Images", "*.jpg;*.jpeg;*.png;*.gif"),
                ("Archives", "*.zip;*.rar;*.7z")
            ]
        )
        
        if file_path and self.on_send_file:
            self.on_send_file(file_path)
    
    def add_transfer_log(self, message: str):
        """Add transfer log entry"""
        self.history_text.configure(state="normal")
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.history_text.insert("end", f"[{timestamp}] {message}\n")
        self.history_text.configure(state="disabled")
        self.history_text.see("end")
    
    def open_downloads(self):
        """Open downloads folder"""
        downloads_path = Path("mesh_downloads")
        downloads_path.mkdir(exist_ok=True)
        
        import subprocess
        import platform
        
        try:
            if platform.system() == "Windows":
                os.startfile(str(downloads_path))
            elif platform.system() == "Darwin":
                subprocess.run(["open", str(downloads_path)])
            else:
                subprocess.run(["xdg-open", str(downloads_path)])
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open folder: {e}")


class MeshNetworkApp:
    """Main mesh network application window"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.mesh_node = None
        self.setup_window()
        self.setup_ui()
        self.apply_modern_theme()
        
    def setup_window(self):
        """Setup main window"""
        self.root.title("Mesh Network - Professional Edition")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Center window on screen
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
        
        # Handle close event
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
    
    def setup_ui(self):
        """Setup the main UI"""
        # Menu bar
        self.setup_menu()
        
        # Main content
        self.setup_main_content()
        
        # Status bar
        self.status_bar = StatusBar(self.root)
    
    def setup_menu(self):
        """Setup menu bar"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Network menu
        network_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Network", menu=network_menu)
        network_menu.add_command(label="Connect...", command=self.connect_to_network)
        network_menu.add_command(label="Disconnect", command=self.disconnect_from_network)
        network_menu.add_separator()
        network_menu.add_command(label="Settings...", command=self.show_settings)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Network Info", command=self.show_network_info)
        tools_menu.add_command(label="Clear Chat", command=self.clear_chat)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def setup_main_content(self):
        """Setup main content area"""
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Chat tab
        self.chat_widget = ChatWidget(self.notebook)
        self.chat_widget.on_send_message = self.send_chat_message
        self.notebook.add(self.chat_widget, text="💬 Chat")
        
        # Peers tab  
        self.peers_widget = PeersWidget(self.notebook)
        self.notebook.add(self.peers_widget, text="👥 Peers")
        
        # Files tab
        self.files_widget = FileTransferWidget(self.notebook)
        self.files_widget.on_send_file = self.send_file
        self.notebook.add(self.files_widget, text="📁 Files")
    
    def apply_modern_theme(self):
        """Apply modern theme styling"""
        style = ttk.Style()
        
        # Configure the style theme
        try:
            style.theme_use('clam')  # Use clam theme as base
        except:
            pass
        
        # Custom styles would go here
        # Note: Full theming requires more complex setup
    
    def connect_to_network(self):
        """Show connection dialog and connect"""
        dialog = ConnectionDialog(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            self.start_mesh_node(dialog.result)
    
    def start_mesh_node(self, config):
        """Start the mesh network node"""
        try:
            # Here you would initialize your actual mesh node
            # self.mesh_node = MeshNetworkFactory.create_mesh_node(
            #     config["name"], config["port"], config["password"]
            # )
            # self.mesh_node.start()
            
            # For demo purposes, simulate connection
            self.status_bar.set_status(f"Connected as {config['name']}", True, 0)
            
            # Add system message
            self.chat_widget.add_message(f"Connected to mesh network as {config['name']}", "system")
            
            messagebox.showinfo("Connected", "Successfully connected to mesh network!")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
    
    def disconnect_from_network(self):
        """Disconnect from network"""
        if self.mesh_node:
            self.mesh_node.stop()
            self.mesh_node = None
        
        self.status_bar.set_status("Disconnected", False, 0)
        self.chat_widget.add_message("Disconnected from mesh network", "system")
    
    def send_chat_message(self, message):
        """Send chat message"""
        if self.mesh_node:
            # Send through mesh node
            # count = self.mesh_node.send_message(message)
            count = 1  # Demo
            
            # Add to our chat display
            self.chat_widget.add_message(f"You: {message}", "own")
            
            if count == 0:
                self.chat_widget.add_message("⚠️ No peers available", "system")
        else:
            self.chat_widget.add_message("⚠️ Not connected to network", "system")
    
    def send_file(self, file_path):
        """Send file"""
        if self.mesh_node:
            filename = os.path.basename(file_path)
            self.files_widget.add_transfer_log(f"Sending: {filename}")
            
            # Here you would send through mesh node
            # success = self.mesh_node.send_file(file_path)
            success = True  # Demo
            
            if success:
                self.files_widget.add_transfer_log(f"✓ Sent: {filename}")
            else:
                self.files_widget.add_transfer_log(f"✗ Failed: {filename}")
        else:
            messagebox.showwarning("Not Connected", "Please connect to network first")
    
    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings dialog coming soon!")
    
    def show_network_info(self):
        """Show network information"""
        info = "Network Information:\n\n"
        info += f"Status: {'Connected' if self.mesh_node else 'Disconnected'}\n"
        info += f"Peers: {len(self.peers_widget.tree.get_children())}\n"
        info += f"Node ID: {'demo-node-id' if self.mesh_node else 'N/A'}\n"
        
        messagebox.showinfo("Network Info", info)
    
    def clear_chat(self):
        """Clear chat history"""
        if messagebox.askyesno("Clear Chat", "Clear all chat messages?"):
            self.chat_widget.chat_text.configure(state="normal")
            self.chat_widget.chat_text.delete(1.0, "end")
            self.chat_widget.chat_text.configure(state="disabled")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Mesh Network - Professional Edition

A peer-to-peer communication application that allows
secure messaging and file sharing without internet.

Features:
• Real-time messaging
• File sharing
• End-to-end encryption
• Peer discovery
• Modern user interface

Built with Python and Tkinter
"""
        messagebox.showinfo("About", about_text)
    
    def on_closing(self):
        """Handle application closing"""
        if self.mesh_node:
            if messagebox.askyesno("Exit", "Disconnect from network and exit?"):
                self.disconnect_from_network()
                self.root.destroy()
        else:
            self.root.destroy()
    
    def run(self):
        """Run the application"""
        # Show connection dialog on startup
        self.root.after(1000, self.connect_to_network)
        
        # Start main loop
        self.root.mainloop()


def main():
    """Main entry point"""
    app = MeshNetworkApp()
    app.run()


if __name__ == "__main__":
    main()