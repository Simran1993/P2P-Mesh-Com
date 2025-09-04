#!/usr/bin/env python3
"""
Professional Mesh Network Desktop Application - Complete Integrated Version
Combines the modern UI with the object-oriented mesh network backend
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import tkinter.font as tkFont
from typing import Optional, Dict, List, Set, Callable, Protocol
import threading
import time
import json
import os
import socket
import uuid
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

# Encryption imports
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# ==================== Data Classes and Enums ====================

class MessageType(Enum):
    """Enumeration of message types"""
    DISCOVERY = "discovery"
    CHAT = "chat"
    FILE_CHUNK = "file_chunk"
    FILE_REQUEST = "file_request"
    PEER_LIST = "peer_list"


@dataclass
class PeerInfo:
    """Data class for peer information"""
    peer_id: str
    name: str
    ip: str
    port: int
    last_seen: float
    
    @property
    def address(self) -> str:
        return f"{self.ip}:{self.port}"
    
    @property
    def last_seen_formatted(self) -> str:
        return datetime.fromtimestamp(self.last_seen).strftime("%H:%M:%S")
    
    def is_stale(self, timeout: float = 30.0) -> bool:
        return time.time() - self.last_seen > timeout


@dataclass
class Message:
    """Base message data class"""
    message_type: MessageType
    message_id: str
    sender_id: str
    sender_name: str
    timestamp: float
    content: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "type": self.message_type.value,
            "message_id": self.message_id,
            "sender_id": self.sender_id,
            "sender_name": self.sender_name,
            "timestamp": self.timestamp,
            "content": self.content
        }
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'Message':
        return cls(
            message_type=MessageType(data["type"]),
            message_id=data["message_id"],
            sender_id=data["sender_id"],
            sender_name=data["sender_name"],
            timestamp=data["timestamp"],
            content=data.get("content")
        )


@dataclass
class FileChunkMessage(Message):
    """File chunk message with additional file data"""
    file_id: str = None
    chunk_index: int = None
    chunk_data: str = None
    file_metadata: Dict = None
    
    def to_dict(self) -> Dict:
        data = super().to_dict()
        data.update({
            "file_id": self.file_id,
            "chunk_index": self.chunk_index,
            "chunk_data": self.chunk_data,
            "file_metadata": self.file_metadata
        })
        return data


# ==================== Abstract Interfaces ====================

class ICryptoProvider(ABC):
    """Abstract base class for encryption providers"""
    
    @abstractmethod
    def encrypt(self, data: str) -> str:
        pass
    
    @abstractmethod
    def decrypt(self, data: str) -> str:
        pass


class IFileManager(ABC):
    """Abstract base class for file management"""
    
    @abstractmethod
    def prepare_file(self, file_path: str) -> Dict:
        pass
    
    @abstractmethod
    def receive_chunk(self, file_id: str, chunk_index: int, 
                     chunk_data: str, metadata: Dict) -> Optional[str]:
        pass


# ==================== Concrete Implementations ====================

class FernetCryptoProvider(ICryptoProvider):
    """Fernet-based encryption provider"""
    
    def __init__(self, password: Optional[str] = None):
        self._fernet: Optional[Fernet] = None
        if CRYPTO_AVAILABLE and password:
            self._setup_encryption(password)
    
    def _setup_encryption(self, password: str) -> None:
        """Setup encryption with password"""
        salt = b'mesh_network_salt_2024'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        self._fernet = Fernet(key)
    
    def encrypt(self, data: str) -> str:
        """Encrypt string data"""
        if not self._fernet:
            return data
        return base64.b64encode(self._fernet.encrypt(data.encode())).decode()
    
    def decrypt(self, data: str) -> str:
        """Decrypt string data"""
        if not self._fernet:
            return data
        try:
            return self._fernet.decrypt(base64.b64decode(data.encode())).decode()
        except Exception:
            return "[ENCRYPTED MESSAGE - WRONG PASSWORD]"


class ChunkedFileManager(IFileManager):
    """File manager that handles chunked file transmission"""
    
    def __init__(self, download_dir: str = "mesh_downloads", chunk_size: int = 8192):
        self._download_dir = Path(download_dir)
        self._download_dir.mkdir(exist_ok=True)
        self._chunk_size = chunk_size
        self._file_chunks: Dict[str, Dict] = {}
        self._lock = threading.RLock()
    
    def prepare_file(self, file_path: str) -> Dict:
        """Prepare file for transmission"""
        file_path = Path(file_path)
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        file_id = str(uuid.uuid4())
        file_size = file_path.stat().st_size
        
        # Calculate file hash
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            content = f.read()
            hasher.update(content)
        
        file_hash = hasher.hexdigest()
        
        # Split into chunks
        chunks = []
        for i in range(0, len(content), self._chunk_size):
            chunk_data = content[i:i + self._chunk_size]
            chunks.append(base64.b64encode(chunk_data).decode())
        
        return {
            "file_id": file_id,
            "filename": file_path.name,
            "file_size": file_size,
            "file_hash": file_hash,
            "total_chunks": len(chunks),
            "chunks": chunks
        }
    
    def receive_chunk(self, file_id: str, chunk_index: int, 
                     chunk_data: str, metadata: Dict) -> Optional[str]:
        """Receive file chunk and return path if complete"""
        with self._lock:
            if file_id not in self._file_chunks:
                self._file_chunks[file_id] = {
                    "metadata": metadata,
                    "chunks": {},
                    "received_chunks": 0
                }
            
            file_info = self._file_chunks[file_id]
            if chunk_index not in file_info["chunks"]:
                file_info["chunks"][chunk_index] = chunk_data
                file_info["received_chunks"] += 1
            
            # Check if file is complete
            if file_info["received_chunks"] == metadata["total_chunks"]:
                return self._assemble_file(file_id)
            
            return None
    
    def _assemble_file(self, file_id: str) -> str:
        """Assemble complete file from chunks"""
        file_info = self._file_chunks[file_id]
        metadata = file_info["metadata"]
        
        # Reconstruct file
        file_data = b""
        for i in range(metadata["total_chunks"]):
            chunk_data = base64.b64decode(file_info["chunks"][i].encode())
            file_data += chunk_data
        
        # Verify hash
        hasher = hashlib.sha256()
        hasher.update(file_data)
        if hasher.hexdigest() != metadata["file_hash"]:
            raise ValueError("File corruption detected - hash mismatch")
        
        # Save file with unique name
        output_path = self._get_unique_file_path(metadata["filename"])
        with open(output_path, 'wb') as f:
            f.write(file_data)
        
        # Cleanup
        del self._file_chunks[file_id]
        
        return str(output_path)
    
    def _get_unique_file_path(self, filename: str) -> Path:
        """Get unique file path to avoid conflicts"""
        output_path = self._download_dir / filename
        counter = 1
        while output_path.exists():
            name, ext = os.path.splitext(filename)
            output_path = self._download_dir / f"{name}_{counter}{ext}"
            counter += 1
        return output_path


class PeerManager:
    """Manages peer connections and state"""
    
    def __init__(self):
        self._peers: Dict[str, PeerInfo] = {}
        self._lock = threading.RLock()
        self._observers: List[Callable[[List[PeerInfo]], None]] = []
    
    def add_peer(self, peer: PeerInfo) -> bool:
        """Add or update a peer"""
        with self._lock:
            is_new = peer.peer_id not in self._peers
            self._peers[peer.peer_id] = peer
            if is_new:
                print(f"Discovered new peer: {peer.name} ({peer.peer_id}) at {peer.address}")
                self._notify_observers()
            return is_new
    
    def remove_peer(self, peer_id: str) -> bool:
        """Remove a peer"""
        with self._lock:
            if peer_id in self._peers:
                peer_name = self._peers[peer_id].name
                del self._peers[peer_id]
                print(f"Peer {peer_name} ({peer_id}) disconnected")
                self._notify_observers()
                return True
            return False
    
    def get_all_peers(self) -> List[PeerInfo]:
        """Get all peers"""
        with self._lock:
            return list(self._peers.values())
    
    def get_peer(self, peer_id: str) -> Optional[PeerInfo]:
        """Get specific peer"""
        with self._lock:
            return self._peers.get(peer_id)
    
    def cleanup_stale_peers(self) -> None:
        """Remove stale peers"""
        with self._lock:
            stale_peer_ids = [
                peer_id for peer_id, peer in self._peers.items()
                if peer.is_stale()
            ]
            
            for peer_id in stale_peer_ids:
                self.remove_peer(peer_id)
    
    def add_observer(self, observer: Callable[[List[PeerInfo]], None]) -> None:
        """Add peer list observer"""
        self._observers.append(observer)
    
    def _notify_observers(self) -> None:
        """Notify all observers of peer list changes"""
        peers = self.get_all_peers()
        for observer in self._observers:
            try:
                observer(peers)
            except Exception as e:
                print(f"Error notifying peer observer: {e}")


class MeshNode:
    """Main mesh network node implementing the core functionality"""
    
    def __init__(self, node_name: str, port: int = 9999, password: str = None):
        self._node_id = str(uuid.uuid4())[:8]
        self._node_name = node_name
        self._local_ip = self._get_local_ip()
        self._port = port
        
        # Components
        self._crypto_provider = FernetCryptoProvider(password)
        self._file_manager = ChunkedFileManager()
        self._peer_manager = PeerManager()
        
        # State
        self._message_cache: Set[str] = set()
        self._running = False
        self._server_socket: Optional[socket.socket] = None
        self._broadcast_socket: Optional[socket.socket] = None
        self._threads: List[threading.Thread] = []
        
        # Observer callbacks
        self._message_observers: List[Callable[[str], None]] = []
        self._file_observers: List[Callable[[str, str], None]] = []
        
        print(f"Node initialized: {self._node_name} ({self._node_id}) at {self._local_ip}:{port}")
    
    @property
    def node_id(self) -> str:
        return self._node_id
    
    @property
    def node_name(self) -> str:
        return self._node_name
    
    @property
    def peers(self) -> List[PeerInfo]:
        return self._peer_manager.get_all_peers()
    
    def start(self) -> None:
        """Start the mesh node"""
        self._running = True
        self._setup_networking()
        
        # Start network threads
        threads = [
            threading.Thread(target=self._listen_for_connections, daemon=True),
            threading.Thread(target=self._discovery_broadcast_loop, daemon=True),
            threading.Thread(target=self._listen_for_discovery, daemon=True),
            threading.Thread(target=self._cleanup_loop, daemon=True)
        ]
        
        for thread in threads:
            thread.start()
            self._threads.append(thread)
        
        print(f"Mesh node {self._node_name} started successfully!")
    
    def stop(self) -> None:
        """Stop the mesh node"""
        print("Shutting down mesh node...")
        self._running = False
        
        if self._server_socket:
            self._server_socket.close()
        if self._broadcast_socket:
            self._broadcast_socket.close()
        
        print("Mesh node shutdown complete")
    
    def send_message(self, content: str) -> int:
        """Send chat message to all peers"""
        encrypted_content = self._crypto_provider.encrypt(content)
        
        message = Message(
            message_type=MessageType.CHAT,
            message_id=str(uuid.uuid4()),
            sender_id=self._node_id,
            sender_name=self._node_name,
            timestamp=time.time(),
            content=encrypted_content
        )
        
        self._message_cache.add(message.message_id)
        return self._broadcast_message(message)
    
    def send_file(self, file_path: str) -> bool:
        """Send file to all peers"""
        try:
            file_info = self._file_manager.prepare_file(file_path)
            
            # Send each chunk
            for i, chunk_data in enumerate(file_info["chunks"]):
                chunk_message = FileChunkMessage(
                    message_type=MessageType.FILE_CHUNK,
                    message_id=str(uuid.uuid4()),
                    sender_id=self._node_id,
                    sender_name=self._node_name,
                    timestamp=time.time(),
                    file_id=file_info["file_id"],
                    chunk_index=i,
                    chunk_data=chunk_data,
                    file_metadata={
                        "filename": file_info["filename"],
                        "file_size": file_info["file_size"],
                        "file_hash": file_info["file_hash"],
                        "total_chunks": file_info["total_chunks"]
                    }
                )
                
                self._message_cache.add(chunk_message.message_id)
                self._broadcast_message(chunk_message)
                time.sleep(0.05)  # Small delay between chunks
            
            return True
            
        except Exception as e:
            print(f"Error sending file: {e}")
            return False
    
    def add_message_observer(self, observer: Callable[[str], None]) -> None:
        """Add message observer"""
        self._message_observers.append(observer)
    
    def add_file_observer(self, observer: Callable[[str, str], None]) -> None:
        """Add file observer"""
        self._file_observers.append(observer)
    
    def add_peer_observer(self, observer: Callable[[List[PeerInfo]], None]) -> None:
        """Add peer observer"""
        self._peer_manager.add_observer(observer)
    
    # Private methods
    def _get_local_ip(self) -> str:
        """Get local IP address"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except:
            return "127.0.0.1"
    
    def _setup_networking(self) -> None:
        """Setup network sockets"""
        # TCP server socket
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server_socket.bind((self._local_ip, self._port))
        self._server_socket.listen(10)
        
        # UDP broadcast socket
        self._broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    def _listen_for_connections(self) -> None:
        """Listen for incoming TCP connections"""
        while self._running:
            try:
                client_socket, addr = self._server_socket.accept()
                thread = threading.Thread(
                    target=self._handle_peer_connection,
                    args=(client_socket, addr),
                    daemon=True
                )
                thread.start()
            except Exception as e:
                if self._running:
                    print(f"Connection accept error: {e}")
    
    def _handle_peer_connection(self, client_socket: socket.socket, addr) -> None:
        """Handle incoming peer connection"""
        try:
            while self._running:
                data = client_socket.recv(65536)
                if not data:
                    break
                
                try:
                    message_dict = json.loads(data.decode())
                    message = self._create_message_from_dict(message_dict)
                    self._handle_message(message)
                except json.JSONDecodeError:
                    print(f"Invalid JSON received from {addr}")
        except Exception as e:
            if self._running:
                print(f"Error handling peer {addr}: {e}")
        finally:
            client_socket.close()
    
    def _create_message_from_dict(self, data: Dict) -> Message:
        """Factory method to create appropriate message type"""
        message_type = MessageType(data["type"])
        
        if message_type == MessageType.FILE_CHUNK:
            return FileChunkMessage(
                message_type=message_type,
                message_id=data["message_id"],
                sender_id=data["sender_id"],
                sender_name=data["sender_name"],
                timestamp=data["timestamp"],
                file_id=data.get("file_id"),
                chunk_index=data.get("chunk_index"),
                chunk_data=data.get("chunk_data"),
                file_metadata=data.get("file_metadata")
            )
        else:
            return Message.from_dict(data)
    
    def _handle_message(self, message: Message) -> None:
        """Handle received message"""
        if message.message_id in self._message_cache:
            return
        
        self._message_cache.add(message.message_id)
        
        if message.message_type == MessageType.CHAT:
            self._handle_chat_message(message)
        elif message.message_type == MessageType.FILE_CHUNK:
            self._handle_file_chunk(message)
        
        # Relay message (mesh behavior)
        self._relay_message(message)
    
    def _handle_chat_message(self, message: Message) -> None:
        """Handle chat message"""
        decrypted_content = self._crypto_provider.decrypt(message.content)
        timestamp = datetime.fromtimestamp(message.timestamp).strftime("%H:%M:%S")
        display_msg = f"[{timestamp}] {message.sender_name}: {decrypted_content}"
        
        print(display_msg)
        
        for observer in self._message_observers:
            try:
                observer(display_msg)
            except Exception as e:
                print(f"Error notifying message observer: {e}")
    
    def _handle_file_chunk(self, message: FileChunkMessage) -> None:
        """Handle file chunk message"""
        try:
            file_path = self._file_manager.receive_chunk(
                message.file_id,
                message.chunk_index,
                message.chunk_data,
                message.file_metadata
            )
            
            if file_path:  # File complete
                timestamp = datetime.fromtimestamp(message.timestamp).strftime("%H:%M:%S")
                file_msg = f"[{timestamp}] File received: {message.file_metadata['filename']} -> {file_path}"
                print(file_msg)
                
                for observer in self._file_observers:
                    try:
                        observer(file_msg, file_path)
                    except Exception as e:
                        print(f"Error notifying file observer: {e}")
                        
        except Exception as e:
            print(f"Error handling file chunk: {e}")
    
    def _broadcast_message(self, message: Message) -> int:
        """Broadcast message to all peers"""
        success_count = 0
        for peer in self._peer_manager.get_all_peers():
            if self._send_to_peer(peer, message):
                success_count += 1
        return success_count
    
    def _relay_message(self, message: Message) -> None:
        """Relay message to other peers (exclude sender)"""
        for peer in self._peer_manager.get_all_peers():
            if peer.peer_id != message.sender_id:
                self._send_to_peer(peer, message)
    
    def _send_to_peer(self, peer: PeerInfo, message: Message) -> bool:
        """Send message to specific peer"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(5)
                sock.connect((peer.ip, peer.port))
                sock.send(json.dumps(message.to_dict()).encode())
                return True
        except Exception as e:
            print(f"Failed to send to {peer.name}: {e}")
            return False
    
    def _discovery_broadcast_loop(self) -> None:
        """Periodically broadcast discovery messages"""
        while self._running:
            try:
                discovery_data = {
                    "type": MessageType.DISCOVERY.value,
                    "node_id": self._node_id,
                    "node_name": self._node_name,
                    "ip": self._local_ip,
                    "port": self._port,
                    "timestamp": time.time()
                }
                
                self._broadcast_socket.sendto(
                    json.dumps(discovery_data).encode(),
                    ('<broadcast>', self._port + 1)
                )
                time.sleep(5)
            except Exception as e:
                if self._running:
                    print(f"Discovery broadcast error: {e}")
    
    def _listen_for_discovery(self) -> None:
        """Listen for discovery broadcasts"""
        discovery_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        discovery_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            discovery_socket.bind(('', self._port + 1))
        except:
            print("Warning: Could not bind discovery socket")
            return
        
        while self._running:
            try:
                data, addr = discovery_socket.recvfrom(1024)
                discovery_data = json.loads(data.decode())
                
                if discovery_data["type"] == MessageType.DISCOVERY.value:
                    # Don't add ourselves
                    if discovery_data["node_id"] != self._node_id:
                        peer = PeerInfo(
                            peer_id=discovery_data["node_id"],
                            name=discovery_data["node_name"],
                            ip=discovery_data["ip"],
                            port=discovery_data["port"],
                            last_seen=time.time()
                        )
                        self._peer_manager.add_peer(peer)
            except Exception as e:
                if self._running:
                    print(f"Discovery listen error: {e}")
        
        discovery_socket.close()
    
    def _cleanup_loop(self) -> None:
        """Background cleanup loop"""
        while self._running:
            self._peer_manager.cleanup_stale_peers()
            
            # Cleanup old messages from cache
            if len(self._message_cache) > 1000:
                self._message_cache.clear()
            
            time.sleep(10)


# ==================== Modern UI Components ====================

class ModernStyle:
    """Modern UI styling constants"""
    
    # Colors
    PRIMARY_COLOR = "#2E3440"
    SECONDARY_COLOR = "#3B4252"
    ACCENT_COLOR = "#5E81AC"
    SUCCESS_COLOR = "#A3BE8C"
    WARNING_COLOR = "#EBCB8B"
    ERROR_COLOR = "#BF616A"
    TEXT_COLOR = "#ECEFF4"
    BG_COLOR = "#2E3440"
    CARD_COLOR = "#3B4252"
    
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
        self.dialog.geometry("400x350")
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
        self.name_var = tk.StringVar(value=f"User-{socket.gethostname()}")
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
        password_entry.pack(fill="x", pady=(5, 10))
        
        # Encryption status
        if CRYPTO_AVAILABLE:
            ttk.Label(main_frame, text="✓ Encryption available", 
                     foreground="green").pack(anchor="w", pady=(0, 10))
        else:
            ttk.Label(main_frame, text="⚠ Install cryptography for encryption", 
                     foreground="orange").pack(anchor="w", pady=(0, 10))
        
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
            
            name = self.name_var.get().strip()
            if not name:
                messagebox.showerror("Error", "Please enter a display name")
                return
            
            password = self.password_var.get().strip() or None
            if password and not CRYPTO_AVAILABLE:
                messagebox.showwarning("Warning", 
                    "Encryption password ignored - cryptography not available")
                password = None
            
            self.result = {
                "name": name,
                "port": port,
                "password": password
            }
            
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
                peer.name,
                peer.peer_id,
                peer.address,
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
        
        ttk.Button(send_frame, text="Select File to Send", 
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
        ttk.Button(history_frame, text="Open Downloads Folder",
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
    """Main mesh network application window with integrated backend"""
    
    def __init__(self):
        self.root = tk.Tk()
        self.mesh_node: Optional[MeshNode] = None
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
        self.notebook.add(self.chat_widget, text="Chat")
        
        # Peers tab  
        self.peers_widget = PeersWidget(self.notebook)
        self.peers_widget.refresh_peers = self.refresh_peers
        self.notebook.add(self.peers_widget, text="Peers")
        
        # Files tab
        self.files_widget = FileTransferWidget(self.notebook)
        self.files_widget.on_send_file = self.send_file
        self.notebook.add(self.files_widget, text="Files")
    
    def apply_modern_theme(self):
        """Apply modern theme styling"""
        style = ttk.Style()
        
        # Configure the style theme
        try:
            style.theme_use('clam')  # Use clam theme as base
        except:
            pass
    
    def connect_to_network(self):
        """Show connection dialog and connect"""
        dialog = ConnectionDialog(self.root)
        self.root.wait_window(dialog.dialog)
        
        if dialog.result:
            self.start_mesh_node(dialog.result)
    
    def start_mesh_node(self, config):
        """Start the mesh network node"""
        try:
            # Create and start mesh node
            self.mesh_node = MeshNode(
                config["name"], 
                config["port"], 
                config["password"]
            )
            
            # Connect observers
            self.mesh_node.add_message_observer(self.on_message_received)
            self.mesh_node.add_file_observer(self.on_file_received)
            self.mesh_node.add_peer_observer(self.on_peers_updated)
            
            # Start the node
            self.mesh_node.start()
            
            # Update UI
            self.status_bar.set_status(f"Connected as {config['name']}", True, 0)
            
            # Add system message
            self.chat_widget.add_message(f"Connected to mesh network as {config['name']}", "system")
            
            messagebox.showinfo("Connected", "Successfully connected to mesh network!")
            
        except Exception as e:
            messagebox.showerror("Connection Error", f"Failed to connect: {e}")
            if self.mesh_node:
                self.mesh_node.stop()
                self.mesh_node = None
    
    def disconnect_from_network(self):
        """Disconnect from network"""
        if self.mesh_node:
            self.mesh_node.stop()
            self.mesh_node = None
        
        self.status_bar.set_status("Disconnected", False, 0)
        self.chat_widget.add_message("Disconnected from mesh network", "system")
        self.peers_widget.update_peers([])
    
    def send_chat_message(self, message):
        """Send chat message"""
        if self.mesh_node:
            count = self.mesh_node.send_message(message)
            
            # Add to our chat display
            timestamp = datetime.now().strftime("%H:%M:%S")
            our_message = f"[{timestamp}] {self.mesh_node.node_name}: {message}"
            self.chat_widget.add_message(our_message, "own")
            
            if count == 0:
                self.chat_widget.add_message("No peers available", "system")
        else:
            self.chat_widget.add_message("Not connected to network", "system")
    
    def send_file(self, file_path):
        """Send file"""
        if self.mesh_node:
            filename = os.path.basename(file_path)
            self.files_widget.add_transfer_log(f"Sending: {filename}")
            
            # Send in background thread
            def send_thread():
                try:
                    success = self.mesh_node.send_file(file_path)
                    if success:
                        self.root.after(0, lambda: self.files_widget.add_transfer_log(f"Sent: {filename}"))
                    else:
                        self.root.after(0, lambda: self.files_widget.add_transfer_log(f"Failed: {filename}"))
                except Exception as e:
                    self.root.after(0, lambda: self.files_widget.add_transfer_log(f"Error: {e}"))
            
            threading.Thread(target=send_thread, daemon=True).start()
        else:
            messagebox.showwarning("Not Connected", "Please connect to network first")
    
    def refresh_peers(self):
        """Refresh peers display"""
        if self.mesh_node:
            self.peers_widget.update_peers(self.mesh_node.peers)
    
    def on_message_received(self, message: str):
        """Handle message received from mesh node"""
        self.root.after(0, lambda: self.chat_widget.add_message(message))
    
    def on_file_received(self, message: str, file_path: str):
        """Handle file received from mesh node"""
        self.root.after(0, lambda: self.files_widget.add_transfer_log(message))
        self.root.after(0, lambda: self.chat_widget.add_message(f"File received: {os.path.basename(file_path)}", "file"))
    
    def on_peers_updated(self, peers: List[PeerInfo]):
        """Handle peers list updated"""
        self.root.after(0, lambda: self.peers_widget.update_peers(peers))
        self.root.after(0, lambda: self.status_bar.set_status(
            f"Connected as {self.mesh_node.node_name if self.mesh_node else 'N/A'}", 
            bool(self.mesh_node), 
            len(peers)
        ))
    
    def show_settings(self):
        """Show settings dialog"""
        messagebox.showinfo("Settings", "Settings dialog coming soon!")
    
    def show_network_info(self):
        """Show network information"""
        if self.mesh_node:
            info = f"Network Information:\n\n"
            info += f"Status: Connected\n"
            info += f"Node Name: {self.mesh_node.node_name}\n"
            info += f"Node ID: {self.mesh_node.node_id}\n"
            info += f"Local IP: {self.mesh_node._local_ip}\n"
            info += f"Port: {self.mesh_node._port}\n"
            info += f"Peers: {len(self.mesh_node.peers)}\n"
            info += f"Encryption: {'Enabled' if self.mesh_node._crypto_provider._fernet else 'Disabled'}\n"
        else:
            info = "Network Information:\n\nStatus: Disconnected"
        
        messagebox.showinfo("Network Info", info)
    
    def clear_chat(self):
        """Clear chat history"""
        if messagebox.askyesno("Clear Chat", "Clear all chat messages?"):
            self.chat_widget.chat_text.configure(state="normal")
            self.chat_widget.chat_text.delete(1.0, "end")
            self.chat_widget.chat_text.configure(state="disabled")
    
    def show_about(self):
        """Show about dialog"""
        about_text = """Mesh Network - Professional Edition v2.0

A peer-to-peer communication application that allows
secure messaging and file sharing without internet.

Features:
• Real-time messaging with encryption
• Chunked file sharing with integrity checking
• Peer discovery and mesh networking
• Modern professional interface
• Cross-platform compatibility
• Object-oriented architecture

Built with Python and Tkinter
Backend: Object-oriented mesh network system
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
    print("=== Professional Mesh Network Application ===")
    print(f"Encryption available: {CRYPTO_AVAILABLE}")
    print("Starting application...")
    print("=" * 50)
    
    app = MeshNetworkApp()
    app.run()


if __name__ == "__main__":
    main()