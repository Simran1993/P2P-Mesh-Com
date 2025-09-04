# Mesh Network - Professional Edition

A decentralized peer-to-peer communication application that enables secure messaging and file sharing without requiring internet connectivity or central servers.

## Overview

This application creates a mesh network where devices can communicate directly with each other, automatically discovering peers and routing messages through multiple hops to ensure connectivity across the network. It features end-to-end encryption, chunked file transfer with integrity verification, and a modern GUI interface.

## Tech Stacka

### Core Technologies
- **Language**: Python 3.7+
- **GUI Framework**: Tkinter (built-in)
- **Encryption**: Cryptography library (Fernet symmetric encryption with PBKDF2)
- **Architecture**: Object-oriented design with observer pattern

### Networking Protocols

#### Primary Communication
- **TCP (Transmission Control Protocol)**: Used for reliable message and file transfer
  - Port: User-defined (default 9999)
  - Ensures message delivery and ordering
  - Connection-oriented communication between peers

#### Peer Discovery
- **UDP (User Datagram Protocol)**: Used for network broadcasting and peer discovery
  - Port: Primary port + 1 (default 10000)
  - Broadcasts discovery messages every 5 seconds
  - Enables automatic network topology mapping

#### Application Layer Protocol
- **JSON-based messaging**: Custom protocol for structured communication
- **Message Types**:
  - `discovery`: Peer announcement and network join
  - `chat`: Text message communication
  - `file_chunk`: File data transmission in chunks
  - `peer_list`: Network topology updates

#### Network Topology
- **Mesh Architecture**: True peer-to-peer with message relaying
- **Automatic Routing**: Messages propagate through multiple hops
- **Fault Tolerance**: Network remains functional if individual nodes fail
- **Dynamic Discovery**: Peers automatically find and connect to each other

### Security Features
- **Encryption**: AES-128 encryption via Fernet (when password provided)
- **Key Derivation**: PBKDF2 with 100,000 iterations and salt
- **File Integrity**: SHA256 hashing for corruption detection
- **Message Deduplication**: Prevents infinite loops in mesh routing

### File Transfer Protocol
- **Chunked Transfer**: Files split into 8KB chunks for reliable transmission
- **Base64 Encoding**: Binary data encoded for JSON transport
- **Integrity Verification**: SHA256 hash verification on reassembly
- **Automatic Reassembly**: Chunks combined and saved to downloads folder

## Features

### Core Functionality
- Real-time peer-to-peer messaging
- Secure file sharing with integrity checking
- Automatic peer discovery and connection
- Message encryption with password protection
- Cross-platform compatibility (Windows, Linux, macOS)

### User Interface
- Modern tabbed interface (Chat, Peers, Files)
- Real-time message display with syntax highlighting
- Peer management with connection status
- File transfer progress tracking
- Connection status indicators
- Professional styling and error handling

### Network Features
- Mesh topology with automatic routing
- Fault-tolerant communication
- Stale peer cleanup (30-second timeout)
- Message caching to prevent duplicates
- Background thread management

## Installation

### Requirements
```bash
# Required
python >= 3.7

# Optional (for encryption)
pip install cryptography
```

### Quick Start
```bash
# Clone or download the application
python mesh_network_app.py

# Or install dependencies first
pip install cryptography
python mesh_network_app.py
```

### Building Executable
```bash
# Install PyInstaller
pip install pyinstaller

# Build standalone executable
pyinstaller --onefile --windowed mesh_network_app.py

# Or use provided build script
python build.py
```

## Usage

### Basic Operation
1. Launch the application
2. Connect to network using the dialog:
   - Enter your display name
   - Set port number (default 9999)
   - Optional: Set encryption password
3. Start chatting and sharing files with discovered peers

### Network Setup
- **Single Device Testing**: Use different ports (9999, 10000, etc.)
- **LAN Deployment**: Ensure devices are on same subnet
- **Firewall Configuration**: Open chosen ports for TCP/UDP
- **WiFi Hotspot**: One device can create hotspot for direct connection

### File Sharing
1. Go to "Files" tab
2. Click "Select File to Send"
3. Choose file and confirm
4. File chunks will be transmitted to all connected peers
5. Received files appear in `mesh_downloads/` folder

## Network Protocol Details

### Discovery Protocol (UDP Broadcast)
```json
{
  "type": "discovery",
  "node_id": "abcd1234",
  "node_name": "User-Device",
  "ip": "192.168.1.100",
  "port": 9999,
  "timestamp": 1699123456.789
}
```

### Chat Message Protocol (TCP)
```json
{
  "type": "chat",
  "message_id": "unique-uuid",
  "sender_id": "abcd1234",
  "sender_name": "User-Device",
  "timestamp": 1699123456.789,
  "content": "encrypted_message_content"
}
```

### File Transfer Protocol (TCP)
```json
{
  "type": "file_chunk",
  "message_id": "unique-uuid",
  "sender_id": "abcd1234",
  "sender_name": "User-Device",
  "timestamp": 1699123456.789,
  "file_id": "file-uuid",
  "chunk_index": 0,
  "chunk_data": "base64_encoded_chunk",
  "file_metadata": {
    "filename": "document.pdf",
    "file_size": 12345,
    "file_hash": "sha256_hash",
    "total_chunks": 3
  }
}
```

## Architecture

### Object-Oriented Design
```
MeshNode (Core)
├── FernetCryptoProvider (Encryption)
├── ChunkedFileManager (File Handling)
├── PeerManager (Peer State)
└── NetworkTransport (TCP/UDP)

MeshNetworkApp (GUI)
├── ChatWidget (Messaging UI)
├── PeersWidget (Network View)
├── FileTransferWidget (File UI)
└── StatusBar (Connection Status)
```

### Design Patterns
- **Observer Pattern**: GUI updates from network events
- **Strategy Pattern**: Pluggable encryption providers
- **Factory Pattern**: Message type creation
- **Singleton-like**: Single mesh node per application

### Threading Model
- **Main Thread**: GUI and user interaction
- **Network Threads**: TCP server, UDP discovery, cleanup
- **Background Tasks**: File transfer, message processing
- **Thread Safety**: Locks and thread-safe queues

## Configuration

### Default Settings
- **Port**: 9999 (TCP), 10000 (UDP discovery)
- **Chunk Size**: 8KB for file transfers
- **Peer Timeout**: 30 seconds
- **Discovery Interval**: 5 seconds
- **Download Folder**: `mesh_downloads/`

### Customization
```python
# In code customization
node = MeshNode(
    node_name="CustomName",
    port=8888,
    password="encryption_key"
)
```

## Troubleshooting

### Common Issues
1. **No Peers Found**
   - Check firewall settings
   - Ensure devices on same network
   - Verify port availability

2. **Connection Failed**
   - Different ports for multiple instances
   - Admin permissions may be required
   - Antivirus software blocking connections

3. **File Transfer Fails**
   - Large files may take time
   - Network interruption during transfer
   - Check available disk space

4. **Encryption Not Working**
   - Install: `pip install cryptography`
   - All peers must use same password
   - Password case-sensitive

### Debug Mode
```python
# Enable detailed logging
python mesh_network_app.py --debug
```

### Port Testing
```bash
# Test port availability
netstat -an | grep 9999
telnet localhost 9999
```

## Security Considerations

### Encryption Details
- **Algorithm**: AES-128 in Fernet format
- **Key Derivation**: PBKDF2-HMAC-SHA256
- **Salt**: Fixed application salt (not cryptographically ideal)
- **Iterations**: 100,000 PBKDF2 rounds

### Security Limitations
- Fixed salt reduces security against rainbow tables
- No forward secrecy (same key for all messages)
- Peer authentication relies on network trust
- No certificate validation for peer identity

### Recommendations for Production
- Implement unique per-session salts
- Add peer certificate verification
- Use ephemeral key exchange (like Signal Protocol)
- Add message authentication codes (MAC)

## Performance

### Scalability
- **Optimal Network Size**: 5-20 peers
- **Message Propagation**: O(n) where n = number of peers
- **Memory Usage**: ~10MB base + message cache
- **File Transfer Rate**: ~1-5 MB/s depending on network

### Optimization Tips
- Use wired connections for better performance
- Keep networks small for faster message propagation
- Close unused applications to free network bandwidth
- Use dedicated WiFi network for mesh communication

## Development

### Project Structure
```
mesh_network_app.py         # Main application file
├── Data Classes            # Message, PeerInfo definitions
├── Abstract Interfaces     # Crypto, File, Transport abstractions
├── Concrete Implementations # Network, crypto, file handling
├── UI Components          # GUI widgets and dialogs
└── Main Application       # Integration and orchestration
```

### Extending Functionality
```python
# Custom encryption provider
class CustomCryptoProvider(ICryptoProvider):
    def encrypt(self, data: str) -> str:
        # Your encryption logic
        pass
    
    def decrypt(self, data: str) -> str:
        # Your decryption logic
        pass
```

### Testing
```python
# Run multiple instances for testing
python mesh_network_app.py --port 9999 --name "Node1"
python mesh_network_app.py --port 10001 --name "Node2"
```

## License

This project is provided as-is for educational and personal use. The networking protocols and cryptographic implementations should be reviewed by security professionals before production deployment.

## Contributing

Potential improvements:
- Implement proper key exchange protocols
- Add voice/video call support
- Create mobile app versions
- Add group chat functionality
- Implement distributed file storage
- Add network visualization tools

## Technical References

- **TCP/IP Protocol**: RFC 793, RFC 791
- **UDP Protocol**: RFC 768
- **JSON Format**: RFC 7159
- **Fernet Encryption**: Cryptography.io specification
- **PBKDF2**: RFC 2898
- **SHA-256**: FIPS 180-4

---

*Built with Python • Tkinter • TCP/UDP • Fernet Encryption*