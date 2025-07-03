#!/usr/bin/env python3
"""
Python service that acts as a bridge between Samba VFS module and database.
Uses Unix domain sockets for IPC.
"""

import os
import sys
import json
import socket
import threading
import logging
from typing import Dict, Any
import time

# Add parent directory to path so we can import db_service
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from db_service import DatabaseService  # Import your actual database service module

# Import your actual database library here
# import your_database_library as db_lib

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("vfs_tracim_service.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("vfs_tracim_service")

# Socket path
SOCKET_PATH = "/var/run/vfs_tracim_service.sock"

# Globals
active_connections = {}  # Map of connection IDs to user info
file_handles = {}        # Map of file handles to file info
dir_handles = {}         # Map of directory handles to directory info
next_handle_id = 1       # Counter for generating unique handle IDs



class SocketServer:
    """Server that listens on a Unix domain socket and handles requests."""
    
    def __init__(self, socket_path: str):
        self.socket_path = socket_path
        self.db_service = DatabaseService()
        self.running = False
        self.sock = None
    
    def start(self):
        """Start the server."""
        # Remove socket file if it already exists
        try:
            os.unlink(self.socket_path)
        except OSError:
            if os.path.exists(self.socket_path):
                raise
        
        # Create socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self.socket_path)
        
        # Set permissions on socket file
        os.chmod(self.socket_path, 0o777)
        
        # Start listening
        self.sock.listen(5)
        self.running = True
        
        logger.info(f"Server started, listening on {self.socket_path}")
        
        # Accept connections
        while self.running:
            try:
                conn, addr = self.sock.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn,))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(f"Error accepting connection: {e}")
                if not self.running:
                    break
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.sock:
            self.sock.close()
        # Remove socket file
        try:
            os.unlink(self.socket_path)
        except OSError:
            pass
        logger.info("Server stopped")
    
    def handle_client(self, conn: socket.socket):
        """Handle a client connection."""
        client_id = threading.get_ident()
        logger.info(f"New client connection: {client_id}")
        
        try:
            while self.running:
                # Receive data
                data = conn.recv(8192)
                if not data:
                    break
                # Parse request
                try:
                    request = json.loads(data.decode('utf-8'))
                except json.JSONDecodeError as e:
                    logger.error(f"Invalid JSON: {e}")
                    response = {"success": False, "error": "Invalid JSON request"}
                    conn.sendall(json.dumps(response).encode('utf-8'))
                    continue
                # Process request
                response = self.process_request(request)
                
                # Send response
                conn.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(f"Error handling client {client_id}: {e}")
        finally:
            conn.close()
            logger.info(f"Client connection closed: {client_id}")
    
    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a client request and return a response."""
        op = request.get("op")
        logger.debug(f"Processing request: {op}")
        
        try:
            if op == "init":
                return self.db_service.init_connection(
                    request.get("service", ""),
                    request.get("user", "")
                )
            elif op == "disconnect":
                return self.db_service.disconnect()
            elif op == "stat":
                file_info = self.db_service.get_file_info(
                    request.get("path", ""),
                    request.get("user", "")
                )
                
                if not file_info.get("exists", False):
                    return {"success": False, "error": "File not found"}
                
                return {
                    "success": True,
                    "size": file_info.get("size", 0),
                    "is_directory": file_info.get("is_directory", False),
                    "mtime": file_info.get("mtime", int(time.time()))
                }
            elif op == "open":
                return self.db_service.open_file(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("flags", 0),
                    request.get("mode", 0)
                )
            elif op == "read":
                return self.db_service.read_file(
                    request.get("handle", -1),
                    request.get("size", 0)
                )
            elif op == "write":
                return self.db_service.write_file(
                    request.get("handle", -1),
                    request.get("data", ""),
                    request.get("size", 0)
                )
            elif op == "close":
                return self.db_service.close_file(
                    request.get("handle", -1)
                )
            elif op == "opendir":
                return self.db_service.open_directory(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("mask", "")
                )
            elif op == "readdir":
                return self.db_service.read_directory(
                    request.get("handle", -1)
                )
            elif op == "closedir":
                return self.db_service.close_directory(
                    request.get("handle", -1)
                )
            else:
                logger.warning(f"Unknown operation: {op}")
                return {"success": False, "error": f"Unknown operation: {op}"}
        except Exception as e:
            logger.error(f"Error processing request {op}: {e}")
            return {"success": False, "error": str(e)}

def main():
    """Main entry point."""
    try:
        server = SocketServer(SOCKET_PATH)
        logger.info("Starting server...")
        server.start()
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received, shutting down...")
        server.stop()
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())