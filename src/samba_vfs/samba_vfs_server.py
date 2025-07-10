#!/usr/bin/env python3
"""
Python service that acts as a bridge between Samba VFS module and database.
Uses Unix domain sockets for IPC.
"""

import os
import json
import socket
import threading
import logging
from typing import Dict, Any
import time
from tracim_backend.lib.utils.logger import logger

class SambaVFSServer:
    """Server that listens on a Unix domain socket and handles requests."""

    def __init__(self, service, socket:str=None):
        self._socket_path = socket
        self._fs_service = service
        self.running = False
        self.sock = None
    
    def run(self):
        """Start the server."""
        # Remove socket file if it already exists
        try:
            os.unlink(self._socket_path)
        except OSError:
            if os.path.exists(self._socket_path):
                raise
        
        # Create socket
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.bind(self._socket_path)
        
        # Set permissions on socket file
        os.chmod(self._socket_path, 0o777)
        
        # Start listening
        self.sock.listen(5)
        self.running = True

        logger.info(self, f"Server started, listening on {self._socket_path}")

        # Accept connections
        while self.running:
            try:
                conn, addr = self.sock.accept()
                client_thread = threading.Thread(target=self.handle_client, args=(conn,))
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                logger.error(self, f"Error accepting connection: {e}")
                if not self.running:
                    break
    
    def stop(self):
        """Stop the server."""
        self.running = False
        if self.sock:
            self.sock.close()
        # Remove socket file
        try:
            os.unlink(self._socket_path)
        except OSError:
            pass
        logger.info(self, "Server stopped")
    
    def handle_client(self, conn: socket.socket):
        """Handle a client connection."""
        client_id = threading.get_ident()
        logger.info(self, f"New client connection: {client_id}")

        try:
            while self.running:
                # Receive data
                data = conn.recv(8192)
                if not data:
                    break
                # Parse request
                try:
                    d = data.decode('utf-8').strip()
                    if d == "":
                        logger.warning(self, f"Received empty data from client {client_id}")
                    else:
                        request = json.loads(d)
                except json.JSONDecodeError as e:
                    logger.error(self, f"Invalid JSON: '{d}' : error {e}")
                    response = {"success": False, "error": "Invalid JSON request"}
                    conn.sendall(json.dumps(response).encode('utf-8'))
                    continue
                response = self.process_request(request)
                
                # Send response
                conn.sendall(json.dumps(response).encode('utf-8'))
        except Exception as e:
            logger.error(self, f"Error handling client {client_id}: {e}")
        finally:
            conn.close()
            logger.info(self, f"Client connection closed: {client_id}")

    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a client request and return a response."""
        op = request.get("op")
        logger.debug(self, f"Processing request: {op}")
        try:
            if op == "init":
                return self._fs_service.init_connection(
                    request.get("service", ""),
                    request.get("user", "")
                )
            elif op == "disconnect":
                return self._fs_service.disconnect()
            elif op == "stat":
                file_info = self._fs_service.get_file_info(
                    request.get("path", ""),
                    request.get("user", "")
                )
                
                if not file_info.get("exists", False):
                    logger.warning(self, f"process_request(stat) : File not found: {request.get('path', '')}")
                    return {"success": False, "error": "File not found"}
                logger.warning(self, f"process_request(stat) : File = {file_info}")
                return {
                    "success": True,
                    "size": file_info.get("size", 0),
                    "mode": (0o40755 if file_info.get("is_directory", False) else 0o00644),
                    "mtime": file_info.get("mtime", int(time.time()))
                }
            elif op == "open":
                return self._fs_service.open_file(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("flags", 0),
                    request.get("mode", 0)
                )
            elif op == "read":
                return self._fs_service.read_file(
                    request.get("handle", -1),
                    request.get("size", 0)
                )
            elif op == "write":
                return self._fs_service.write_file(
                    request.get("handle", -1),
                    request.get("data", ""),
                    request.get("size", 0)
                )
            elif op == "close":
                return self._fs_service.close_file(
                    request.get("handle", -1)
                )
            elif op == "opendir":
                return self._fs_service.open_directory(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("mask", "")
                )
            elif op == "readdir":
                return self._fs_service.read_directory(
                    request.get("handle", -1)
                )
            elif op == "closedir":
                return self._fs_service.close_directory(
                    request.get("handle", -1)
                )
            else:
                logger.warning(self, f"process_request({op}) : Unknown operation")
                return {"success": False, "error": f"Unknown operation: {op}"}
        except Exception as e:
            logger.error(self, f"Error processing request {op}: {e}")
            return {"success": False, "error": str(e)}
