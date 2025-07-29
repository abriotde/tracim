#!/usr/bin/env python3
"""
Python service that acts as a bridge between Samba VFS module and database.
Uses Unix domain sockets for IPC.
"""

import os
import json
import socket
import threading
import traceback
from typing import Dict, Any
import time
from tracim_backend.lib.utils.logger import logger
from tracim_backend.lib.samba_vfs.file_system_service import (
	FileSystemException, FLockType, FLockWhence
)

class SambaVFSServer:
    """Server that listens on a Unix domain socket and handles requests."""

    MAX_RESPONSE_SIZE = 32768
    MAX_REQUEST_SIZE = 65536
    # SOCKET_ENCODING = "utf-8"
    SOCKET_ENCODING = "ascii"

    def __init__(self, service, socket:str=None):
        """
        """
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
                data = b''
                data = conn.recv(self.MAX_REQUEST_SIZE)
                if not data:
                    logger.info(self, f"Recv nothing.")
                    break
                # Parse request
                requests = []
                try:
                    d = data.decode(encoding=self.SOCKET_ENCODING).strip()
                    if d == "":
                        logger.warning(self, f"Received empty data from client {client_id}")
                    else:
                        requests = d.split('\n')
                except json.JSONDecodeError as e:
                    logger.error(self, f"Invalid JSON: '{d}' : error {e}")
                    response = {"success": False, "error": "Invalid JSON request"}
                    conn.sendall((json.dumps(response)+"\n").encode(encoding=self.SOCKET_ENCODING))
                    continue
                for request in requests:
                    if len(request)>1:
                        response = self.process_request(json.loads(request))
					    # Send response
                        resp = (json.dumps(response)+"\n").encode(encoding=self.SOCKET_ENCODING)
                        logger.warning(self, f"send response {resp}")
                        assert(len(resp)<self.MAX_RESPONSE_SIZE)
                        conn.sendall(resp)
        except Exception as e:
            logger.error(self, f"Error handling client {client_id}: {e}")
        finally:
            conn.close()
            logger.info(self, f"Client connection closed: {client_id}")

    def process_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """Process a client request and return a response."""
        op = request.get("op")
        logger.debug(self, f"Processing request: {op} : {request}")
        try:
            if op == "init":
                return self._fs_service.init_connection(
                    request.get("service", ""),
                    request.get("user", ""),
                    mount_point=request.get("mount", "/")
                )
            elif op == "disconnect":
                return self._fs_service.disconnect()
            elif op == "stat":
                path = request.get("path", "")
                user = request.get("user", "")
                if path!="":
                    file_info = self._fs_service.get_file_info(path, user)
                else:
                    fd = request.get("fd", -1)
                    file_info = self._fs_service.get_file_info_fd(fd, user)
                
                if not file_info.get("exists", False):
                    logger.warning(self, f"process_request(stat) : File not found: {request.get('path', '')}")
                    return {"success": False, "error": "File not found"}
                # logger.warning(self, f"process_request(stat) : File = {file_info}")
                is_dir = file_info.get("is_directory", False)
                mode = file_info.get("mode", (0o755 if is_dir else 0o644))
                mtime = file_info.get("mtime", int(time.time()))
                return {
                    "success": True,
                    "size": file_info.get("size", 0),
                    "is_dir": is_dir,
                    "mode": mode,
                    "mtime": file_info.get("mtime", int(time.time())),
                    "ctime": file_info.get("ctime", mtime),
                    "atime": file_info.get("atime", mtime),
                }
            elif op == "open":
                result = {"fd": self._fs_service.open_file(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("flags", 0),
                    request.get("mode", 0)
                )}
            elif op == "read":
                return self._fs_service.read_file(
                    request.get("fd", -1),
                    request.get("size", 0)
                )
            elif op == "write":
                return self._fs_service.write_file(
                    request.get("fd", -1),
                    request.get("data", ""),
                    request.get("size", 0),
                    request.get("offset", 0)
                )
            elif op == "create":
                return self._fs_service.create_file(
                    path=request.get("path", ""),
                    user=request.get("user", ""),
                    disposition=request.get("disposition", 0),
                    options=request.get("options", 0),
                    attr=request.get("attr", 0),
                    size=request.get("size", 0),
                    is_dir=request.get("dir", 0)==1,
                    fd=request.get("fd", -1)
                )
            elif op == "close":
                return self._fs_service.close_file(
                    request.get("handle", -1)
                )
            elif op == "opendir":
                result = {"fd": self._fs_service.open_directory(
                    request.get("path", ""),
                    request.get("user", ""),
                    request.get("mask", "")
                )}
            elif op == "readdir":
                return self._fs_service.read_directory(
                    request.get("handle", -1)
                )
            elif op == "closedir":
                return self._fs_service.close_directory(
                    request.get("handle", -1)
                )
            elif op == "unlink":
                result = self._fs_service.unlink(
                    path=request.get("path", ""),
                    fd=request.get("fd", 0),
                    flags=request.get("flags", 0)
                )
            elif op == "lock":
                    result = self._fs_service.lock_file(
						fd=request.get("fd", -1),
						len=request.get("len", -1),
						pid=request.get("pid", -1),
						start=request.get("start", -1),
						type=FLockType.fromStr(request.get("type", "")),
						whence=FLockWhence.fromStr(request.get("whence", ""))
					).toDict()
            elif op == "rename":
                    result = self._fs_service.rename_file(
						src=request.get("src", ""),
						dst=request.get("dst", ""),
						srcfd=request.get("srcfd", 0),
						dstfd=request.get("dstfd", 0)
					)
            elif op == "xattr":
                    result = self._fs_service.xattr_file(
						user=request.get("user", ""),
						path=request.get("path", ""),
						name=request.get("name", ""),
						value=request.get("value", None)
					)
            elif op == "truncate":
                    result = self._fs_service.truncate(
						user=request.get("user", ""),
						fd=request.get("fd", 0)
					)
            elif op == "allocate":
                    result = self._fs_service.allocate(
						user=request.get("user", ""),
						fd=request.get("fd", 0),
						offset=request.get("offset", 0),
						len=request.get("len", 0)
					)
            else:
                logger.warning(self, f"process_request({op}) : Unknown operation")
                return {"success": False, "error": f"Unknown operation: {op}"}
            if isinstance(result, dict):
                result["success"] = True
            else:
                result = {"success":True}
            return result
        except FileSystemException as e:
            return {"success":False, "error":e.message}
        except Exception as e:
            tb = traceback.format_exc()
            logger.error(self, f"Error processing request {op}: {e} : {tb}")
            return {"success": False, "error": str(e)}
