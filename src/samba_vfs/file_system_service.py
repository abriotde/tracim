
import os
from typing import Dict, Any, Optional
import time
import typing
from dataclasses import dataclass, field
from pluggy import PluginManager
from tracim_backend.config import CFG
from tracim_backend.exceptions import NotAuthenticated
from tracim_backend.models.tracim_session import TracimSession
from tracim_backend.models.auth import User
from tracim_backend.models.data import Content
from tracim_backend.models.data import Workspace
from tracim_backend.lib.core.user import UserApi
from tracim_backend.lib.utils.logger import logger
from tracim_backend.lib.utils.request import TracimContext
from tracim_backend.lib.webdav.resources import WorkspaceAndContentContainer
from tracim_backend.lib.webdav.dav_provider import ProcessedWebdavPath

@dataclass
class SambaVFSSession:
    service:str
    user:str
    connected_at:float
    workspace:WorkspaceAndContentContainer

@dataclass
class SambaVFSFileHandler:
	path:str
	username:str
	flags:int = 0
	mode:int = 0
	position:int = 0
	content:str = b"" # Case file: binary content
	mask:int = 0
	entries:list[str] = field(default_factory=lambda: []) # Case dir: list of files

class SambaVFSTracimContext(TracimContext):
    def __init__(
        self,
        app_config,
        user:str,
        plugin_manager:PluginManager=None
    ):
        super().__init__()
        self._candidate_parent_content = None
        self._app_config = app_config
        self._session = None
        self._plugin_manager = plugin_manager
        self._username = user
        self.processed_path = None
        self.processed_destpath = None

    @property
    def dbsession(self) -> TracimSession:
        assert self._session
        return self._session

    @dbsession.setter
    def dbsession(self, session: TracimSession) -> None:
        self._session = session

    @property
    def app_config(self) -> CFG:
        return self._app_config

    @property
    def plugin_manager(self) -> PluginManager:
        return self._plugin_manager

    @property
    def current_user(self) -> User:
        """
        Current authenticated user if exist
        """
        if not self._current_user:
            uapi = UserApi(None, show_deleted=True, session=self.dbsession, config=self.app_config)
            user = uapi.get_one_by_login(self._username)
            self.set_user(user)
        return self._current_user

    def _get_current_webdav_username(self) -> str:
        if not self.environ.get("wsgidav.auth.user_name"):
            raise NotAuthenticated("User not found")
        return self.environ["wsgidav.auth.user_name"]

    @property
    def current_workspace(self) -> typing.Optional[Workspace]:
        """
        Workspace of current ressources used if exist, for example,
        if you are editing content 21 in workspace 3,
        current_workspace will be 3.
        """
        return self.processed_path.current_workspace

    @property
    def current_content(self) -> typing.Optional[Content]:
        """
        Current content if exist, if you are editing content 21, current content
        will be content 21.
        """
        return self.processed_path.current_content

    def set_destpath(self, destpath: str) -> None:
        self.processed_destpath = ProcessedWebdavPath(
            path=destpath,
            current_user=self.current_user,
            session=self.dbsession,
            app_config=self.app_config,
        )

    @property
    def candidate_parent_content(self) -> typing.Optional[Content]:
        return self.processed_destpath.current_parent_content

    @property
    def candidate_workspace(self) -> typing.Optional[Workspace]:
        return self.processed_destpath.current_workspace


class FileSystemService:
    """Interface to the actual database operations."""
    
    def __init__(self, config):
        """
        config: TracimConfig
        """
        # Initialize your database connection here
        # self.db = db_lib.connect()
        self.db = None  # Placeholder - replace with your actual DB connection
        logger.info(self, "Tracim file service initialized")
        self.file_handles:Dict[int, SambaVFSFileHandler] = {}  # Store open file handles
        self.dir_handles:Dict[int, SambaVFSFileHandler] = {}  # Store open directory handles
        self.active_connections:Dict[int, SambaVFSSession] = {}  # Store active connections
        self.active_users:Dict[str, int] = {} # Index connection's id by username.
        self.next_handle_id = 1  # Incremental ID for file and directory handles, do not use 0 as it can be confused to NULL in C VFS cast.
        self.config = config
        self._files = {}
        self.mount_point = ""

    def get_file_info_fd(self, fd: int, username: str) -> Dict[str, Any]:
        finfo = self.file_handles.get(fd, None)
        if finfo is None:
            return {"exists": False}
        return self.get_file_info(finfo.path, username)

    def get_file_info(self, path: str, username: str) -> Dict[str, Any]:
        """Get information about a file or directory."""
        logger.info(self, f"Getting file info for {path} (user: {username})")
        # logger.info(self, f"Opened files are {self.file_handles}")
        default_file_infos = {"exists": False}
        path = os.path.normpath(path)
        if path in [self.mount_point, "/"]:
            path="."
        file_infos = self._files.get(path, default_file_infos)
        # logger.info(self, f"file_infos: {file_infos}")
        return file_infos
    
    def open_file(self, path: str, username: str, flags: int, mode: int) -> Dict[str, Any]:
        """Open a file and return a handle to it."""
        logger.info(self, f"Opening file {path} (user: {username}, flags: {flags})")
        # logger.info(self, f"Opened files are {self.file_handles}")
        
        # Check if file exists and user has permissions
        file_info = self.get_file_info(path, username)
        if not file_info.get("exists", False):
            return {"success": False, "error": "File not found"}
        
        # Check read/write permissions based on flags
        read_required = (flags & os.O_RDONLY) or (flags & os.O_RDWR)
        write_required = (flags & os.O_WRONLY) or (flags & os.O_RDWR)
        
        if read_required and not file_info.get("can_read", False):
            return {"success": False, "error": "Permission denied (read)"}
        
        if write_required and not file_info.get("can_write", False):
            return {"success": False, "error": "Permission denied (write)"}
        
        # Placeholder - store file info for later operations
        handle_id = self.next_handle_id
        self.next_handle_id += 1
        
        self.file_handles[handle_id] = SambaVFSFileHandler(
            path= path,
            username= username,
            flags= flags,
            mode= mode,
            position= 0,
            content= file_info.get("content", "")
		)
        return {
            "success": True,
            "handle": handle_id
        }
    
    def read_file(self, handle: int, size: int) -> Dict[str, Any]:
        """Read data from a file."""
        logger.info(self, f"Reading from handle {handle}, size {size}")
        
        file_info = self.file_handles.get(handle, None)
        if file_info is None:
            return {"success": False, "error": "Invalid file handle {handle}."}
        
        content = file_info.content
        position = file_info.position
        
        # Read from current position
        data = content[position:position + size]
        file_info.position += len(data)
        
        # This is where you'd call your actual database library
        # TODO
        
        return {
            "success": True,
            "data": data,
            "size": len(data)
        }
    
    def write_file(self, handle: int, data: str, size: int) -> Dict[str, Any]:
        """Write data to a file."""
        logger.info(self, f"Writing to handle {handle}, size {size}")
        
        if handle not in self.file_handles:
            return {"success": False, "error": "Invalid file handle"}
        
        file_info = self.file_handles[handle]
        
        # Check write permission based on flags
        write_allowed = (file_info["flags"] & os.O_WRONLY) or (file_info["flags"] & os.O_RDWR)
        if not write_allowed:
            return {"success": False, "error": "File not opened for writing"}
        
        # This is where you'd call your actual database library
        # return self.db.write_file(handle, data, size)
        
        # Placeholder implementation
        position = file_info.position
        content = file_info.content
        
        # If position is at the end, append
        if position >= len(content):
            file_info.content = content + data[:size]
        else:
            # Otherwise, overwrite/insert
            file_info.content = content[:position] + data[:size] + content[position + size:]
        
        file_info.position += size
        
        return {
            "success": True,
            "bytes_written": size
        }

    def create_file(self, path:str="", mode=0, flags=0, attr=0, size=0) -> Dict[str, Any]:
        if path=="":
            return {
                "success": False,
                "error": "No path given"
            }
        path = os.path.normpath(path)
        self._files[path] = {
            "exists": True,
            "is_directory": False,
            "size": size,
            "mtime": int(time.time()),
            "can_read": True,
            "can_write": True
        }
        return {
			"success": True,
			"size": size
		}

    def close_file(self, handle: int) -> Dict[str, Any]:
        """Close a file handle."""
        if handle not in self.file_handles:
            return {"success": False, "error": "Invalid file handle"}
        file_info = self.file_handles.pop(handle)
        logger.info(self, f"Closed file {handle} : {file_info.path}")
        return {"success":True, "fd":handle, "path":file_info.path}
    
    def open_directory(self, path: str, username: str, mask: str) -> Dict[str, Any]:
        """Open a directory for reading."""
        logger.info(self, f"Opening directory {path} (user: {username})")
        
        # Check if directory exists and user has permissions
        dir_info = self.get_file_info(path, username)
        if not dir_info.get("exists", False):
            return {"success": False, "error": "Directory not found"}
        
        if not dir_info.get("is_directory", False):
            return {"success": False, "error": "Not a directory"}
        
        if not dir_info.get("can_read", False):
            return {"success": False, "error": "Permission denied"}
        
        # Placeholder - set up directory contents for readdir
        handle_id = self.next_handle_id
        self.next_handle_id += 1
        
        # workspace = self._get_workspace(username)
        # files = workspace.get_member_list()
        # logger.info(self, f"workspace files : {files}")
        # Simulate directory entries based on path
        entries = []
        path = os.path.normpath(path)
        if path.strip()==".":
            path=""
        for fpath in self._files.keys():
            fpath_parent = os.path.dirname(fpath)
            logger.info(self, f"Test2 {fpath_parent} : {path}")
            if fpath_parent==path and path not in [".",".."]:
                entries.append(os.path.basename(fpath))
        self.dir_handles[handle_id] = SambaVFSFileHandler(
            path= path,
            username= username,
            mask= mask,
            entries= entries,
            position= 0
		)
        
        return {
            "success": True,
            "handle": handle_id,
            "entries": entries
        }
    
    def read_directory(self, handle: int) -> Dict[str, Any]:
        """Read the next entry from a directory."""
        logger.info(self, f"Reading from directory handle {handle}")
        if handle not in self.dir_handles:
            return {"success": False, "error": "Invalid directory handle"}
        dir_info = self.dir_handles[handle]
        entries = dir_info.entries
        position = dir_info.position
        logger.info(self, f"read_directory(fd={handle}) : entries={entries}, position={position}")
        if position >= len(entries):
            return {"success": False, "error": "No more entries"}
        
        # Get next entry
        entry_name = entries[position]
        dir_info.position = position+1
        
        # Determine entry type
        entry_path = os.path.join(dir_info.path, entry_name)
        entry_info = self.get_file_info(entry_path, dir_info.username)
        entry_type = 4 if entry_info.get("is_directory", False) else 8  # DT_DIR = 4, DT_REG = 8
        
        return {
            "success": True,
            "name": entry_name,
            "type": entry_type,
            "ino": hash(entry_path) & 0xFFFFFFFF  # Fake inode number
        }
    
    def close_directory(self, handle: int) -> Dict[str, Any]:
        """Close a directory handle."""
        logger.info(self, f"Closing directory handle {handle}")
        
        if handle not in self.dir_handles:
            return {"success": False, "error": "Invalid directory handle"}
        
		# Clean up handle
        dir_info = self.dir_handles.pop(handle)
        logger.info(self, f"Closed directory {dir_info.path}")
        return {"success":True, "handle":handle}

    def init_connection(self, service:str, user:str, mount_point:str="/") -> Dict[str, Any]:
        """Initialize a new connection."""
        logger.info(self, f"Initializing connection for service {service}, user {user}")
        
        # This is where you'd call your actual database library to set up the connection
        # return self.db.init_connection(service, user)
        
        # Placeholder
        self.mount_point = os.path.normpath(mount_point)
        conn_id = self.next_handle_id
        self.next_handle_id += 1
        context = SambaVFSTracimContext(self.config, "TheAdmin") # TODO User is set in hardcoded to 'TheAdmin' should be 'user'
        """ workspace_container = WorkspaceAndContentContainer(
            path="/",
            environ={},
            label="",
            content=None,
            workspace=None,
            provider=None,
            tracim_context=context
        ) """
        session = SambaVFSSession(service, user, time.time(), None)
        self.active_connections[conn_id] = session
        self.active_users[user] = conn_id
        self._files = {
        	".": {
                "exists": True,
                "is_directory": True,
                "size": 16,
                "mtime": int(time.time()),
                "can_read": True,
                "can_write": True
            },
        	f"user_{user}" : {
                "exists": True,
                "is_directory": True,
                "size": 16,
                "mtime": int(time.time()),
                "can_read": True,
                "can_write": True
            },
            f"user_{user}/test.txt" : {
                "exists": True,
                "is_directory": False,
                "size": 1324,
                "mtime": int(time.time()),
                "can_read": True,
                "can_write": True,
                "content": "Hello, world!"
            },
            f"user_{user}/docs" : {
                "exists": True,
                "is_directory": False,
                "size": 1324,
                "mtime": int(time.time()),
                "can_read": True,
                "can_write": True,
                "content": "My docs!"
            }
        }
        return {"success": True, "connection_id": conn_id}

    def _get_workspace(self, username:str):
        """
        """
        conn_id = self.active_users.get(username)
        if conn_id is None:
            return None
        connection = self.active_connections.get(conn_id)
        if connection is None:
            return None
        return connection.workspace

    def disconnect(self, conn_id: Optional[int] = None) -> Dict[str, Any]:
        """Close a connection."""
        logger.info(self, f"Disconnecting connection {conn_id}")

        infos = self.active_connections.get(conn_id, None)
        if infos is not None:
            self.active_connections.pop(conn_id)
            self.active_users.pop(infos["user"])
        
        return {"success": True}
