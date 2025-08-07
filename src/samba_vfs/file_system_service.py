
import os
from typing import Dict, Any, Optional
import time
import typing
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from pluggy import PluginManager
from pathlib import Path
from tracim_backend.lib.utils.logger import logger

class FileSystemException(Exception):
	def __init__(self, message):
		super().__init__(message)
		self.message = message

class SambaVFSFile:
	def __init__(self, is_directory, path="", 
			mtime=None, atime=None, ctime=None, can_read=True, can_write=True,
			content="", size=16, xattr=None):
		self.exists = True
		self.is_directory = is_directory
		self.size = size
		if ctime is None:
			if mtime is not None:
				ctime = mtime
			elif atime is not None:
				ctime = atime
			else:
				ctime = int(time.time())
		self.ctime = ctime # Create time
		if mtime is None:
			mtime = ctime
		self.mtime = mtime # Modify time
		if atime is None:
			atime = mtime
		self.atime = atime # Access time
		self.can_read = can_read
		self.can_write = can_write
		mode = 0o755 if is_directory else 0o644
		self.mode = mode
		self.content = content
		if xattr is None:
			xattr = {}
		self.xattr = xattr
		self.inode = hash(path) & 0xFFFFFFFF

	def set_path(self, path):
		self.path = path
		self.inode = hash(path) & 0xFFFFFFFF

	def toDict(self):
		return {
			"path" : self.path,
			"exists" : self.exists,
			"is_directory" : self.is_directory,
			"size" : self.size,
			"mtime" : self.mtime,
			"can_read" : self.can_read,
			"can_write" : self.can_write,
			"content" : self.content,
			"xattr" : self.xattr,
			"inode" : self.inode
		}


# Check smb_constants.h to update these constants.
class FileDisposition(IntEnum):
	FILE_SUPERSEDE = 0 			# File exists overwrite/supersede. File not exist create.
	FILE_OPEN = 1 				# File exists open. File not exist fail.
	FILE_CREATE = 2 				# File exists fail. File not exist create.
	FILE_OPEN_IF = 3 				# File exists open. File not exist create.
	FILE_OVERWRITE = 4 			# File exists overwrite. File not exist fail.
	FILE_OVERWRITE_IF = 5 		# File exists overwrite. File not exist create.

# Check smb_constants.h to update these constants.
class FileOptions(IntEnum):
	FILE_DIRECTORY_FILE = 0x0001
	FILE_WRITE_THROUGH = 0x0002
	FILE_SEQUENTIAL_ONLY = 0x0004
	FILE_NO_INTERMEDIATE_BUFFERING = 0x0008
	FILE_SYNCHRONOUS_IO_ALERT = 0x0010	# may be ignored
	FILE_SYNCHRONOUS_IO_NONALERT = 0x0020	# may be ignored
	FILE_NON_DIRECTORY_FILE = 0x0040
	FILE_CREATE_TREE_CONNECTION = 0x0080	# ignore, should be zero
	FILE_COMPLETE_IF_OPLOCKED = 0x0100	# ignore, should be zero
	FILE_NO_EA_KNOWLEDGE = 0x0200
	FILE_EIGHT_DOT_THREE_ONLY = 0x0400 # aka OPEN_FOR_RECOVERY: ignore, should be zero
	FILE_RANDOM_ACCESS = 0x0800
	FILE_DELETE_ON_CLOSE = 0x1000
	FILE_OPEN_BY_FILE_ID = 0x2000
	FILE_OPEN_FOR_BACKUP_INTENT = 0x4000
	FILE_NO_COMPRESSION = 0x8000
	FILE_RESERVER_OPFILTER = 0x00100000	# ignore, should be zero
	FILE_OPEN_REPARSE_POINT = 0x00200000
	FILE_OPEN_NO_RECALL = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY = 0x00800000 # ignore should be zero

class FileInfo(IntEnum):
	FILE_WAS_SUPERSEDED = 0
	FILE_WAS_OPENED = 1
	FILE_WAS_CREATED = 2
	FILE_WAS_OVERWRITTEN = 3

class FLockType(Enum):
	RDLCK = 1
	WRLCK = 2
	RWLCK = 3
	UNLCK = 4

	def __str__(self):
		if self==FLockType.RDLCK:
				return "r"
		if self==FLockType.WRLCK:
				return "w"
		if self==FLockType.RWLCK:
				return "rw"
		if self==FLockType.UNLCK:
				return "un"
	def fromStr(value:str):
		for member in FLockType:
			if str(member)==value:
				return member
		return FLockType.UNLCK


class FLockWhence(Enum):
	SEEK_SET = 1
	SEEK_CUR = 2
	SEEK_END = 3

	def __str__(self):
		if self==FLockWhence.SEEK_SET:
				return "set"
		if self==FLockWhence.SEEK_CUR:
				return "cur"
		if self==FLockWhence.SEEK_END:
				return "end"

	def fromStr(value:str):
		for member in FLockType:
			if str(member)==value:
				return member
		return FLockType.UNLCK

@dataclass
class FLock:
	type:FLockType # F_RDLCK  F_WRLCK  F_UNLCK
	whence:FLockWhence # SEEK_SET SEEK_CUR SEEK_END
	start:int
	len:int
	pid:int

	def toDict(self):
		return {
			"type": str(self.type), 
			"whence": str(self.whence),
			"start": self.start,
			"len": self.len,
			"pid": self.pid
		  }

@dataclass
class SambaVFSSession:
	service:str
	user:str
	connected_at:float
	workspace: Optional[Any]  # Placeholder for workspace object, replace with actual type if known

@dataclass
class SambaVFSFileHandler:
	path:str
	username:str
	flags:int = 0
	mode:int = 0
	position:int = 0
	content:str = b"" # Case file: binary content
	mask:int = 0
	data:object = None
	entries:list[str] = field(default_factory=lambda: []) # Case dir: list of files

class FileSystemService:
	"""
	File system service for handling file operations for Samba VFS Module.
	"""
	
	def __init__(self, config):
		"""
		config: TracimConfig
		"""
		# Initialize your database connection here
		# self.db = db_lib.connect()
		self.db = None  # Placeholder - replace with your actual DB connection
		logger.info(self, "Tracim file service initialized")
		self._file_descriptors:Dict[int, SambaVFSFileHandler] = {}  # Store open file handles
		self._active_sessions:Dict[int, SambaVFSSession] = {}  # Store active connections
		self._active_users:Dict[str, int] = {} # Index connection's id by username.
		self._next_fd = 1  # Incremental ID for file and directory handles, do not use 0 as it can be confused to NULL in C VFS cast.
		self.config = config
		self._files = {}
		self.mount_point = ""

	def get_file_info_fd(self, fd: int, username: str) -> Dict[str, Any]:
		"""
		Same as get_file_info but using file descriptor.
		"""
		finfo = self._file_descriptors.get(fd, None)
		if finfo is None:
			raise FileSystemException("Invalid file descriptor")
		return self.get_file_info(finfo.path, username)

	def get_file_info(self, path: str, username: str) -> Dict[str, Any]:
		"""
		Get information about a file or directory. Owner, rights, group, file type(folder, link)
		"""
		logger.info(self, f"Getting file info for {path} (user: {username})")
		path = os.path.normpath(path)
		if path in [self.mount_point, "/"]:
			path="."
		file_infos = self._files.get(path, None)
		if file_infos is None or not file_infos.exists:
			raise FileSystemException("File not found")
		# logger.info(self, f"file_infos: {file_infos}")
		return file_infos

	def open_file(self, path: str, username: str, flags: int, mode: int, fd: int = 0) -> Dict[str, Any]:
		"""
		Open a file and return a file descriptor to it. Used to to create a new file (using flags).
		"""
		# logger.info(self, f"Opening file {path} (user: {username}, flags: {flags})")
		
		# Check if file exists and user has permissions
		file_info = self.get_file_info(path, username)
		# flags = 133120 = 0x20800 = O_NONBLOCK|O_LARGEFILE
		directory_required = (flags & os.O_DIRECTORY)
		if file_info is None or not file_info.exists:
			create_required = (flags & os.O_CREAT)
			if not create_required:
				raise FileSystemException("File not found (Flags : O_DIRECTORY={directory_required}, O_CREAT={create_required}.)")
			self.create_file(path=path, username=username, disposition=FileDisposition.FILE_CREATE)
			file_info = self.get_file_info(path, username)
		if directory_required:
			if not file_info.is_directory:
				raise FileSystemException("Not a directory")

		# Check read/write permissions based on flags
		read_required = (flags & os.O_RDONLY) or (flags & os.O_RDWR)
		write_required = (flags & os.O_WRONLY) or (flags & os.O_RDWR)
		if read_required and not file_info.can_read:
			raise FileSystemException("Permission denied (read)")
		if write_required and not file_info.can_write:
			raise FileSystemException("Permission denied (write)")

		# Placeholder - store file info for later operations
		if fd<=0:
			fd = self._next_fd
			self._next_fd += 1
		
		self._file_descriptors[fd] = SambaVFSFileHandler(
			path=path,
			username=username,
			flags=flags,
			mode=mode,
			position=0,
			content=file_info.content
		)
		return fd
	
	def read_file(self, handle: int, size: int) -> Dict[str, Any]:
		"""
		Read data from a file.
		"""
		# logger.info(self, f"Reading from handle {handle}, size {size}")
		
		file_info = self._file_descriptors.get(handle, None)
		if file_info is None:
			return {"success": False, "error": "Invalid file handle {handle}."}
		
		content = file_info.content
		position = file_info.position
		
		# Read from current position
		data = content[position:position + size]
		file_info.position += len(data)
		
		return data

	def unlink(self, path:str, fd:int, flags:int) -> bool:
		"""
		Remove a file or a directory, but keep datas to allow close file later.
		TODO : recursive for directories ?
		"""
		finfo = self._files.get(path, None)
		if finfo is not None:
			finfo.exists = False
			self.check_del(finfo)
		return True

	def check_del(self, finfo):
		"""
		Delete a file or directory if it is marked for deletion and all fd are closed.
		"""
		# Check if file is marked for deletion
		if not finfo.exists:
			# Check open files
			path = finfo.path
			for i, file_info in self._file_descriptors.items():
				if file_info.path == path:
					return False
			if path in self._files:
				del self._files[path]
				return True
			# else:
			#	# Should be impossible, but maybe on multi threaded access?
			#	raise FileSystemException("File not found")
		
		# if flags & AT_REMOVEDIR: # AT_REMOVEDIR=0x200 cf fcntl.h
		# del self._files[path]
		# Remove all opened files : Unix way is to wait they close there fd?
		# foodict = {k: v for k, v in self._file_descriptors.items() if v.path!=path}
		# self._file_descriptors = foodict
		return False
	
	def write_file(self, handle: int, data: str, size: int, offset:int) -> Dict[str, Any]:
		"""
		Write data to a file.
		"""
		# logger.info(self, f"Writing to handle {handle}, size {size}")

		file_info = self._file_descriptors.get(handle, None)
		if file_info is None:
			raise FileSystemException("Invalid file handle {handle}.")
		
		# Check write permission based on flags
		flag = file_info.flags
		write_allowed = (flag & os.O_WRONLY) or (flag & os.O_RDWR)
		if not write_allowed:
			raise FileSystemException("File not opened for writing")

		# Placeholder implementation
		position = offset if offset>=0 else file_info.position
		content = file_info.content
		if position >= len(content):
			file_info.content = content + data[:size]
		else:
			file_info.content = content[:position] + data[:size] + content[position + size:]
		file_info.position = position+size
		
		return size

	def create_real_file(self, path:str="", user:str="", is_directory:bool=False):
		self._files[path] = SambaVFSFile(
			path=path,
			is_directory=is_directory
		)

	def create_file(self, path:str="", user:str="", 
			options:FileOptions=0, disposition:FileDisposition=0, attr=0, size=0, fd=-1) -> Dict[str, Any]:
		"""
		Unless it's name, it seam not called to create a file (It's open_file with create options).
		It is call on creating a new directory environment on client side (after "cd"). It is also called to create a directory.
		* @param disposition : 
		* @param options : 
		* @return:
		 * info:FileInfo
		 * fd : File descriptor of the opened file (if asked).
		"""
		if path=="":
			raise FileSystemException("No path given")
		is_dir = options & int(FileOptions.FILE_DIRECTORY_FILE) != 0
		fd = -1
		path = os.path.normpath(path)
		info = -1
		exists = False
		try:
			file_info = self.get_file_info(path, user)
			exists = file_info is not None
		except FileSystemException as e: # File not exists
			if (disposition & int(FileDisposition.FILE_CREATE) != 0) or (disposition == FileDisposition.FILE_OVERWRITE_IF):
				exists = True
				info = FileInfo.FILE_WAS_CREATED
				self.create_real_file(path, user, is_directory=is_dir)
				file_info = self.get_file_info(path, user)
			else:
				logger.info(self, "create_file() : ERROR get_file_info : {e.message}")
				raise FileSystemException(f"No such file : {path}")
		if exists and ((options & int(FileDisposition.FILE_OPEN)) or (options & int(FileDisposition.FILE_OVERWRITE))):
			ok = False
			if fd>0:
				finfo = self._file_descriptors.get(fd, None)
				if finfo is not None and finfo.path==path:
					ok = True
			if not ok:
				if is_dir:
					fd = self.open_directory(path, user, mask=0)
				else:
					fd = self.open_file(path, user, flags=0, mode=0)
				if fd>0 and info==-1:
					if options & int(FileDisposition.FILE_OVERWRITE):
						info = FileInfo.FILE_WAS_OVERWRITTEN
					else:
						info = FileInfo.FILE_WAS_OPENED
		retValue = {
			"size": size,
			"info": int(info),
			"fd": fd,
			"ino": file_info.inode
		}
		return retValue

	def lock_file(self, fd, len, pid, start, type:FLockType, whence:FLockWhence):
		"""
		Work 'like' posix lock()
		"""
		f_getlck = (pid == -1)
		finfo = self._file_descriptors.get(fd, None)
		if finfo is None:
			raise FileSystemException("No such file.")
		lock_infos = self._files.get(finfo.path).get("lock", None)
		if lock_infos is None:
			lock_infos = FLock(FLockType.UNLCK, FLockWhence.SEEK_SET, 0, 0, pid)
		if f_getlck:
			return lock_infos
		if lock_infos.type!=FLockType.UNLCK and pid!=lock_infos.pid: # File was lock
			raise FileSystemException("File '{finfo.path}' already locked by another pid ({pid}!={lock_infos.pid}).")
		elif type==FLockType.UNLCK and pid!=lock_infos.pid: # Want to unlock file
			raise FileSystemException("Can't unlock '{finfo.path}' whitch is locked by another pid ({pid}!={lock_infos.pid}).")
		
		lock_infos.len = len
		lock_infos.pid = pid
		lock_infos.start = start
		lock_infos.type = type
		lock_infos.whence = whence
		return lock_infos
	
	def rename_file(self, src:str, dst:str, srcfd:int, dstfd:int, username:str):
		"""
		Could be used to rename a file or directory.
		"""
		src_fdinfo = self._file_descriptors.get(srcfd, None)
		if src_fdinfo is None:
			raise FileSystemException("Source folder not found by file descriptor ({srcfd}).")
		srcpath = str(Path(src_fdinfo.path) / src)
		if srcfd != dstfd: # If source and dest folders differs.
			dst_fdinfo = self._file_descriptors.get(dstfd, None)
			if dst_fdinfo is None:
				raise FileSystemException("Destination folder not found by file descriptor ({dstfd}).")
		else:
			dst_fdinfo = src_fdinfo
		dstpath = str(Path(dst_fdinfo.path) / dst)
		try:
			src_finfo = self.get_file_info(srcpath, username)
		except FileSystemException as e:
			raise FileSystemException("Source file not found ({srcpath}).")
		try:
			dst_finfo = self.get_file_info(dstpath, username)
			raise FileSystemException("Can't rename {src}, destination file path ever exists ({dst}). Erase it?")
		except FileSystemException as e:
			pass
		src_finfo.set_path(dstpath)
		logger.info(self, f"Renaming file {srcpath} to {dstpath}")
		self._files[dstpath] = src_finfo
		# Change file path from all open
		for fd, info in self._file_descriptors.items():
			if info.path == srcpath:
				info.path = dstpath
		del self._files[srcpath]
		return True
		

	def close_file(self, handle: int) -> Dict[str, Any]:
		"""
		Close a file descriptor.
		"""
		if handle not in self._file_descriptors:
			raise FileSystemException("Invalid file handle")
		file_info = self._file_descriptors.pop(handle)
		file = self._files.get(file_info.path, None)
		if file is not None:
			file.content = file_info.content
			self.check_del(file)
		logger.info(self, f"Closed file {handle} : {file_info.path}")
		return True

	def open_directory(self, path: str, username: str, mask: str) -> Dict[str, Any]:
		"""
		Open a directory for listing containing files. 
		"""
		# logger.info(self, f"Opening directory {path} (user: {username})")
		
		# Check if directory exists and user has permissions
		dir_info = self.get_file_info(path, username)
		if dir_info is None or not dir_info.exists:
			raise FileSystemException("Directory not found")
		if not dir_info.is_directory:
			raise FileSystemException("Not a directory")
		if not dir_info.can_read:
			raise FileSystemException("Permission denied")
		# workspace = self._get_workspace(username)
		# files = workspace.get_member_list()
		# logger.info(self, f"workspace files : {files}")
		# Simulate directory entries based on path
		entries = []
		path = os.path.normpath(path)
		if path.strip()==".":
			path=""
		for fpath, finfo in self._files.items():
			fpath_parent = os.path.dirname(fpath)
			if not finfo.exists:
				continue
			if fpath_parent==path and path not in [".",".."]:
				entries.append(os.path.basename(fpath))
		fd = self._next_fd
		self._next_fd += 1
		self._file_descriptors[fd] = SambaVFSFileHandler(
			path=path,
			username=username,
			mask=mask,
			entries=entries,
			position= 0
		)
		return fd
	
	def read_directory(self, handle: int) -> Dict[str, Any]:
		"""
		Read the next entry from a directory.
		No need to change it for Tracim.
		"""
		# logger.info(self, f"Reading from directory handle {handle}")
		dir_info = self._file_descriptors.get(handle)
		if dir_info is None:
			raise FileSystemException("Invalid directory handle")
		entries = dir_info.entries
		position = dir_info.position
		# logger.info(self, f"read_directory(fd={handle}) : entries={entries}, position={position}")
		if position >= len(entries):
			raise FileSystemException("No more entries")

		# Get next entry
		entry_name = entries[position]
		dir_info.position = position+1
		
		# Determine entry type
		entry_path = os.path.join(dir_info.path, entry_name)
		entry_info = self.get_file_info(entry_path, dir_info.username)
		entry_type = 4 if entry_info.is_directory else 8  # DT_DIR = 4, DT_REG = 8
		inode = entry_info.inode
		return {
			"name": entry_name,
			"type": entry_type,
			"ino": inode,
		}
	
	def close_directory(self, handle: int) -> Dict[str, Any]:
		"""Close a directory handle."""
		# logger.info(self, f"Closing directory handle {handle}")
		if handle not in self._file_descriptors:
			return {"success": False, "error": "Invalid directory handle"}
		# Clean up handle
		dir_info = self._file_descriptors.pop(handle)
		# logger.info(self, f"Closed directory {dir_info.path}")
		return True

	def xattr_file(self, user, path, name, value=None):
		"""
		If value is None: Get xattr value. Else set.
		"""
		finfo = self._files.get(path, None)
		if finfo is None:
			raise FileSystemException("No such file {path}")
		xattrs = finfo.xattr
		if value is None:
			return {"value":xattrs.get(name, "")}
		else:
			xattrs[name] = value
			return True

	def truncate(self, user="", fd=0):
		"""
		Truncate a file to zero length.
		"""
		finfo = self._file_descriptors.get(fd, None)
		if finfo is None:
			raise FileSystemException("No such file descriptor :{fd}")
		finfo.content = ""
		return True

	def allocate(self, user, fd, offset=0, len=0):
		"""
		Allocate space for a file.
		No need to change it for Tracim?
		"""
		finfo = self._file_descriptors.get(fd, None)
		if finfo is None:
			raise FileSystemException("No such file descriptor :{fd}")
		return True

	def init_connection(self, service:str, user:str, mount_point:str="/") -> Dict[str, Any]:
		"""
		Initialize a new connection.
		"""
		logger.info(self, f"Initializing connection for service {service}, user {user}")
		
		# This is where you'd call your actual database library to set up the connection
		# return self.db.init_connection(service, user)
		
		# Placeholder
		self.mount_point = os.path.normpath(mount_point)
		conn_id = self._next_fd
		self._next_fd += 1
		session = SambaVFSSession(service, user, time.time(), None)
		self._active_sessions[conn_id] = session
		self._active_users[user] = conn_id
		self._files = {
			".": SambaVFSFile(
				is_directory=True,
				size=16
			),
			f"user_{user}" : SambaVFSFile(
				is_directory=True,
				size=16
			),
			f"user_{user}/test.txt" : SambaVFSFile(
				is_directory=False,
				size=1324,
				content="Hello, world!"
			),
			f"user_{user}/docs" : SambaVFSFile(
				is_directory=False,
				size=1324,
				content="My docs!"
			)
		}
		for path, f in self._files.items():
			f.set_path(path)
		return conn_id

	def get_session(self, username:str):
		"""
		Get the session for a user.
		"""
		conn_id = self._active_users.get(username)
		if conn_id is None:
			return None
		return self._active_sessions.get(conn_id)

	def set_session(self, username:str, session):
		"""
		Get the session for a user.
		# TODO : Add multi-session by user.
		"""
		conn_id = self._active_users.get(username)
		if conn_id is not None:
			self.disconnect(username)
		else:
			conn_id = self._next_fd
			self._next_fd += 1
		self._active_sessions[conn_id] = session
		self._active_users[username] = conn_id
		return conn_id

	def disconnect(self, username) -> Dict[str, Any]:
		"""
		Close a connection.
		"""
		logger.info(self, f"Disconnecting connection {username}")
		conn_id = self._active_users.get(username, None)
		if conn_id is not None:
			self._active_sessions.pop(conn_id)
			self._active_users.pop(username)
		return True
