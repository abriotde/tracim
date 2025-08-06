
import os
from typing import Dict, Any, Optional
import time
import typing
from enum import Enum, IntEnum
from dataclasses import dataclass, field
from pluggy import PluginManager
from pathlib import Path
import transaction
from wsgidav.dav_provider import DAVCollection
from wsgidav.dav_provider import DAVNonCollection
from wsgidav.dav_provider import _DAVResource
from tracim_backend.config import CFG
from tracim_backend.exceptions import NotAuthenticated
from tracim_backend.models.tracim_session import TracimSession
from tracim_backend.models.auth import User
from tracim_backend.models.data import (
	Content, Workspace
)
from tracim_backend.models.setup_models import (
	create_dbsession_for_context, get_engine, get_session_factory
)
from tracim_backend.lib.core.user import UserApi
from tracim_backend.lib.core.content import ContentApi
from tracim_backend.lib.core.plugins import init_plugin_manager
from tracim_backend.lib.utils.logger import logger
from tracim_backend.lib.utils.request import TracimContext
from tracim_backend.lib.webdav.resources import (
	WorkspaceAndContentContainer,
	FolderResource,
	FileResource,
	RootResource
)
from tracim_backend.lib.webdav.dav_provider import (
	ProcessedWebdavPath, TracimDavProvider
)
from tracim_backend.tests.utils import WedavEnvironFactory
from tracim_backend.tests.utils import UserApiFactory

from .file_system_service import (
	FileSystemException,
	FileDisposition,
	FileOptions,
	FileInfo,
	FLockType,
	FLockWhence,
	FLock,
	FileSystemService,
	SambaVFSSession,
	SambaVFSFileHandler,
	SambaVFSFile
)
from pathlib import PurePath

class SambaVFSTracimSession(TracimSession):
	"""
	"""
	def __init__(
			self, service:str,
			user:str,
			connected_at:float,
			workspace: Optional[Any],
			args:tuple=(),
			kwargs:dict=None
	):
		super().__init__(args, kwargs)
		self.service = service
		self.user = user
		self.connected_at = connected_at
		self.workspace = workspace

class SambaVFSTracimContext(TracimContext):
	"""
	See dav_provider.py : WebdavTracimContext
	"""
	def __init__(
		self,
		app_config,
		user:str,
		plugin_manager:PluginManager=None,
		session:TracimSession=None
	):
		super().__init__()
		self._candidate_parent_content = None
		self._app_config = app_config
		self._session = session
		if plugin_manager is None:
			plugin_manager = init_plugin_manager(app_config)
		self._plugin_manager = plugin_manager
		self._username = user
		self.processed_path = None
		self.processed_destpath = None

	def set_path(self, path: str) -> None:
		"""
		See dav_provider.py : WebdavTracimContext.set_path
		"""
		self.processed_path = ProcessedWebdavPath(
			path=path,
			current_user=self.current_user,
			session=self.dbsession,
			app_config=self.app_config,
		)

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
			self._current_user = user
		return self._current_user

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


class TracimFileSystemService(FileSystemService):
	"""
	File system service for handling file operations for Samba VFS Module.
	"""
	
	def __init__(self, config, *args, **kwargs):
		"""
		config: TracimConfig
		"""
		super().__init__(config)
		self._args = args
		self._kwargs = kwargs

	def get_file_info(self, path: str, username: str) -> Dict[str, Any]:
		"""
		Get information about a file or directory. Owner, rights, group, file type(folder, link)
		"""
		if path in [self.mount_point, "."]:
			path="/"
		session = self.get_session(username)
		filelist = PurePath(path).parts
		if len(filelist) == 0 or filelist[0]=="":
			fileresource = session
		else:
			fileresource = session.provider.get_resource_inst(
				path,
				session.environ,
			)
		if fileresource is None:
			raise FileSystemException("File not found ({filelist}).")
		logger.info(self, f"File resource : {fileresource} ({filelist})")
		logger.debug(self, f"get_file_info: {path} for user {username}")
		if isinstance(fileresource, FolderResource) \
				or isinstance(fileresource, RootResource) \
				or fileresource==session:
			is_dir = True
		elif isinstance(fileresource, FileResource):
			is_dir = False
		else:
			is_dir = False
		return SambaVFSFile(path=path, is_directory=is_dir)

	def open_file(self, path: str, username: str, flags: int, mode: int, fd: int = 0) -> Dict[str, Any]:
		"""
		Open a file and return a file descriptor to it. Used to to create a new file (using flags).
		"""
		return super().open_file(
			path=path,
			username=username,
			flags=flags,
			mode=mode,
			fd=fd
		)
	
	def read_file(self, handle: int, size: int) -> Dict[str, Any]:
		"""
		Read data from a file.
		"""
		return super().read_file(
			handle=handle,
			size=size
		)

	def unlink(self, path:str, fd:int, flags:int) -> bool:
		"""
		Remove a file or a directory, but keep datas to allow close file later.
		TODO : recursive for directories ?
		"""
		return super().unlink(
			path=path,
			fd=fd,
			flags=flags
		)
	
	def write_file(self, handle: int, data: str, size: int, offset:int) -> Dict[str, Any]:
		"""
		Write data to a file.
		"""
		return super().write_file(
			handle=handle,
			data=data,
			size=size,
			offset=offset
		)

	def create_real_file(self, path:str="", user:str="", is_directory:bool=False):
		"""
		TODO
		"""
		return True

	def lock_file(self, fd, len, pid, start, type:FLockType, whence:FLockWhence):
		"""
		Work 'like' posix lock()
		"""
		return super().lock_file(
			fd=fd,
			len=len,
			pid=pid,
			start=start,
			type=type,
			whence=whence
		)
	
	def rename_file(self, src:str, dst:str, srcfd:int, dstfd:int, username:str):
		"""
		Could be used to rename a file or directory.
		"""
		
		return super().rename_file(
			src=src,
			dst=dst,
			srcfd=srcfd,
			dstfd=dstfd
		)
		

	def close_file(self, handle: int) -> Dict[str, Any]:
		"""
		Close a file descriptor.
		"""
		return super().close_file(
			handle=handle
		)

	def open_directory(self, path: str, username: str, mask: str) -> Dict[str, Any]:
		"""
		Open a directory for listing containing files. 
		"""
		session = self.get_session(username)
		# TODO go to path
		entries = session.get_member_names()
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
	
	def close_directory(self, handle: int) -> Dict[str, Any]:
		"""Close a directory handle."""
		return super().close_directory(
			handle=handle
		)

	def xattr_file(self, user, path, name, value=None):
		"""
		If value is None: Get xattr value. Else set.
		"""
		return super().xattr_file(
			user=user,
			path=path,
			name=name,
			value=value
		)

	def truncate(self, user="", fd=0):
		"""
		Truncate a file to zero length.
		"""
		return super().truncate(
			user=user,
			fd=fd
		)

	def init_connection(self, service:str, username:str, mount_point:str="/") -> Dict[str, Any]:
		"""
		Initialize a new connection.
		"""
		logger.info(self, f"Initializing connection for service {service}, user {username}")

		# This is where you'd call your actual database library to set up the connection
		# return self.db.init_connection(service, user)
		
		# Placeholder
		self.mount_point = os.path.normpath(mount_point)
		# middleware.py : TracimEnv.__call__(self, environ, start_response)
		# session = SambaVFSTracimSession(service, user, time.time(), None, args=self._args, kwargs=self._kwargs)
		tracim_context = SambaVFSTracimContext(self.config, user="TheAdmin") # TODO User is set in hardcoded to 'TheAdmin' should be 'user'
		engine = get_engine(self.config)
		session_factory = get_session_factory(engine)
		dbsession = create_dbsession_for_context(
			session_factory, transaction.manager, tracim_context
		)
		tracim_context.dbsession = dbsession
		path = "" # TODO : Set the path to "/" ?
		tracim_context.set_path(path)
		webdav_provider = TracimDavProvider(app_config=self.config, manage_locks=False)
		user_api = UserApi(
            session=dbsession,
            config=self.config,
            current_user=None,
        )
		admin_user = user_api.get_one_by_login("admin@admin.admin")
		webdav_environ_factory = WedavEnvironFactory(
			provider=webdav_provider,
			session=dbsession,
			app_config=self.config,
			admin_user=admin_user,
		)
		environ = webdav_environ_factory.get(admin_user)
		root = webdav_provider.get_resource_inst(
			"/",
			environ=environ
		)
		children = root.get_member_list() # WorkspaceResource(DAVCollection) list : https://wsgidav.readthedocs.io/en/latest/_autosummary/wsgidav.dav_provider.DAVCollection.html
		# content_api = ContentApi(
		# 	session=dbsession,
		# 	config=self.config,
		# 	current_user=admin_user,
		# 	show_active=True,
		# 	show_deleted=False,
		# 	show_archived=False,
		# )
		workspace_container = WorkspaceAndContentContainer(
			path=path,
			environ=environ,
			label="",
			content=None,
			workspace=children[0].workspace if children else None,  # Use first child as workspace if exists
			provider=webdav_provider,
			tracim_context=tracim_context
		)
		conn_id = self.set_session(username, workspace_container)
		logger.info(self, f"Session initialized: {conn_id} for user {username} on service {service}")
		return conn_id