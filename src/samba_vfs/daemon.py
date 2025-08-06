import typing

from tracim_backend.config import CFG
from tracim_backend.lib.samba_vfs.samba_vfs_server import SambaVFSServer
from tracim_backend.lib.utils.daemon import FakeDaemon
from tracim_backend.lib.utils.logger import logger
from tracim_backend.views import BASE_API
from tracim_backend.lib.samba_vfs.file_system_service import FileSystemService
from tracim_backend.lib.samba_vfs.tracim_file_system_service import TracimFileSystemService
from tracim_backend.lib.utils.logger import logger

class SambaVFSDaemon(FakeDaemon):
    """
    Thread containing a daemon who fetch new mail from a mailbox and
    send http request to a tracim endpoint to handle them.
    """

    def __init__(self, config: "CFG", burst=True, *args, **kwargs):
        """
        :param config: Tracim Config
        :param burst: if true, run one time, if false, run continuously
        """
        super().__init__(*args, **kwargs)
        self.config = config
        self._service:SambaVFSServer = None
        self.burst = burst
        self._args = args
        self._kwargs = kwargs

    def append_thread_callback(self, callback: typing.Callable) -> None:
        logger.warning(self, "SambaVFSDaemon does not implement append_thread_callback")
        pass

    def stop(self) -> None:
        if self._service:
            self._service.stop()

    def run(self) -> None:
        self._service = SambaVFSServer(
            # service=FileSystemService(self.config),
            service=TracimFileSystemService(self.config, self._args, self._kwargs),
            socket="/srv/samba_vfs_tracim_service.sock" # TODO self.config.SAMBA__VFS__SOCKET
        )
        self._service.run()
