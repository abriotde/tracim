# coding=utf-8
# Runner for daemon
from tracim_backend.lib.samba_vfs.daemon import SambaVFSDaemon
from tracim_backend.lib.utils.daemon import initialize_config_from_environment

app_config = initialize_config_from_environment()
daemon = SambaVFSDaemon(app_config, burst=False)
daemon.run()
