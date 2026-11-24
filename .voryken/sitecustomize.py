"""Enabled only for opted-in worker subprocesses, never globally on the PC."""
import os
if os.environ.get('VORYKEN_SQLITE_RPC_CONFIG'):
    from sqlite_bridge_client import install_from_env
    install_from_env()
