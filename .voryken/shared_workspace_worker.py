"""Montaje autenticado SMB sobre Tailscale para el worker Windows."""
from __future__ import annotations
import os
from pathlib import Path
import re
import socket
import time

def validate_share_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r'[a-zA-Z0-9_-]{1,55}\$?', value):
        raise ValueError('Nombre SMB no válido.')
    return value

SHARE_DRIVE = 'V:'

def mapped_project_dir(config: dict, driver=None) -> Path:
    """Map an authenticated, private SMB share in this Windows logon session.

    driver is injectable for tests. The password never appears on the command line
    or in the public workflow. Use the Windows networking API in-process.
    """
    required = {'host', 'name', 'username', 'password'}
    if not isinstance(config, dict) or not required.issubset(config):
        raise RuntimeError('Faltan las credenciales del directorio compartido.')
    import ipaddress
    host = str(config['host'])
    addr = ipaddress.ip_address(host)
    if addr not in ipaddress.ip_network('100.64.0.0/10') or addr.version != 4:
        raise RuntimeError('La carpeta debe estar alojada en una IP privada de Tailscale.')
    name = validate_share_name(str(config['name']))
    remote = f'\\\\{host}\\{name}'
    if driver is None:
        if os.name != 'nt':
            raise RuntimeError('El montaje SMB requiere Windows.')
        driver = _map_windows_smb
    # GitHub and Tailscale need a few seconds to establish their paths.
    # On a fresh runner, wait for SMB to become reachable before mapping.
    if driver is _map_windows_smb:
        last_error = None
        for attempt in range(8):
            try:
                with socket.create_connection((host, 445), timeout=4):
                    break
            except OSError as exc:
                last_error = exc
                if attempt < 7:
                    time.sleep(5)
        else:
            raise ConnectionError('No llega al puerto SMB 445 del PC por Tailscale. '
                                  'Comprueba el servicio Compartir archivos, el firewall y que el PC siga conectado.') from last_error
    driver(SHARE_DRIVE, remote, str(config['username']), str(config['password']))
    root = Path(SHARE_DRIVE + '\\')
    if driver is _map_windows_smb and not root.is_dir():
        raise RuntimeError('La carpeta compartida no se puede leer después del montaje.')
    return root


def _map_windows_smb(drive: str, unc: str, username: str, password: str) -> None:
    """WNetAddConnection2W: avoids exposing the SMB password in net.exe argv."""
    import ctypes
    from ctypes import wintypes

    class NETRESOURCEW(ctypes.Structure):
        _fields_ = [('dwScope', wintypes.DWORD), ('dwType', wintypes.DWORD),
                    ('dwDisplayType', wintypes.DWORD), ('dwUsage', wintypes.DWORD),
                    ('lpLocalName', wintypes.LPWSTR), ('lpRemoteName', wintypes.LPWSTR),
                    ('lpComment', wintypes.LPWSTR), ('lpProvider', wintypes.LPWSTR)]

    resource = NETRESOURCEW(0, 1, 0, 0, drive, unc, None, None)
    mpr = ctypes.WinDLL('mpr', use_last_error=True)
    func = mpr.WNetAddConnection2W
    func.argtypes = [ctypes.POINTER(NETRESOURCEW), wintypes.LPCWSTR,
                     wintypes.LPCWSTR, wintypes.DWORD]
    func.restype = wintypes.DWORD
    code = func(ctypes.byref(resource), password, username, 0)
    if code:
        raise OSError(f'No se pudo montar la carpeta SMB (código Windows {code}). '
                      'Comprueba Tailscale, los permisos de la carpeta y el puerto 445.')
