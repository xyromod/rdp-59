"""Worker control service for ONE authorized program inside a temporary Windows runner.

Binds only inside the GitHub runner and authorizes commands using a unique token.
Access from the manager is additionally limited to Tailscale addresses by Windows Firewall.
"""
from __future__ import annotations
import base64
import http.client
import hmac
import io
import json
import os
import shutil
import secrets
import signal
import socket
import subprocess
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler
from low_latency_http import LowLatencyHTTPServer
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from shared_workspace_worker import mapped_project_dir

AGENT_PORT=18765
MAX_ARCHIVE_SIZE=20*1024*1024
# One persistent localhost HTTP connection per inbound gateway connection/thread.
# Reusing it avoids reconnecting for every CSS/JS/API request.
_origin_thread = threading.local()
ORIGIN_TIMEOUT = 22

def _origin_connection(port):
    connections=getattr(_origin_thread, 'connections', None)
    if connections is None:
        connections={}
        _origin_thread.connections=connections
    connection=connections.get(port)
    if connection is None:
        connection=http.client.HTTPConnection('127.0.0.1',port,timeout=ORIGIN_TIMEOUT)
        connections[port]=connection
    return connection

def _reset_origin_connection(port):
    connections=getattr(_origin_thread,'connections',{})
    connection=connections.pop(port,None)
    if connection:
        try:connection.close()
        except OSError:pass


class Runner:
    def __init__(self, package: Path, encryption_key: str):
        self.lock = threading.Lock()
        self.process = None
        self.error = None
        self.started_at = None
        self.path = Path(os.getenv('RUNNER_TEMP') or '.').resolve() / 'voryken_program'
        self.path.mkdir(parents=True, exist_ok=True)
        self.ready = False
        self.output=None
        self.shared_root = None
        self.sqlite_rpc_config = None
        self.shared_unc = None
        self.smb_mount_ms = None
        self.local_log_offset = 0
        self.local_log_path = None
        self.shared_log_path = None
        self.log_mirror_thread = None
        self.log_mirror_stop = threading.Event()
        self.tunnel_stop = threading.Event()
        self.tunnel_proc = None
        self.tunnel_log = None
        self.tunnel_thread = None
        self.tunnel_status = 'inactive'
        # Only these pre-approved loopback HTTP ports may be reached by the gateway.
        try:
            raw_ports=json.loads(os.environ.get('VORYKEN_RELAY_PORTS','[]'))
            self.relay_ports={int(x) for x in raw_ports if 1 <= int(x) <= 65535}
        except (ValueError, TypeError):
            self.relay_ports=set()
        self.cloudflare_token = os.environ.get('VORYKEN_CLOUDFLARE_TUNNEL_TOKEN', '')
        self.cloudflare_routes = []
        if self.cloudflare_token:
            try:
                self.cloudflare_routes = [row for row in json.loads(os.environ.get('VORYKEN_CLOUDFLARE_ROUTES', '[]'))
                                          if isinstance(row, dict) and isinstance(row.get('port'), int)
                                          and 1 <= row['port'] <= 65535][:10]
            except (ValueError, TypeError):
                self.cloudflare_routes = []
        if self.cloudflare_routes:
            self.tunnel_status = 'awaiting_program'
        self.restarting = False
        self.restart_id = None
        self.restart_error = None
        self.restart_phase = ''
        self.restart_completed_at = None
        self.stage = 'Iniciando agente (no depende del montaje SMB)'
        # CRITICAL: expose /status before SMB connects or pip installs. Previously
        # the HTTP server could be silent for up to 15 minutes while preparing.
        self.preparer = threading.Thread(target=self._prepare_background,
            args=(package, encryption_key), name='VorykenPreparation', daemon=True)
        self.preparer.start()

    def _prepare_background(self, package, encryption_key):
        try:
            self._prepare(package, encryption_key)
            with self.lock:
                self.ready = True
                self.error = None
                self.stage = 'Proyecto preparado; esperando START'
            print('VORYKEN_PROGRAM_PREPARED=1', flush=True)
        except Exception as exc:
            with self.lock:
                self.ready = False
                self.error = f'{type(exc).__name__}: {exc}'
                self.stage = 'Preparación fallida'
            print('VORYKEN_PREPARE_FAILED=' + self.error, flush=True)

    def _progress(self, message):
        with self.lock:
            self.stage = message
        print('VORYKEN_PREPARING=' + message, flush=True)

    def _prepare(self, package, key):
        self._progress('Descifrando configuración de ejecución')
        ciphertext=package.read_bytes()
        if len(ciphertext)>MAX_ARCHIVE_SIZE:raise RuntimeError('Package too large')
        plaintext=AESGCM(base64.urlsafe_b64decode(key)).decrypt(ciphertext[:12],ciphertext[12:],None)
        with zipfile.ZipFile(io.BytesIO(plaintext)) as z:
            if len(z.infolist())>500:raise RuntimeError('Too many project files')
            total=0
            for entry in z.infolist():
                total+=entry.file_size
                target=(self.path/entry.filename).resolve()
                if not target.is_relative_to(self.path) or total>20*1024*1024:
                    raise RuntimeError('Invalid project ZIP')
            z.extractall(self.path)
        self.config=json.loads((self.path/'_voryken_project.json').read_text(encoding='utf-8'))
        if bool(self.config.get('shared_workspace')):
            shared_json = os.environ.get('VORYKEN_SHARE_CONFIG', '')
            if not shared_json:
                raise RuntimeError('El programa requiere SMB, pero falta VORYKEN_SHARE_CONFIG')
            self._progress('Montando SMB de tu PC a través de Tailscale (puerto 445)')
            print('VORYKEN_SHARED_MOUNT_START=1',flush=True)
            share_settings = json.loads(shared_json)
            self.shared_unc = '\\\\' + str(share_settings["host"]) + '\\' + str(share_settings["name"])
            smb_started=time.perf_counter()
            self.shared_root = mapped_project_dir(share_settings)
            self.smb_mount_ms=round((time.perf_counter()-smb_started)*1000,1)
            sqlite_settings = share_settings.get('sqlite_rpc')
            if sqlite_settings:
                # The manager must explicitly enable and authorize this service.
                import ipaddress
                host = ipaddress.ip_address(str(sqlite_settings.get('host','')))
                if host not in ipaddress.ip_network('100.64.0.0/10'):
                    raise RuntimeError('SQLite central exige una IP Tailscale privada')
                if len(str(sqlite_settings.get('token',''))) < 32:
                    raise RuntimeError('Falta la credencial del servicio SQLite')
                self.sqlite_rpc_config = sqlite_settings
            relative = Path(self.config['entry'])
            if relative.is_absolute() or any(piece == '..' for piece in relative.parts):
                raise RuntimeError('Ruta del archivo Python no permitida en carpeta compartida')
            shared_entry = self.shared_root / relative
            if not shared_entry.is_file():
                raise RuntimeError('El archivo de inicio no existe en la carpeta SMB compartida')
            self.entry = shared_entry
            working_dir = self.shared_root
            self._progress('Carpeta SMB conectada; archivo Python encontrado')
            print('VORYKEN_SHARED_WORKSPACE_READY=1',flush=True)
        else:
            entry=(self.path/self.config['entry']).resolve()
            if not entry.is_relative_to(self.path) or not entry.is_file():
                raise RuntimeError('Entry not found')
            self.entry=entry
            working_dir = self.path
        install=str(self.config.get('install_command') or '').strip()
        if install=='python -m pip install -r requirements.txt' and not (working_dir/'requirements.txt').is_file():
            install=''
        if install:
            self._progress('Instalando dependencias; puede tardar varios minutos')
            print('Installing project requirements...',flush=True)
            subprocess.run(install, cwd=working_dir, shell=True, check=True,timeout=900)
            print('VORYKEN_REQUIREMENTS_OK=1',flush=True)
        # Ready is only published by _prepare_background after all steps complete.

    def _start_tunnel_when_web_ready(self):
        """Do not attach traffic to a standby runner before its web origin listens.

        The public DNS hostname/port mappings must already be configured in Cloudflare.
        During a handoff, the old connector stops with the old program; the new
        connector is launched only when the new local HTTP port starts listening.
        """
        if not self.cloudflare_token or not self.cloudflare_routes:
            return
        self.tunnel_status = 'waiting_for_http_origin'
        end_at = time.monotonic() + 180
        while not self.tunnel_stop.is_set() and time.monotonic() < end_at:
            program = self.process
            if not program or program.poll() is not None:
                self.tunnel_status = 'program_not_running'
                return
            for route in self.cloudflare_routes:
                try:
                    with socket.create_connection(('127.0.0.1', route['port']), timeout=0.8):
                        port_ready = True
                except (OSError, TimeoutError):
                    port_ready = False
                if port_ready:
                    break
            else:
                self.tunnel_stop.wait(2)
                continue
            # A web server is reachable. Launch cloudflared using the secret as an
            # environment variable so it never appears on the command line.
            binary = Path(os.getenv('RUNNER_TEMP') or '.') / 'cloudflared.exe'
            if not binary.is_file():
                self.tunnel_status = 'connector_not_installed'
                return
            try:
                env = os.environ.copy()
                env['TUNNEL_TOKEN'] = self.cloudflare_token
                env.pop('VORYKEN_CLOUDFLARE_TUNNEL_TOKEN', None)
                env.pop('VORYKEN_SHARE_CONFIG', None)
                env.pop('VORYKEN_PROJECT_KEY', None)
                env.pop('VORYKEN_AGENT_TOKEN', None)
                env.pop('VORYKEN_CLOUDFLARE_ROUTES', None)
                env.pop('VORYKEN_RELAY_PORTS', None)
                self.tunnel_log = open(Path(os.getenv('RUNNER_TEMP') or '.')/'voryken_cloudflare.log', 'ab', buffering=0)
                opts = {'env':env,'stdout':self.tunnel_log,'stderr':subprocess.STDOUT,'stdin':subprocess.DEVNULL}
                if os.name == 'nt': opts['creationflags'] = subprocess.CREATE_NO_WINDOW
                self.tunnel_proc = subprocess.Popen([str(binary), 'tunnel', '--no-autoupdate', 'run'], **opts)
                self.tunnel_stop.wait(3)
                if self.tunnel_proc.poll() is not None:
                    self.tunnel_status = 'connector_exited_early'
                    return
                self.tunnel_status = 'connected_connector_started'
                print('VORYKEN_CLOUDFLARE_CONNECTOR_STARTED=1', flush=True)
                while not self.tunnel_stop.wait(3):
                    if self.process is None or self.process.poll() is not None:
                        self.tunnel_status = 'program_exited'
                        break
                    if self.tunnel_proc.poll() is not None:
                        self.tunnel_status = 'connector_exited'
                        break
                break
            except Exception as exc:
                self.tunnel_status = 'connector_error: ' + type(exc).__name__
                print('VORYKEN_CLOUDFLARE_FAILED=' + type(exc).__name__, flush=True)
                return
        else:
            self.tunnel_status = 'origin_port_not_available'
        if self.tunnel_proc and self.tunnel_proc.poll() is None:
            self.tunnel_proc.terminate()
            try: self.tunnel_proc.wait(timeout=8)
            except subprocess.TimeoutExpired: self.tunnel_proc.kill()
        if self.tunnel_log and not self.tunnel_log.closed:
            self.tunnel_log.close()

    def web_proxy(self, data):
        """Authorized HTTP/1.1 bridge to a predefined local port.

        The caller has the agent bearer token; destination is ALWAYS loopback.
        No external URLs/IP addresses are accepted.
        """
        if not isinstance(data, dict):
            return {'ok':False,'error':'Bad JSON'}
        try:
            port=int(data.get('port', 0))
            method=str(data.get('method','GET')).upper()
            path=str(data.get('path','/'))
            body=base64.b64decode(data.get('body_b64',''), validate=True)
            headers=data.get('headers',{})
            if port not in self.relay_ports:
                return {'ok':False,'error':'Port not allowlisted'}
            if method not in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'):
                return {'ok':False,'error':'Method not supported'}
            if (not path.startswith('/') or path.startswith('//') or len(path)>8192 or
                    len(body)>12*1024*1024 or not isinstance(headers,dict) or len(headers)>64):
                return {'ok':False,'error':'Invalid HTTP request'}
            skip={'connection','keep-alive','proxy-authenticate','proxy-authorization',
                  'te','trailer','transfer-encoding','upgrade','content-length'}
            clean_headers={str(k):str(v) for k,v in headers.items()
                if str(k).lower() not in skip and len(str(k))<100 and len(str(v))<8192
                and '\r' not in str(v) and '\n' not in str(v)}
            con=http.client.HTTPConnection('127.0.0.1',port,timeout=50)
            try:
                con.request(method,path,body=body,headers=clean_headers)
                result=con.getresponse()
                payload=result.read(24*1024*1024+1)
                if len(payload)>24*1024*1024:
                    return {'ok':False,'error':'Response too large'}
                blocked={'connection','keep-alive','proxy-authenticate','proxy-authorization',
                         'te','trailer','transfer-encoding','upgrade','content-length'}
                result_headers=[[k,v] for k,v in result.getheaders() if k.lower() not in blocked]
                return {'ok':True,'status':result.status,'headers':result_headers,
                        'body_b64':base64.b64encode(payload).decode('ascii')}
            finally:con.close()
        except (ValueError,TypeError,OSError,http.client.HTTPException) as exc:
            return {'ok':False,'error':type(exc).__name__ + ': ' + str(exc)[:180]}

    def web_proxy_fast(self, meta, body):
        """Binary HTTP relay. No JSON/base64 copies of page bodies.

        Authorization is checked by Handler before calling this method.
        The only allowed origin is localhost on explicitly permitted ports.
        """
        try:
            if not isinstance(meta,dict):return 400, [], b'Invalid metadata'
            port=int(meta.get('port',0))
            method=str(meta.get('method','GET')).upper()
            path=str(meta.get('path','/'))
            headers=meta.get('headers',{})
            with self.lock:
                allowed=port in self.relay_ports
            if not allowed:return 403, [], b'Port not allowlisted'
            if method not in ('GET','HEAD','POST','PUT','PATCH','DELETE','OPTIONS'):
                return 400, [], b'Unsupported method'
            if (not path.startswith('/') or path.startswith('//') or len(path)>8192
                    or len(body)>12*1024*1024 or not isinstance(headers,dict)
                    or len(headers)>64):
                return 400, [], b'Invalid request'
            blocked={'connection','keep-alive','proxy-authenticate','proxy-authorization',
                     'te','trailer','transfer-encoding','upgrade','content-length'}
            clean={str(k):str(v) for k,v in headers.items()
                   if str(k).lower() not in blocked and len(str(k))<100 and len(str(v))<8192
                   and '\r' not in str(v) and '\n' not in str(v)}
            began=time.perf_counter()
            # A pooled connection can become stale during an idle period.
            # Only idempotent reads may be retried; POST/PATCH must NEVER be replayed.
            for attempt in range(2 if method in ('GET','HEAD','OPTIONS') else 1):
                connection=_origin_connection(port)
                try:
                    connection.request(method,path,body=body,headers=clean)
                    response=connection.getresponse()
                    raw=response.read(24*1024*1024+1)
                    if len(raw)>24*1024*1024:
                        _reset_origin_connection(port)
                        return 502, [], b'Response too large'
                    output=[(k,v) for k,v in response.getheaders() if k.lower() not in blocked]
                    output.append(('X-Voryken-Origin-Ms',str(round((time.perf_counter()-began)*1000,1))))
                    return response.status,output,raw
                except (OSError,http.client.HTTPException):
                    _reset_origin_connection(port)
                    if attempt==0 and method in ('GET','HEAD','OPTIONS'):
                        continue
                    raise
        except (OSError,TypeError,ValueError,http.client.HTTPException) as exc:
            return 502,[],(type(exc).__name__+': '+str(exc)[:140]).encode('utf-8')

    def update_relay_ports(self,ports):
        if not isinstance(ports,list) or len(ports)>40:
            return {'ok':False,'error':'Invalid port list'}
        try:
            clean={int(x) for x in ports}
            if not clean or any(not 1<=p<=65535 for p in clean):
                return {'ok':False,'error':'Invalid port'}
        except (ValueError,TypeError):
            return {'ok':False,'error':'Invalid port'}
        with self.lock:self.relay_ports.update(clean)
        return {'ok':True,'ports':sorted(self.relay_ports)}

    def restart(self, entry=None, install_command=None):
        """Restart ONLY this project's process in the SAME runner.

        Never deletes or creates a GitHub repository, changes other projects or
        updates the shared project files. Changes on SMB are read on restart.
        """
        with self.lock:
            if not self.ready:
                return {'ok':False,'error':self.error or 'El proyecto todavía se prepara'}
            if self.restarting:
                return {'ok':False,'error':'Ya se está reiniciando este proyecto'}
            try:
                relative, target, command = self._restart_inputs(entry, install_command)
            except (OSError,ValueError) as exc:
                return {'ok':False,'error':str(exc)}
            self.restarting = True
            self.restart_id = secrets.token_hex(10)
            self.restart_error = None
            self.restart_completed_at = None
            self.restart_phase = 'Esperando detención del proceso actual'
            restart_id = self.restart_id
        threading.Thread(target=self._restart_background,
            args=(relative,target,command),daemon=True,
            name='VorykenProcessRestart').start()
        return {'ok':True,'status':'restarting','restart_id':restart_id}

    def _restart_inputs(self, entry, install_command):
        import re
        name = str(entry if entry is not None else self.config['entry']).strip().replace('\\','/')
        if not name or len(name)>300 or ':' in name or '\x00' in name:
            raise ValueError('Archivo de inicio inválido')
        relative=Path(name)
        if relative.is_absolute() or '..' in relative.parts or not name.lower().endswith('.py'):
            raise ValueError('El archivo Python debe estar dentro del proyecto compartido')
        root=(self.shared_root or self.path).resolve()
        target=(root/relative).resolve()
        if not target.is_relative_to(root) or not target.is_file():
            raise ValueError('El Python actualizado no existe en la carpeta compartida: '+name)
        command=str(install_command if install_command is not None else
                    self.config.get('install_command','')).strip()
        if len(command)>500 or any(x in command for x in ('\n','\r','\x00')):
            raise ValueError('Comando de requerimientos inválido')
        if command=='python -m pip install -r requirements.txt' and not (root/'requirements.txt').is_file():
            command=''
        return relative,target,command

    def _restart_background(self, relative, target, command):
        old_entry=self.entry
        old_entry_name=self.config.get('entry','')
        old_install=self.config.get('install_command','')
        try:
            self.restart_phase='Deteniendo el Python anterior'
            stopped=self.stop()
            if not stopped.get('ok'):
                raise RuntimeError('No se pudo detener el Python anterior')
            self.restart_phase='Releyendo archivos nuevos de la carpeta SMB'
            if not target.is_file():
                raise RuntimeError('El archivo Python desapareció antes del reinicio')
            self.entry=target
            self.config['entry']=relative.as_posix()
            self.config['install_command']=command
            if command:
                self.restart_phase='Actualizando dependencias del proyecto'
                cwd=self.shared_root or self.path
                logfile=self.path/'restart_requirements.log'
                old_size=logfile.stat().st_size if logfile.exists() else 0
                with logfile.open('ab') as log:
                    log.write((f'\n--- RESTART {time.strftime("%Y-%m-%d %H:%M:%S")} ---\n').encode())
                    result=subprocess.run(command,cwd=cwd,shell=True,stdout=log,
                                          stderr=subprocess.STDOUT,timeout=900)
                if self.shared_root:
                    try:
                        run_id=''.join(c for c in os.environ.get('GITHUB_RUN_ID','worker') if c.isalnum())[:24]
                        remote=self.shared_root/'.voryken_logs'/run_id/'restart_requirements.log'
                        remote.parent.mkdir(parents=True,exist_ok=True)
                        with logfile.open('rb') as src,remote.open('ab') as dest:
                            src.seek(old_size)
                            shutil.copyfileobj(src,dest,512*1024)
                    except OSError:
                        # Requirements result is still available in runner log;
                        # never let a temporary SMB outage overwrite pip's status.
                        print('VORYKEN_REQUIREMENTS_LOG_MIRROR_FAILED=1',flush=True)
                if result.returncode:
                    raise RuntimeError('Falló la instalación de dependencias (código '
                                       +str(result.returncode)+'). Revisa restart_requirements.log')
            self.restart_phase='Iniciando Python actualizado'
            result=self.start()
            if not result.get('ok'):
                raise RuntimeError(str(result.get('error','No inició el Python')))
            time.sleep(2)
            if not self.process or self.process.poll() is not None:
                raise RuntimeError('El Python se cerró después del reinicio')
            self.restart_phase='Python actualizado y ejecutándose'
            print('VORYKEN_PROJECT_RESTART_OK=1',flush=True)
        except Exception as exc:
            self.restart_error=type(exc).__name__+': '+str(exc)
            self.restart_phase='Reinicio fallido'
            print('VORYKEN_PROJECT_RESTART_FAILED='+self.restart_error,flush=True)
            # Attempt to restore the original command if the new setup fails;
            # never claim success until the manager checks the restart_error.
            if not self.process or self.process.poll() is not None:
                try:
                    self.entry=old_entry
                    self.config['entry']=old_entry_name
                    self.config['install_command']=old_install
                    self.start()
                    self.restart_phase='Reinicio falló; se intentó recuperar el Python anterior'
                except Exception as recovery:
                    self.restart_phase+='; recuperación fallida: '+type(recovery).__name__
        finally:
            with self.lock:
                self.restarting=False
                self.restart_completed_at=time.time()

    def _sync_program_log(self):
        """Append new program output to PC in batches without blocking Python."""
        if not self.local_log_path or not self.shared_log_path:return
        if not self.local_log_path.is_file():return
        position=self.local_log_offset
        with self.local_log_path.open('rb') as source:
            source.seek(position)
            chunk=source.read(512*1024)
        if not chunk:return
        self.shared_log_path.parent.mkdir(parents=True,exist_ok=True)
        with self.shared_log_path.open('ab',buffering=512*1024) as target:
            target.write(chunk)
        self.local_log_offset += len(chunk)

    def _mirror_logs(self):
        while not self.log_mirror_stop.wait(3):
            try:self._sync_program_log()
            except OSError:pass  # keep local bytes; next sync retries
        # Best-effort bounded final flush at shutdown or restart.
        until=time.monotonic()+9
        try:
            while time.monotonic()<until:
                position=self.local_log_offset
                self._sync_program_log()
                if self.local_log_offset==position:break
        except OSError:pass

    def start(self):
        with self.lock:
            if not self.ready:return {'ok':False,'status':'error' if self.error else 'preparing',
                                      'stage':self.stage,'error':self.error or 'El proyecto todavía se está preparando'}
            if self.process and self.process.poll() is None:return {'ok':True,'status':'running'}
            cwd = self.shared_root or self.path
            # Writes NEVER block the Python process on SMB. The only permanent
            # log is still on the PC; a short-lived runner file is flushed in batches.
            if getattr(self,'log_mirror_thread',None) and self.log_mirror_thread.is_alive():
                self.log_mirror_stop.set()
                self.log_mirror_thread.join(timeout=5)
            self.log_mirror_thread = None
            if self.output and not self.output.closed:
                self.output.close()
            log_path = self.path / 'program.log'
            self.output=open(log_path,'ab', buffering=0)
            self.local_log_path=log_path
            self.local_log_offset=log_path.stat().st_size
            self.shared_log_path=None
            if self.shared_root:
                identifier = ''.join(c for c in os.environ.get('GITHUB_RUN_ID', 'worker') if c.isalnum())[:24]
                self.shared_log_path=self.shared_root/'.voryken_logs'/identifier/'program.log'
            if not hasattr(self,'log_mirror_stop'):
                self.log_mirror_stop=threading.Event()
            self.log_mirror_stop.clear()
            if self.shared_log_path:
                self.log_mirror_thread=threading.Thread(target=self._mirror_logs,
                    daemon=True,name='VorykenLogMirror')
                self.log_mirror_thread.start()
            options=dict(cwd=cwd, stdout=self.output, stderr=subprocess.STDOUT,stdin=subprocess.DEVNULL)
            # The data is never duplicated: V: points to the live directory on the host PC.
            env = os.environ.copy()
            if self.shared_root:
                env['VORYKEN_SHARED_DIR'] = str(self.shared_root)
                env['VORYKEN_SHARED_MODE'] = 'live'
                # Bytecode is disposable performance cache only; project source,
                # databases and persistent data NEVER leave the owner's PC.
                env['PYTHONPYCACHEPREFIX'] = str(self.path/'_python_bytecode_cache')
                if getattr(self,'sqlite_rpc_config',None):
                    env['VORYKEN_SQLITE_RPC_CONFIG'] = json.dumps(self.sqlite_rpc_config)
                    env['VORYKEN_SHARED_UNC'] = str(getattr(self,'shared_unc','') or '')
                    # sitecustomize and its private helper reside with worker_agent,
                    # not inside the user's shared project directory.
                    runtime_lib = str(Path(__file__).resolve().parent)
                    env['PYTHONPATH'] = runtime_lib + os.pathsep + env.get('PYTHONPATH','')
            env.pop('VORYKEN_SHARE_CONFIG', None)
            env.pop('VORYKEN_PROJECT_KEY', None)
            env.pop('VORYKEN_AGENT_TOKEN', None)
            env.pop('VORYKEN_CLOUDFLARE_TUNNEL_TOKEN', None)
            env.pop('VORYKEN_CLOUDFLARE_ROUTES', None)
            env.pop('VORYKEN_RELAY_PORTS', None)
            options['env'] = env
            if os.name=='nt': options['creationflags']=subprocess.CREATE_NEW_PROCESS_GROUP
            self.tunnel_stop.clear()
            command=[sys.executable,'-u',str(self.entry)]
            if getattr(self,'sqlite_rpc_config',None):
                # Explicit wrapper means the proxy also works on Python installs
                # with another sitecustomize already present on PYTHONPATH.
                runtime=Path(__file__).resolve().parent/'sqlite_project_launcher.py'
                if not runtime.is_file():
                    raise RuntimeError('Falta sqlite_project_launcher.py en el agente nuevo')
                command=[sys.executable,'-u',str(runtime),str(self.entry)]
            self.process=subprocess.Popen(command,**options)
            self.started_at=time.time()
            if self.cloudflare_routes:
                self.tunnel_thread = threading.Thread(target=self._start_tunnel_when_web_ready,
                    daemon=True, name='CloudflareOriginMonitor')
                self.tunnel_thread.start()
            self.error=None
            print('VORYKEN_PROGRAM_STARTED=1 PID='+str(self.process.pid),flush=True)
            return {'ok':True,'status':'running','pid':self.process.pid, 'shared':bool(self.shared_root)}

    def stop(self):
        self.tunnel_stop.set()
        tunnel = self.tunnel_proc
        if tunnel and tunnel.poll() is None:
            tunnel.terminate()
            try: tunnel.wait(timeout=7)
            except subprocess.TimeoutExpired: tunnel.kill()
        self.tunnel_status = 'stopped'
        with self.lock:
            p=self.process
            if p and p.poll() is None:
                # On Windows CTRL_BREAK allows the program to flush last writes
                # if it registers a handler. Termination remains a fallback.
                if os.name == 'nt':
                    try:
                        p.send_signal(signal.CTRL_BREAK_EVENT)
                        p.wait(timeout=10)
                    except (OSError, subprocess.TimeoutExpired):
                        if p.poll() is None: p.terminate()
                else:
                    p.terminate()
                try: p.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    p.kill()
                    p.wait(timeout=6)
            if self.output and not self.output.closed:
                self.output.close()
            self.log_mirror_stop.set()
        if self.log_mirror_thread:
            self.log_mirror_thread.join(timeout=5)
        return {'ok':True, 'status':'stopped'}

    def state(self):
        with self.lock:
            p=self.process
            if self.restarting:status='restarting'
            elif p is None:status=('ready' if self.ready else 'error' if self.error else 'preparing')
            else:status='running' if p.poll() is None else 'exited'
            return {'ok':True,'status':status,'pid':p.pid if p else None,
                    'uptime_sec':round(time.time()-self.started_at,1) if self.started_at else None,
                    'exit_code':p.poll() if p else None,'shared':bool(self.shared_root),
                    'error':self.error,'stage':self.stage,
                    'restarting':self.restarting, 'restart_id':self.restart_id,
                    'restart_phase':self.restart_phase, 'restart_error':self.restart_error,
                    'restart_completed_at':self.restart_completed_at,
                    'sqlite_central':bool(getattr(self,'sqlite_rpc_config',None)),
                    'smb_mount_ms':getattr(self,'smb_mount_ms',None),
                    'tunnel_status':self.tunnel_status,
                    'domain_routes':len(self.cloudflare_routes), 'relay_ports':sorted(self.relay_ports)}


def serve(runner,auth):
    class Handler(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'  # allow keep-alive between gateway and worker
        def log_message(self,format,*args):return
        def _authorized(self):
            expected='Bearer '+auth
            return hmac.compare_digest(self.headers.get('Authorization',''),expected)
        def respond(self,code,obj):
            encoded=json.dumps(obj).encode('utf-8')
            self.send_response(code)
            self.send_header('Content-Type','application/json')
            self.send_header('Content-Length',str(len(encoded)))
            self.end_headers();self.wfile.write(encoded)
        def finish(self):
            try:
                super().finish()
            finally:
                # Agent-side origin sockets are thread-local. Close them when
                # this incoming proxy session ends to avoid leaking handles.
                connections=getattr(_origin_thread,'connections',{})
                for conn in connections.values():
                    try:conn.close()
                    except OSError:pass
                _origin_thread.connections={}

        def do_GET(self):
            if not self._authorized():return self.respond(401,{'ok':False,'error':'unauthorized'})
            if self.path!='/status':return self.respond(404,{'ok':False})
            self.respond(200,runner.state())
        def do_POST(self):
            if not self._authorized():return self.respond(401,{'ok':False,'error':'unauthorized'})
            if self.path=='/webproxy-fast':
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    encoded=self.headers.get('X-Voryken-Meta','')
                    if length<0 or length>12*1024*1024 or len(encoded)>24000:
                        return self.respond(413,{'ok':False,'error':'Request too large'})
                    meta=json.loads(base64.urlsafe_b64decode(encoded))
                    raw=self.rfile.read(length) if length else b''
                    status,headers,payload=runner.web_proxy_fast(meta,raw)
                except (ValueError,TypeError,KeyError,json.JSONDecodeError):
                    status,headers,payload=400,[],b'Invalid request metadata'
                self.send_response(status)
                self.send_header('X-Voryken-Bridge','fast')
                if status==502:self.send_header('X-Voryken-Error','Origin unavailable')
                for k,v in headers:
                    if k.lower() not in ('content-length','transfer-encoding','connection'):
                        self.send_header(k,str(v).replace('\r','').replace('\n',''))
                self.send_header('Content-Length',str(len(payload)))
                self.end_headers()
                if payload:self.wfile.write(payload)
                return
            if self.path=='/relay-ports':
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if not 0<length<3000:return self.respond(413,{'ok':False,'error':'Bad config size'})
                    incoming=json.loads(self.rfile.read(length))
                    result=runner.update_relay_ports(incoming.get('ports'))
                except (ValueError,TypeError,json.JSONDecodeError):
                    result={'ok':False,'error':'Invalid relay configuration'}
                return self.respond(200 if result.get('ok') else 400,result)
            if self.path=='/webproxy':
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if length<=0 or length>18*1024*1024:
                        return self.respond(413,{'ok':False,'error':'Request too large'})
                    data=json.loads(self.rfile.read(length))
                    result=runner.web_proxy(data)
                except (ValueError,TypeError,json.JSONDecodeError):
                    result={'ok':False,'error':'Malformed JSON'}
                return self.respond(200 if result.get('ok') else 502,result)
            if self.path=='/restart':
                try:
                    length=int(self.headers.get('Content-Length','0'))
                    if length<0 or length>3000:return self.respond(413,{'ok':False,'error':'Configuración demasiado grande'})
                    params=json.loads(self.rfile.read(length)) if length else {}
                    if not isinstance(params,dict):raise ValueError('Invalid payload')
                    res=runner.restart(params.get('entry'),params.get('install_command'))
                except (ValueError,TypeError,json.JSONDecodeError):
                    res={'ok':False,'error':'Datos inválidos para reiniciar'}
            elif self.path=='/start':
                res=({'ok':False,'error':'Reinicio en curso'} if runner.restarting else runner.start())
            elif self.path=='/stop':
                res=({'ok':False,'error':'Reinicio en curso'} if runner.restarting else runner.stop())
            else:return self.respond(404,{'ok':False})
            self.respond(200 if res.get('ok') else 409,res)
    server=LowLatencyHTTPServer(('0.0.0.0',AGENT_PORT), Handler)
    print(f'VORYKEN_WORKER_AGENT_READY=1 PORT={AGENT_PORT}',flush=True)
    print('VORYKEN_WORKER_NOTE=Preparación de SMB y dependencias transcurre en otro hilo',flush=True)
    try:server.serve_forever(poll_interval=1)
    finally:server.server_close()

def main():
    auth=os.environ.get('VORYKEN_AGENT_TOKEN','')
    key=os.environ.get('VORYKEN_PROJECT_KEY','')
    if len(auth)<32 or not key:raise RuntimeError('Missing worker secrets')
    runner=Runner(Path('.voryken/project.enc'),key)
    serve(runner,auth)

if __name__=='__main__':main()
