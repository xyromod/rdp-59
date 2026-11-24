"""Opt-in SQLite DB-API bridge: SQL runs on the user's PC, not over SMB.

This is an optional compatibility layer for applications using sqlite3.connect.
It deliberately raises errors for unsupported advanced methods (no silent data
fallback). The project source and the SQLite database remain on the user's PC.
"""
from __future__ import annotations
import base64
import http.client
import json
import os
from pathlib import Path, PureWindowsPath
import secrets
import sqlite3
import threading

try:
    from sqlite_wire import encode, decode
except ImportError:
    # Worker zip includes both python modules in .voryken/.
    from .sqlite_wire import encode, decode

_ORIGINAL_CONNECT = sqlite3.connect
_tls = threading.local()


class CentralRPC:
    def __init__(self, config):
        self.host = config['host']
        self.port = int(config.get('port', 18766))
        self.token = config['token']
        self.project = config['project']

    def _connection(self):
        existing = getattr(_tls, 'sqlite_http', None)
        key = (self.host, self.port)
        if not existing or existing[0] != key:
            if existing:
                try:existing[1].close()
                except OSError:pass
            conn = http.client.HTTPConnection(self.host, self.port, timeout=10)
            _tls.sqlite_http = (key,conn)
            return conn
        return existing[1]

    def request(self, op, payload):
        blob = json.dumps({'project':self.project,'op':op,'data':payload},
                          separators=(',',':')).encode('utf-8')
        con = self._connection()
        try:
            con.request('POST','/sqlite',body=blob,
                        headers={'X-Voryken-Token':self.token,
                                 'Content-Type':'application/json'})
            response=con.getresponse()
            result=json.loads(response.read(12*1024*1024+1))
            if response.status != 200:
                raise sqlite3.OperationalError('Servicio SQLite central: HTTP '+str(response.status))
            if not result.get('ok'):
                errors={'IntegrityError':sqlite3.IntegrityError,'ProgrammingError':sqlite3.ProgrammingError,
                        'OperationalError':sqlite3.OperationalError,'DataError':sqlite3.DataError,
                        'DatabaseError':sqlite3.DatabaseError,'InterfaceError':sqlite3.InterfaceError}
                klass=errors.get(result.get('type'),sqlite3.OperationalError)
                raise klass(str(result.get('error','Error SQLite remoto')))
            return result['result']
        except (OSError, http.client.HTTPException, ValueError) as exc:
            # Never replay a write: it might have executed before the socket died.
            try:con.close()
            except OSError:pass
            _tls.sqlite_http=None
            raise sqlite3.OperationalError('No se pudo contactar el servicio SQLite de tu PC: '
                                           +str(exc)[:120]) from exc


class RemoteRow:
    """Compatible name/index access for sqlite3.Row-style web applications."""
    def __init__(self, names, values):
        self._names = tuple(names)
        self._values = tuple(values)
        self._lookup = {name.lower():i for i,name in enumerate(self._names) if isinstance(name,str)}
    def __getitem__(self,key):
        if isinstance(key,str):return self._values[self._lookup[key.lower()]]
        return self._values[key]
    def keys(self):return list(self._names)
    def __iter__(self):return iter(self._values)
    def __len__(self):return len(self._values)
    def __eq__(self,other):return self._values == tuple(other) if isinstance(other,(RemoteRow,tuple,list)) else False
    def __repr__(self):return '<RemoteSQLite.Row '+repr(self._values)+'>'


class RemoteCursor:
    def __init__(self,connection):
        self.connection=connection
        self.cid=secrets.token_urlsafe(10)
        self.description=None
        self.rowcount=-1
        self.lastrowid=None
        self.arraysize=1
        self._buffer=[]
        self._exhausted=True
        self._closed=False

    def _check(self):
        self.connection._check()
        if self._closed:raise sqlite3.ProgrammingError('Cursor cerrado')

    def _send(self,op,sql,params):
        self._check()
        data={'session':self.connection.session,'cursor':self.cid,'sql':sql,
              'params':encode(params)}
        reply=self.connection.rpc.request(op,data)
        self.description=[tuple(x) for x in reply['description']] if reply.get('description') else None
        self.rowcount=reply.get('rowcount',-1)
        self.lastrowid=reply.get('lastrowid')
        self._buffer=decode(reply.get('rows',[]))
        self._exhausted=not bool(reply.get('has_more'))
        self.connection._properties(reply)
        return self

    def execute(self,sql,parameters=()):return self._send('execute',sql,parameters)
    def executemany(self,sql,seq_of_parameters):
        return self._send('executemany',sql,list(seq_of_parameters))
    def executescript(self,sql_script):return self._send('executescript',sql_script,())

    def _need(self):
        if self._buffer or self._exhausted:return
        result=self.connection.rpc.request('fetch',{'session':self.connection.session,
                                                    'cursor':self.cid,'limit':128})
        self._buffer=decode(result.get('rows',[]))
        self._exhausted=not result.get('has_more',False)

    def _make_row(self,values):
        if self.connection.row_factory is None:return tuple(values)
        names=[d[0] for d in (self.description or [])]
        if self.connection.row_factory is sqlite3.Row:
            return RemoteRow(names, values)
        return self.connection.row_factory(self,tuple(values))

    def fetchone(self):
        self._check()
        if self.description is None:return None
        self._need()
        if not self._buffer:return None
        return self._make_row(self._buffer.pop(0))
    def fetchmany(self,size=None):
        self._check()
        count=self.arraysize if size is None else int(size)
        if count<0:count=0
        result=[]
        for _ in range(count):
            row=self.fetchone()
            if row is None:break
            result.append(row)
        return result
    def fetchall(self):
        self._check()
        result=[]
        while True:
            row=self.fetchone()
            if row is None:break
            result.append(row)
        return result
    def close(self):
        if self._closed:return
        self._closed=True
        if not self.connection._closed:
            self.connection.rpc.request('close_cursor',{'session':self.connection.session,
                                                        'cursor':self.cid})
    def __iter__(self):return self
    def __next__(self):
        row=self.fetchone()
        if row is None:raise StopIteration
        return row


class RemoteConnection:
    def __init__(self, rpc, path, timeout=5., isolation_level='',check_same_thread=True):
        self.rpc=rpc
        self._closed=False
        self._thread=threading.get_ident() if check_same_thread else None
        self.row_factory=None
        self.text_factory=str
        self.isolation_level=isolation_level
        self._total_changes=0
        self._in_transaction=False
        response=rpc.request('connect',{'path':path, 'timeout':timeout,
                                        'isolation_level':isolation_level})
        self.session=response['session']

    def _check(self):
        if self._closed:raise sqlite3.ProgrammingError('Conexión SQLite cerrada')
        if self._thread is not None and threading.get_ident()!=self._thread:
            raise sqlite3.ProgrammingError('Conexión SQLite usada desde otro hilo')
    def _properties(self,reply):
        self._in_transaction=reply.get('in_transaction',self._in_transaction)
        self._total_changes=reply.get('total_changes',self._total_changes)
    @property
    def in_transaction(self):return self._in_transaction
    @property
    def total_changes(self):return self._total_changes
    def cursor(self,factory=None):
        self._check()
        if factory is not None:raise NotImplementedError('Cursor factory no compatible con SQLite remoto')
        return RemoteCursor(self)
    def execute(self,sql,parameters=()):return self.cursor().execute(sql,parameters)
    def executemany(self,sql,seq_of_parameters):return self.cursor().executemany(sql,seq_of_parameters)
    def executescript(self,sql):return self.cursor().executescript(sql)
    def commit(self):
        self._check()
        self._properties(self.rpc.request('commit',{'session':self.session}))
    def rollback(self):
        self._check()
        self._properties(self.rpc.request('rollback',{'session':self.session}))
    def close(self):
        if self._closed:return
        self._closed=True
        self.rpc.request('close',{'session':self.session})
    def __enter__(self):self._check();return self
    def __exit__(self,exc_type,exc,tb):
        if exc_type:self.rollback()
        else:self.commit()
    def __getattr__(self,name):
        raise NotImplementedError('SQLite central no admite todavía Connection.'+name+
                                  '; desactiva esta opción para este proyecto.')


def database_relative(path, shared_root, unc_root=None):
    """Map the V: drive OR its known UNC representation back to the PC project.

    pathlib.Path.resolve() on Windows may return the server UNC path instead of
    the mapped drive name; both must use the same central SQLite database.
    """
    if not isinstance(path,(str,bytes,os.PathLike)):
        return None
    p=os.fsdecode(path)
    if p == ':memory:' or p.startswith('file:'):
        return None
    if '\x00' in p or not p:return None
    # Windows extended-length paths are permitted only for the known share.
    if p.startswith('\\\\?\\UNC\\'):
        p='\\\\'+p[len('\\\\?\\UNC\\'):]
    elif p.startswith('\\\\?\\'):
        p=p[len('\\\\?\\'):]
    drive=PureWindowsPath(p)
    if drive.is_absolute():
        roots=[PureWindowsPath(shared_root)]
        if unc_root:roots.append(PureWindowsPath(unc_root))
        for root in roots:
            try:return drive.relative_to(root).as_posix()
            except ValueError:pass
        return None
    if ':' in p or p.startswith(('/', '\\')):return None
    return p.replace('\\','/')

def install_from_env():
    raw=os.environ.get('VORYKEN_SQLITE_RPC_CONFIG','')
    if not raw:return False
    config=json.loads(raw)
    rpc=CentralRPC(config)
    shared=os.environ.get('VORYKEN_SHARED_DIR','V:\\')
    shared_unc=os.environ.get('VORYKEN_SHARED_UNC')
    def connect(database, timeout=5., detect_types=0, isolation_level='', check_same_thread=True,
                factory=None, cached_statements=128, uri=False, **kwargs):
        rel=database_relative(database,shared,shared_unc)
        if rel is None:
            return _ORIGINAL_CONNECT(database,timeout=timeout,detect_types=detect_types,
                                     isolation_level=isolation_level,check_same_thread=check_same_thread,
                                     factory=factory or sqlite3.Connection,
                                     cached_statements=cached_statements,uri=uri,**kwargs)
        if factory is not None or detect_types or uri or kwargs:
            raise NotImplementedError('Esta configuración SQLite requiere el driver local o una adaptación específica')
        return RemoteConnection(rpc,rel,timeout,isolation_level,check_same_thread)
    sqlite3.connect=connect
    sqlite3.dbapi2.connect=connect
    return True
