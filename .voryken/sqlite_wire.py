"""Minimal typed JSON codec for private sqlite RPC; no pickle or executable payloads."""
import base64


def encode(value):
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        return {'$blob': base64.b64encode(bytes(value)).decode('ascii')}
    if isinstance(value, (tuple, list)):
        return [encode(item) for item in value]
    if isinstance(value, dict):
        return {str(k): encode(v) for k, v in value.items()}
    raise TypeError('Tipo SQLite no transferible: ' + type(value).__name__)


def decode(value):
    if isinstance(value, dict):
        if set(value) == {'$blob'} and isinstance(value['$blob'], str):
            return base64.b64decode(value['$blob'], validate=True)
        return {k: decode(v) for k, v in value.items()}
    if isinstance(value, list):
        return [decode(item) for item in value]
    return value
