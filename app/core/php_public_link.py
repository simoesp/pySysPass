"""Read PHP public-link Vault snapshots without instantiating PHP objects."""

from dataclasses import dataclass
import hashlib
import re

from app.core.defuse_compat import decrypt_with_password


VAULT_CLASS = b'SP\\Core\\Crypt\\Vault'
ACCOUNT_CLASS = b'SP\\DataModel\\AccountExtData'
MAX_SERIALIZED_BYTES = 4 * 1024 * 1024


@dataclass(frozen=True)
class _Object:
    name: bytes
    properties: dict


class _Reader:
    """Bounded, data-only subset of PHP serialize; reject references and hooks."""

    def __init__(self, data: bytes):
        if len(data) > MAX_SERIALIZED_BYTES:
            raise ValueError('PHP snapshot is too large')
        self.data = data
        self.offset = 0
        self.nodes = 0

    def _take(self, size: int) -> bytes:
        if size < 0 or self.offset + size > len(self.data):
            raise ValueError('Truncated PHP snapshot')
        value = self.data[self.offset:self.offset + size]
        self.offset += size
        return value

    def _expect(self, expected: bytes) -> None:
        if self._take(len(expected)) != expected:
            raise ValueError('Invalid PHP snapshot syntax')

    def _number(self, delimiter: bytes) -> int:
        end = self.data.find(delimiter, self.offset, self.offset + 22)
        if end < 0:
            raise ValueError('Invalid PHP number')
        raw = self.data[self.offset:end]
        if not re.fullmatch(rb'-?\d{1,20}', raw):
            raise ValueError('Invalid PHP number')
        self.offset = end + len(delimiter)
        return int(raw)

    def _string(self) -> bytes:
        size = self._number(b':')
        self._expect(b'"')
        result = self._take(size)
        self._expect(b'"')
        return result

    def value(self, depth: int = 0):
        self.nodes += 1
        if depth > 16 or self.nodes > 4096:
            raise ValueError('PHP snapshot nesting or item limit exceeded')
        kind = self._take(1)
        if kind == b'N':
            self._expect(b';')
            return None
        self._expect(b':')
        if kind == b's':
            result = self._string()
            self._expect(b';')
            return result
        if kind in (b'i', b'b'):
            result = self._number(b';')
            if kind == b'b':
                if result not in (0, 1):
                    raise ValueError('Invalid PHP boolean')
                return bool(result)
            return result
        if kind not in (b'O', b'a'):
            raise ValueError('Unsupported PHP serialized type')
        name = None
        if kind == b'O':
            name = self._string()
            if name not in (VAULT_CLASS, ACCOUNT_CLASS):
                raise ValueError('Unsupported PHP object class')
            self._expect(b':')
        count = self._number(b':')
        if count < 0 or count > 1024:
            raise ValueError('PHP property count exceeded')
        self._expect(b'{')
        values = {}
        for _ in range(count):
            key = self.value(depth + 1)
            if not isinstance(key, (bytes, int)) or isinstance(key, bool) or key in values:
                raise ValueError('Invalid or duplicate PHP property')
            values[key] = self.value(depth + 1)
        self._expect(b'}')
        return _Object(name, values) if name is not None else values


def _object(data: bytes, name: bytes) -> dict:
    reader = _Reader(data)
    result = reader.value()
    if reader.offset != len(data) or not isinstance(result, _Object) or result.name != name:
        raise ValueError('Unexpected PHP snapshot object')
    return result.properties


def is_php_object(data: bytes | str | None) -> bool:
    if isinstance(data, str):
        return data.startswith('O:')
    return isinstance(data, bytes) and data.startswith(b'O:')


@dataclass(frozen=True)
class PublicLinkSnapshot:
    id: int
    name: str
    login: str | None
    url: str | None
    notes: str | None
    category_id: int | None
    client_id: int | None
    category_name: str | None
    client_name: str | None
    password: str


def read_public_link_snapshot(data: bytes, link_hash: bytes, password_salt: str, account_id: int) -> PublicLinkSnapshot:
    if not password_salt:
        raise ValueError('PHP password salt is unavailable')
    vault = _object(data, VAULT_CLASS)
    prefix = b'\x00' + VAULT_CLASS + b'\x00'
    ciphertext = vault.get(prefix + b'data')
    key = vault.get(prefix + b'key')
    if not isinstance(ciphertext, bytes) or not isinstance(key, bytes):
        raise ValueError('PHP Vault ciphertext/key missing')
    seed = hashlib.sha1(password_salt.encode('utf-8') + link_hash).hexdigest()  # nosec B324 -- PHP format
    plaintext = decrypt_with_password(ciphertext.decode('ascii'), key.decode('ascii'), seed)
    account = _object(plaintext.encode('utf-8'), ACCOUNT_CLASS)

    def integer(name: bytes) -> int:
        value = account.get(name)
        if isinstance(value, bytes) and re.fullmatch(rb'\d{1,20}', value):
            value = int(value)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError('Invalid PHP account identifier')
        return value

    def string(name: bytes, nullable: bool = False) -> str | None:
        value = account.get(name)
        if value is None and nullable:
            return None
        if not isinstance(value, bytes):
            raise ValueError('Invalid PHP account text')
        return value.decode('utf-8')

    if integer(b'id') != account_id:
        raise ValueError('PHP link snapshot belongs to a different account')
    return PublicLinkSnapshot(
        id=account_id, name=string(b'name'), login=string(b'login', True),
        url=string(b'url', True), notes=string(b'notes', True),
        category_id=integer(b'categoryId') or None, client_id=integer(b'clientId') or None,
        category_name=string(b'categoryName', True), client_name=string(b'clientName', True),
        password=string(b'pass'),
    )
