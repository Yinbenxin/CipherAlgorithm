from typing import Union

BytesLike = Union[bytes, bytearray, memoryview]


def as_bytes(value: BytesLike, name: str) -> bytes:
    """Normalize a bytes-like argument for the native module.

    Rejects ``int`` and ``str`` explicitly: ``bytes(16)`` silently creates
    sixteen zero bytes, which would be a dangerous key.
    """
    if isinstance(value, bytes):
        return value
    if isinstance(value, (bytearray, memoryview)):
        return bytes(value)
    raise TypeError(f"{name} must be bytes, bytearray or memoryview, not {type(value).__name__}")
