import base64
from typing import List

BLOCK_SIZE = 8  # 64 бита
ROUNDS = 10     # рекомендуемое число раундов для варианта с 128-битным ключом



_EXP = [0] * 256
_LOG = [0] * 256

def _init_tables() -> None:
    """Инициализация таблиц exp/log для операций SAFER-подобного шифра."""
    # exp: 45^x (mod 257), 256 -> 0
    for i in range(256):
        y = pow(45, i, 257)
        if y == 256:
            y = 0
        _EXP[i] = y

    # log: обратное преобразование, log_45(x), log_45(0) = 128
    for i, val in enumerate(_EXP):
        x = val
        if x == 0:
            # по определению ниже установим log(0)=128
            continue
        _LOG[x] = i & 0xFF
    _LOG[0] = 128  # специальное значение, как в описании SAFER

_init_tables()

def _sbox_exp(x: int) -> int:
    return _EXP[x & 0xFF]

def _sbox_log(x: int) -> int:
    return _LOG[x & 0xFF]

# --- Вспомогательные функции ---

def _derive_key(key_str: str) -> bytes:
    """
    Преобразование произвольной строковой фразы пользователя в 128-битный ключ.
    Ключ усечён/дополнен до 16 байт.
    """
    kb = key_str.encode("utf-8")
    if len(kb) < 16:
        kb = kb.ljust(16, b"\x00")
    else:
        kb = kb[:16]
    return kb

def _rotate_byte_left6(b: int) -> int:
    """Циклический сдвиг байта влево на 6 бит (как в SAFER K-128 для подключей)."""
    b &= 0xFF
    return ((b << 6) & 0xFF) | (b >> 2)

def _generate_round_keys(master: bytes, rounds: int = ROUNDS) -> List[bytes]:
    """
    Генерация списка подключей из 128-битного ключа.
    Упрощённо: на каждом шаге выполняется циклический сдвиг каждого байта на 6 бит,
    в качестве подключа берутся первые 8 байт.
    """
    if len(master) != 16:
        raise ValueError("master key must be 16 bytes (128 бит).")

    state = list(master)
    round_keys: List[bytes] = []

    for _ in range(rounds):
        round_keys.append(bytes(state[:8]))
        state = [_rotate_byte_left6(b) for b in state]

    return round_keys

# --- Feistel-сети над блоком 64 бита ---

def _split_block(block: bytes) -> tuple[bytes, bytes]:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block size must be 8 bytes")
    return block[:4], block[4:]

def _join_block(left: bytes, right: bytes) -> bytes:
    return left + right

def _F(right: bytes, rk: bytes) -> bytes:
    """
    Раундовая функция F: XOR с подключом, нелинейность через exp/log,
    затем простое PHT-подобное линейное перемешивание.
    """
    if len(right) != 4:
        raise ValueError("Right half must be 4 bytes")
    if len(rk) < 4:
        raise ValueError("Round key must be at least 4 bytes")

    x = [(right[i] ^ rk[i]) & 0xFF for i in range(4)]

    # SAFER-подобное применение exp/log попеременно
    for i in range(4):
        if i % 2 == 0:
            x[i] = _sbox_exp(x[i])
        else:
            x[i] = _sbox_log(x[i])

    # PHT-подобное смешивание (по два байта)
    y0 = (2 * x[0] + x[1]) & 0xFF
    y1 = (x[0] + x[1]) & 0xFF
    y2 = (2 * x[2] + x[3]) & 0xFF
    y3 = (x[2] + x[3]) & 0xFF

    return bytes([y0, y1, y2, y3])

def encrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """Шифрование одного 64-битного блока в сети Фейстеля."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block must be 8 bytes")
    left, right = _split_block(block)

    for rk in round_keys:
        F_out = _F(right, rk[:4])
        left, right = right, bytes((l ^ f) & 0xFF for l, f in zip(left, F_out))

    return _join_block(left, right)

def decrypt_block(block: bytes, round_keys: List[bytes]) -> bytes:
    """Расшифрование одного 64-битного блока (обратная сеть Фейстеля)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError("Block must be 8 bytes")
    left, right = _split_block(block)

    for rk in reversed(round_keys):
        F_out = _F(left, rk[:4])
        left, right = bytes((r ^ f) & 0xFF for r, f in zip(right, F_out)), left

    return _join_block(left, right)

# --- Паддинг и режим CBC ---

def _pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    if pad_len == 0:
        pad_len = block_size
    return data + bytes([pad_len]) * pad_len

def _pkcs7_unpad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Invalid padded data length")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError("Invalid padding length")
    if data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Invalid padding bytes")
    return data[:-pad_len]

def _derive_iv(key: bytes) -> bytes:
    """
    Простая детерминированная генерация IV из ключа:
    первые 8 байт XOR с константой 0xA5. В реальных системах
    IV должен быть случайным.
    """
    return bytes((b ^ 0xA5) & 0xFF for b in key[:BLOCK_SIZE])

# --- Публичные функции шифрования / расшифрования сообщения ---

def encrypt_message(plaintext: str, key_str: str, rounds: int = ROUNDS) -> str:
    """
    Шифрует произвольную текстовую строку.
    :return: base64-строка, включающая IV + шифртекст.
    """
    master = _derive_key(key_str)
    round_keys = _generate_round_keys(master, rounds)
    iv = _derive_iv(master)

    data = _pkcs7_pad(plaintext.encode("utf-8"), BLOCK_SIZE)
    prev = iv
    chunks = []

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        xored = bytes(b ^ p for b, p in zip(block, prev))
        cblock = encrypt_block(xored, round_keys)
        chunks.append(cblock)
        prev = cblock

    result = iv + b"".join(chunks)
    return base64.b64encode(result).decode("ascii")

def decrypt_message(ciphertext_b64: str, key_str: str, rounds: int = ROUNDS) -> str:
    """
    Расшифровывает base64-строку, полученную из encrypt_message.
    :return: исходный текст (UTF-8).
    """
    raw = base64.b64decode(ciphertext_b64.encode("ascii"))
    if len(raw) < BLOCK_SIZE:
        raise ValueError("Ciphertext too short")

    iv = raw[:BLOCK_SIZE]
    cipher = raw[BLOCK_SIZE:]

    master = _derive_key(key_str)
    round_keys = _generate_round_keys(master, rounds)

    prev = iv
    chunks = []

    for i in range(0, len(cipher), BLOCK_SIZE):
        block = cipher[i:i + BLOCK_SIZE]
        dblock = decrypt_block(block, round_keys)
        pblock = bytes(b ^ p for b, p in zip(dblock, prev))
        chunks.append(pblock)
        prev = block

    data = b"".join(chunks)
    data = _pkcs7_unpad(data, BLOCK_SIZE)
    return data.decode("utf-8")
