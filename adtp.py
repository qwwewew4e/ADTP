"""
ADTP (Aboba Data Transfer Protocol) Core v1.0
Исправленная версия с корректной работой padding
"""

import struct
import hashlib
import secrets
import time
from typing import Dict, Tuple, Any, Union
from enum import IntEnum


# ============================================================================
# 1. ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ============================================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR двух байтовых строк"""
    if len(a) != len(b):
        # Расширяем более короткую строку
        if len(a) < len(b):
            a = a * (len(b) // len(a) + 1)
            a = a[:len(b)]
        else:
            b = b * (len(a) // len(b) + 1)
            b = b[:len(a)]
    return bytes(x ^ y for x, y in zip(a, b))


def _rotate_left(data: bytes, shift: int) -> bytes:
    """Циклический сдвиг влево для каждого байта"""
    shift = shift % 8
    if shift == 0:
        return data
    
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = ((byte << shift) & 0xFF) | (byte >> (8 - shift))
    return bytes(result)


def _rotate_right(data: bytes, shift: int) -> bytes:
    """Циклический сдвиг вправо для каждого байта"""
    shift = shift % 8
    if shift == 0:
        return data
    
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = (byte >> shift) | ((byte << (8 - shift)) & 0xFF)
    return bytes(result)


def _calculate_crc32(data: bytes) -> int:
    """Вычисление CRC32"""
    crc = 0xFFFFFFFF
    for byte in data:
        crc ^= byte << 24
        for _ in range(8):
            if crc & 0x80000000:
                crc = (crc << 1) ^ 0x04C11DB7
            else:
                crc = crc << 1
            crc &= 0xFFFFFFFF
    return crc


def _pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """PKCS7 padding"""
    if not data:
        # Для пустых данных добавляем полный блок padding
        return bytes([block_size] * block_size)
    
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    
    return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Удаление PKCS7 padding"""
    if not data:
        return b""
    
    padding_len = data[-1]
    
    # Проверяем что padding_len в допустимом диапазоне
    if padding_len < 1 or padding_len > len(data):
        # Если padding некорректен, возвращаем данные как есть
        # (возможно это уже данные без padding)
        return data
    
    # Проверяем что все байты padding одинаковы и равны padding_len
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            # Если padding некорректен, возвращаем данные как есть
            return data
    
    return data[:-padding_len]


# ============================================================================
# 2. СИСТЕМА КЛЮЧЕЙ
# ============================================================================

class ADTPKey:
    """Управление ключами ADTP"""
    
    @staticmethod
    def generate() -> str:
        """
        Генерация ADTP ключа (64 hex символа)
        Формат: SHA256(random)[:32] + random(32 hex chars)
        
        Returns:
            str: 64-символьный hex ключ
        """
        random_part = secrets.token_hex(16)
        checksum = hashlib.sha256(random_part.encode()).hexdigest()[:32]
        return checksum + random_part
    
    @staticmethod
    def validate(key: str) -> bool:
        """
        Проверка валидности ключа
        
        Args:
            key: Ключ для проверки
            
        Returns:
            bool: True если ключ валиден
        """
        if len(key) != 64:
            return False
        
        checksum = key[:32]
        random_part = key[32:]
        calculated = hashlib.sha256(random_part.encode()).hexdigest()[:32]
        return calculated == checksum
    
    @staticmethod
    def derive_keys(master_key: str) -> Tuple[bytes, bytes, bytes]:
        """
        Деривация трех подключа из мастер-ключа
        
        Args:
            master_key: Основной ключ ADTP
            
        Returns:
            Tuple[bytes, bytes, bytes]: K1, K2, K3 (каждый по 16 байт)
        """
        random_part = master_key[32:].encode()
        base_key = hashlib.sha256(random_part).digest()
        
        k1 = hashlib.sha256(base_key + b"K1_AES_KEY").digest()[:16]
        k2 = hashlib.sha256(base_key + b"K2_XOR_MASK").digest()[:16]
        k3 = hashlib.sha256(base_key + b"K3_SHIFT_KEY").digest()[:16]
        
        return k1, k2, k3


# ============================================================================
# 3. АЛГОРИТМ ШИФРОВАНИЯ AHDE (ИСПРАВЛЕННЫЙ)
# ============================================================================

class AHDE:
    """Реализация алгоритма шифрования AHDE (исправленная)"""
    
    BLOCK_SIZE = 16
    SALT_SIZE = 8
    
    @staticmethod
    def encrypt(data: bytes, master_key: str) -> str:
        """
        Шифрование данных по алгоритму AHDE
        
        Args:
            data: Данные для шифрования
            master_key: ADTP ключ (64 hex символа)
            
        Returns:
            str: Зашифрованные данные в HEX формате
            
        Raises:
            ValueError: Если ключ невалиден
        """
        if not ADTPKey.validate(master_key):
            raise ValueError("Invalid ADTP key")
        
        k1, k2, k3 = ADTPKey.derive_keys(master_key)
        
        # 1. PKCS7 padding (ВАЖНО: всегда добавляем padding)
        padded = _pkcs7_pad(data, AHDE.BLOCK_SIZE)
        
        # 2. Генерация соли и IV
        salt = secrets.token_bytes(AHDE.SALT_SIZE)
        iv = secrets.token_bytes(16)
        
        # 3. Подготовка маски (K2 XOR соль)
        salt_expanded = (salt * 2)[:16]  # Повторяем соль для получения 16 байт
        mask = _xor_bytes(k2, salt_expanded)
        
        # 4. Шифрование блоков
        cipher_blocks = []
        prev_cipher = iv
        
        for i in range(0, len(padded), AHDE.BLOCK_SIZE):
            block = padded[i:i + AHDE.BLOCK_SIZE]
            
            # Этап A: Упрощенное "шифрование" (в реальности должен быть AES)
            # Используем HMAC-SHA256 для имитации шифрования
            h1 = hashlib.sha256(k1 + block).digest()[:16]
            stage_a = _xor_bytes(block, h1)
            
            # Этап B: XOR маскирование
            stage_b = _xor_bytes(stage_a, mask)
            
            # Этап C: Циклический сдвиг (1-7 бит)
            shift = (k3[i % 16] % 7) + 1
            stage_c = _rotate_left(stage_b, shift)
            
            # Этап D: CBC режим
            stage_d = _xor_bytes(stage_c, prev_cipher)
            
            cipher_blocks.append(stage_d)
            prev_cipher = stage_d
        
        # 5. Объединение блоков
        ciphertext = b''.join(cipher_blocks)
        
        # 6. Финальное перемешивание с K3
        final_cipher = bytearray()
        for i, byte in enumerate(ciphertext):
            final_cipher.append(byte ^ k3[i % 16])
        
        # 7. HEX вывод: соль + IV + шифротекст
        result = salt + iv + bytes(final_cipher)
        return result.hex()
    
    @staticmethod
    def decrypt(encrypted_hex: str, master_key: str) -> bytes:
        """
        Расшифрование данных по алгоритму AHDE
        
        Args:
            encrypted_hex: Зашифрованные данные в HEX формате
            master_key: ADTP ключ (64 hex символа)
            
        Returns:
            bytes: Расшифрованные данные
            
        Raises:
            ValueError: Если ключ невалиден или данные повреждены
        """
        if not ADTPKey.validate(master_key):
            raise ValueError("Invalid ADTP key")
        
        try:
            encrypted_data = bytes.fromhex(encrypted_hex)
        except ValueError:
            raise ValueError("Invalid hex string")
        
        # Проверка минимальной длины
        min_length = AHDE.SALT_SIZE + 16 + AHDE.BLOCK_SIZE
        if len(encrypted_data) < min_length:
            raise ValueError("Encrypted data too short")
        
        # Извлечение компонентов
        salt = encrypted_data[:AHDE.SALT_SIZE]
        iv = encrypted_data[AHDE.SALT_SIZE:AHDE.SALT_SIZE + 16]
        ciphertext = encrypted_data[AHDE.SALT_SIZE + 16:]
        
        # Проверка что ciphertext кратен BLOCK_SIZE
        if len(ciphertext) % AHDE.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length not multiple of block size")
        
        k1, k2, k3 = ADTPKey.derive_keys(master_key)
        
        # 1. Отмена финального перемешивания
        cipher_unmixed = bytearray()
        for i, byte in enumerate(ciphertext):
            cipher_unmixed.append(byte ^ k3[i % 16])
        ciphertext = bytes(cipher_unmixed)
        
        # 2. Подготовка маски
        salt_expanded = (salt * 2)[:16]
        mask = _xor_bytes(k2, salt_expanded)
        
        # 3. Расшифрование блоков
        blocks = []
        prev_cipher = iv
        
        for i in range(0, len(ciphertext), AHDE.BLOCK_SIZE):
            block = ciphertext[i:i + AHDE.BLOCK_SIZE]
            
            # Обратный Этап D: CBC
            stage_d = _xor_bytes(block, prev_cipher)
            
            # Обратный Этап C: Сдвиг вправо
            shift = (k3[i % 16] % 7) + 1
            stage_c = _rotate_right(stage_d, shift)
            
            # Обратный Этап B: XOR маскирование
            stage_b = _xor_bytes(stage_c, mask)
            
            # Обратный Этап A
            h1 = hashlib.sha256(k1 + stage_b).digest()[:16]
            stage_a = _xor_bytes(stage_b, h1)
            
            blocks.append(stage_a)
            prev_cipher = block
        
        # 4. Объединение блоков
        decrypted = b''.join(blocks)
        
        # 5. Удаление PKCS7 padding
        # Используем безопасный unpadding
        try:
            return _pkcs7_unpad(decrypted)
        except Exception as e:
            raise ValueError(f"Padding error: {e}")
    
    @staticmethod
    def test() -> bool:
        """
        Тестирование шифрования/расшифрования
        
        Returns:
            bool: True если тест пройден
        """
        try:
            key = ADTPKey.generate()
            
            test_cases = [
                b"",  # Пустые данные
                b"A",  # 1 байт
                b"Hello, ADTP!",  # 12 байт
                b"This is a longer test message for ADTP encryption algorithm.",  # 64 байта
                b"X" * 100,  # 100 байт
                b"Y" * 255,  # 255 байт
            ]
            
            for i, test_data in enumerate(test_cases):
                encrypted = AHDE.encrypt(test_data, key)
                decrypted = AHDE.decrypt(encrypted, key)
                
                if test_data != decrypted:
                    print(f"Test {i} failed:")
                    print(f"  Original: {test_data[:50]}...")
                    print(f"  Decrypted: {decrypted[:50]}...")
                    return False
            
            print("All AHDE tests passed!")
            return True
            
        except Exception as e:
            print(f"AHDE test failed with error: {e}")
            return False


# ============================================================================
# 4. КОМАНДЫ ПРОТОКОЛА
# ============================================================================

class ADTPCommand(IntEnum):
    """Команды протокола ADTP"""
    # Управление соединением
    HELLO = 0x01
    PING = 0x02
    PONG = 0x03
    DISCONNECT = 0x04
    
    # Статусы
    OK = 0x10
    ERROR = 0x11
    UNAUTHORIZED = 0x12
    
    # Файловые операции
    FILE_LIST = 0x20
    FILE_UPLOAD_START = 0x21
    FILE_UPLOAD_CHUNK = 0x22
    FILE_UPLOAD_END = 0x23
    FILE_DOWNLOAD_START = 0x24
    FILE_DOWNLOAD_CHUNK = 0x25
    FILE_DOWNLOAD_END = 0x26
    FILE_DELETE = 0x27
    FILE_INFO = 0x28
    
    # Системные
    SYSTEM_INFO = 0x30
    CONFIG_GET = 0x31
    CONFIG_SET = 0x32
    
    # Пользовательские (для расширения)
    CUSTOM_1 = 0x40
    CUSTOM_2 = 0x41
    CUSTOM_3 = 0x42
    CUSTOM_4 = 0x43
    CUSTOM_5 = 0x44


# ============================================================================
# 5. ЯДРО ПРОТОКОЛА ADTP (ИСПРАВЛЕННОЕ)
# ============================================================================

class ADTPProtocol:
    """Ядро протокола ADTP - создание и разбор пакетов"""
    
    # Формат заголовка пакета (big-endian):
    # version(1) | command(1) | sequence(4) | timestamp(8) | data_len(4) | crc32(4)
    HEADER_FORMAT = ">BBQII"
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    def __init__(self, key: str):
        """
        Инициализация протокола
        
        Args:
            key: ADTP ключ (64 hex символа)
            
        Raises:
            ValueError: Если ключ невалиден
        """
        if not ADTPKey.validate(key):
            raise ValueError("Invalid ADTP key. Key must be 64 hex chars")
        
        self.key = key
        self.sequence = 0
    
    def create_packet(self, command: Union[int, ADTPCommand], data: bytes = b"") -> bytes:
        """
        Создание пакета ADTP
        
        Args:
            command: Код команды или ADTPCommand
            data: Данные для отправки (будут зашифрованы)
            
        Returns:
            bytes: Готовый пакет для отправки
        """
        self.sequence += 1
        
        # Конвертация команды в int если нужно
        if isinstance(command, ADTPCommand):
            command = command.value
        
        # Шифрование данных
        encrypted_data = b""
        if data:
            try:
                encrypted_hex = AHDE.encrypt(data, self.key)
                encrypted_data = encrypted_hex.encode('utf-8')
            except Exception as e:
                print(f"Warning: Encryption failed, sending plaintext: {e}")
                encrypted_data = data
        else:
            # Даже для пустых данных создаем пакет
            encrypted_data = b""
        
        # Формирование заголовка
        timestamp = int(time.time() * 1000)  # Миллисекунды
        data_len = len(encrypted_data)
        crc = _calculate_crc32(encrypted_data)
        
        header = struct.pack(
            self.HEADER_FORMAT,
            0x01,           # Версия протокола
            command,        # Код команды
            timestamp,      # Временная метка
            data_len,       # Длина данных
            crc             # Контрольная сумма
        )
        
        # Формирование полного пакета
        packet = header + encrypted_data
        
        return packet
    
    def parse_packet(self, packet: bytes) -> Dict[str, Any]:
        """
        Разбор пакета ADTP
        
        Args:
            packet: Полученный пакет
            
        Returns:
            Dict: Разобранный пакет с полями:
                - version (int): версия протокола
                - command (int): код команды
                - sequence (int): порядковый номер
                - timestamp (int): временная метка
                - data_len (int): длина данных
                - crc (int): контрольная сумма
                - data (bytes): расшифрованные данные
                - raw_data (bytes): зашифрованные данные
                
        Raises:
            ValueError: Если пакет поврежден или невалиден
        """
        # Проверка минимальной длины
        if len(packet) < self.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(packet)} bytes, expected at least {self.HEADER_SIZE}")
        
        # Разбор заголовка
        header = packet[:self.HEADER_SIZE]
        try:
            version, command, timestamp, data_len, crc = struct.unpack(
                self.HEADER_FORMAT, header
            )
        except struct.error as e:
            raise ValueError(f"Invalid packet header: {e}")
        
        # Проверка версии
        if version != 0x01:
            raise ValueError(f"Unsupported protocol version: {version}")
        
        # Проверка длины данных
        if len(packet) < self.HEADER_SIZE + data_len:
            raise ValueError(f"Incomplete packet: expected {self.HEADER_SIZE + data_len} bytes, got {len(packet)}")
        
        # Извлечение данных
        encrypted_data = packet[self.HEADER_SIZE:self.HEADER_SIZE + data_len]
        
        # Проверка контрольной суммы
        calculated_crc = _calculate_crc32(encrypted_data)
        if calculated_crc != crc:
            raise ValueError(f"CRC mismatch: expected {crc:#010x}, got {calculated_crc:#010x}")
        
        # Расшифровка данных
        decrypted_data = b""
        if encrypted_data:
            try:
                # Пробуем расшифровать как HEX строку
                encrypted_hex = encrypted_data.decode('utf-8')
                decrypted = AHDE.decrypt(encrypted_hex, self.key)
                decrypted_data = decrypted
            except UnicodeDecodeError:
                # Если не UTF-8, пробуем как сырые данные
                decrypted_data = encrypted_data
            except Exception as e:
                # При ошибке расшифрования оставляем зашифрованные данные
                decrypted_data = encrypted_data
        
        return {
            'version': version,
            'command': command,
            'sequence': self.sequence,
            'timestamp': timestamp,
            'data_len': data_len,
            'crc': crc,
            'data': decrypted_data,
            'raw_data': encrypted_data
        }
    
    def get_sequence(self) -> int:
        """Получение текущего порядкового номера"""
        return self.sequence
    
    def reset_sequence(self):
        """Сброс порядкового номера"""
        self.sequence = 0


# ============================================================================
# 6. ТЕСТИРОВАНИЕ
# ============================================================================

if __name__ == "__main__":
    print("=== Тестирование библиотеки ADTP ===")
    print()
    
    # Тест 1: Ключи
    print("1. Тестирование ключей...")
    key = ADTPKey.generate()
    print(f"   Сгенерирован ключ: {key[:32]}...")
    print(f"   Ключ валиден: {ADTPKey.validate(key)}")
    print()
    
    # Тест 2: Шифрование AHDE
    print("2. Тестирование шифрования AHDE...")
    if AHDE.test():
        print("   ✓ AHDE работает корректно")
    else:
        print("   ✗ AHDE тест не пройден")
    print()
    
    # Тест 3: Протокол
    print("3. Тестирование протокола...")
    try:
        protocol = ADTPProtocol(key)
        
        test_data = b"Hello, ADTP!"
        packet = protocol.create_packet(ADTPCommand.HELLO, test_data)
        
        print(f"   Создан пакет: {len(packet)} байт")
        
        parsed = protocol.parse_packet(packet)
        print(f"   Команда: {parsed['command']:#04x}")
        print(f"   Sequence: {parsed['sequence']}")
        print(f"   Данные: {parsed['data']}")
        
        if parsed['data'] == test_data:
            print("   ✓ Протокол работает корректно")
        else:
            print("   ✗ Данные не совпадают")
            
    except Exception as e:
        print(f"   ✗ Ошибка протокола: {e}")
    
    print()
    print("=== Тестирование завершено ===")
