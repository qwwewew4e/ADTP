ADTP (Aboba Data Transfer Protocol) Core Library v1.0
Оглавление
Описание

Быстрый старт

Установка

Архитектура

Компоненты библиотеки

Детальное использование

Примеры кода

Формат протокола

Алгоритм AHDE

Безопасность

Производительность

Ограничения

Лицензия

Описание
ADTP (Aboba Data Transfer Protocol) - это легковесный, безопасный протокол для передачи файлов и данных с использованием единого ключа шифрования. Библиотека предоставляет чистое ядро протокола без внешних зависимостей.

Основные особенности:

🛡️ Единый ключ - один ключ для всех операций

🔒 Многослойное шифрование - алгоритм AHDE

📦 Минимальные накладные расходы - компактные пакеты

🔄 Проверка целостности - CRC32 для каждого пакета

🚀 Высокая производительность - чистая реализация на Python

🧩 Модульность - отдельные компоненты для разных задач

Быстрый старт
1. Генерация ключа
python
from adtp import ADTPKey

# Генерация нового ключа
key = ADTPKey.generate()
print(f"ADTP Key: {key}")
2. Шифрование данных
python
from adtp import AHDE

# Шифрование данных
data = b"Secret message"
encrypted = AHDE.encrypt(data, key)

# Расшифрование
decrypted = AHDE.decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
3. Работа с протоколом
python
from adtp import ADTPProtocol, ADTPCommand
import json

# Инициализация протокола
protocol = ADTPProtocol(key)

# Создание пакета
packet_data = json.dumps({"action": "ping"}).encode()
packet = protocol.create_packet(ADTPCommand.PING, packet_data)

# Разбор пакета
parsed = protocol.parse_packet(packet)
print(f"Command: {parsed['command']}")
Установка
Требования
Python 3.6 или выше

Нет внешних зависимостей

Установка библиотеки
bash
# 1. Скопируйте файл adtp.py в ваш проект
cp adtp.py /путь/к/вашему/проекту/

# 2. Импортируйте в коде
from adtp import ADTPKey, AHDE, ADTPProtocol, ADTPCommand
Архитектура
Структура библиотеки
text
adtp.py
├── Утилиты (вспомогательные функции)
├── ADTPKey (управление ключами)
├── AHDE (алгоритм шифрования)
├── ADTPCommand (перечисление команд)
└── ADTPProtocol (ядро протокола)
Принцип работы
text
Клиент <--> [Шифрование AHDE] <--> Пакет ADTP <--> [Сеть] <--> Сервер
                      ↑                              ↑
                Единый ключ                     Единый ключ
Компоненты библиотеки
1. ADTPKey - Управление ключами
python
class ADTPKey:
    @staticmethod
    def generate() -> str           # Генерация 64-символьного ключа
    @staticmethod
    def validate(key: str) -> bool  # Проверка ключа
    @staticmethod
    def derive_keys(master_key: str) -> Tuple[bytes, bytes, bytes]  # Деривация
Формат ключа:

text
b5d1f5e8a3c9024f8e6d7c5b3a291f4e  # Контрольная сумма (32 символа)
a9c8b7e6d5f4a3b2c1d0e9f8a7b6c5d4  # Случайная часть (32 символа)
2. AHDE - Алгоритм шифрования
python
class AHDE:
    BLOCK_SIZE = 16      # Размер блока
    SALT_SIZE = 8        # Размер соли
    
    @staticmethod
    def encrypt(data: bytes, master_key: str) -> str
    @staticmethod
    def decrypt(encrypted_hex: str, master_key: str) -> bytes
3. ADTPCommand - Команды протокола
python
class ADTPCommand(IntEnum):
    # Управление соединением
    HELLO = 0x01
    PING = 0x02
    PONG = 0x03
    DISCONNECT = 0x04
    
    # Статусы
    OK = 0x10
    ERROR = 0x11
    
    # Файловые операции
    FILE_LIST = 0x20
    FILE_UPLOAD_START = 0x21
    FILE_UPLOAD_CHUNK = 0x22
    FILE_UPLOAD_END = 0x23
    FILE_DOWNLOAD_START = 0x24
    FILE_DOWNLOAD_CHUNK = 0x25
    FILE_DOWNLOAD_END = 0x26
    FILE_DELETE = 0x27
    
    # Системные команды
    SYSTEM_INFO = 0x30
    
    # Пользовательские команды
    CUSTOM_1 = 0x40
    CUSTOM_2 = 0x41
    CUSTOM_3 = 0x42
4. ADTPProtocol - Ядро протокола
python
class ADTPProtocol:
    def __init__(self, key: str)
    def create_packet(self, command, data: bytes = b"") -> bytes
    def parse_packet(self, packet: bytes) -> Dict[str, Any]
    def get_sequence(self) -> int
    def reset_sequence(self)
Детальное использование
Инициализация
python
from adtp import ADTPKey, AHDE, ADTPProtocol, ADTPCommand

# 1. Создание или загрузка ключа
key = ADTPKey.generate()  # или используйте существующий ключ

# 2. Проверка ключа
if not ADTPKey.validate(key):
    raise ValueError("Invalid key")

# 3. Создание экземпляра протокола
protocol = ADTPProtocol(key)
Шифрование данных
python
# Текст для шифрования
plaintext = b"Confidential data"

# Шифрование
encrypted_hex = AHDE.encrypt(plaintext, key)
# Результат: "8e3a7b1c4f9d2a6b..." (HEX строка)

# Расшифрование
decrypted_bytes = AHDE.decrypt(encrypted_hex, key)
# Результат: b"Confidential data"
Работа с пакетами
python
import json

# Создание пакета с JSON данными
data_dict = {
    "filename": "document.pdf",
    "size": 1024000,
    "checksum": "a1b2c3d4"
}
data_bytes = json.dumps(data_dict).encode()

packet = protocol.create_packet(
    command=ADTPCommand.FILE_UPLOAD_START,
    data=data_bytes
)

# Разбор пакета
try:
    parsed = protocol.parse_packet(packet)
    
    print(f"Command: {parsed['command']}")
    print(f"Sequence: {parsed['sequence']}")
    print(f"Timestamp: {parsed['timestamp']}")
    print(f"Data length: {parsed['data_len']} bytes")
    
    # Декодирование JSON данных
    if parsed['data']:
        received_data = json.loads(parsed['data'].decode())
        print(f"Filename: {received_data['filename']}")
        
except ValueError as e:
    print(f"Packet error: {e}")
Примеры кода
Пример 1: Полный цикл шифрования
python
from adtp import ADTPKey, AHDE
import secrets

# Генерация ключа
key = ADTPKey.generate()
print(f"Key: {key}")
print(f"Valid: {ADTPKey.validate(key)}")

# Тестовые данные разного размера
test_cases = [
    b"Short",
    b"Medium length data" * 10,
    secrets.token_bytes(1024),  # 1KB случайных данных
    secrets.token_bytes(10 * 1024),  # 10KB
]

for i, data in enumerate(test_cases, 1):
    print(f"\nTest {i}: {len(data)} bytes")
    
    # Шифрование
    encrypted = AHDE.encrypt(data, key)
    print(f"  Encrypted length: {len(encrypted)} chars")
    
    # Расшифрование
    decrypted = AHDE.decrypt(encrypted, key)
    
    # Проверка
    if data == decrypted:
        print(f"  ✓ Success")
    else:
        print(f"  ✗ Failed")
        print(f"  Original: {data[:50]}...")
        print(f"  Decrypted: {decrypted[:50]}...")
Пример 2: Эмуляция клиент-серверного обмена
python
from adtp import ADTPProtocol, ADTPCommand
import json
import time

class MockNetwork:
    """Мок-класс для эмуляции сети"""
    
    def __init__(self, key):
        self.client_proto = ADTPProtocol(key)
        self.server_proto = ADTPProtocol(key)
        self.buffer = b""
    
    def client_send(self, command, data_dict=None):
        """Клиент отправляет данные"""
        data = json.dumps(data_dict or {}).encode()
        packet = self.client_proto.create_packet(command, data)
        self.buffer = packet
        print(f"Client → Server: {command.name if hasattr(command, 'name') else hex(command)}")
        return len(packet)
    
    def server_receive(self):
        """Сервер получает данные"""
        if not self.buffer:
            return None
        
        parsed = self.server_proto.parse_packet(self.buffer)
        
        # Декодирование данных
        if parsed['data']:
            try:
                data = json.loads(parsed['data'].decode())
            except:
                data = parsed['data'].hex()
        else:
            data = None
        
        print(f"Server received:")
        print(f"  Command: {parsed['command']:#04x}")
        print(f"  Sequence: {parsed['sequence']}")
        print(f"  Data: {data}")
        
        self.buffer = b""
        return parsed
    
    def server_send(self, command, data_dict=None):
        """Сервер отправляет ответ"""
        data = json.dumps(data_dict or {}).encode()
        packet = self.server_proto.create_packet(command, data)
        self.buffer = packet
        print(f"Server → Client: {command.name if hasattr(command, 'name') else hex(command)}")
        return len(packet)
    
    def client_receive(self):
        """Клиент получает ответ"""
        if not self.buffer:
            return None
        
        parsed = self.client_proto.parse_packet(self.buffer)
        self.buffer = b""
        return parsed

# Использование
key = ADTPKey.generate()
network = MockNetwork(key)

# Клиент запрашивает список файлов
print("=" * 50)
network.client_send(ADTPCommand.FILE_LIST, {"path": "/documents"})

# Сервер обрабатывает запрос
server_received = network.server_receive()

# Сервер отвечает
network.server_send(ADTPCommand.OK, {
    "files": ["doc1.txt", "doc2.pdf", "image.jpg"],
    "count": 3
})

# Клиент получает ответ
client_received = network.client_receive()
if client_received:
    data = json.loads(client_received['data'].decode())
    print(f"Client received files: {data['files']}")
Пример 3: Работа с файлами
python
from adtp import ADTPProtocol, ADTPCommand
import os
import json

class FileTransfer:
    """Утилита для передачи файлов через ADTP"""
    
    def __init__(self, key):
        self.protocol = ADTPProtocol(key)
    
    def create_upload_packets(self, filepath, chunk_size=65536):
        """Создание пакетов для загрузки файла"""
        if not os.path.exists(filepath):
            raise FileNotFoundError(f"File not found: {filepath}")
        
        filename = os.path.basename(filepath)
        filesize = os.path.getsize(filepath)
        
        packets = []
        
        # 1. Пакет начала загрузки
        start_data = json.dumps({
            "action": "upload_start",
            "filename": filename,
            "size": filesize,
            "chunks": (filesize + chunk_size - 1) // chunk_size
        }).encode()
        
        packets.append(
            self.protocol.create_packet(ADTPCommand.FILE_UPLOAD_START, start_data)
        )
        
        # 2. Пакеты с данными
        with open(filepath, 'rb') as f:
            chunk_num = 0
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                
                chunk_data = json.dumps({
                    "chunk": chunk_num,
                    "size": len(chunk),
                    "data": chunk.hex()
                }).encode()
                
                packets.append(
                    self.protocol.create_packet(ADTPCommand.FILE_UPLOAD_CHUNK, chunk_data)
                )
                
                chunk_num += 1
        
        # 3. Пакет завершения
        end_data = json.dumps({
            "action": "upload_end",
            "filename": filename,
            "total_chunks": chunk_num
        }).encode()
        
        packets.append(
            self.protocol.create_packet(ADTPCommand.FILE_UPLOAD_END, end_data)
        )
        
        return packets
    
    def parse_upload_packet(self, packet):
        """Разбор пакета загрузки файла"""
        parsed = self.protocol.parse_packet(packet)
        
        if parsed['data']:
            data = json.loads(parsed['data'].decode())
            data['raw_packet'] = parsed
            return data
        
        return parsed

# Использование
key = ADTPKey.generate()
transfer = FileTransfer(key)

# Создание тестового файла
test_file = "test_document.txt"
with open(test_file, "w") as f:
    f.write("This is a test document for ADTP protocol.\n" * 100)

# Генерация пакетов
packets = transfer.create_upload_packets(test_file, chunk_size=1024)

print(f"Created {len(packets)} packets for file: {test_file}")
print(f"Total size: {sum(len(p) for p in packets)} bytes")

# Разбор первого пакета
if packets:
    parsed = transfer.parse_upload_packet(packets[0])
    print(f"\nFirst packet info:")
    print(f"  Command: {parsed['raw_packet']['command']:#04x}")
    print(f"  Filename: {parsed['filename']}")
    print(f"  Size: {parsed['size']} bytes")
    print(f"  Chunks: {parsed['chunks']}")

# Очистка
os.remove(test_file)
Формат протокола
Структура пакета ADTP
text
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Version(1)   |   Command(1)  |         Sequence(4)          |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Timestamp(8)                         |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|        Data Length(4)         |          CRC32(4)            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                     Encrypted Data(variable)                  |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
Описание полей
Поле	Размер	Описание	Пример
Version	1 байт	Версия протокола	0x01
Command	1 байт	Код команды	0x21 (FILE_UPLOAD_START)
Sequence	4 байта	Порядковый номер пакета	12345
Timestamp	8 байт	Время создания (мс)	1640995200000
Data Length	4 байта	Длина зашифрованных данных	256
CRC32	4 байта	Контрольная сумма	0xA1B2C3D4
Encrypted Data	variable	Зашифрованные данные	Зависит от AHDE
Пример заголовка
python
# Версия 1, команда HELLO, последовательность 1
header = struct.pack(">BBQII",
    0x01,            # Version
    0x01,            # Command (HELLO)
    1,               # Sequence
    1640995200000,   # Timestamp
    128,             # Data Length
    0xA1B2C3D4       # CRC32
)
Алгоритм AHDE
Процесс шифрования
text
Входные данные → Процесс AHDE → HEX вывод
     ↓                    ↓           ↓
   "Hello"       Многослойное     "8e3a7b1c..."
                шифрование
Шаг 1: Подготовка данных
python
# Исходные данные
data = b"Secret message"

# 1. PKCS7 padding до размера кратного 16 байтам
# Если data = 14 байт → padding = 2 байта со значением 0x02
padded = data + b"\x02\x02"  # 16 байт
Шаг 2: Генерация случайных значений
python
salt = secrets.token_bytes(8)   # 8 байт соли
iv = secrets.token_bytes(16)    # 16 байт IV
Шаг 3: Шифрование блоков (для каждого 16-байтового блока)
Этап A: Первичное шифрование

python
k1_hash = sha256(K1 + block)[:16]  # HMAC-SHA256
stage_a = block XOR k1_hash        # Побитовый XOR
Этап B: XOR-маскирование

python
salt_expanded = (salt * 2)[:16]    # Расширение соли до 16 байт
mask = K2 XOR salt_expanded        # Создание маски
stage_b = stage_a XOR mask         # Применение маски
Этап C: Циклический сдвиг

python
shift = (K3[i % 16] % 7) + 1      # Сдвиг от 1 до 7 бит
stage_c = rotate_left(stage_b, shift)  # Циклический сдвиг влево
Этап D: CBC-цепочка

python
if first_block:
    stage_d = stage_c XOR iv      # XOR с IV для первого блока
else:
    stage_d = stage_c XOR previous_cipher  # XOR с предыдущим блоком
Шаг 4: Финальное перемешивание
python
final_cipher = bytearray()
for i, byte in enumerate(ciphertext):
    final_cipher.append(byte ^ K3[i % 16])  # XOR с K3
Шаг 5: Формирование результата
python
result = salt + iv + bytes(final_cipher)  # Конкатенация
return result.hex()  # HEX представление
Формат зашифрованных данных
text
[Соль: 8 байт][IV: 16 байт][Шифротекст: N*16 байт]
       ↓            ↓              ↓
    Random       Random      Зашифрованные
                          блоки данных
Пример работы
text
Исходные данные: b"Hello World!"
Длина: 12 байт

1. Padding: b"Hello World!\x04\x04\x04\x04" (16 байт)
2. Генерация соли: b"\x1a\x2b\x3c\x4d\x5e\x6f\x70\x81"
3. Генерация IV: b"\x91\xa2\xb3\xc4\xd5\xe6\xf7\x08\x19\x2a\x3b\x4c\x5d\x6e\x7f\x80"
4. Шифрование блоков...
5. Финальный результат: "1a2b3c4d5e6f708191a2b3c4d5e6f70819..." (HEX)
Безопасность
Особенности безопасности AHDE
Соль (Salt) - 8 случайных байт для каждого шифрования

Предотвращает атаки по словарю

Даже одинаковые данные дают разные шифротексты

IV (Initialization Vector) - 16 случайных байт

Обеспечивает уникальность CBC цепочки

Защищает от pattern analysis

Многослойное шифрование

4 этапа обработки каждого блока

Комбинация XOR, сдвигов и CBC

Усложняет криптоанализ

Ключевая система

3 производных ключа из одного мастер-ключа

Разделение функций (шифрование, маскирование, сдвиг)

Рекомендации по безопасности
Генерация ключей

python
# Правильно
key = ADTPKey.generate()  # Используйте встроенную генерацию

# Неправильно
key = "my_secret_password"  # Слабый ключ
Хранение ключей

python
# Безопасное хранение
import os

# Чтение ключа из защищенного файла
with open("/secure/path/adtp.key", "rb") as f:
    key = f.read().decode().strip()

# Проверка ключа
if not ADTPKey.validate(key):
    raise SecurityError("Invalid or tampered key")
Защита от атак

Используйте разные ключи для разных серверов

Регулярно обновляйте ключи в продакшене

Ограничивайте количество попыток подключения

Известные ограничения безопасности
Не использует AES - вместо этого HMAC-SHA256 (менее безопасно)

Самодельная криптография - не проходила аудит

Для продакшена рекомендуется использовать TLS поверх ADTP

Производительность
Бенчмарки (примерные)
python
import time
from adtp import ADTPKey, AHDE

# Тестирование скорости
key = ADTPKey.generate()
test_sizes = [100, 1000, 10000, 100000]  # байт

for size in test_sizes:
    data = b"x" * size
    
    start = time.time()
    encrypted = AHDE.encrypt(data, key)
    encrypt_time = time.time() - start
    
    start = time.time()
    decrypted = AHDE.decrypt(encrypted, key)
    decrypt_time = time.time() - start
    
    print(f"Size: {size:6d} bytes | "
          f"Encrypt: {encrypt_time:.4f}s | "
          f"Decrypt: {decrypt_time:.4f}s | "
          f"Total: {encrypt_time + decrypt_time:.4f}s")
Ожидаемые результаты:

1 KB: ~0.001-0.003 секунды

10 KB: ~0.01-0.03 секунды

100 KB: ~0.1-0.3 секунды

1 MB: ~1-3 секунды

Оптимизация
Размер чанков

python
# Оптимальный размер для файлов
CHUNK_SIZE = 65536  # 64KB - баланс скорости и памяти
Буферизация

python
# Используйте буферизацию для больших файлов
BUFFER_SIZE = 8192  # 8KB буфер
Параллельная обработка

python
# Для многопоточности создавайте отдельный протокол для каждого потока
import threading

class ThreadSafeProtocol:
    def __init__(self, key):
        self.key = key
        self.lock = threading.Lock()
    
    def create_packet(self, command, data):
        with self.lock:
            protocol = ADTPProtocol(self.key)
            return protocol.create_packet(command, data)
Ограничения
Технические ограничения
Максимальный размер пакета

text
Data Length: 4 байта (unsigned int)
Максимальное значение: 4,294,967,295 байт (~4 GB)

Практический лимит: рекомендуется ≤ 16 MB на пакет
Производительность

Чистый Python (медленнее чем C/C++)

Нет аппаратного ускорения AES

Подходит для средних объемов данных

Совместимость

Только Python 3.6+

Little-endian / Big-endian (используется big-endian)

Нет поддержки других языков

Рекомендации по использованию
Для небольших файлов (< 10 MB)

python
# Прямая передача
protocol.create_packet(command, file_data)
Для больших файлов (> 10 MB)

python
# Чанкование
chunk_size = 65536  # 64KB
for chunk in read_file_in_chunks(filepath, chunk_size):
    protocol.create_packet(FILE_UPLOAD_CHUNK, chunk)
Для потоковой передачи

python
# Используйте буферизацию
buffer = b""
while data_stream.has_data():
    buffer += data_stream.read(4096)
    if len(buffer) >= 65536:
        send_packet(buffer[:65536])
        buffer = buffer[65536:]
