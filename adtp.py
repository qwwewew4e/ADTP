"""
ADTP (Aboba Data Transfer Protocol) Library
"""

import struct
import hashlib
import secrets
import time
from typing import Dict, Tuple, Any, Union
from enum import IntEnum


# ============================================================================
# UTILITIES
# ============================================================================

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings"""
    if len(a) != len(b):
        # Extend shorter string
        if len(a) < len(b):
            a = (a * ((len(b) // len(a)) + 1))[:len(b)]
        else:
            b = (b * ((len(a) // len(b)) + 1))[:len(a)]
    return bytes(x ^ y for x, y in zip(a, b))


def _rotate_left(data: bytes, shift: int) -> bytes:
    """Rotate left each byte"""
    shift = shift % 8
    if shift == 0:
        return data
    
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = ((byte << shift) & 0xFF) | (byte >> (8 - shift))
    return bytes(result)


def _rotate_right(data: bytes, shift: int) -> bytes:
    """Rotate right each byte"""
    shift = shift % 8
    if shift == 0:
        return data
    
    result = bytearray(len(data))
    for i, byte in enumerate(data):
        result[i] = (byte >> shift) | ((byte << (8 - shift)) & 0xFF)
    return bytes(result)


def _calculate_crc32(data: bytes) -> int:
    """Calculate CRC32"""
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
        return bytes([block_size] * block_size)
    
    padding_len = block_size - (len(data) % block_size)
    if padding_len == 0:
        padding_len = block_size
    
    return data + bytes([padding_len] * padding_len)


def _pkcs7_unpad(data: bytes) -> bytes:
    """Remove PKCS7 padding"""
    if not data or len(data) < 1:
        return b""
    
    padding_len = data[-1]
    
    if padding_len < 1 or padding_len > len(data):
        return data
    
    for i in range(1, padding_len + 1):
        if data[-i] != padding_len:
            return data
    
    return data[:-padding_len]


# ============================================================================
# KEY MANAGEMENT
# ============================================================================

class ADTPKey:
    """ADTP Key Management"""
    
    @staticmethod
    def generate() -> str:
        """
        Generate ADTP key (64 hex chars)
        Format: SHA256(random)[:32] + random(32 hex chars)
        """
        random_part = secrets.token_hex(16)
        checksum = hashlib.sha256(random_part.encode()).hexdigest()[:32]
        return checksum + random_part
    
    @staticmethod
    def validate(key: str) -> bool:
        """
        Validate key
        
        Args:
            key: Key to validate
            
        Returns:
            bool: True if key is valid
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
        Derive three subkeys from master key
        
        Args:
            master_key: Main ADTP key
            
        Returns:
            Tuple[bytes, bytes, bytes]: K1, K2, K3 (each 16 bytes)
        """
        random_part = master_key[32:].encode()
        base_key = hashlib.sha256(random_part).digest()
        
        k1 = hashlib.sha256(base_key + b"K1_AES_KEY").digest()[:16]
        k2 = hashlib.sha256(base_key + b"K2_XOR_MASK").digest()[:16]
        k3 = hashlib.sha256(base_key + b"K3_SHIFT_KEY").digest()[:16]
        
        return k1, k2, k3


# ============================================================================
# AHDE ENCRYPTION
# ============================================================================

class AHDE:
    """AHDE Encryption Algorithm - Correct Implementation"""
    
    BLOCK_SIZE = 16
    SALT_SIZE = 8
    
    @staticmethod
    def encrypt(data: bytes, master_key: str) -> str:
        """
        Encrypt data using AHDE algorithm
        
        Process:
        1. PKCS7 padding to 16 bytes
        2. Generate salt (8 bytes)
        3. For each 16-byte block:
           A: XOR with K1
           B: XOR with mask (K2 XOR salt)
           C: Rotate left by shift bits
           D: CBC chaining
        4. Final XOR with K3
        5. Output: salt + iv + ciphertext (HEX)
        """
        if not ADTPKey.validate(master_key):
            raise ValueError("Invalid ADTP key")
        
        # Derive keys
        k1, k2, k3 = ADTPKey.derive_keys(master_key)
        
        # 1. PKCS7 padding
        padded = _pkcs7_pad(data, AHDE.BLOCK_SIZE)
        
        # 2. Generate salt and IV
        salt = secrets.token_bytes(AHDE.SALT_SIZE)
        iv = secrets.token_bytes(AHDE.BLOCK_SIZE)
        
        # 3. Prepare mask (K2 XOR expanded salt)
        # Expand salt to 16 bytes by repeating
        salt_expanded = (salt * 2)[:AHDE.BLOCK_SIZE]
        mask = _xor_bytes(k2, salt_expanded)
        
        # 4. Encrypt blocks with CBC
        cipher_blocks = []
        prev_cipher = iv
        
        for block_idx in range(0, len(padded), AHDE.BLOCK_SIZE):
            block = padded[block_idx:block_idx + AHDE.BLOCK_SIZE]
            
            # STAGE A: XOR with K1
            stage_a = _xor_bytes(block, k1)
            
            # STAGE B: XOR with mask
            stage_b = _xor_bytes(stage_a, mask)
            
            # STAGE C: Rotate left (1-7 bits based on K3)
            shift_idx = (block_idx // AHDE.BLOCK_SIZE) % len(k3)
            shift_amount = (k3[shift_idx] % 7) + 1  # 1-7 bits
            stage_c = _rotate_left(stage_b, shift_amount)
            
            # STAGE D: CBC mode
            stage_d = _xor_bytes(stage_c, prev_cipher)
            
            cipher_blocks.append(stage_d)
            prev_cipher = stage_d
        
        # 5. Combine all cipher blocks
        ciphertext = b''.join(cipher_blocks)
        
        # 6. Final mixing with K3
        final_cipher = bytearray()
        for i, byte in enumerate(ciphertext):
            final_cipher.append(byte ^ k3[i % len(k3)])
        
        # 7. Return salt + IV + ciphertext in HEX
        result = salt + iv + bytes(final_cipher)
        return result.hex()
    
    @staticmethod
    def decrypt(encrypted_hex: str, master_key: str) -> bytes:
        """
        Decrypt data using AHDE algorithm
        
        Reverse process of encryption
        """
        if not ADTPKey.validate(master_key):
            raise ValueError("Invalid ADTP key")
        
        try:
            # Convert from HEX
            encrypted_data = bytes.fromhex(encrypted_hex)
        except ValueError:
            raise ValueError("Invalid hex string")
        
        # Check minimum length
        min_length = AHDE.SALT_SIZE + AHDE.BLOCK_SIZE + AHDE.BLOCK_SIZE
        if len(encrypted_data) < min_length:
            raise ValueError("Encrypted data too short")
        
        # Extract components
        salt = encrypted_data[:AHDE.SALT_SIZE]
        iv = encrypted_data[AHDE.SALT_SIZE:AHDE.SALT_SIZE + AHDE.BLOCK_SIZE]
        ciphertext = encrypted_data[AHDE.SALT_SIZE + AHDE.BLOCK_SIZE:]
        
        # Verify ciphertext length is multiple of block size
        if len(ciphertext) % AHDE.BLOCK_SIZE != 0:
            raise ValueError("Ciphertext length not multiple of block size")
        
        # Derive keys
        k1, k2, k3 = ADTPKey.derive_keys(master_key)
        
        # 1. Prepare mask (must be same as encryption)
        salt_expanded = (salt * 2)[:AHDE.BLOCK_SIZE]
        mask = _xor_bytes(k2, salt_expanded)
        
        # 2. Remove final mixing with K3
        cipher_unmixed = bytearray()
        for i, byte in enumerate(ciphertext):
            cipher_unmixed.append(byte ^ k3[i % len(k3)])
        ciphertext = bytes(cipher_unmixed)
        
        # 3. Decrypt blocks in reverse
        blocks = []
        prev_cipher = iv
        
        for block_idx in range(0, len(ciphertext), AHDE.BLOCK_SIZE):
            block = ciphertext[block_idx:block_idx + AHDE.BLOCK_SIZE]
            
            # REVERSE STAGE D: CBC
            stage_c = _xor_bytes(block, prev_cipher)
            
            # REVERSE STAGE C: Rotate right
            shift_idx = (block_idx // AHDE.BLOCK_SIZE) % len(k3)
            shift_amount = (k3[shift_idx] % 7) + 1
            stage_b = _rotate_right(stage_c, shift_amount)
            
            # REVERSE STAGE B: XOR with mask
            stage_a = _xor_bytes(stage_b, mask)
            
            # REVERSE STAGE A: XOR with K1
            original_block = _xor_bytes(stage_a, k1)
            
            blocks.append(original_block)
            prev_cipher = block
        
        # 4. Combine blocks and remove padding
        decrypted = b''.join(blocks)
        return _pkcs7_unpad(decrypted)
    
    @staticmethod
    def test() -> bool:
        """Test AHDE encryption/decryption"""
        print("Testing AHDE encryption...")
        
        key = ADTPKey.generate()
        print(f"Test key: {key[:32]}...")
        
        test_cases = [
            (b"", "Empty data"),
            (b"A", "Single byte"),
            (b"Hello, ADTP!", "Short text"),
            (b"This is a test message", "Medium text"),
            (b"!@#$%^&*()", "Special chars"),
            (secrets.token_bytes(16), "16 random bytes"),
            (secrets.token_bytes(100), "100 random bytes"),
        ]
        
        all_passed = True
        
        for data, description in test_cases:
            try:
                print(f"\n{description} ({len(data)} bytes):")
                
                encrypted = AHDE.encrypt(data, key)
                print(f"  Encrypted: {len(encrypted)} hex chars")
                
                decrypted = AHDE.decrypt(encrypted, key)
                
                if data == decrypted:
                    print(f"  ✓ PASSED")
                else:
                    print(f"  ✗ FAILED")
                    print(f"    Original: {data[:32]}..." if len(data) > 32 else f"    Original: {data}")
                    print(f"    Decrypted: {decrypted[:32]}..." if len(decrypted) > 32 else f"    Decrypted: {decrypted}")
                    all_passed = False
                    
            except Exception as e:
                print(f"  ✗ ERROR: {e}")
                all_passed = False
        
        if all_passed:
            print("\n✅ All AHDE tests passed!")
        else:
            print("\n❌ Some AHDE tests failed")
        
        return all_passed


# ============================================================================
# PROTOCOL COMMANDS
# ============================================================================

class ADTPCommand(IntEnum):
    """ADTP Protocol Commands"""
    HELLO = 0x01
    PING = 0x02
    PONG = 0x03
    DISCONNECT = 0x04
    
    OK = 0x10
    ERROR = 0x11
    UNAUTHORIZED = 0x12
    
    FILE_LIST = 0x20
    FILE_UPLOAD_START = 0x21
    FILE_UPLOAD_CHUNK = 0x22
    FILE_UPLOAD_END = 0x23
    FILE_DOWNLOAD_START = 0x24
    FILE_DOWNLOAD_CHUNK = 0x25
    FILE_DOWNLOAD_END = 0x26
    FILE_DELETE = 0x27
    FILE_INFO = 0x28
    
    SYSTEM_INFO = 0x30
    CONFIG_GET = 0x31
    CONFIG_SET = 0x32
    
    CUSTOM_1 = 0x40
    CUSTOM_2 = 0x41
    CUSTOM_3 = 0x42


# ============================================================================
# ADTP PROTOCOL
# ============================================================================

class ADTPProtocol:
    """ADTP Protocol Core"""
    
    HEADER_FORMAT = ">BBQII"  # version(1) | command(1) | sequence(4) | timestamp(8) | data_len(4) | crc32(4)
    HEADER_SIZE = struct.calcsize(HEADER_FORMAT)
    
    def __init__(self, key: str):
        """
        Initialize protocol
        
        Args:
            key: ADTP key (64 hex chars)
        """
        if not ADTPKey.validate(key):
            raise ValueError("Invalid ADTP key")
        
        self.key = key
        self.sequence = 0
    
    def create_packet(self, command: Union[int, ADTPCommand], data: bytes = b"") -> bytes:
        """
        Create ADTP packet
        
        Args:
            command: Command code or ADTPCommand
            data: Data to send (will be encrypted)
            
        Returns:
            bytes: Packet ready to send
        """
        self.sequence += 1
        
        if isinstance(command, ADTPCommand):
            command = command.value
        
        # Encrypt data
        encrypted_data = b""
        if data:
            try:
                encrypted_hex = AHDE.encrypt(data, self.key)
                encrypted_data = encrypted_hex.encode('utf-8')
            except Exception as e:
                # Fallback to plaintext if encryption fails
                print(f"Warning: Encryption failed, using plaintext: {e}")
                encrypted_data = data
        
        # Create header
        timestamp = int(time.time() * 1000)
        data_len = len(encrypted_data)
        crc = _calculate_crc32(encrypted_data)
        
        header = struct.pack(
            self.HEADER_FORMAT,
            0x01,           # Protocol version
            command,        # Command code
            timestamp,      # Timestamp (ms)
            data_len,       # Data length
            crc             # CRC32 checksum
        )
        
        return header + encrypted_data
    
    def parse_packet(self, packet: bytes) -> Dict[str, Any]:
        """
        Parse ADTP packet
        
        Args:
            packet: Received packet
            
        Returns:
            Dict: Parsed packet with fields
            
        Raises:
            ValueError: If packet is invalid
        """
        if len(packet) < self.HEADER_SIZE:
            raise ValueError(f"Packet too short: {len(packet)} bytes")
        
        try:
            # Parse header
            header = packet[:self.HEADER_SIZE]
            version, command, timestamp, data_len, crc = struct.unpack(
                self.HEADER_FORMAT, header
            )
            
            if version != 0x01:
                raise ValueError(f"Unsupported protocol version: {version}")
            
            # Check data length
            if len(packet) < self.HEADER_SIZE + data_len:
                raise ValueError(f"Incomplete packet")
            
            # Extract encrypted data
            encrypted_data = packet[self.HEADER_SIZE:self.HEADER_SIZE + data_len]
            
            # Verify CRC
            calculated_crc = _calculate_crc32(encrypted_data)
            if calculated_crc != crc:
                raise ValueError(f"CRC mismatch: {calculated_crc:#010x} != {crc:#010x}")
            
            # Decrypt data
            decrypted_data = b""
            if encrypted_data:
                try:
                    # Try to decrypt as AHDE encrypted data
                    encrypted_hex = encrypted_data.decode('utf-8')
                    decrypted_data = AHDE.decrypt(encrypted_hex, self.key)
                except (UnicodeDecodeError, ValueError):
                    # If not UTF-8 or decryption fails, use raw data
                    decrypted_data = encrypted_data
                except Exception as e:
                    # Other decryption errors
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
            
        except struct.error as e:
            raise ValueError(f"Invalid packet header: {e}")
    
    def get_sequence(self) -> int:
        """Get current sequence number"""
        return self.sequence
    
    def reset_sequence(self):
        """Reset sequence number"""
        self.sequence = 0


# ============================================================================
# SELF-TEST
# ============================================================================

def self_test():
    """Run comprehensive self-test"""
    print("=" * 60)
    print("ADTP Library Self-Test")
    print("=" * 60)
    
    results = []
    
    # Test 1: Key system
    print("\n1. Testing key system...")
    try:
        key = ADTPKey.generate()
        print(f"   Key generated: {key[:32]}...")
        print(f"   Key valid: {ADTPKey.validate(key)}")
        
        # Test invalid keys
        invalid_key = "invalid" * 10
        print(f"   Invalid key rejected: {not ADTPKey.validate(invalid_key)}")
        
        results.append(("Key System", True))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        results.append(("Key System", False))
    
    # Test 2: AHDE encryption
    print("\n2. Testing AHDE encryption...")
    try:
        ahde_passed = AHDE.test()
        results.append(("AHDE Encryption", ahde_passed))
    except Exception as e:
        print(f"   ✗ Error: {e}")
        results.append(("AHDE Encryption", False))
    
    # Test 3: Protocol
    print("\n3. Testing protocol...")
    try:
        key = ADTPKey.generate()
        protocol = ADTPProtocol(key)
        
        # Test with empty data
        packet1 = protocol.create_packet(ADTPCommand.HELLO, b"")
        parsed1 = protocol.parse_packet(packet1)
        print(f"   Empty packet: {len(packet1)} bytes")
        
        # Test with data
        test_data = b"Test message"
        packet2 = protocol.create_packet(ADTPCommand.PING, test_data)
        parsed2 = protocol.parse_packet(packet2)
        
        if parsed2['data'] == test_data:
            print(f"   Data packet: {len(packet2)} bytes, data matches")
            results.append(("Protocol", True))
        else:
            print(f"   ✗ Data mismatch")
            print(f"     Expected: {test_data}")
            print(f"     Got: {parsed2['data']}")
            results.append(("Protocol", False))
            
    except Exception as e:
        print(f"   ✗ Error: {e}")
        results.append(("Protocol", False))
    
    # Summary
    print("\n" + "=" * 60)
    print("Test Results:")
    print("-" * 60)
    
    all_passed = True
    for test_name, passed in results:
        status = "✓ PASSED" if passed else "✗ FAILED"
        print(f"  {test_name:20} {status}")
        if not passed:
            all_passed = False
    
    print("-" * 60)
    if all_passed:
        print("✅ All tests passed!")
    else:
        print("❌ Some tests failed")
    
    return all_passed


if __name__ == "__main__":
    self_test()
