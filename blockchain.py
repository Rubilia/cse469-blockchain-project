import os
import uuid
import maya
import struct
import hashlib

from enum import Enum
from typing import Optional, List
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


# Hardcode values 
AES_KEY: bytes = b"R0chLi4uLi4uLi4u"

# Hard coded passwords
BCHOC_PASSWORD_POLICE = 'P80P'
BCHOC_PASSWORD_LAWYER = 'L76L'
BCHOC_PASSWORD_ANALYST = 'A65A'
BCHOC_PASSWORD_EXECUTIVE = 'E69E'
BCHOC_PASSWORD_CREATOR = 'C67C'


class BlockStatus(Enum):
    INIT = 'INIT'
    CHECKED_IN = 'CHECKED_IN'
    CHECKED_OUT = 'CHECKED_OUT'
    DISPOSED = 'DISPOSED'
    DESTROYED = 'DESTROYED'
    RELEASED = 'RELEASED'

    @classmethod
    def parse(cls, name: str):
        try:
            return cls[name.upper()]
        except KeyError:
            return None


class BlockEntry:
    hash_value: bytes
    timestamp: Optional[maya.MayaDT]
    case_id: Optional[uuid.UUID]
    evidence_id: int
    status: BlockStatus
    author: Optional[str]
    owner: Optional[str]
    payload_size: int
    payload: str

    def __init__(self):
        self.hash_value = b'\x00' * 32
        self.timestamp = None
        self.case_id = None
        self.evidence_id = 0
        self.status = BlockStatus.INIT
        self.author = None
        self.owner = None
        self.payload_size = 14
        self.payload = "Initial block\x00"

    @classmethod
    def deserialize(cls, data: bytes):
        if len(data) < 144:
            exit(1)

        instance = cls()
        unpacked = struct.unpack('32s d 32s 32s 12s 12s 12s I', data[:144])

        instance.hash_value = unpacked[0]
        instance.timestamp = maya.MayaDT(unpacked[1]) if unpacked[1] != 0.0 else None

        if unpacked[2] != b'0' * 32:
            decrypted_uuid = cls._decrypt(bytes.fromhex(unpacked[2].decode()), pad=False)
            instance.case_id = uuid.UUID(bytes=decrypted_uuid)
        else:
            instance.case_id = None

        if unpacked[3] != b'0' * 32:
            decrypted_evidence_id = cls._decrypt(bytes.fromhex(unpacked[3].decode()), pad=False)
            instance.evidence_id = int.from_bytes(decrypted_evidence_id, 'big')
        else:
            instance.evidence_id = 0

        status_name = unpacked[4].decode().strip('\x00')
        instance.status = BlockStatus.parse(status_name)

        instance.author = unpacked[5].decode().strip('\x00') if unpacked[5].strip(b'\x00') else None
        owner_name = unpacked[6].decode().strip('\x00')
        instance.owner = owner_name if owner_name else None
        instance.payload_size = unpacked[7]
        instance.payload = data[144:144 + instance.payload_size].decode()

        return instance

    def __len__(self):
        return 144 + self.payload_size

    def serialize(self) -> bytes:
        packed = struct.pack(
            '32s d 32s 32s 12s 12s 12s I',
            self.hash_value,
            self.timestamp.epoch if self.timestamp else 0.0,
            self._encrypt(self.case_id.bytes, pad=False).hex().encode() if self.case_id else b'0' * 32,
            self._encrypt(self.evidence_id.to_bytes(16, 'big'), pad=False).hex().encode() if self.evidence_id else b'0' * 32,
            self.status.name.encode().ljust(12, b'\x00'),
            self.author.encode().ljust(12, b'\x00') if self.author else b'\x00' * 12,
            self.owner.name.encode().ljust(12, b'\x00') if self.owner else b'\x00' * 12,
            self.payload_size
        )
        packed += self.payload.encode()
        return packed

    @staticmethod
    def _encrypt(data: bytes, pad: bool = False) -> bytes:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        if pad:
            data_padded = pad(data, AES.block_size)
            return cipher.encrypt(data_padded)
        else:
            return cipher.encrypt(data)

    @staticmethod
    def _decrypt(data: bytes, pad: bool = False) -> bytes:
        cipher = AES.new(AES_KEY, AES.MODE_ECB)
        decrypted = cipher.decrypt(data)
        if pad:
            return unpad(decrypted, AES.block_size)
        else:
            return decrypted

    def compute_hash(self) -> bytes:
        return hashlib.sha256(self.serialize()[32:]).digest()

    def get_encrypted_case_id(self) -> str:
        if not self.case_id:
            return "00000000-0000-0000-0000-000000000000"
        encrypted_uuid = self._encrypt(self.case_id.bytes, pad=False)
        return encrypted_uuid.hex()


def blockchain_loader(func):
    def wrapper(self, *args, **kwargs):
        self.load_blockchain()
        return func(self, *args, **kwargs)
    return wrapper


class BlockChain:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.entries: List[BlockEntry] = []

    def init_blockchain(self):
        if not os.path.exists(self.file_path):
            self.entries = [BlockEntry()]
            self.save_blockchain()
            return print('Blockchain file not found. Created INITIAL block.')
        
        self.load_blockchain()
        print('Blockchain file found with INITIAL block.')

    
    def save_blockchain(self):
        with open(self.file_path, 'wb') as f:
            for b in self.entries:
                f.write(b.serialize())
    
    def load_blockchain(self):
        with open(self.file_path, 'rb') as f:
            for b in f:
                self.entries.append(BlockEntry.deserialize(b))

    @blockchain_loader
    def add_entry(self, case_id: str, evidence_ids: List[str], author: str, password: str):
        if password != BCHOC_PASSWORD_CREATOR:
            print('Invalid password')
            exit(2)

        # Detect duplicates
        seen_item_ids = set()
        for b in self.entries:
            if b.evidence_id in evidence_ids and b.evidence_id in seen_item_ids:
                print('Duplicate evidence IDs!')
                exit(3)
            seen_item_ids.add(b.evidence_id)

        # Duplicates in item_ids
        for i in range(len(evidence_ids)):
            for j in range(i + 1, len(evidence_ids)):
                if evidence_ids[i] == evidence_ids[j]:
                    print('Duplicate evidence ids!')
                    exit(4)

        # Case id must be a uuid
        try:
            case_uuid = uuid.UUID(case_id)
        except ValueError:
            print("case_id must be a valid UUID!")
            exit(5)

        # Add all blocks
        for evidence_id in evidence_ids:
            entry = BlockEntry()
            entry.hash_value = self.entries[-1].compute_hash()
            entry.timestamp = maya.now()
            entry.case_id = case_uuid
            entry.evidence_id = evidence_id
            entry.status = BlockStatus.CHECKED_IN
            entry.author = author
            entry.payload_size = 0
            entry.payload = ""
            self.entries.append(entry)
            print(f'Added item: {evidence_id}\nStatus: CHECKEDIN\nTime of action: {entry.timestamp.iso8601()}')

        # Save blockchain to the file
        self.save_blockchain()
