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
AES_KEY: bytes = b"R0chLi4uLi4uLi4="

# Hard coded passwords
BCHOC_PASSWORD_POLICE = 'P80P'
BCHOC_PASSWORD_LAWYER = 'L76L'
BCHOC_PASSWORD_ANALYST = 'A65A'
BCHOC_PASSWORD_EXECUTIVE = 'E69E'
BCHOC_PASSWORD_CREATOR = 'C67C'


class BlockStatus(Enum):
    INITIAL = 'INITIAL'
    CHECKEDIN = 'CHECKEDIN'
    CHECKEDOUT = 'CHECKEDOUT'
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
        self.status = BlockStatus.INITIAL
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
            self._encrypt(self.evidence_id.to_bytes(16, 'big')).hex().encode() if self.evidence_id else b'0' * 32,
            self.status.name.encode().ljust(12, b'\x00'),
            self.author.encode().ljust(12, b'\x00') if self.author else b'\x00' * 12,
            self.owner.encode().ljust(12, b'\x00') if self.owner else b'\x00' * 12,
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
        self.entries = []
        self.init_blockchain()
        return func(self, *args, **kwargs)
    return wrapper


class BlockChain:
    def __init__(self, file_path: str):
        self.file_path = file_path
        self.entries: List[BlockEntry] = []

    def init_blockchain(self, verbose=False):
        if not os.path.exists(self.file_path):
            self.entries = [BlockEntry()]
            self.save_blockchain()
            if verbose:
                print('Blockchain file not found. Created INITIAL block.')
            return
        
        self.load_blockchain()
        if verbose:
            print('Blockchain file found with INITIAL block.')

    
    def save_blockchain(self):
        if os.path.exists(self.file_path):
            os.remove(self.file_path)
        with open(self.file_path, 'wb') as f:
            for b in self.entries:
                f.write(b.serialize())
    
    def load_blockchain(self):
        with open(self.file_path, 'rb') as f:
            blockchain = f.read()
        self.entries = []
        while blockchain:
            b = BlockEntry.deserialize(blockchain)
            self.entries.append(b)
            blockchain = blockchain[len(b):]

    @blockchain_loader
    def add_entry(self, case_id: str, evidence_ids: List[str], author: str, password: str):
        if password != BCHOC_PASSWORD_CREATOR:
            print('Wrong password')
            exit(1)

        # Detect duplicates
        seen_item_ids = set()
        for b in self.entries:
            if b.evidence_id in evidence_ids and b.evidence_id in seen_item_ids:
                print('Duplicate evidence IDs!')
                exit(1)
            seen_item_ids.add(b.evidence_id)

        # Duplicate evidence_ids
        if len(set(evidence_ids).intersection(set(b.evidence_id for b in self.entries))) > 0:
            print('Duplicate evidence ids!')
            exit(1)

        # Case id must be a uuid
        try:
            case_uuid = uuid.UUID(case_id)
        except ValueError:
            print("case_id must be a valid UUID!")
            exit(1)

        # Add all blocks
        for evidence_id in evidence_ids:
            entry = BlockEntry()
            entry.hash_value = self.entries[-1].compute_hash()
            entry.timestamp = maya.now()
            entry.case_id = case_uuid
            entry.evidence_id = evidence_id
            entry.status = BlockStatus.CHECKEDIN
            entry.author = author
            entry.payload_size = 0
            entry.payload = ""
            self.entries.append(entry)
            print(f'Added item: {evidence_id}\nStatus: CHECKEDIN\nTime of action: {entry.timestamp.iso8601()}')

        # Save blockchain to the file
        self.save_blockchain()

    @blockchain_loader
    def checkout_entry(self, evidence_id: str, password: str):
        # Password must be correct
        owner = ''
        if password == BCHOC_PASSWORD_EXECUTIVE:
            owner = 'EXECUTIVE'
        elif password == BCHOC_PASSWORD_LAWYER:
            owner = 'LAWYER'
        elif password == BCHOC_PASSWORD_POLICE:
            owner = 'POLICE'
        elif password == BCHOC_PASSWORD_ANALYST:
            owner = 'ANALYST'
        else:
            print('Wrong password')
            exit(1)

        # Process all evidence ids and checkout
        found = False
        for i in range(len(self.entries) - 1, -1, -1):
            # Find a block entry with a matching evidence id
            entry = self.entries[i]
            if evidence_id != entry.evidence_id:
                continue
            
            if entry.status == BlockStatus.CHECKEDOUT:
                print(f'Item #{evidence_id} is already checked out!')
                break
            if entry.status != BlockStatus.CHECKEDIN:
                print(f'Item #{evidence_id} cannot be checked out: it is not checked in!')
                break

            found = True
            new_entry = BlockEntry()
            new_entry.hash_value = self.entries[-1].compute_hash()
            new_entry.timestamp = maya.now()
            new_entry.case_id = entry.case_id
            new_entry.evidence_id = evidence_id
            new_entry.status = BlockStatus.CHECKEDOUT
            new_entry.author = entry.author
            new_entry.owner = owner
            new_entry.payload_size = entry.payload_size
            new_entry.payload = entry.payload
            self.entries.append(new_entry)
            print(f'Case: {new_entry.case_id}\nChecked out item: {evidence_id}\nStatus: CHECKEDOUT\nTime of action: {new_entry.timestamp.iso8601()}')
            break
                

        if not found:
            print(f'Item #{evidence_id} was not found!')
            exit(1)

        self.save_blockchain()

    @blockchain_loader
    def checkin_entry(self, evidence_id: str, password: str):
        # Password must be correct
        owner = ''
        if password == BCHOC_PASSWORD_EXECUTIVE:
            owner = 'EXECUTIVE'
        elif password == BCHOC_PASSWORD_LAWYER:
            owner = 'LAWYER'
        elif password == BCHOC_PASSWORD_POLICE:
            owner = 'POLICE'
        elif password == BCHOC_PASSWORD_ANALYST:
            owner = 'ANALYST'
        else:
            print('Wrong password')
            exit(1)

        found = False
        for i in range(len(self.entries) - 1, -1, -1):
            # Find a block entry with a matching evidence id
            entry = self.entries[i]
            if evidence_id != entry.evidence_id:
                continue
            
            if entry.status == BlockStatus.CHECKEDIN:
                print(f'Item #{evidence_id} is already checked in!')
                break
            if entry.status != BlockStatus.CHECKEDOUT:
                print(f'Item #{evidence_id} cannot be checked in: it is not checked out!')
                break

            found = True
            new_entry = BlockEntry()
            new_entry.hash_value = self.entries[-1].compute_hash()
            new_entry.timestamp = maya.now()
            new_entry.case_id = entry.case_id
            new_entry.evidence_id = evidence_id
            new_entry.status = BlockStatus.CHECKEDIN
            new_entry.author = entry.author
            new_entry.owner = owner
            new_entry.payload_size = entry.payload_size
            new_entry.payload = entry.payload
            self.entries.append(new_entry)
            print(f'Case: {new_entry.case_id}\nChecked in item: {evidence_id}\nStatus: CHECKEDIN\nTime of action: {new_entry.timestamp.iso8601()}')
            break


        if not found:
            print(f'Item #{evidence_id} was not found!')
            exit(1)

        self.save_blockchain()

    @blockchain_loader
    def remove_entry(self, evidence_id: str, why: str, password: str):
        if why != 'DISPOSED' and why != 'DESTROYED' and why != 'RELEASED':
            print('Invalid why')
            exit(1)

        if password != BCHOC_PASSWORD_CREATOR:
            print('Wrong password')
            exit(1)

        found = False
        for i in range(len(self.entries) - 1, -1, -1):
            # Find a block entry with a matching evidence id
            entry = self.entries[i]
            if evidence_id != entry.evidence_id:
                continue
            
            if entry.status != BlockStatus.CHECKEDIN:
                print(f'Item #{evidence_id} cannot be removed: it is not checked in!')
                break

            found = True
            new_entry = BlockEntry()
            new_entry.hash_value = self.entries[-1].compute_hash()
            new_entry.timestamp = maya.now()
            new_entry.case_id = entry.case_id
            new_entry.evidence_id = evidence_id
            new_entry.status = BlockStatus(why)
            new_entry.author = entry.author
            new_entry.owner = entry.owner
            new_entry.payload_size = 0
            new_entry.payload = ''
            self.entries.append(new_entry)
            print(f'Removed item: {new_entry.evidence_id}\nStatus: {why}\nTime of action: {new_entry.timestamp.iso8601()}')
            break

        if not found:
            print(f'Item #{evidence_id} was not found!')
            exit(1)

        self.save_blockchain()

    @blockchain_loader
    def verify_chain(self) -> None:
        if not self.entries:
            print("Blockchain is empty.")
            exit(1)
        
        seen_hashes = set()
        removed_evidence_ids = set()
        
        # Initialize with the first block
        previous_block = self.entries[0]
        seen_hashes.add(previous_block.hash_value)
        
        # Check if the first block removes any evidence
        if previous_block.status == BlockStatus.DESTROYED or previous_block.status == BlockStatus.DISPOSED or previous_block.status == BlockStatus.RELEASED:
            removed_evidence_ids.add(previous_block.evidence_id)
        
        # Go through blockchain and check each block from 2nd
        for current_block in self.entries[1:]:
            # Don't allow check in/out after removal
            if (current_block.status == BlockStatus.CHECKEDIN or current_block.status == BlockStatus.CHECKEDOUT) and current_block.evidence_id in removed_evidence_ids:
                print(f"Transactions in blockchain: {len(self.entries)}\nState of blockchain: ERROR\nBad Block: {current_block.case_id}\nItem checked in or out after removal from chain.")
                exit(1)
            
            if current_block.status == BlockStatus.DESTROYED or current_block.status == BlockStatus.DISPOSED or current_block.status == BlockStatus.RELEASED:
                removed_evidence_ids.add(current_block.evidence_id)
            
            # Detect duplicate hashes
            if current_block.hash_value in seen_hashes:
                print(f"Transactions in blockchain: {len(self.entries)}\nState of blockchain: ERROR\nBad Block: {current_block.case_id}\nParent Block: {previous_block.case_id}\nTwo blocks were found with the same parent")
                exit(1)
            
            # Make sure current blocks hashes match previous block
            expected_hash = previous_block.compute_hash()
            if current_block.hash_value != expected_hash:
                print(f"Transactions in blockchain: {len(self.entries)}\nState of blockchain: ERROR\nBad Block: {current_block.case_id}\nBlock contents do not match block checksum.")
                exit(1)
            
            seen_hashes.add(current_block.hash_value)
            previous_block = current_block
        
        # Report correct blockchain
        print(f"Transactions in blockchain: {len(self.entries)}\nState of blockchain: CLEAN")

    @blockchain_loader
    def show_cases(self):
        cases_set = {entry.case_id for entry in self.entries if entry.case_id and entry.case_id != "None"}
        
        if cases_set:
            for case in sorted(cases_set, reverse=True):
                print(case)
        else:
            print("No cases found in the blockchain.")

    @blockchain_loader
    def show_items(self, case_id):
        items = {entry.evidence_id for entry in self.entries if str(entry.case_id) == case_id}
        if items:
            for item in sorted(items, reverse=True):
                print(item)
        else:
            print("No items found for this case")
