import base64
import binascii
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import PKCS1_v1_5

def generate_file_hash(file_path):
    sha256_hash = hashlib.sha256()

    with open(file_path,"rb") as f:
        # Read and update hash in chunks of 4K
        for byte_block in iter(lambda: f.read(4096),b""):
            sha256_hash.update(byte_block)
    
    return sha256_hash.hexdigest()

def is_elf_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            # Read the ELF header
            elf_header = f.read(64)
            if len(elf_header) < 64:
                return False

            # Check the magic number (7f 45 4c 46)
            if elf_header[0:4] != b'\x7fELF':
                return False

            # Check the file class (1 for 32-bit, 2 for 64-bit)
            if elf_header[4] not in [1, 2]:
                return False

            # Check the data encoding (1 for little endian, 2 for big endian)
            if elf_header[5] not in [1, 2]:
                return False

            # Check the ELF version (1 for original version of ELF)
            if elf_header[6] != 1:
                return False

            # Check the OS/ABI (0 for System V, 3 for Linux)
            if elf_header[7] not in [0, 3]:
                return False

            # Check the ABI version (0 for System V, non-zero for others)
            if elf_header[8] != 0:
                return False

            # Check the type (1 for relocatable, 2 for executable, 3 for shared, 4 for core)
            if int.from_bytes(elf_header[16:18], 'little') not in [1, 2, 3, 4]:
                return False

        return True
    except Exception as e:
        print(f"Error checking if file is an ELF file: {e}")
        return False

def verify(content, signature, public_key):
    try:
        public_key = RSA.import_key(public_key)
    except ValueError:
        return 
    verifier = PKCS1_v1_5.new(public_key)
    try:
        decoded_signature = base64.b64decode(signature)
    except binascii.Error:
        return 
    valid = verifier.verify(SHA256.new(content), decoded_signature)
    return valid


def generate(n=2048):
    keypair = RSA.generate(n)
    private_key = keypair.export_key()
    public_key = keypair.public_key().export_key()
    return private_key, public_key

def is_pe_file(file_path):
    try:
        with open(file_path, 'rb') as f:
            dos_header = f.read(64)
            if len(dos_header) < 64:
                return False

            if dos_header[0:2] != b'MZ':
                return False

            pe_offset = int.from_bytes(dos_header[60:64], 'little')
            f.seek(pe_offset)

            pe_header = f.read(24)
            if len(pe_header) < 24:
                return False

            if pe_header[0:4] != b'PE\x00\x00':
                return False

            opt_header_size = int.from_bytes(pe_header[20:22], 'little')

            opt_header = f.read(opt_header_size)
            if len(opt_header) < opt_header_size:
                return False

            if opt_header[0:2] not in [b'\x0b\x01', b'\x0b\x02']:
                return False

        return True
    except Exception as e:
        print(f"Error checking if file is a PE file: {e}")
        return False