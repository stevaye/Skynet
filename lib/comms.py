import struct

from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Random import get_random_bytes
from Crypto import *

from dh import create_dh_key, calculate_dh_secret

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            self.send(bytes(str(my_public_key), "ascii"))
            # Receive their public key
            their_public_key = int(self.recv())
            # Obtain our shared secret
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            print("Shared hash: {}".format(shared_hash))

        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        #ciper object goes here

        key = get_random_bytes(AES.block_size)
        iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(key, AES.MODE_CBC, iv)
        # msg = iv + cipher.encrypt(b'Attack at dawn')

        if self.cipher:   
            encrypted_data = self.cipher.encrypt(data)
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self): #recieve strips the IV off either the end or front of the encrypted message (IV is 16 bits)
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            data = self.cipher.decrypt(encrypted_data)
            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data


    # ANSI X.923 pads the message with zeroes
    # The last byte is the number of zeroes added
    # This should be checked on unpadding
    def ANSI_X923_pad(m, pad_length):
    # Work out how many bytes need to be added
        required_padding = pad_length - (len(m) % pad_length)
        # Use a bytearray so we can add to the end of m
        b = bytearray(m)
        # Then k-1 zero bytes, where k is the required padding
        b.extend(bytes("\x00" * (required_padding-1), "ascii"))
        # And finally adding the number of padding bytes added
        b.append(required_padding)
        return bytes(b)

    def ANSI_X923_unpad(m, pad_length):
        # The last byte should represent the number of padding bytes added
        required_padding = m[-1]
        # Ensure that there are required_padding - 1 zero bytes
        if m.count(bytes([0]), -required_padding, -1) == required_padding - 1:
            return m[:-required_padding]
        else:
            # Raise an exception in the case of an invalid padding
            raise AssertionError("Padding was invalid")

    def close(self):
        self.conn.close()