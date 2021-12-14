import socket
import json


class RSA:
    """
    Class defining RSA utility functions
    """
    def encrypt(message: tuple, key: tuple):
        """
        Encrypts the 'message'=(m1,m2,...) via RSA algorithm using the 'key'=(e,n)
        """
        e, n = key

        cipher = list()
        for m in message:
            cipher.append(RSA.rsa_core_operation(m, e, n))

        return tuple(cipher)

    def decrypt(message: tuple, key: tuple):
        """
        Decrypts the 'message'=(m1,m2,...) via RSA algorithm using the 'key'=(d,n)
        """
        d, n = key

        plain = list()
        for m in message:
            plain.append(RSA.rsa_core_operation(m, d, n))

        return tuple(plain)

    def rsa_core_operation(m, x, n):
        """
        Returns m^x (mod n) which is the core operation in RSA encryption/decryption.

        This function is a recursive, efficient implementation of the same.
        """
        if x == 1:
            return m % n

        x_ = x//2
        m_ = RSA.rsa_core_operation(m, x_, n) % n

        if x % 2 == 0:
            return (m_*m_) % n
        else:
            return (((m_*m_) % n)*m) % n

    def rsa_encode_string(msg):
        """
        Encodes a given string into tuple of ascii ints.
        """
        tup = []
        for m in msg.lower():
            if m.isalpha():
                tup.append(ord(m) - ord("a"))
            elif m.isdigit():
                tup.append(26 + ord(m) - ord("0"))
        return tuple(tup)

    def rsa_decode_string(tup):
        """
        Decodes a given tuple of ascii ints back to string.
        """
        msg = ""
        for t in tup:
            if t < 26:
                msg += chr(t+ord("a"))
            else:
                msg += chr(t-26+ord("0"))
        return msg


class TransportAuthority:

    def __init__(self, authorityName, port, kPU, kPR, hashFunction=lambda x: (sum(x) % 83)):
        self.authorityName = authorityName
        self.port = port
        self.kPU = kPU
        self.kPR = kPR
        self.hashFunction = hashFunction
        self.managingAuthority = None
        self.publicKeyDirectory = {authorityName: kPU + (self.sign(kPU),)}
        self.portDirectory = {authorityName: port}

    def addPortToDirectory(self, authorityName: str, port: int, setAsManager=False):
        """
        Adding port information about connected authorities (adjacent tier authorities).
        """
        self.portDirectory[authorityName] = port
        if setAsManager:
            self.managingAuthority = authorityName

    def addkPUToDirectory(self, authorityName: str, kPU, setAsManager=False):
        """
        Adding public key information about connected authorities (adjacent tier authorities).
        """
        signed_cert = kPU + (self.sign(kPU),)
        self.publicKeyDirectory[authorityName] = signed_cert
        if setAsManager:
            self.managingAuthority = authorityName

    def obtainPU(self, authorityName):
        """
        Aqcuire (if not already present) and return public key for 'authorityName'.
        """
        if authorityName in self.publicKeyDirectory:
            return self.publicKeyDirectory[authorityName]

        signed_cert = self.requestPURemote(authorityName)
        cert = signed_cert[:-1]
        sign = signed_cert[-1]

        if self.verify(cert, sign, self.managingAuthority):
            self.addkPUToDirectory(authorityName, kPU=cert)
            return self.publicKeyDirectory[authorityName]

    def requestPURemote(self, authorityName):
        """
        Acquire signed certificate from the managing authority.
        """
        dest_port = self.portDirectory[self.managingAuthority]
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", dest_port))
        msg = json.dumps({
            "type": 2,
            "authorityName": authorityName,
        })
        s.send(msg.encode())
        signed_cert = json.loads(s.recv(1024).decode())["signed_cert"]
        return tuple(signed_cert)

    def sign(self, cert: tuple):
        """
        Generates a signature by encrypting the 
         hashed certificate using own kPR.
        """
        return RSA.encrypt((self.hashFunction(cert),), self.kPR)[0]

    def verify(self, cert: tuple, sign: int, signingAuthority: str):
        """
        Verifies the given certificate against the provided 
         signature if the signing authority is known.
        """
        self.obtainPU(signingAuthority)

        if signingAuthority in self.publicKeyDirectory:
            d, n, _ = self.publicKeyDirectory[signingAuthority]
            return self.hashFunction(cert) == RSA.decrypt((sign,), (d, n))[0]
