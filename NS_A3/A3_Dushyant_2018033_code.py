import time
import random


class RSA:
    """
    Class defining RSA utility functions
    """
    def encrypt(message:tuple, key:tuple):
        """
        Encrypts the 'message'=(m1,m2,...) via RSA algorithm using the 'key'=(e,n)
        """
        e, n = key
        
        cipher = list()
        for m in message:
            cipher.append(RSA.rsa_core_operation(m, e, n))
            
        return tuple(cipher)

    def decrypt(message:tuple, key:tuple):
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
        if x==1:
            return m%n
        
        x_ = x//2
        m_ = RSA.rsa_core_operation(m, x_, n)%n

        if x%2==0:
            return (m_*m_ )%n
        else:
            return ((( m_*m_ )%n)*m)%n

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
            if t<26:
                msg += chr(t+ord("a"))
            else:
                msg += chr(t-26+ord("0"))
        return msg


class PKDA:
    """
    The Public Key Distribution Authority Entity.
    """

    def __init__(self, mappings, pr_key, pu_key):
        """
        PKDA stores a table 'mappings' (client_id) --> (public key = (e,n))
        - pr_key is PKDA's private key.
        - pu_key is PKDA's public key.
        """
        self.mappings = mappings
        self.pr_key = pr_key
        self.pu_key = pu_key
    
    def process_message_from_client(self, message):
        """
        Function to simulate processing of a client request to obtain public key.

        message = encrypted(client_id, t1, n1)
        - client_id : whose public key is requested : str
        - t1 : timestamp in seconds : int
        - n1 : nonce : int

        Returns encrypted
        """
        client_id, t1, n1 = RSA.decrypt(message, self.pr_key)

        client_pu_key = self.mappings.get(client_id)
        x,y = client_pu_key

        n2 = self.nonce_response(n1)

        t2 = self.generate_timestamp()

        return RSA.encrypt( (x, y, client_id, t2, n2), self.pr_key)
    
    def nonce_response(self, n):
        """
        Simulates operation on nonce.
        """
        return n+1
    
    def generate_timestamp(self):
        """
        Generates timestamp to send with a request or response.
        """
        return int(time.time())


class Client:
    """
    The Client Entity.
    """

    def __init__(self, client_id, pr_key, pu_key, pkda_pu_key):
        """
        - Clients also maintain 'mappings' (client_id) --> (public key)
         as and when they get to know public keys of others.
        - pr_key is own private key.
        - pu_key is own public key.
        - pkda_pu_key : PKDA's public key.
        """
        self.mappings = dict()

        self.client_id = client_id
        self.pr_key = pr_key
        self.pu_key = pu_key
        self.pkda_pu_key = pkda_pu_key
    
    def gen_message_for_pkda(self, client_id:int):
        """
        Function to generate message requesting PKDA for public key.
        - client_id : whose public key is needed.
        """
        n1 = self.nonce_generate()
        t1 = self.generate_timestamp()

        message = (client_id, t1, n1)
        return RSA.encrypt(message, self.pkda_pu_key)
    
    def process_message_from_pkda(self, message):
        """
        Function to process the response from PKDA on requesting public key
        - message : tuple of ints (encrypted
        Decrypts the message to obtain the public key requested and adds to own mappings table.
        """
        x, y, client_id, t2, n2 = RSA.decrypt(message, self.pkda_pu_key)
        self.mappings[client_id] = (x,y)
        return (x, y, client_id, t2, n2)

    def gen_message_for_client(self, client_id:int, msg:str, nonce=None):
        """
        Generate message for sending to a client
        - client_id : receiver client id
        - msg : text message to send (will be encoded as integers)
        - nonce(default=None) : auto-generated in case of request message and needs to be supplied in case of reply.
        """
        t1 = self.generate_timestamp()
        
        n1 = -1
        if nonce is None:
            n1 = self.nonce_generate()
        else:
            n1 = self.nonce_response(nonce)

        message = [t1,n1,self.client_id]
        message.extend( RSA.rsa_encode_string(msg) )
        
        return RSA.encrypt(message, key=self.mappings.get(client_id))

    def process_message_from_client(self, message):
        """
        Processes message received from a client.
        - message : tuple of ints (encrypted)
        Returns the decrypted arguments.
        """
        tup = RSA.decrypt(message, self.pr_key)

        t1 = tup[0]
        n1 = tup[1]
        client_id_sender = tup[2]

        msg = tup[3:]
        
        text_msg = RSA.rsa_decode_string(msg)

        return (t1,n1,client_id_sender,text_msg)

    def nonce_generate(self):
        """
        Generates nonce numbers to send with a request or response.
        """
        lower_limit=1
        upper_limit=self.pu_key[1]-2
        return random.randint(lower_limit,upper_limit)

    def nonce_response(self, n):
        """
        Simulates operation on nonce.
        """
        return n+1
    
    def generate_timestamp(self):
        """
        Generates timestamp to send with a request or response.
        """
        return int(time.time())


if __name__=="__main__":
    global_mappings = { 1:(29,91), 2:(17,91) }

    pkda = PKDA(global_mappings, pr_key=(13,119), pu_key=(37,119))
    A = Client(client_id=1, pr_key=(5,91), pu_key=(29,91), pkda_pu_key=pkda.pu_key)
    B = Client(client_id=2, pr_key=(17,91), pu_key=(17,91), pkda_pu_key=pkda.pu_key)

    # A requests B's public key from PKDA
    m = A.gen_message_for_pkda(client_id=2)
    resp = pkda.process_message_from_client(message=m)
    print(A.process_message_from_pkda(message=resp))

    # B requests A's public key from PKDA
    m = B.gen_message_for_pkda(client_id=1)
    resp = pkda.process_message_from_client(message=m)
    print(B.process_message_from_pkda(message=resp))

    # A sends Hi1, Hi2, Hi3
    m1 = A.gen_message_for_client(B.client_id, msg="Hello123")
    m2 = A.gen_message_for_client(B.client_id, msg="Hi2")
    m3 = A.gen_message_for_client(B.client_id, msg="Hi3")

    t1,n1,cl1,text_msg = B.process_message_from_client(message=m1)
    print(t1,n1,cl1,text_msg)
    t2,n2,cl2,text_msg = B.process_message_from_client(message=m2)
    print(t2,n2,cl2,text_msg)
    t3,n3,cl3,text_msg = B.process_message_from_client(message=m3)
    print(t3,n3,cl3,text_msg)

    # B sends GotIt1, GotIt2, GotIt3
    m1 = B.gen_message_for_client(A.client_id, msg="GotIt1", nonce=n1)
    m2 = B.gen_message_for_client(A.client_id, msg="GotIt2", nonce=n2)
    m3 = B.gen_message_for_client(A.client_id, msg="GotIt3", nonce=n3)

    print(A.process_message_from_client(message=m1))
    print(A.process_message_from_client(message=m2))
    print(A.process_message_from_client(message=m3))
