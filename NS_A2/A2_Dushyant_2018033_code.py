import numpy as np
import galois

GF = galois.GF(2**8, (1,0,0,0,1,1,0,1,1))


def encrypt(p, k):
    """
    Perform 128-bit AES encryption (10 rounds)

    Parameters
        - p : 128-bit input plaintext state matrix, 4x4 unsigned bytes
        - k : 128-bit key for AES encryption, 4x4 unsigned bytes
    
    Returns 128-bit ciphertext, 4x4 unsigned byte matrix
    """
    # get the subkeys
    subkeys = get_subkeys(np.copy(k))

    # initial add round key
    out = add_round_key(p, subkeys[0])

    # first 9 rounds
    for i in range(1,10):
        out = encrypt_round(out, subkeys[i])
    
    # final round without mix-columns
    out = encrypt_round(out, subkeys[10], mix_cols=False)

    return out

def decrypt(c, k):
    """
    Perform 128-bit AES decryption (10 rounds)

    Parameters
        - p : 128-bit input plaintext state matrix, 4x4 unsigned bytes
        - k : 128-bit key for AES encryption, 4x4 unsigned bytes
    
    Returns 128-bit ciphertext, 4x4 unsigned byte matrix
    """
    # get the subkeys
    subkeys = get_subkeys(np.copy(k))
    
    # initial round without mix-columns
    out = decrypt_round(c, subkeys[10], mix_cols=False)

    # next remaining 9 rounds
    for i in range(9,0,-1):
        out = decrypt_round(out, subkeys[i])

    # final add round key
    out = add_round_key(out, subkeys[0])

    return out


def get_subkeys(k, n_rounds=10):
    """
    Calculates the subkeys using the given key.

    Parameters
        - k : input key matrix, 4x4 unsigned bytes (128-bits)
        - n_rounds (default=10) : number of rounds of AES, 10 rounds => 1+10 subkeys

    Returns the list of 'n_rounds+1' subkeys, where each subkey is a 4x4 unsigned byte matrix.
    """
    rc_mat = [1,2,4,8,16,32,64,128,27,54]
    key_matrix=[]
    key_matrix.append(np.array(k)) # for round 0
    for i in range(0,n_rounds):
        j=[]
        for j1 in range(0,4):
            col_sum = int(int(k[0][j1])*pow(256,3)+int(k[1][j1])*pow(256,2)+int(k[2][j1])*pow(256,1)+int(k[3][j1])*1)
            j.append(col_sum)
        galwa_dec = cal_subKey(j[3],rc_mat[i])
        #print("galwa dec ",hex(galwa_dec))

        k1=[0,0,0,0] 
        k1[0] = galwa_dec^j[0]
        k1[1] = k1[0]^j[1]
        k1[2] = k1[1]^j[2]
        k1[3] = k1[2]^j[3]

        

        ## now converitng k1 to 4x4 matrix of decimal numbers 


        for c in range(0,4):  # for column iteration

            binary = bin(k1[c])  # converting to a binary 
            mat_updated = (32-len(binary[2:]))*'0' + binary[2:]  # making it a 32-bit

            for c1 in range(0,4):       ## for row iteration 
                decimal_num = cal_decimal(mat_updated[8*c1:8*(c1+1)])
                k[c1][c] = decimal_num
                #print("k[c1][c] ","c1 :",c1," c: ",c," ",hex(k[c1][c]))

        ## appending new key for each round         
        key_matrix.append(np.array(k))     

    return(key_matrix)

def cal_decimal(binary):
    """
    This function takes binary (string) and gives the decimal for that binary 
    """
    d  = 0
    power=0
    for i in range(0,len(binary)):
        if(binary[len(binary)-1-i]=='1'):
            d = d+ pow(2,power)
            power=power+1
        elif(binary[len(binary)-1-i]=='0'):
            d = d+0
            power=power+1
    return(d)        

def cal_subKey(mat,rc):
    """
    input is decimal for each round, it calculated the galwa function of last 32-bit of pevious round subkey 
    """
    intermediate = []
    binary = bin(mat)  # converting to a binary 
    mat_updated = (32-len(binary[2:]))*'0' + binary[2:]  # making it a 32-bit

    for i in range(0,4):
        decimal_num = cal_decimal(mat_updated[8*i:8*(i+1)])
        intermediate.append(decimal_num)

    intermediate_left_rotated =   intermediate[1:]+[intermediate[0]] # rotating left by  one pos

    intermediate_subsituted=[]

    ## this loop performs s-box substitution of each element of intermediate_left_rotated
    for i in range(0,len(intermediate)):
        substituted = substitute(intermediate_left_rotated[i])
        intermediate_subsituted.append(substituted)

    rc_mat=[]
    rc_mat.append(rc)
    rc_mat.append(0) 
    rc_mat.append(0) 
    rc_mat.append(0)

    final_out=[]


    # performing galwa addition 
    for i in range(0,4):
        final_out.append(rc_mat[i]^intermediate_subsituted[i])

    dec_final_out =  int(int(final_out[0])*pow(256,3)+ int(final_out[1])*pow(256,2)+ int(final_out[2])*pow(256,1)+int(final_out[3])*1)
    

    return(dec_final_out)   


def encrypt_round(inp, subkey, mix_cols=True, inverse=False):
    """
    Perform an AES encryption round.
    
    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - subkey : 128 bit subkey to be used in this round.
        - mix_cols (default=True) : whether or not to mix columns (to handle round 10)
    
    Returns the output state matrix after performing an encryption round of AES.
    """
    out = substitute_bytes(inp)

    out = shift_rows(out)

    if mix_cols:
        out = mix_columns(out)
    
    out = add_round_key(out, subkey)

    return out

def decrypt_round(inp, subkey, mix_cols=True):
    """
    Perform an AES decryption round.
    
    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - subkey : 128 bit subkey to be used in this round.
        - mix_cols (default=True) : whether or not to mix columns (to handle round 10)
    
    Returns the output state matrix after performing a decryption round of AES.
    """
    out = add_round_key(inp, subkey)

    if mix_cols:
        out = mix_columns(out, inverse=True)

    out = shift_rows(out, inverse=True)

    out = substitute_bytes(out, inverse=True)
    
    return out

def substitute(xy, inverse=False):
    """
    Obtain s-box substitute for one element (8-bits)
    
    Parameters
        - xy : input element (int 0-255)
        - inverse (default=False) : whether to use the inverse s-box substitution
    
    Returns the s-box/inverse-s-box entry for given xy
    """
    s_box = None
    if not inverse:
        s_box = np.array([
            [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
            [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
            [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
            [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
            [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
            [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
            [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
            [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
            [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
            [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
            [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
            [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
            [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
            [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
            [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
            [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
        ])
    else:
        s_box = np.array([
            [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
            [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
            [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
            [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
            [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
            [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
            [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
            [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
            [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
            [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
            [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
            [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
            [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
            [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
            [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
            [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
        ])
    x = xy//16
    y = xy%16
    return s_box[x,y]

def substitute_bytes(inp, inverse=False):
    """
    Perform substitute bytes operation.

    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - inverse (default=False) : whether to use the inverse s-box substitution

    Returns out(i,j) = s-box(inp(i,j)) or inverse-s-box(inp(i,j))
    """
    for i in range(4):
        for j in range(4):
            xy = int(inp[i,j])
            inp[i,j] = substitute(xy, inverse=inverse)
    return inp

def shift_rows(inp, inverse=False):
    """
    Perform shift rows operation.

    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - inverse (default=False) : whether to use the inverse s-box substitution

    Returns the resultant state matrix
    """
    if not inverse:
        inp[1,:] = np.roll(inp[1,:],-1)
        inp[2,:] = np.roll(inp[2,:],-2)
        inp[3,:] = np.roll(inp[3,:],-3)
    else:
        inp[1,:] = np.roll(inp[1,:],1)
        inp[2,:] = np.roll(inp[2,:],2)
        inp[3,:] = np.roll(inp[3,:],3)
    return inp

def mix_columns(inp, inverse=False):
    """
    Perform mix columns operation.

    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - inverse (default=False) : whether to use the inverse s-box substitution

    Returns the resultant state matrix
    """
    inp = GF(inp)
    MC = None

    if not inverse:
        MC = GF(np.array([
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]))    
    else:
        MC = GF(np.array([
            [0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]
        ]))
    
    return np.array(np.dot(MC, inp))

def add_round_key(inp, subkey):
    """
    Perform add round key operation.

    Parameters
        - inp : input state matrix, 4x4 unsigned bytes
        - subkey : 128 bit subkey to be used in this round.

    Returns out(i,j) = inp(i,j)^subkey(i,j) for all i,j in {0,1,2,3} (^ is bitwise xor)
    """
    return inp^subkey


def print_hex(mat):
    """
    Prints a state as hex codes.
    """
    s = ""
    for i in range(4):
        for j in range(4):
            s += hex(mat[i,j]) + " "
        s += "\n"
    print(s)



if __name__=="__main__":

    inp1 = np.array([
        [0x01, 0x23, 0x45, 0x67],
        [0x89, 0xab, 0xcd, 0xef],
        [0xfe, 0xdc, 0xba, 0x98],
        [0x76, 0x54, 0x32, 0x10]
    ])
    inp2 = inp1.T

    key = np.array([
        [0x0f,0x15,0x71,0xc9],
        [0x47,0xd9,0xe8,0x59],
        [0x0c,0xb7,0xad,0xd6],
        [0xaf,0x7f,0x67,0x98]
    ]).T

    ciph1 = encrypt(inp1, key)
    deciph1= decrypt(ciph1, key)

    ciph2 = encrypt(inp2, key)
    deciph2= decrypt(ciph2, key)

    
    print("KEY USED")
    print_hex(key)
    print()

    print("PlainText-1")
    print_hex(inp1)
    print("CipherText-1")
    print_hex(ciph1)
    print("DecipheredText-1")
    print_hex(deciph1)
    print()

    print("PlainText-2")
    print_hex(inp2)
    print("CipherText-2")
    print_hex(ciph2)
    print("DecipheredText-2")
    print_hex(deciph2)
    print()

