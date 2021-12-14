import math 
import numpy as np
import random 
import itertools

def custom_hash(plainText, hash_length = 8):
	"""
	Generates 8 character hash code for the given input plaintext

	Input: 
	 - plainText : the plaintext in string format. Should only consist of characters a-z.
	 - hash_length : number of characters to use in the hash code.
	
	Outputs hash code for the input plaintext in string format.
	"""
	# hash code accumulator
	hash_code = hash_length*[0]

	# reshaping to matrix form
	cols = hash_length
	rows = 0

	# calculating required row count
	if (len(plainText)%hash_length==0):
		rows = len(plainText)//key_length
	else:
		rows =  len(plainText)//key_length +1
	
	ptr = 0	# pointer to move through the input plaintext

	# iterate over the rows
	for i in range(0,rows):
	
		# left shift operation
		hash_code = hash_code[1:] + hash_code[:1]

		for j in range(0,cols):

			if (ptr>=len(plainText)):	# padding (when plaintext ends but there is still space in the row)
				hash_code[j] = (0^(hash_code[j]))
			else:						# character-wise xor hash_code with current row of plaintext (a-z mapped to 0-25)
				hash_code[j] = (ord(plainText[ptr]) - ord("a")) ^ (hash_code[j])
				ptr = ptr+1

   # mapping back 0-25 to a-z and converting to string
	hash_value = ""
	for col in hash_code:
		hash_value += chr( ord("a") + col%26 )

	# return the string
	return hash_value

def Encryptor(plainText, key_vect):
	"""
	Encrypts plainText using Transposition Cipher, taking key_vect as the key.

	Input: 
	 - plainText : the plaintext in string format. Should only consist of characters a-z.
	 - key_vect : key in list format, should be a permutation of { 1 ... len(key_vect) }
	
	Outputs the ciphertext in string format consisting of characters a-z only.
	"""

	# filling the plainText in array
	key_length = len(key_vect) 
	rows = len(plainText)//key_length
	mat = []
	ptrToplain=0
	for i in range(0,rows):
		mat.append([])
		for j in range(0,key_length):
			mat[i].append(plainText[ptrToplain])
			ptrToplain+=1

	# now obtaining the cipher text
	max_key = max(key_vect)
	curr_keyVal = 1
	cipherText = ''
	for i in range(0,max_key):
		col_index = key_vect.index(curr_keyVal)
		for j in range(0,rows):
			cipherText = cipherText+ mat[j][col_index]
		curr_keyVal = curr_keyVal+1	

	return cipherText

def Decryptor(cipherText, key_vect):
	"""
	Decrypts cipherText using Transposition Cipher, taking key_vect as the key.

	Input: 
	 - cipherText : the ciphertext in string format. Should only consist of characters a-z.
	 - key_vect : key in list format, should be a permutation of { 1 ... len(key_vect) }
	
	Outputs the plaintext in string format consisting of characters a-z only.
	"""

	# filling the cipherText in array
	decipherText=''
	groupLength = len(cipherText)//len(key_vect)
	
	maxKey = max(key_vect)
	mat=[]
	fake = len(key_vect)*['a']
	for i in range(0,maxKey):
		mat.append([])

	ptr= 0
	curr_keyVal = 1
	for i in range(0,maxKey):
		text = cipherText[ptr:ptr+groupLength]
		
		ptr= ptr+groupLength										
		col_index = key_vect.index(curr_keyVal)
		
		L=[]
		for j in range(0,groupLength):
			
			L.append(text[j])
		mat[col_index] = L;	
		curr_keyVal= curr_keyVal+1
	
	# now obtaining the plaintext
	for i in range(0,groupLength):
	 	for j in range(0,maxKey):
	 		decipherText = decipherText + mat[j][i]

	return(decipherText)

def preprocess(string):
	"""
	Function for cleaning the string.
	Filters the string to contain only characters a-z

	Input : string input

	Outputs processed string.
	"""
	string_ = ""
	for i in string.lower():
		if i in "abcdefghijklmnopqrstuvwxyz":
			string_+=i
	return string_

def padding(plainText, key_length, hash_code_length = 8):
	"""
	Performs padding on plaintext taking into account the given hash_code length and the key size.
	Padding ensures that the plaintext along with the concatenated hash fits into the transposition matrix.

	Input
	 - plainText : the plaintext in string format. Should only consist of characters a-z.
	 - key_length : length of the key in use for transposition algorithm
	 - hash_code_length : number of characters in use for the hash code.
	
	Outputs padded plaintext in string format consisting of characters a-z only.
	"""
	# pre calculating padding length given hash_code length
	paddingLength = math.ceil((len(plainText)+hash_code_length)/key_length)*key_length - (len(plainText)+hash_code_length)

	# padding the plaintext with random characters out of a-z
	for i in range(0,paddingLength):
		plainText = plainText + chr(random.randint(97,122))

	return plainText

def propertyCheck(plainText, hash_code_length = 8):
	"""
	Performs property check on the plainText, i.e. checks whether last 'hash_code_length'
	 characters match the hash code generated from the rest of the characters.

	Input
	 - plainText : the plaintext in string format. Should only consist of characters a-z.
	 - hash_code_length : number of characters in use for the hash code.
	
	Outputs True or False based on whether propertyCheck is satisfied.
	"""
	computedHash = custom_hash(plainText[0:len(plainText)-hash_code_length])
	return (computedHash==plainText[-hash_code_length:])

def bruteForce(cipherText, key_set):
	"""
	Performs brute force on the given cipherText and key_set, trying to decrypt 
	 with every key and performing propertyCheck.

	Input
	 - cipherText : the ciphertextx in string format. Should only consist of characters a-z.
	 - key_set : list of keys to attempt decrypting on.
	
	Outputs list of keys out of key_set, that satisfied the propertyCheck on the given cipherText.
	"""
	keys = []
	for key in key_set:
		if propertyCheck(Decryptor(cipherText,key)):
			keys.append(key)
	return keys


	   
if __name__ == "__main__":
	key_length = 9
	key = list( np.random.permutation(list(range(1,key_length+1))) )

	print("Randomly Generated Key:", key)
	
	plainTextList = [ "i am hritik goel studying at IIITD", 
		"This is our NS assignment one", 
		"my partner is Dushyant panchal", 
		"we have been assigned project two", 
		"Project involves transposition cipher system with brute force attack"
	]
	
	cipher_list=[]

	for i in range(0,len(plainTextList)):
		plainText = plainTextList[i]
		filteredText =  preprocess(plainText)
		paddedText  = padding(filteredText,key_length)
		hashValue = custom_hash(paddedText)
		hashedText  = paddedText + hashValue
		cipherText = Encryptor(hashedText,key)
		decipherText = Decryptor(cipherText,key)

		cipher_list.append(cipherText)
		
		print(f"Sample-{i+1}--------------------------------------------")
		print("plainText:", plainText)
		print("processedText:", paddedText)
		print("hashvalue:", hashValue)
		print("hashedText:", hashedText)
		print("cipherText:", cipherText)
		print("decipherText:", decipherText)
		print("----------------------------------------------------")

		print()

	# breaking the cipher
	
	print("\nLaunching brute force ...")
	
	print("Starting key searchh from length 1 to 9")
	
	final_key = ""
	
	# collecting possible keys for first cipherText 
	all_keys=[]
	for i in range(1,9+1):
		all_keys.extend( bruteForce(cipher_list[0], itertools.permutations(list(range(1,i+1)))) )

	# trying the obtained keys on all other samples
	for key in all_keys:
		flag = 1
		for cipher in cipher_list:
			if not propertyCheck(Decryptor(cipher,key)):
				flag = 0
				break

		if flag==1:
			final_key = key
			break

	print("Woooo! Found key : ",final_key)
	 		

