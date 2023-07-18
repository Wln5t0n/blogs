---
title: HELL OR HELL [1337-CTF]
tags: Hill-cipher Module-26 Matrix Encryption Key Decode
---

# 1337-CTF 
The Hill cipher is a polygraphic substitution cipher built on concepts from Linear Algebra. The Hill cipher makes use of modulo arithmetic, matrix multiplication, and matrix inverses; hence, it is a more mathematical cipher than others. The Hill cipher is also a block cipher, so, theoretically, it can work on arbitrary sized blocks.

Polygraphic substitution is a uniform substitution where a block of letters is substituted by a word, character, number, etc.

**Made by:- `Lester S. Hill` In 1929**

## Encryption

Encrypting with the Hill cipher is built on the following operation:  

**E(K, P) = (K*P) mod 26**

```ruby
import time
import hillCypher as hc

wait = .5

#MAIN PROGRAM

#Lets the user decides if he wants to use his own key to encode or if he wants to or have a key randomly
#assigned for him
choiceKey = input("Have you already chosen a key(a) or do you want a random key?(b):\n")

while choiceKey != "a" and choiceKey != "b":
	choiceKey = input('Please type "a" or "b" as your answer:\n')

time.sleep(wait)

if choiceKey == "b":
	K = hc.randomKey()
else:
	K = hc.chooseKey()

time.sleep(wait)

#Transform the user's message into a matrix with numbers associated to each characters 
message = input("What message do you want to encode? Write it below:\n")
messageNumber = hc.messageNumbers(message)
M = hc.matrix(messageNumber)

#encodes the message M with the key K (matrix multiplication)
encodedNumber = M.dot(K)

time.sleep(wait)

#gives back a message with characters and not numbers
hc.messageEncoded(encodedNumber, hc.alphabet)

time.sleep(wait)

input("\nPress enter to exit the encoder.\nDon't forget you'll need the key to decode the message")
```

Flag i want to encode:- `crypto-is-my-cup-of-tea-dont-you-think`
key i used:- `367659934` 
```ruby
^^/D/c/Hill-Or-Hell >>> python3 encoder.py                                                                                                                    10:45:32 
Have you already chosen a key(a) or do you want a random key?(b):
367659934
Please type "a" or "b" as your answer:
a
What key do you want to use? Please present a key with 9 numbers, without spaces:
367659934
What message do you want to encode? Write it below:
crypto-is-my-cup-of-tea-dont-you-think

Your encoded message is:
324 169 263 285 227 332 303 280 361 381 318 421 285 256 315 357 287 440 372 242 390 291 117 152 210 127 199 459 341 508 441 277 402 171 173 228 333 206 285

Press enter to exit the encoder.
Don't forget you'll need the key to decode the message
```

## Decode script
```ruby
import hillCypher as hc

#MAIN PROGRAM
	
code = hc.code()
C = hc.matrix(code)

K = hc.chooseKey()
invK = hc.np.linalg.inv(K)

messageNumber = C.dot(invK)

message = hc.messageText(messageNumber, hc.alphabet)
message = "".join(message)

print("\nThe message is:")
print(message)

input("\nPress enter to exit the decoder")
```



## Output:- 
```ruby
^^/D/c/Hill-Or-Hell >>> python3 decoder.py                                                                                                                (2) 10:51:08 
What's the code to be decoded? Write it down below:
324 169 263 285 227 332 303 280 361 381 318 421 285 256 315 357 287 440 372 242 390 291 117 152 210 127 199 459 341 508 441 277 402 171 173 228 333 206 285
What key do you want to use? Please present a key with 9 numbers, without spaces:
367659934

The message is:
crypto*is*my*cup*of*tea*dont*you*think 

Press enter to exit the decoder
```

**Flag:- `TCA{crypto-is-my-cup-of-tea-dont-you-think}`**

# Decode script breakdown

- First we imports the hillCypher module `import hillCypher as hc`
- `code()` makes random consisting of uppercase letters and spaces, and returns it as a string
- `matrix()` takes message from `code()` convert it to matrix. each message is representation by number accourding to the position eg. (a=0,b=1, and so on...) and the space is represented by the number 26. The matrix is a numpy array.
- `chooseKey()` makes random 2x2 matrix as the encryption key. This key is used to encrypt the message in the Hill cipher.
- `inv()` inverse the encryption key. This will help to decrypt the encrypted message.
- Then encrypted message is decrypted by multiplying the ciphertext matrix with the inverse of the encryption key. This is done with the `dot()` method of numpy arrays.
- `messageText()` function takes the resulting matrix of decrypted numbers and converts it back into a string of uppercase letters and spaces.

# Hill Cipher Module Script

```ruby
import random as rd
import numpy as np

alphabet = ("a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z", " ", ",", "'", "!", "?", "*")

#Creates a random key, while making sure the key can be inversed
def randomKey():
	
	while True:
		numbers = 0
		numbers = list()
		
		for number in range (0, 9):
			number = rd.randint(1, 9)
			numbers.append(number)
		key = createKey(numbers)
		
		if not verifyKey(key):
			break

	printKey = list()
	for row in key:
		for number in row:
			printKey.append(str(number))
	
	print("\nYour new key is:")
	print("".join(printKey))
	
	return key

#Verifies if the key for the cypher can be reversed
def verifyKey(key):
	return ((np.linalg.det(key) <= 0.5) and (np.linalg.det(key) >= -0.5)) or (np.linalg.det(key) % 5 == 0) or (np.linalg.det(key) % 3 == 0) or (np.linalg.det(key) % 2 == 0)

#Creates a 3x3 matrix with a list of 9 numbers
def createKey(numbers):
	key = np.array([[numbers[0], numbers[1], numbers[2]], [numbers[3], numbers[4], numbers[5]], [numbers[6], numbers[7], numbers[8]]])
	return key

#Lets the user use it's own key to encode the message while making sure the key can be reversed
def chooseKey():
	chosenKey = input("What key do you want to use? Please present a key with 9 numbers, without spaces:\n")	
	
	while not chosenKey.isdigit() or len(chosenKey) != 9:
		chosenKey = input("Your key has to be 9 numbers without any spaces. Choose another key:\n")
	
	numbers = list()
	for number in chosenKey:
		numbers.append(int(number))
	
	key = createKey(numbers)
	
	while verifyKey(key):
		chosenKey = input("Your key is not valid. Please choose another one:\n")
		numbers = list()
		for number in chosenKey:
			numbers.append(int(number))
		key = createKey(numbers)
		
		print("\nYour key is:")
		print(key)
		
	return key

#Takes the message to encrypt and transforms it into a list of numbers
def messageNumbers(message):
	message = message.lower()
	messageNumber = list()		#List with the message characters transformed into numbers as objects
	
	for char in message:
		if char in alphabet:		#transforms each characters into a number accordingly to it's position in the alphabet list
			index = alphabet.index(char)
			messageNumber.append(index)
		else:			#assign the * character to a character which isn't part of the alphabet
			messageNumber.append(len(alphabet) - 1)
	if (len(messageNumber) % 3 != 0):		#makes sure the message's lentgh is a multiple of 3, so the matrix can have rows of 3 elements
		nbrAjout = 3 - len(messageNumber) % 3
		for x in range (0, nbrAjout): 	#if not, add spaces until it can be divised by 3
			x = 26
			messageNumber.append(x)
	return messageNumber

#puts a list into a matrix with 3 columns and n rows
def matrix(matrix):
	nbrRange = len(matrix) // 3		#determines the number of rows for the matrix containing the list
	M = np.array([matrix[0], matrix[1], matrix[2]])	#Creates the first row(minimum number of row)
	if nbrRange > 1:		#if it needs more rows, create them and add them to the matrix
		for x in range (1, nbrRange):
			arrays = np.array([matrix[0 + 3*x], matrix[1 + 3*x], matrix[2 + 3*x]])
			M = np.vstack([M, arrays])
	return(M)

#takes the encoded message and converts it back into a string of characters
def messageEncoded(encodedNumber, alphabet):
	encodedNumber = encodedNumber.tolist()
	encodedMessage = list()
	try:
		for row in encodedNumber:
			for number in row:
				encodedMessage.append(str(number))
	except:
		for number in encodedNumber:
			encodedMessage.append(str(number))
	print("\nYour encoded message is:")
	print(" ".join(encodedMessage))
	
#asks the user for the code to be decoded	
def code():
	code = input("What's the code to be decoded? Write it down below:\n")
	code = code.split()
	
	while len(code) % 3 != 0:		#makes sure the code is valid(it has to be a multiple of 3 to be put back as a matrix)
		code = input("Your code has to be numbers, with a total of numbers which is a multiple of 3. Otherwise, there is a mistake. Try again:\n")
		code = code.split()
		
	codeList = list()
	for number in code:		#puts all the string numbers making the code in a list of integers
		number = int(number)
		codeList.append(number)
	
	return codeList

def messageText(messageNumber, alphabet):
	message = list()
	try:
		for number in messageNumber:
			number = int(round(number))
			number = number % 32 - 1
			message.append(alphabet[number])
	except:
		for row in messageNumber:
			for number in row:
				number = int(round(number))
				number = number % 32
				message.append(alphabet[number])
	return message
```

***
**Activate-Windows(Wln5t0n)**


<!--more-->


