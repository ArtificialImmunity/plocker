#!/usr/bin/env python
from os.path import isdir,isfile,abspath,expanduser,getsize,splitext
from os import chmod,mkdir
from getpass import getuser as whoami
from getpass import getpass
from sys import exit

from StringIO import StringIO
from pickle import dump,loads
from struct import pack,unpack,calcsize

from Crypto.Cipher import AES
from bcrypt import hashpw, gensalt
from hashlib import sha256
from random import randint

HOME_DIR=expanduser('~')+'/'
LOCKER_DIR=HOME_DIR+'.Locker/'
USER_FILE=LOCKER_DIR+'.secret.p'
DB_FILE=LOCKER_DIR+'.secrets'

HOLDER=[]
key=sha256('').digest()

try:
	if not isdir(LOCKER_DIR):
		mkdir(LOCKER_DIR,0700)
except:
	print ("[-] Error accessing .Locker, exiting")
	exit()
		

def createUser():
	username=whoami()
	print ("Enter new password for user: "+username)
	passwordHash=hashpw(getpass(),gensalt())
	try:
		with open(USER_FILE, 'w+') as f:
			userData=username+":"+passwordHash
			f.write(userData)
		chmod(USER_FILE,0400) #create one user then block write permissions
		print ("[+] Successfully created user '"+username+"'")
	except IOError:
		print ("[-] Error writing to file: " + USER_FILE + " - Make sure user doesn't already exist")
	return

def validate():
	global key
	loginName=whoami()
	username=''
	passwordHash=''
	with open(USER_FILE,'ro') as f:
		userData=f.read().split(":")
		username=userData[0]
		passwordHash=userData[1]
	inputp=getpass()
	passwordGuess=hashpw(inputp,passwordHash)
	if loginName == username and passwordGuess == passwordHash:
		key=sha256(inputp).digest()
		retrieveEntries()
		return True
	else:
		return False
def login():
	loginName=whoami()
	print ("Login: " + loginName)
	if validate():
		print ("[+] Successful Login")
		return True
	else:
		print ("[-] Failed Login")
		return False
	
def encryptSecrets():
	""" 
	Encrypts data with key value
	"""
	n=16
	buff=StringIO()#	make buffer
	iv=''.join(chr(randint(0,0xFF)) for i in range(16))#	make iv value
	dump(HOLDER,buff)	#add pickled data to rest of buffer
	buff.seek(0)	#go to beginning of buffer
	encryptor = AES.new(key,AES.MODE_CBC,iv)	#make encryptor
	edata=''	#init encrypted data holder
	data=buff.read()	#read the rest to encrypt and write to file
	edata+=iv	#add iv to start

	#Make sure data is of length divisable by 16. if not, add some null bytes
	if len(data) % n != 0:
		RB=(n-len(data)%n)
		data+=pack(str(RB)+'B',*([0]*RB))
	data=[data[i:i+n] for i in range(0,len(data),n)]	#break up data into chucnks of 16

	for d in data:
		edata+=encryptor.encrypt(d)	#encrypt that mofo

	with open(DB_FILE,'w+'):	#empty file for new write (TODO:need to make .tmp file)
		pass
	with open(DB_FILE,'w+') as f:
		f.write(edata)	#write encrypted data
	return



def decryptSecrets():
	"""
	Decrypts a the .secrets file which contains user/pass
	information and saves it to the holder
	
	"""
	buff=StringIO()	#Start new buffer for reading in encrypted data
	global HOLDER
	try:
		with open(DB_FILE, 'rb') as f:	#open file
			iv = f.read(16)	#get the iv val (first 16 bytes)
			decryptor = AES.new(key, AES.MODE_CBC, iv)	#start decryptor

			while True:
				chunk = f.read(16)	#read in chunks of data to decrypt
				if len(chunk) == 0:	#if theres none left, break
					break
				#decrypt data and write to new buffer
				buff.write(decryptor.decrypt(chunk).split(b'\x00')[0])
		
			HOLDER=loads(buff.getvalue())	#unpack the pickled data
	except IOError:
		print ("[-] Failed to read .secrets file")
		print (" *if this is your first time, make an entry to populate")
	except:
		print ("[-] Failed to Decrypt")
		pass
	return

def printMenu():
	print ("\nPlease select one of the following:")
	print ("[0] - List Available Passwords")
	print ("[1] - Add a Password")
	print ("[2] - Remove a Password")
	print ("[3] - Change Encryption/Login Password")
	print ("[4] - Exit")


def menu():
	"""
	Display the menu
	"""
	numberOfChoices=4
	while True:
		validChoice=False
		while not validChoice:
			#print ("Key = " + key)
			printMenu()
			try:
				choice=int(input("Choice: "))
				if choice<0 or choice>numberOfChoices:
					print ("\n\n[-] Error, invalid choice\n\n")
				else: validChoice=True
			#Allow for Ctrl+C
			except KeyboardInterrupt:
				print ()
				sys.exit()
			#Catch everything else
			except:
				print ("\n\n[-] Error, invalid choice\n\n")
	
		if choice==0:
			listPasses()
		elif choice==1:
			addEntry()
		elif choice==2:
			removeEntry()
		elif choice==3:
			changePassword()
		elif choice==4:
			exit()
		else: print("You shouldn't be here")	
	return

def listPasses():
	#Parse holder for passwords 
	print("\n")
	count=0
	for i in HOLDER:
		print "["+str(count)+"] - "+i['Title']
		count+=1
	return
def addEntry():
	"""
	Update the HOLDER and write it to .secrets 
	"""
	#Get user input, add entry to HOLDER
	entry={'Title':'',
		'Description':'',
		'Username':'',
		'Password':''}
	entry['Title']=raw_input("Enter Title: ")
	entry['Description']=raw_input("Enter Description: ")
	entry['Username']=raw_input("Enter Username: ")
	entry['Password']=getpass()
	HOLDER.append(entry)
	encryptSecrets()
	decryptSecrets()
	print ("[+] Successfully created")
	#print ("\nAdding Entries is coming soon")
	return
def removeEntry():
	"""
	Update the HOLDER and write it to .secrets 
	"""
	#Remove an entry from HOLDER
	print ("\nRemoving Entries is coming soon")
	return
def changePassword():
	"""
	Change the encryption password
	"""
	#Enter pass,
	#Enter new pass twice
	#Re-encryp file
	print ("\nPassword Change is coming soon")
	return
def retrieveEntries():
	"""
	After sucessful login, unencrypt pass file and store in HOLDER 
	"""
	#After decrypt, store in dict format
	decryptSecrets()
	return

def listPass():
	return

def Main():
	if isfile(USER_FILE):
		if login():
			menu()
	else:
		print("[-] Can't find existing user, please create one")
		createUser()

if __name__ == '__main__':
	Main()
