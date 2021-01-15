#!/usr/bin/python
import os
import sys, getopt
import pexpect
import getpass

#-- VARIABLE DECLARATION --#
USERNAME=getpass.getuser()
PASSWORD="admin"
CIPHER="aes128-cbc"
KEXALGORITHMS="diffie-hellman-group1-sha1"
CIPHER_ERR="Unable to negotiate with .* no matching cipher found\.*"

#Set the commands to send to the devices here
COMMANDS=["wr mem", "exit"]

#-- FUNCTTION DECLARATIONS --#
def writeConsole(HOST,SSHMETHOD):
	#SHOW THE HOST THAT IS BEING CONFIGURED, SEND THE COMMANDS THEN EXIT
	print("\tBEGIN CONFIGURING HOST: " + HOST)
	SSHMETHOD.sendline(PASSWORD)
	login = SSHMETHOD.expect(["#", "Password: "], timeout=15)
	#Sebd the commands
	if(login == 0):
		for command in COMMANDS:
			SSHMETHOD.sendline(command)
			print ("\tDONE CONFIGURING HOST: " + HOST)
		return
	elif(login == 1):
		print("\tUsername or Password for " + HOST + " is incorrect exiting...")
		return

def augumentHandler(ARGUMENTS):
	global USERNAME
	global PASSWORD
	global CIPHER
	global KEXALGORITHMS

	try:
		opts, args = getopt.getopt(ARGUMENTS,"hu:p:c:k:",["Username=","Password=","Cipher=","Kexalgorithms="])
	except getopt.GetoptError:
		print("wr-mem_ssh.py -h <Help> -u <Username> -p <Password> -c <Cipher> -k <KexAlgorithms>")
		sys.exit(2)
	for opt, arg in opts:
		if opt == '-h':
			print("wr-mem_ssh.py -h <Help> -u <Username> -p <Password> -c <Cipher> -k <KexAlgorithms>")
			print("By default---> Username= '" + USERNAME + "', Password= '" + PASSWORD + "', Cipher= '" + CIPHER + "', KexAlgorithms= '" + KEXALGORITHMS + "'")
			sys.exit()
		elif opt in ("-u", "--Username"):
			USERNAME = arg
		elif opt in ("-p", "--Password"):
			PASSWORD = arg
		elif opt in ("-c", "--Cipher"):
			CIPHER = arg
		elif opt in ("-k", "--KexAlgorithms"):
			KEXALGORITHMS = arg

def main(argv):

	augumentHandler(argv)

	#OPEN AND READ IN THE IP's TO THE VATIABLE "IPLIST"
	with open ("IP-list.txt", "r") as myfile:
		IPLIST = myfile.read().splitlines()

	os.system("clear")
	#FOR EACH HOST IN THE LIST ATTEMPT TO CONNECT AND CONFIGURE
	for HOST in IPLIST:
		print("--> Attempting to configure host " + HOST)
		#CHECK FOR SSH SETTINGS OF CIPHERS AND KEXALGORITHMS TO CONNECT TO THE SWITCH WITHOUT USER INPUT
		if(CIPHER and not KEXALGORITHMS): #CIPHER IS PRESENT BUT NOT THE KEXALGORITHMS
			SSHMETHOD = pexpect.spawn("ssh " + USERNAME + "@" + HOST + " -o StrictHostKeyChecking=no -c " + CIPHER)
		elif(not CIPHER and KEXALGORITHMS): #KEXALGORITHMS ARE PRESENT BUT NOT THE CIPHER
			SSHMETHOD = pexpect.spawn("ssh " + USERNAME + "@" + HOST + " -o StrictHostKeyChecking=no -o KexAlgorithms=" + KEXALGORITHMS)
		else: #BOTH CIPHER AND KEXALGORITHMS ARE PRESENT
			SSHMETHOD = pexpect.spawn("ssh " + USERNAME + "@" + HOST + " -c " + CIPHER + " -o StrictHostKeyChecking=no -o KexAlgorithms=" + KEXALGORITHMS)

		#LOOK FOR ERRORS, END OF FILE, OR SUCCESFULL CONNECTION TO THE DEVICE
		PROMPT = SSHMETHOD.expect([CIPHER_ERR, "Password: ", ".*(yes/no).*", pexpect.EOF], timeout=15)
		if(PROMPT == 0): #CIPHER MISMATCH: RETURN THE OFFERED CIPHERS FROM THE HOST AND KILL THE SSH CONNECTION
		    CIPHERRETURN = SSHMETHOD.readline().strip().replace("Their offer: ", "")
		    print("\tError: Wrong cipher/algorithm used for " + HOST + " try one of these: " + CIPHERRETURN)
		    SSHMETHOD.kill(0)
		elif(PROMPT == 1): #SUCCESFULL CONNECTION: BEGIN THE LOGIN AND CONFIGURATION PROCESS
		    writeConsole(HOST,SSHMETHOD)
		elif(PROMPT == 2): #SSH HOST KEY ACCEPT: ACCEPT THE HOST KEYS OFFERED BY THE DEVICE THEN BEGIN LOGIN AND CONFIGURATION PROCESS
		    SSHMETHOD.sendline("yes")
		    writeConsole(HOST,SSHMETHOD)
		elif(PROMPT == 3): #HOST KEY IS WRONG OR HOST IS UNREACHABLE
			print("\tError: Host key verification most likely falied or host is unreachable.")
			print("\tTry: ssh-keygen -f /home/" + getpass.getuser() + "/.ssh/known_hosts -R " + '"' + HOST + '"')

#POINT TO MAIN
if __name__ == "__main__":
   main(sys.argv[1:])
