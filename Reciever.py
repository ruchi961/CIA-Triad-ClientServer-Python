#Security Goals
#Receiver Program
import socket,ast,hashlib

def check_confidentiality(packetReceived,key):
    print("".center(80,"*"))
    print("Decrypting data...")
    t=""
    #packetReceived=packetReceived.lower()
    if key!=None and key!="":
        for i in packetReceived:
            if i.isupper():
                alphabet = chr((ord(i)-int(key)-65)%26+65)
            elif i.islower():
                alphabet = chr((ord(i)-int(key)-97)%26+97)
            else:
                
                alphabet = chr(ord(i)-int(key))
                
            t=t+alphabet
        #message
        print("Data successfully decrypted")
        print("The data send by the sender is :",t)
        print("The data packet is decrypted successfully with the secret key\
              \n\nCONFIDENTIALITY goal is achieved.........")
    else:
        print("Key not received. Modified during transmission")
        print("The data packet cannot be decrypted as correct secret key not received\
              \n\nCONFIDENTIALITY goal is not achieved.........")
    return t

    
def check_integrity(message,hashValue,received=True):
    print("".center(80,"*"))
    if received:
        print("Computing the hash of the data...")
        hashedData = hashlib.md5(message.encode())
        hashedDataByte = hashedData.hexdigest()
        print("Hash computed: ",hashedDataByte,"\nHash value received: ",hashValue)
        if hashedDataByte == hashValue:
            print("The data packet is not modified i.e. the data has not lost its integrity\
              \n\nINTEGRITY goal is achieved.........")

        else:
            print("The data packet is modified i.e. the data has lost its integrity\
              \n\nINTEGRITY goal is not achieved.........")
    else:
        print("The data packet cannot be decrypted as key is not received. Cannot check integrity of data\
              \n\nINTEGRITY goal is not achieved.........")
        
        
    
def check_availbility(packetReceived,received=True):
    print("".center(80,"*"))
    if received:
        print("The data packet is received by the receiver successfully i.e. the data is available to the user\
              \n\nAVAILBILITY goal is achieved.........")
    else:
        print("The data packet is can't be decrypted hence the data is not available\
              \n\nAVAILBILITY goal is not achieved.........")
        
def callFunctions(message):
    packetReceived = ast.literal_eval(message)
    #packetReceived = message.split("-")
    print("The Received Packet is : ",packetReceived)
    print("The message received from the Sender is : ",packetReceived['Message'])
    decryptedData = check_confidentiality(packetReceived['Message'],packetReceived['Key'])
    
    if decryptedData=="":
        check_availbility(packetReceived['Message'],received=False)
        check_integrity(decryptedData,packetReceived['Hash'],received=False)
    else:
        check_availbility(packetReceived['Message'])
        check_integrity(decryptedData,packetReceived['Hash'])
def make_connection():
    sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)

    #Get Local machine name
    host = socket.gethostname()
    port = 9999

    #connection to the hostname on the port
    sock.connect((host,port))

    sock.settimeout(5)

    #receive no more than 1024 bytes
    try:
        #normal packet case
        message = sock.recv(1024)
        message = message.decode('ascii')
        print("Received data.........\nChecking whether data satisfies the three security goals 'CIA' \
        Confidentiality,Integrity,Availbility\n")
        print(message)
        callFunctions(message)
        #key modified case
        
        message = sock.recv(1024)
        message = message.decode('ascii')
        print("Received data.........\nChecking whether data satisfies the three security goals 'CIA' \
        Confidentiality,Integrity,Availbility\n")
        print(message)
        callFunctions(message)
        #connection closed case - no packet received
        message = sock.recv(1024)
        message = message.decode('ascii')
        print("Received data.........\nChecking whether data satisfies the three security goals 'CIA' \
        Confidentiality,Integrity,Availbility\n")
        print(message)
        callFunctions(message)

        
    except Exception:
        print("No Packet received from the sender, CIA Triad not satisified.")
    finally:
        print("Closing connection")
        sock.close()
        print("".center(80,"*"))
    
print("".center(80,"*"))
print("\t\t\t\t\tReceiver")
print("".center(80,"*"))

#call function
make_connection()
