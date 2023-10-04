#first import below both lines
from cryptography.hazmat.backends import default_backend;
from cryptography.hazmat.primitives.asymmetric import rsa;

#2nd import below line for signing
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding;

#Fiest create public and privates keys
def generate_keys():
  private = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
  )
  public = private.public_key()
  return private, public #return both public and private key

#Second step is to sign your message
def sign(message, private):
  message = bytes(str(message),'utf-8')
  signature = private.sign(
    message,
    padding.PSS(
      mgf=padding.MGF1(hashes.SHA256()),
      salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
  )
  return signature

# Third step to verify your message
def verify(message,sig,public):
  message = bytes(str(message), 'utf-8')
  try:
    public.verify(
      sig,
      message,
      padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
      ),
      hashes.SHA256()
    )
    return True
  except:
    return False

#First step to print values
if __name__ == '__main__':
  private_key, public_key = generate_keys()
  print(private_key)
  print(public_key)

  #second step to sign/message
  message= "Hello world"
  sig = sign(message, private_key)
  print(sig)

 #Third step is to check verification
correct = verify(message,sig,public_key)
if correct:
  print("Successful")
else:
  print("Failed to get keys ")