# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

import argparse
import copy
import hashlib
import hmac
import json
import re
from base64 import b64encode
from binascii import hexlify
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Hash import SHA256, SHA512
from Cryptodome.PublicKey import RSA
from Cryptodome.Random import get_random_bytes
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Util.Padding import pad, unpad
from enum import Enum

argParser = argparse.ArgumentParser(description='Convert AP5GC SIM json data to encrypted SIM file format')
argParser.add_argument("-A", "--azure", default='AP5GC-Public-Key-1.pem', help="Azure public key file")
argParser.add_argument("-P", "--private", default='AP5GC-Private-Vendor-Test.pem', help="Private key file")
argParser.add_argument("-s", "--sims", default='SimBulkUpload.json', help="SIM credential data (json)")
argParser.add_argument("-d", "--decrypted", default='Output-SimBulkUpload.json', help="Decrypted SIM output file")
argParser.add_argument("-e", "--encrypted", default='Output-SimEncryptedBulkUpload.json', help="Encrypted SIM output file")
argParser.add_argument("-v", "--version", default=1, help="Encrypted SIM JSON version")
argParser.add_argument("-V", "--verbose", action='store_true', help="Enable verbose printing")

verbose=0

def Print(*args, **kwargs):
    if (verbose):
        print(*args, **kwargs)

def SecretToString(secret):
    return hexlify(secret).decode("ascii").upper()

class SimDefinitionFactory:

    class DefinitionSource(Enum):
        BULKFILE = 1

    def __call__(self, source, definition):

        if (SimDefinitionFactory.DefinitionSource.BULKFILE == source):
            sims = []
            with open(definition) as bulkfile:
                jsonSims = json.load(bulkfile)
                for jsonSim in jsonSims:
                    sim = SimDefinition()
                    sim.fromJson(jsonSim)
                    sims.append(sim)
            return sims

        return None

class SimDefinition:

    jsonDefinition = {}
    encrypted = False

    def __init__(self):
        pass

    def __str__(self):
        return json.dumps(self.jsonDefinition, indent=4, sort_keys=True)

    def getJson(self):
        return copy.deepcopy(self.jsonDefinition)

    def fromText(self, text):
        self.jsonDefinition = json.loads(text)

    def fromJson(self, jsonDictionary):
        self.jsonDefinition = jsonDictionary

    def fromFile(self, filepath):
        with open(filepath) as file:
            self.jsonDefinition = json.load(file)

    def encrypt(self, version, authKey, transportKey):
        properties = self.jsonDefinition["properties"]
        iccid = properties["integratedCircuitCardIdentifier"]
        imsi = properties["internationalMobileSubscriberIdentity"]
        ki = properties["authenticationKey"]
        opc = properties["operatorKeyCode"]

        secret = version + ":" + iccid + ":" + imsi + ":" + ki + ":" + opc

        iv = get_random_bytes(16)

        cipherAes = AES.new(transportKey, AES.MODE_CBC, iv)
        cipherText = iv + cipherAes.encrypt(pad(secret.encode('utf-8'), AES.block_size))
        shamac = hmac.new(authKey, cipherText, hashlib.sha512).digest()
        encryptedSecret = shamac + cipherText
        Print("encryptedSecret = " + SecretToString(encryptedSecret))
                
        # Remove KI and OPC from the JSON
        del self.jsonDefinition["properties"]["authenticationKey"]
        del self.jsonDefinition["properties"]["operatorKeyCode"]

        # Add Encrypted Credentials
        self.jsonDefinition["properties"]["encryptedCredentials"] = SecretToString(encryptedSecret)
        
        self.encrypted = True

    def decrypt(self, transportKey, vendorPublicKey):
        properties = self.jsonDefinition["properties"]
        encryptedSecret = bytes.fromhex(properties["encryptedCredentials"])

        del self.jsonDefinition["properties"]["encryptedCredentials"]

        cipherText = []
        try:
            if (len(encryptedSecret) < 33):
                raise ValueError()
            mac = encryptedSecret[:64]
            iv = encryptedSecret[64:80]
            cipherText = encryptedSecret[80:]

            cipherAes = AES.new(transportKey, AES.MODE_CBC, iv)
            cipherText= cipherAes.decrypt(cipherText)
        except ValueError:
            print("Bad tag or message")

        cipherText = unpad(cipherText, 16)
        secret = cipherText.decode('utf-8')
        version, iccid, imsi, ki, opc = secret.split(":")

        properties["version"] = version
        properties["integratedCircuitCardIdentifier"] = iccid
        properties["internationalMobileSubscriberIdentity"] = imsi
        properties["authenticationKey"] = ki
        properties["operatorKeyCode"] = opc

def TransportKeyGenerator():
    transportKey = get_random_bytes(32)
    return transportKey

def ImportRsaKeysFromFile(file):
    with open(file) as contents:
        rsa = RSA.import_key(contents.read())
        return rsa.export_key(format="DER"), rsa.publickey().export_key(format="DER")
    
def ImportRsaPubKeyFromFile(file):
    with open(file) as contents:
        rsa = RSA.import_key(contents.read())
        return rsa.publickey().export_key(format="DER")


args = argParser.parse_args()

# Set the verbosity level
verbose = args.verbose
Print(args)

# Set the Microsoft provided public key
microsoftPublicKey = ImportRsaPubKeyFromFile(args.azure)

# Get the key identifier for the Azure key vault
azureKeyId = int(re.findall(r'\d+', args.azure)[-1])

# Set the SIM file format version
version = args.version

# Read the SIM vendor key information from file
simVendorPrivateKey,simVendorPublicKey = ImportRsaKeysFromFile(args.private)

# Create transportKey for json header
transportKey = TransportKeyGenerator()

# Create Authentication Transport Key
authenticationTransportKey = TransportKeyGenerator()

combinedTransportKey = transportKey + authenticationTransportKey

Print("AP5GC Public Key: " + SecretToString(microsoftPublicKey))
Print("Azure Key Identifier:" + str(azureKeyId))
Print("SIM Vendor Private Key: " + SecretToString(simVendorPrivateKey))
Print("SIM Vendor Public Key: " + SecretToString(simVendorPublicKey))
Print("Encrypting with combined transport key " + SecretToString(combinedTransportKey))

DefinitionSource = SimDefinitionFactory.DefinitionSource

# Read some unecrypted SIMs from file in unencrypted bulk upload JSON format
simDefinitionFactory = SimDefinitionFactory()
simDefinitions = simDefinitionFactory(DefinitionSource.BULKFILE, args.sims)

# Encrypt the SIMs and write out to a new file
listEncryptedSims = []
listDecryptedSims = []
jsonDefinition = {}

# Encrypt the combined transport key with Microsoft public key
rsa = RSA.import_key(microsoftPublicKey)
cipherRsaMicrosoft = PKCS1_OAEP.new(rsa, hashAlgo=SHA256)
encryptedTransportKey = cipherRsaMicrosoft.encrypt(combinedTransportKey)

# Sign the a SHA 512 hash of the encrypted transport key with the vendor private key
cipherRsaVendor = RSA.import_key(simVendorPrivateKey)
signedTransportKey = PKCS1_v1_5.new(cipherRsaVendor).sign(SHA512.new(encryptedTransportKey))

jsonDefinition["version"] = version
jsonDefinition["azureKeyIdentifier"] = azureKeyId
jsonDefinition["vendorKeyFingerprint"] = hashlib.sha256(simVendorPublicKey).hexdigest().upper()
jsonDefinition["encryptedTransportKey"] = SecretToString(encryptedTransportKey)
jsonDefinition["signedTransportKey"] = SecretToString(signedTransportKey)
 
# Encrypt the SIM credentials
for sim in simDefinitions:
    Print(sim)
    sim.encrypt(str(version), authenticationTransportKey, transportKey)
    listEncryptedSims.append(sim.getJson())
    sim.decrypt(transportKey, simVendorPublicKey)
    listDecryptedSims.append(sim.getJson())

jsonDefinition["sims"] = listEncryptedSims
encryptedFile = open(args.encrypted, "w")
decryptedFile = open(args.decrypted, "w")
json.dump(jsonDefinition, encryptedFile, indent=4, sort_keys=False)
json.dump(listDecryptedSims, decryptedFile, indent=4, sort_keys=True)
encryptedFile.close()
decryptedFile.close()
