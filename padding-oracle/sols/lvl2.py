from pwn import *
from tls_parser.parser import TlsRecordParser
from tls_parser.handshake_protocol import TlsHandshakeTypeByte, TlsHandshakeMessage
from tls_parser.record_protocol import TlsRecord, TlsRecordHeader, TlsRecordTypeByte, TlsSubprotocolMessage
from tls_parser.tls_version import TlsVersionEnum
from tls_parser.change_cipher_spec_protocol import TlsChangeCipherSpecRecord
from tls_parser.application_data_protocol import TlsApplicationDataRecord
from hashlib import sha256, sha384
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
import hmac

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from os import urandom

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

from todo import Oracle,bleichenbacher

"""
solution is a brittle TLS_ECDH_RSA handshake
signed using the oracle
"""

def to_record(submessage, kind=TlsRecordTypeByte.HANDSHAKE):
   length = len(submessage.to_bytes())
   header = TlsRecordHeader(kind, TlsVersionEnum.TLSV1_2, length)
   return TlsRecord(header, [submessage])

n = 26291268813205434322264017466748383660040647755600543848624251974465755995834623218180037742778508414611242465409257439413238620403959218562238955554107925737539965183064915295406659060076514593158109171581422604838052326725553677917666879755304830586886767385735521865741957146540793164445625611286234400919075046731518309823286874711537644575001651290887617486902790534368773023951557030783584590073373669615189088933307093289766536677451123927748628328817030825436191116597946125295454084918949756290885636118310806568645403765413177707937259478469114598893484539794342873995545959578569194765181150639154994915921
e = 65537
key = RSA.construct((n,e))
signer = PKCS1_v1_5.new(key)

l = listen(4433)
r = l.wait_for_connection()

client_hello = r.recv()
client_hello = TlsRecordParser.parse_bytes(client_hello)[0]
client_random = client_hello.subprotocol_messages[0].handshake_data[2:2+4+28]

server_hello = bytes.fromhex("03030c885a93e1648a284b891c7ab5aa4778d691c9a5b8aae125ad6aa3ad317c09cb00c030000015ff01000100000b0004030001020023000000170000")
server_random = bytes.fromhex("0c885a93e1648a284b891c7ab5aa4778d691c9a5b8aae125ad6aa3ad317c09cb")
certs = bytes.fromhex("0003670003643082036030820248a003020102020900c74d63b60e7ac448300d06092a864886f70d01010b05003045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c7464301e170d3138303731373139343732385a170d3139303731373139343732385a3045310b30090603550406130241553113301106035504080c0a536f6d652d53746174653121301f060355040a0c18496e7465726e6574205769646769747320507479204c746430820122300d06092a864886f70d01010105000382010f003082010a0282010100d04457e8382e43a8b2c9368fd3a0aa841cd98c52d848de3951111772b47e933edc7c61493780a962d87de4541777b700edd5c701b3e9cbd6133f4beea78bfb8e66264adca3d4b115bae86ad913fe520bd3a9ebbc58a32c6baae917440be5ff855c6b61dab162eaf247c52e58085fe3ae7b0dd925b407486a2e017e59671c93e917cdea2b88e76f386864084101c26c4755c2a04ea16b13ac99de2698f188e5276d91b0d10da936be8d350745530c52ae566a6f39abe026b20eb456ff7545932ce0a5a9ca77fbac90f81be99ac7a55716254571b9a6bf218365c20109529b357e7b9d8cad0593a8a40d628c238177ddf65768e30dc89ef4f4765944313290aa510203010001a3533051301d0603551d0e04160414318c23a9cd6c383b8a4beb056c2d342493466776301f0603551d23041830168014318c23a9cd6c383b8a4beb056c2d342493466776300f0603551d130101ff040530030101ff300d06092a864886f70d01010b050003820101000fdfc19b4615666803b65e6a1930980193e4f110f8f384756aac5242871964434a45904b4574501bd8456e134dcc12f3cc395d09078acf4e1c591de07fe015f41b05fd0930492dcb83b2dfcca03bdb589775f274b9379eab317bc473f75aaff7708219a33546bc44c149e55b640436f0d9879eb003df046e50cf01759c10290cd8d200c79ba50adbe8850647c49c040c0137a5136925ff41f78793cfeca7fed3d858b31c2d89182d30dd9641b0a2ddbbd80bf6e1e633a8fe2213ee1d27687f0b2a4241bca615ded6fd821276114be47cd331eaa640aeaf370b966b3e8a2ab9be4b1039e6a8a28decb8613585d8109f47971f3d5406c1b3defff65b14fd5282c0")

r.send(to_record(TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_HELLO, server_hello)).to_bytes())
r.send(to_record(TlsHandshakeMessage(TlsHandshakeTypeByte.CERTIFICATE, certs)).to_bytes())


privkey = ec.generate_private_key(ec.SECP256R1(), default_backend())

pubkey = privkey.public_key()

def curveparams():
  type = b"\x03" # named_curve
  name = b"\x00\x17" # secp256r1
  keylen = bytes([65])
  pkey = b"\x04" + bytes.fromhex(hex(pubkey.public_numbers().x)[2:].zfill(64) + hex(pubkey.public_numbers().y)[2:].zfill(64))
  sigalgo = b"\x04\x01"
  return type + name + keylen + pkey + sigalgo

to_hash = client_random + server_random + curveparams()[:-2]
hash = sha256(to_hash).digest()

from asn1crypto import algos
tosign = algos.DigestInfo({
  'digest_algorithm': {
    'algorithm': 'sha256'
  },
  'digest': hash
})
tosign = tosign.dump(force=True)

def pad(hash):
    return b"\x00\x01" + b"\xff"*(256 - len(hash) - 3) + b"\x00" + hash

oracle = Oracle(pad(tosign), "localhost")
sig = bleichenbacher(oracle)
serverkey = curveparams() + b"\x01\x00" + sig
print(tosign.hex())
print(pad(tosign).hex())
r.send(to_record(TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_KEY_EXCHANGE, serverkey)).to_bytes())

r.send(to_record(TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_DONE, b"")).to_bytes())

answer = r.recv()

print(answer.hex())

clientkey, consumed1 = TlsRecordParser.parse_bytes(answer)

if len(answer)-consumed1 == 0:
  print(clientkey.subprotocol_messages[0])
  exit()

changespec, consumed2 = TlsRecordParser.parse_bytes(answer[consumed1:])
encryptedfinish = answer[consumed1+consumed2+5:]

serverchangespec = TlsChangeCipherSpecRecord.from_parameters(TlsVersionEnum.TLSV1_2)
r.send(bytes.fromhex("16030300aa040000a600001c2000a03aa9174e129289d5f090d14da89b8f4aa4edd17a620729cdb8322bd983f312d6370766d7c52e840f76583726434c25fd5a802f9095e8dfd54d61baab6b6b97f3b48a01ab65f3b1a06705e9158a0def4ebb68be05e58dc43c0495aae057d9dab41a0196d72f5abb135e3c1b72c04c87c8b87b37e90f60d8dd8f07c8d7f33ae74c6f25e25cd9f353c6a66b1b6fba42f24068997283136fdd70690546f0907f3028") + serverchangespec.to_bytes())

handshake_messages = client_hello.subprotocol_messages[0].to_bytes() + TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_HELLO, server_hello).to_bytes() + TlsHandshakeMessage(TlsHandshakeTypeByte.CERTIFICATE, certs).to_bytes() + TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_KEY_EXCHANGE, serverkey).to_bytes() + TlsHandshakeMessage(TlsHandshakeTypeByte.SERVER_DONE, b"").to_bytes() + clientkey.subprotocol_messages[0].to_bytes()

def prf(secret, label, seed, size):
  seed = label + seed
  a = seed
  r = b""
  while len(r) < size:
    a = hmac.new(secret, a, sha384).digest()
    r += hmac.new(secret, a+seed, sha384).digest()
  return r[:size]

from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicNumbers
x = int(clientkey.subprotocol_messages[0].handshake_data[2:2+32].hex(), 16)
y = int(clientkey.subprotocol_messages[0].handshake_data[2+32:2+2*32].hex(), 16)
c = EllipticCurvePublicNumbers(x,y,ec.SECP256R1())
c = c.public_key(default_backend())
premaster = privkey.exchange(ec.ECDH(), c)
mastersecret = prf(premaster, b"extended master secret", sha384(handshake_messages).digest(), 48)
print("randoms")
print(client_random.hex())
print(server_random.hex())
print("premaster then master")
print(premaster.hex())
print(mastersecret.hex())

mac_key_length = 0
iv_length = 4
key_mat = 32
key_block = prf(mastersecret, b"key expansion", server_random+client_random, 2*mac_key_length + 2*key_mat + 2*iv_length)

clikey = key_block[2*mac_key_length:2*mac_key_length+key_mat]
key = key_block[2*mac_key_length+key_mat:2*mac_key_length+2*key_mat]
print("encry key")
print(key.hex())
print(clikey.hex())
cliiv = key_block[2*mac_key_length+2*key_mat:2*mac_key_length+2*key_mat+iv_length]
iv = key_block[2*mac_key_length+2*key_mat+iv_length:2*mac_key_length+2*key_mat+2*iv_length]
print(iv.hex())
print(cliiv.hex())

def encrypt(data, seq, contenttype):
  print("enc")
  auth = bytes.fromhex(hex(seq)[2:].zfill(16)) + bytes([contenttype]) + b"\x03\x03" + bytes.fromhex(hex(len(data))[2:].zfill(4))
  print(auth.hex())
  print(data.hex())
  gcm = AESGCM(key)
  nonce_explicit = urandom(8)
  encandtag = gcm.encrypt(iv + nonce_explicit, data, auth)
  return nonce_explicit + encandtag

def decrypt(data, seq, contenttype):
  print("dec")
  auth = bytes.fromhex(hex(seq)[2:].zfill(16)) + bytes([contenttype]) + b"\x03\x03" + bytes.fromhex(hex(len(data)-16-8)[2:].zfill(4))
  print(auth.hex())
  print(data.hex())
  gcm = AESGCM(clikey)
  nonce_explicit = data[:8]
  dec = gcm.decrypt(cliiv + nonce_explicit, data[8:], auth)
  return dec

decfinish = decrypt(encryptedfinish, 0, 22)
handshake_messages += decfinish + bytes.fromhex("040000a600001c2000a03aa9174e129289d5f090d14da89b8f4aa4edd17a620729cdb8322bd983f312d6370766d7c52e840f76583726434c25fd5a802f9095e8dfd54d61baab6b6b97f3b48a01ab65f3b1a06705e9158a0def4ebb68be05e58dc43c0495aae057d9dab41a0196d72f5abb135e3c1b72c04c87c8b87b37e90f60d8dd8f07c8d7f33ae74c6f25e25cd9f353c6a66b1b6fba42f24068997283136fdd70690546f0907f3028")
finished = prf(mastersecret, b"server finished", sha384(handshake_messages).digest(), 12)

print("finished")
print(finished.hex())
enc = encrypt(bytes([20]) + bytes.fromhex(hex(len(finished))[2:].zfill(6)) + finished, 0, 22)
print(enc.hex())
r.send(bytes([22, 0x3, 0x3]) + bytes.fromhex(hex(len(enc))[2:].zfill(4)) + enc)

appdata = r.recv()
flag = decrypt(appdata[5:], 1, 23)
print(flag)
