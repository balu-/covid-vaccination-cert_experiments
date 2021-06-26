#!/usr/bin/python3

from base45 import b45decode, b45encode
import zlib
import cbor2

import argparse


def extractCborData(base45:str) -> bytes:
	#check for prefix "HC1:"
	if cert[:4] != "HC1:":
		print("Error - Prefix missmatch")
		exit()

	cert_without_prefix = cert[4:]

	zip_data = b45decode(cert_without_prefix)

	cborData = zlib.decompress(zip_data)

	return cborData

def extractCborHeader(cborData:bytes):
	#print(cbor2.loads(cborData))
	webTokenResult = decodeCBORWebTokenPayload(cborData)
	#webTokenResult
	#// 1: Issuer (2-letter country code)
	# 4: Expiration time (UNIX timestamp in seconds)
	#6: Issued at (UNIX timestamp in seconds)
	return { 'issuer': webTokenResult[1], 'expiration_time': webTokenResult[4], 'issued_at': webTokenResult[6] }


def decodeCBORWebTokenPayload(cborData:bytes):
	cborValue = decodeCBORWebTokenEntries(cborData)
	# here is data hiding ([0]/[1]/[3])
	# maybe cose headers & signature
	# https://pycose.readthedocs.io/en/latest/cose/messages/sign1message.html
	sub_payload = cbor2.loads(cborValue[2])
	return sub_payload


def decodeCBORWebTokenEntries(cborData:bytes):
	cborPayload = cbor2.loads(cborData)
	# 18: CBOR tag value for a COSE Single Signer Data Object
	if not isinstance(cborPayload, cbor2.CBORTag):
		raise Error("Type error")
	if cborPayload.tag != 18:
		raise Error("Type error")

	cborValue = cborPayload.value

	#The message has to have 4 entries.
	if not len(cborValue) == 4:
		raise Error("Type error")

	return cborValue

def extractCertificate(cborData:bytes):
	cborPayload = decodeCBORWebTokenPayload(cborData)
	#extractDigitalGreenCertificate
	#// -260: Container of Digital Green Certificate
	healthCertificateElement = cborPayload[-260]
	#// 1: Digital Green Certificate
	healthCertificateCBOR = healthCertificateElement[1] 
	#maybe todo validateSchema
	
	return healthCertificateCBOR


if __name__ == "__main__":
	# create parser
	parser = argparse.ArgumentParser(description="Decode a vaccination cert")

	# add arguments to the parser
	parser.add_argument("certAsString", help='Certificat in form of a String, it should start with HC1')
	# parse the arguments
	args = parser.parse_args()
	cert = args.certAsString

	cborData = extractCborData(cert)
	print("Header:")
	print(extractCborHeader(cborData))
	print("Cert:")
	print(extractCertificate(cborData))
	# vaccination data
	# Disease or agent targeted, e.g. "tg": "840539006"
    # Vaccine or prophylaxis, e.g. "vp": "1119349007"
    # Vaccine medicinal product,e.g. "mp": "EU/1/20/1528",
    # Marketing Authorization Holder, e.g. "ma": "ORG-100030215",
    # Dose Number, e.g. "dn": 2
    # Total Series of Doses, e.g. "sd": 2,
    # Date of Vaccination, e.g. "dt" : "2021-04-21"
    # Country of Vaccination, e.g. "co": "NL"
    # Certificate Issuer, e.g. "is": "Ministry of Public Health, Welfare and Sport",
    # Unique Certificate Identifier, e.g.  "ci": "urn:uvci:01:NL:PlA8UWS60Z4RZXVALl6GAZ"



