MTPZ
====

More information attainable at [my blog](http://kbhomes.github.com/).

-- Sajid Anwar

Table of Contents
-----------------

1. Supplemental Data Structures
    1. AES Expanded Key
    2. Certificate
    3. RSA Private Key
2. Initialization
3. Application Certificate Message
4. Handshake Response
5. Confirmation Message

1\. Supplemental Data Structures
-------------------------------

### 1.1. AES Expanded Key

Example:

		# Number of rounds (4 bytes)
		0A 00 00 00 
	
		# Actual AES expanded key (0xB4 bytes)
		B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16 20 5D 36 1F 3E 46 70 98 BA E6 F4 08 6F 70 D6 1E 73 AB 44 B7 4D ED 34 2F F7 0B C0 27 98 7B 16 39 56 EC 56 F1 1B 01 62 DE EC 0A A2 F9 74 71 B4 C0 FD 61 EC 63 E6 60 8E BD 0A 6A 2C 44 7E 1B 98 84 42 27 B3 90 A4 47 3D 2D AE 2D 11 69 D0 36 89 ED 67 80 E6 E0 C3 C7 DB CD 6D EA CA A4 BD DC 43 49 A1 9A DD 9A 62 5D 06 57 0F B7 CC F3 B2 6B 8F BA 5E E9 29 AD 3C B4 2F FA 33 03 E3 09 81 68 6C B3 00 B9 44 A1 3C 0D 6B 5B 0F 0E 88 52 8E 66 E4 E1 05 D0 BC B8 39 DD D7 E3 36 D3 5F B1 B8 B5 BB 50 	
		
		# AES expanded key with InvMixColumns applied (0xB4 bytes)
		B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16 40 5A FE B0 91 03 E4 E6 F6 80 E3 35 B6 B1 BA 6A 6C 76 0D 3C FD 75 E9 DA 0B F5 0A EF BD 44 B0 85 CC 02 F6 25 31 77 1F FF 3A 82 15 10 87 C6 A5 95 11 E3 26 C7 20 94 39 38 1A 16 2C 28 9D D0 89 BD 21 BE 5C 85 01 2A 65 BD 1B 3C 49 95 86 EC C0 28 28 7F 70 C6 29 55 15 7B 32 69 5C EE B4 85 9C C6 8D A5 09 5D A4 F0 1C 26 96 99 40 C8 22 1C DC 0E 5C C9 4D EB F8 39 51 CD 6E A0 11 05 4C BC CD 0B E8 B2 14 12 10 8B 45 DF 7E 2B 54 DA 32 97 99 D1 05 D0 BC B8 39 DD D7 E3 36 D3 5F B1 B8 B5 BB 50 	
	
		# Random/irrelevant bytes.
		6C 70 E4 8F 50 00 00 00 4F 00 00 00 3D 00 00 00 B2 4F E0 8F 00 4B E4 8F 20 91 31 00 28 26 10 B0 10 50 E0 8F 94 66 E4 8F 5C 25 00 00 40 48 E4 8F D0 88 37 00 D0 88 37 00 20 91 31 00 98 26 10 B0 5C CF A5 97 34 10 0B 00 5C 25 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 6E 69 74 00 00 00 63 6F 70 79 57 69 74 68 5A FF FF FF FF FF FF FF 00 00 00 00 00

### 1.2. Certificate

Example: 

		# Length of cert (0x137)
		00 00 01 37 
		
			# Some word (0x01)
			01 00 
			
			# Length of inner data (0xB7)
			00 00 00 B7 
			
				# Some byte - must be <= 5 (0x03)
				03 
				
				# Some int (0x00000000)
				00 00 00 00 
				
				# Skipped over
				00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
				
				# Length of canonical name (0x14)
				00 14 
				
					# Canonical name ("Zune Software Leaf 1")
					5A 75 6E 65 20 53 6F 66 74 77 61 72 65 20 4C 65 61 66 20 31 
				
				# Public key exponent (0x010001 or 65537)
				00 01 00 01 
				
				# RSA modulus length (0x80)
				00 80 
				
					# RSA modulus
					E5 77 D3 FC BE 3F 03 E2 4F E8 8C 19 F4 64 98 E1 C7 36 18 1B B2 FE BE 2E EB 1E 26 92 B6 DB D0 D1 83 EB 2B 29 B2 D3 36 45 B8 09 8D C6 74 DD 25 D2 A6 5E DA CD 16 FE 8E 3D FF 01 B2 21 3A A4 4F 3B 2C 68 36 A1 03 56 D4 24 17 01 C2 DB 54 74 9D 89 77 7F 7A 80 90 0F 84 B2 97 35 69 8C 21 2D F5 16 5B 50 22 B5 F3 BF B6 A7 8B F0 34 E2 9F 9B 2B 97 16 D3 D3 29 50 9A 95 AD D7 2D 34 57 C3 D4 D0 CA 
					
			# Rest of the data, unknown.
			7E EA C9 77 6F 4D 73 A4 AA FD 89 6B AA 5A 86 85 C0 5D 5B 74 66 65 21 84 81 67 5E D6 29 B2 55 3A 9D F0 3D 74 58 66 C5 CF 24 03 51 A7 6C 6D BB D0 28 30 E5 F4 72 E2 AD 24 58 7C 7C AB 60 18 FD D9 34 C0 93 DF 41 CA B6 18 7E 6E 1E E9 BB 8D D5 99 F9 A2 10 F4 05 1F CD FD 55 28 8D 97 61 CA 22 C3 21 9E 72 24 76 46 AB 50 50 B0 B2 C7 7F 1D FB 6F 95 45 64 03 61 A2 7C AF CC 59 F3 24 42 E2 1B 7B 00 00 00 00 00 00 00 00 00 00 00 
	
As seen, some of this information is unknown. For our purposes, however, they are not necessary
to be known as they are not used directly.

The public key exponent is used in RSA encryption (`0x010001` is a common exponent). The length of
the RSA modulus, `0x80` or `128` bytes, indicates that the RSA encryption is 1024-bits.

### 1.3. RSA Private Key

Example:

		# RSA private key ("RSA2")
		52 53 41 32 

		# Bit length / 8 + 8 (0x88 = 136)
		88 00 00 00 

		# Bit length (0x400 = 1024)
		00 04 00 00 

		# Bit length / 8 - 1 (0x7F = 127)
		7F 00 00 00 

		# Public exponent (0x10001 = 65537)
		01 00 01 00 

		# Modulus (n = p * q)
		E5 77 D3 FC BE 3F 03 E2 4F E8 8C 19 F4 64 98 E1 C7 36 18 1B B2 FE BE 2E EB 1E 26 92 B6 DB D0 D1 83 EB 2B 29 B2 D3 36 45 B8 09 8D C6 74 DD 25 D2 A6 5E DA CD 16 FE 8E 3D FF 01 B2 21 3A A4 4F 3B 2C 68 36 A1 03 56 D4 24 17 01 C2 DB 54 74 9D 89 77 7F 7A 80 90 0F 84 B2 97 35 69 8C 21 2D F5 16 5B 50 22 B5 F3 BF B6 A7 8B F0 34 E2 9F 9B 2B 97 16 D3 D3 29 50 9A 95 AD D7 2D 34 57 C3 D4 D0 CA 

		00 00 00 00 00 00 00 00 

		# Prime 1 (p)
		E7 B2 65 91 1C 64 9C 1B 9A 63 41 AB 67 A5 A1 90 DF 22 54 7F C2 61 86 A3 21 71 0F 98 37 0A F3 62 B8 8E 58 56 C8 97 06 1D F1 B6 E0 8D BE BD 2A F0 28 30 EC D6 AE 94 4A 0B 05 DB 64 BB 73 E4 BD B1 

		00 00 00 00 

		# Prime 2 (q)
		E0 16 E8 A5 B2 D7 1D B7 A9 39 B8 5C 35 B7 EB A3 BB DE 58 F2 F3 60 6C C1 00 23 49 5A 1A F9 8A 94 A4 92 31 E5 52 32 F1 31 ED A1 1D 45 53 07 C9 83 F3 A6 DB CF AE B5 0A 9E A0 10 AD 60 80 C8 A6 75  

		00 00 00 00 

		# Exponent 1 (d mod (p - 1))
		45 4E A3 FB 28 57 20 2B 51 9F 67 41 72 9B A5 1C C4 E2 6C 0C 5B 84 F8 D5 4B 67 9A 96 99 C0 78 D5 8B 07 69 7D 6C 3B 60 E5 0C 2C FC 36 EA 5B 83 C0 9B 05 27 93 80 5D 73 58 A0 C3 E3 F9 FE CC E9 C1 

		00 00 00 00 

		# Exponent 2 (d mod (q - 1))
		05 E4 34 4B 9E EF 0E E5 F4 3A 03 41 D1 5B BB 83 3B 7E 36 02 75 29 94 D2 62 29 8B 55 26 1E 67 69 4F 06 54 EF 7D 80 BF 5C 9B AD BF B2 41 E3 93 85 B7 93 2C 76 42 56 9A 27 DF 77 70 C7 77 BB 4E BD  

		00 00 00 00 

		# Coefficient
		04 47 B4 EB EF D7 3B F0 EF 05 A5 2D 7D F5 6F 87 4F 5F 72 94 39 F4 BB E5 11 1D B2 8D FC 68 20 D0 16 DA F2 5A 4A 76 A1 AF 53 E5 B9 CD 86 CD 7A 00 62 3B 64 F6 1D 78 71 D0 EE EF 32 BB 64 C7 B5 32 

Similar to the format used by the Windows API for RSA cryptography, this starts off with the bytes
`52 53 41 32`, "RSA2" in ASCII. This is followed by three values all indicating the bit length of
this key. The public exponent, modulus, primes, exponents, and coefficient follow. Notably absent is
the private key itself. However, this can be easily calculated on the fly.

2\. Initialization
-----------------

Seems to be a key expansion as part of AES-128, perhaps with some custom routine.

	Key: 	B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16
	Expanded:

		# Number of rounds (4 bytes)
		0A 00 00 00 
	
		# Actual AES expanded key (0xB4 bytes)
		B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16 20 5D 36 1F 3E 46 70 98 BA E6 F4 08 6F 70 D6 1E 73 AB 44 B7 4D ED 34 2F F7 0B C0 27 98 7B 16 39 56 EC 56 F1 1B 01 62 DE EC 0A A2 F9 74 71 B4 C0 FD 61 EC 63 E6 60 8E BD 0A 6A 2C 44 7E 1B 98 84 42 27 B3 90 A4 47 3D 2D AE 2D 11 69 D0 36 89 ED 67 80 E6 E0 C3 C7 DB CD 6D EA CA A4 BD DC 43 49 A1 9A DD 9A 62 5D 06 57 0F B7 CC F3 B2 6B 8F BA 5E E9 29 AD 3C B4 2F FA 33 03 E3 09 81 68 6C B3 00 B9 44 A1 3C 0D 6B 5B 0F 0E 88 52 8E 66 E4 E1 05 D0 BC B8 39 DD D7 E3 36 D3 5F B1 B8 B5 BB 50 	
		
		# AES expanded key with InvMixColumns applied (0xB4 bytes)
		B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16 40 5A FE B0 91 03 E4 E6 F6 80 E3 35 B6 B1 BA 6A 6C 76 0D 3C FD 75 E9 DA 0B F5 0A EF BD 44 B0 85 CC 02 F6 25 31 77 1F FF 3A 82 15 10 87 C6 A5 95 11 E3 26 C7 20 94 39 38 1A 16 2C 28 9D D0 89 BD 21 BE 5C 85 01 2A 65 BD 1B 3C 49 95 86 EC C0 28 28 7F 70 C6 29 55 15 7B 32 69 5C EE B4 85 9C C6 8D A5 09 5D A4 F0 1C 26 96 99 40 C8 22 1C DC 0E 5C C9 4D EB F8 39 51 CD 6E A0 11 05 4C BC CD 0B E8 B2 14 12 10 8B 45 DF 7E 2B 54 DA 32 97 99 D1 05 D0 BC B8 39 DD D7 E3 36 D3 5F B1 B8 B5 BB 50 	
	
		# Random/irrelevant bytes.
		6C 70 E4 8F 50 00 00 00 4F 00 00 00 3D 00 00 00 B2 4F E0 8F 00 4B E4 8F 20 91 31 00 28 26 10 B0 10 50 E0 8F 94 66 E4 8F 5C 25 00 00 40 48 E4 8F D0 88 37 00 D0 88 37 00 20 91 31 00 98 26 10 B0 5C CF A5 97 34 10 0B 00 5C 25 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 69 6E 69 74 00 00 00 63 6F 70 79 57 69 74 68 5A FF FF FF FF FF FF FF 00 00 00 00 00


Based on the constants used, the custom routine seems actually to be the AES InvMixColumns
routine applied onto the expanded key. As far as I can tell, this isn't part of the 
standard AES encryption or decryption algorithm.

The AES expanded key + InvMixColumns seems to be the correct key used
during encryption or decryption of data. The round number seems to be 0x0A regardless
of what exists at the beginning of expanded key. The random-ish bytes at the end
seem also to be unused, implying that it is simply un-freed memory.
			
A 640-byte block of data is retrieved and decrypted using the expanded key and a slightly modified version of AES.

	Original:	27 17 A7 24 16 49 16 34 E2 AE B7 5F DF 8E 2A 95 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 A5 90 94 E5 E2 D6 04 34 1B D6 E3 66 07 A7 BA B4 CA 0C 5A 2D 05 EF 9F 4C 58 B9 61 11 D5 DD DD 5E D5 04 B4 70 1A EB 10 57 B5 E8 6A BA 96 67 5F 03 DB E4 41 16 B0 4B 30 31 63 72 67 6C 46 8F 1D 12 24 33 20 D7 62 20 22 99 90 DE 06 2B 19 2E 74 16 1A 65 C0 DA D6 38 ED 36 8A 29 75 03 97 86 4A 2E 96 31 CB A2 68 18 9C 64 D3 48 E4 96 5B 22 43 88 8D 83 93 48 07 EB 47 B9 08 51 25 3A EF E4 02 9B 94 7B 2E 06 CA 1F EF BB 20 BB B6 13 0E D1 77 82 7D D4 BB CB AB FE 7C 39 90 74 6D BD 7E 90 B0 CC 24 7C 3B 28 39 3A 94 34 1E 8D B2 39 06 4C 11 E7 F1 48 FF A3 FE 26 80 F0 C4 37 0F C6 A2 9C 12 5D 28 C8 D0 2A 84 37 61 03 53 E6 15 D8 E8 FA EB C3 13 DA 93 E7 38 B8 17 3B 2C 1C 3F 04 32 F0 2A A6 E0 EC A3 BB 91 DC A0 41 49 A6 78 95 61 CE 39 AA CA 3A 12 C5 FD 22 B4 5B E0 4A 5E 9F A2 9D 21 E6 C2 39 ED 03 62 AB 6D C9 DA 3E D1 16 BA 30 5F 89 69 97 B6 BC C2 A6 7B B2 8F F9 FB D6 2C 78 41 CF F1 EB E5 47 5B 4D 4A BB 63 E8 E0 B8 01 30 CA 20 60 5F C8 70 11 E7 A5 1D D4 BA EB B5 07 ED BA 74 DC B2 A3 EE 58 CF 33 89 89 AA 55 14 AB 86 0E 76 24 52 D1 75 6F 6A 45 19 26 81 01 96 95 73 F2 FF 5E B4 D3 46 1F 84 C9 AB 59 55 3B 34 80 D5 9B 2D F8 FB B9 38 BE B4 08 11 C1 D5 78 13 7B 8B 75 5A 66 AA 89 C0 6A 1D D7 63 A0 1D 95 4C DD CF 33 F7 CF 64 6E 4B 71 70 3F 85 F0 88 97 34 1F B1 AB 5E 27 2B 43 C3 67 8E 53 3F 78 E1 0E 13 B1 81 CF 2E 11 AF 6F EF 15 1D 4F 05 FD 9C D7 98 A3 0B 84 9F BE 77 7F 48 D0 A1 A2 C9 8F AF 02 4F 48 2B EC 67 64 A9 71 7D 6E 0B A5 10 7F D1 A8 D0 F1 7C 05 10 91 C9 54 E5 DC 7F 50 42 49 9E 18 49 B0 4F 0E AA 61 77 BB 82 66 35 76 C1 3C 10 F2 A7 5F 8E A7 B1 CD 2D 4A 6D 65 19 3F 77 2F 07 BA 7D 60 3F A8 E2 BF 10 0D 2B 34 C5 A8 99 06 C2 5F 82 B4 AA 6C F5 D2 8A 59 61 4B 78 A5 FF F3 A3 5F 93 D4 21 77 0F 06 1E 58 87 E5 EB 50 DF 47 EA 28 6D F2 68 ED 43 77 FA E7 58 62 CE 8A 4C 59 1D 69 72 FA 43 8E A8 67 9C 68 B6 68 A3 3E 38 7A 7D 71 2B D0 DB FB 3E

	Decrypted:	# Number of certificates
				02 

				# Certificate 1 (see 1.2 for structure)
				00 00 01 35 01 00 00 00 00 B5 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 5A 75 6E 65 20 53 6F 66 74 77 61 72 65 20 43 41 20 31 00 01 00 01 00 80 33 6E E6 AA 07 BF B3 FF D0 40 24 CE C3 8B E6 49 7E F6 0E 3D 7F 68 2E 0F F1 5E 6C 65 FF 61 3B DE 17 6F AD 71 37 88 4E 80 A8 13 CF 53 C3 10 1A A5 1B 9E 4F 54 B2 4F D5 14 CD C5 09 B6 B7 1E 1F 48 51 3D F0 64 44 D9 B5 59 63 E8 12 1C 4C 69 B6 7D 6A 13 14 F9 73 C9 58 5C 29 BB 99 0A D7 FD 15 1D BB CB 4F 9E D7 DF E2 92 BA 4E D9 C6 AC F5 8E 6A DE EF 5B 87 7A 1C 15 45 74 26 34 91 69 46 45 9B 09 4B 25 9E D8 5E F0 2B 08 A3 18 E6 7A FD 68 C2 89 A8 C6 A6 1B C8 02 3C A8 7F E3 67 BD CC 08 56 C3 D1 57 58 C8 66 E5 3F B5 2E 86 EC 56 9C 9C 07 0A 22 17 4F BD 7C 4D CD 39 5E C6 85 30 16 34 51 CE 1F 58 80 44 A0 6E BB 95 A6 D4 BE 68 B0 89 A4 F2 5A 61 2F FC EA 56 C1 C3 F8 A6 88 0C 05 76 F2 65 74 B6 4F F8 3D 28 68 F0 FE 36 96 BC 84 25 48 7A E0 62 D4 8A AD FD 08 8A 97 87 B8 06 81 0B ED 

				# Certificate 2 (see 1.2 for structure)				
				00 00 01 37 01 00 00 00 00 B7 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 5A 75 6E 65 20 53 6F 66 74 77 61 72 65 20 4C 65 61 66 20 31 00 01 00 01 00 80 E5 77 D3 FC BE 3F 03 E2 4F E8 8C 19 F4 64 98 E1 C7 36 18 1B B2 FE BE 2E EB 1E 26 92 B6 DB D0 D1 83 EB 2B 29 B2 D3 36 45 B8 09 8D C6 74 DD 25 D2 A6 5E DA CD 16 FE 8E 3D FF 01 B2 21 3A A4 4F 3B 2C 68 36 A1 03 56 D4 24 17 01 C2 DB 54 74 9D 89 77 7F 7A 80 90 0F 84 B2 97 35 69 8C 21 2D F5 16 5B 50 22 B5 F3 BF B6 A7 8B F0 34 E2 9F 9B 2B 97 16 D3 D3 29 50 9A 95 AD D7 2D 34 57 C3 D4 D0 CA 7E EA C9 77 6F 4D 73 A4 AA FD 89 6B AA 5A 86 85 C0 5D 5B 74 66 65 21 84 81 67 5E D6 29 B2 55 3A 9D F0 3D 74 58 66 C5 CF 24 03 51 A7 6C 6D BB D0 28 30 E5 F4 72 E2 AD 24 58 7C 7C AB 60 18 FD D9 34 C0 93 DF 41 CA B6 18 7E 6E 1E E9 BB 8D D5 99 F9 A2 10 F4 05 1F CD FD 55 28 8D 97 61 CA 22 C3 21 9E 72 24 76 46 AB 50 50 B0 B2 C7 7F 1D FB 6F 95 45 64 03 61 A2 7C AF CC 59 F3 24 42 E2 1B 7B 00 00 00 00 00 00 00 00 00 00 00 
	
The decrypted data is exactly the two certificates that are sent by the Zune
Software on Windows. Since this is constant in both the Mac OS X application
and the Windows Zune Software, I assume that this is merely sent to appease the device,
if you will.
			
			
A 704-byte block of data is then decrypted in the same manner as before, again using the expanded key.

	Original:	4A 84 6A E0 82 F9 F3 41 A1 CF 8B B7 E0 20 35 7B B7 61 03 DE 27 D1 F5 A0 A2 46 C9 73 2D 50 74 1E A8 DE D9 6B D2 7D 8D 69 6B F3 34 6D 42 14 2E B9 1D 5B 82 1D 7F 72 40 5D 67 07 33 CA 1A D3 CA 8E 18 29 48 60 43 48 D6 FC 9A EA 77 7F 43 C6 43 A9 D5 86 61 4B D6 7A 10 85 12 6A CF 2C 1B 1E B4 3C F5 A4 27 D7 9A FC A4 D1 FA 41 85 0F 72 48 6A 2F DA 2D 29 72 3F E5 01 DD 61 F4 F6 F4 14 91 CC A2 DA 2B 4F B7 73 BB 80 E8 4A F0 4E C6 63 C4 4A 22 EF 33 CE 29 28 CE CB FB AE FC 64 87 60 F2 FE 6D F8 30 C2 5B 1A 73 0C 5A 2C 0B EE 18 E6 78 18 08 7E C9 D4 37 C8 97 49 BD 38 75 EE 31 2F 52 2B F1 CA 4B FB D2 37 A8 38 3B 9B A1 AB 61 7A 75 2B A0 85 15 F8 E8 9F A2 5B 02 8C EB 9B DE CD 41 69 0A F1 84 56 3A A7 AD 01 BD 7C 7E 2B BE 79 62 4E 7F 2F AB B8 33 9E B4 A2 C7 46 38 56 03 88 EB E3 3B D5 60 74 31 7F A3 8A 9F C6 14 7F D9 19 44 E0 E3 8C F8 5F D6 F3 31 53 4E 06 BF C4 ED D2 65 52 1A 94 74 98 4A 6A 7C F4 74 60 6D 3B 41 75 6E 86 27 32 6F D7 C9 10 1A 07 67 82 8C B6 2C 28 33 CC 23 83 D1 9B 4D 24 52 3E C3 DE 33 A1 5D 31 64 8F F5 3C 5C FC 24 6B AC 1B FA 1F EB 7F 82 13 B2 B7 70 35 BF 7C 7C E1 3F 74 1A E0 2A 1C B0 14 4F AB E3 49 7E A6 CE DA D5 94 DB FF 4C 6B E8 5D 30 9C DC 0B ED AF 59 0F 48 17 3C EF A9 F5 25 20 CD 12 22 64 17 E8 ED F9 59 87 89 A2 71 1A E0 BF F5 AC F5 E0 1E 00 B7 7D 4D E0 35 69 DF E0 03 7C 6E 0A E5 7A E9 D6 14 9F A0 BE B2 36 1A 86 68 F6 BC 6A 97 75 47 C7 89 2E 13 77 B2 CD 34 EC 07 D2 AC 02 90 C4 1D 2E A7 29 70 C0 B8 F0 9A A1 7C 29 65 84 4A 12 F9 7C E0 E0 58 A6 DF C6 36 83 47 AC 2C 5A AA C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7 C5 31 20 AE DE F5 3A E7 81 82 B1 A4 34 F1 43 A7

	Decrypted: 	# RSA private key information (see 1.3 for structure)
				52 53 41 32 88 00 00 00 00 04 00 00 7F 00 00 00 01 00 01 00 E5 77 D3 FC BE 3F 03 E2 4F E8 8C 19 F4 64 98 E1 C7 36 18 1B B2 FE BE 2E EB 1E 26 92 B6 DB D0 D1 83 EB 2B 29 B2 D3 36 45 B8 09 8D C6 74 DD 25 D2 A6 5E DA CD 16 FE 8E 3D FF 01 B2 21 3A A4 4F 3B 2C 68 36 A1 03 56 D4 24 17 01 C2 DB 54 74 9D 89 77 7F 7A 80 90 0F 84 B2 97 35 69 8C 21 2D F5 16 5B 50 22 B5 F3 BF B6 A7 8B F0 34 E2 9F 9B 2B 97 16 D3 D3 29 50 9A 95 AD D7 2D 34 57 C3 D4 D0 CA 00 00 00 00 00 00 00 00 B1 BD E4 73 BB 64 DB 05 0B 4A 94 AE D6 EC 30 28 F0 2A BD BE 8D E0 B6 F1 1D 06 97 C8 56 58 8E B8 62 F3 0A 37 98 0F 71 21 A3 86 61 C2 7F 54 22 DF 90 A1 A5 67 AB 41 63 9A 1B 9C 64 1C 91 65 B2 E7 00 00 00 00 75 A6 C8 80 60 AD 10 A0 9E 0A B5 AE CF DB A6 F3 83 C9 07 53 45 1D A1 ED 31 F1 32 52 E5 31 92 A4 94 8A F9 1A 5A 49 23 00 C1 6C 60 F3 F2 58 DE BB A3 EB B7 35 5C B8 39 A9 B7 1D D7 B2 A5 E8 16 E0 00 00 00 00 C1 E9 CC FE F9 E3 C3 A0 58 73 5D 80 93 27 05 9B C0 83 5B EA 36 FC 2C 0C E5 60 3B 6C 7D 69 07 8B D5 78 C0 99 96 9A 67 4B D5 F8 84 5B 0C 6C E2 C4 1C A5 9B 72 41 67 9F 51 2B 20 57 28 FB A3 4E 45 00 00 00 00 BD 4E BB 77 C7 70 77 DF 27 9A 56 42 76 2C 93 B7 85 93 E3 41 B2 BF AD 9B 5C BF 80 7D EF 54 06 4F 69 67 1E 26 55 8B 29 62 D2 94 29 75 02 36 7E 3B 83 BB 5B D1 41 03 3A F4 E5 0E EF 9E 4B 34 E4 05 00 00 00 00 32 B5 C7 64 BB 32 EF EE D0 71 78 1D F6 64 3B 62 00 7A CD 86 CD B9 E5 53 AF A1 76 4A 5A F2 DA 16 D0 20 68 FC 8D B2 1D 11 E5 BB F4 39 94 72 5F 4F 87 6F F5 7D 2D A5 05 EF F0 3B D7 EF EB B4 47 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
	
This decrypted data is the RSA private key that corresponds to the software's certificate. As the 
certificate transmits its public key (public exponent and modulus), and the software holds the corresponding private key,
there is now a mechanism for the device and the software to communicate securely.

3\. Application Certificate Message
----------------------------------

What follows is an application certificate message, as captured from a session using the 
Windows Zune software.

	# Marker bytes
	02 01 

		# Marker (0x01), certificates length (0x275)
		01 00 00 02 75 

			# Certificate count.
			02 

				# Certificate 1 (see 1.2 for structure)
				00 00 01 35 01 00 00 00 00 B5 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 12 5A 75 6E 65 20 53 6F 66 74 77 61 72 65 20 43 41 20 31 00 01 00 01 00 80 33 6E E6 AA 07 BF B3 FF D0 40 24 CE C3 8B E6 49 7E F6 0E 3D 7F 68 2E 0F F1 5E 6C 65 FF 61 3B DE 17 6F AD 71 37 88 4E 80 A8 13 CF 53 C3 10 1A A5 1B 9E 4F 54 B2 4F D5 14 CD C5 09 B6 B7 1E 1F 48 51 3D F0 64 44 D9 B5 59 63 E8 12 1C 4C 69 B6 7D 6A 13 14 F9 73 C9 58 5C 29 BB 99 0A D7 FD 15 1D BB CB 4F 9E D7 DF E2 92 BA 4E D9 C6 AC F5 8E 6A DE EF 5B 87 7A 1C 15 45 74 26 34 91 69 46 45 9B 09 4B 25 9E D8 5E F0 2B 08 A3 18 E6 7A FD 68 C2 89 A8 C6 A6 1B C8 02 3C A8 7F E3 67 BD CC 08 56 C3 D1 57 58 C8 66 E5 3F B5 2E 86 EC 56 9C 9C 07 0A 22 17 4F BD 7C 4D CD 39 5E C6 85 30 16 34 51 CE 1F 58 80 44 A0 6E BB 95 A6 D4 BE 68 B0 89 A4 F2 5A 61 2F FC EA 56 C1 C3 F8 A6 88 0C 05 76 F2 65 74 B6 4F F8 3D 28 68 F0 FE 36 96 BC 84 25 48 7A E0 62 D4 8A AD FD 08 8A 97 87 B8 06 81 0B ED 

				# Certificate 2 (see 1.2 for structure)
				00 00 01 37 01 00 00 00 00 B7 03 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 14 5A 75 6E 65 20 53 6F 66 74 77 61 72 65 20 4C 65 61 66 20 31 00 01 00 01 00 80 E5 77 D3 FC BE 3F 03 E2 4F E8 8C 19 F4 64 98 E1 C7 36 18 1B B2 FE BE 2E EB 1E 26 92 B6 DB D0 D1 83 EB 2B 29 B2 D3 36 45 B8 09 8D C6 74 DD 25 D2 A6 5E DA CD 16 FE 8E 3D FF 01 B2 21 3A A4 4F 3B 2C 68 36 A1 03 56 D4 24 17 01 C2 DB 54 74 9D 89 77 7F 7A 80 90 0F 84 B2 97 35 69 8C 21 2D F5 16 5B 50 22 B5 F3 BF B6 A7 8B F0 34 E2 9F 9B 2B 97 16 D3 D3 29 50 9A 95 AD D7 2D 34 57 C3 D4 D0 CA 7E EA C9 77 6F 4D 73 A4 AA FD 89 6B AA 5A 86 85 C0 5D 5B 74 66 65 21 84 81 67 5E D6 29 B2 55 3A 9D F0 3D 74 58 66 C5 CF 24 03 51 A7 6C 6D BB D0 28 30 E5 F4 72 E2 AD 24 58 7C 7C AB 60 18 FD D9 34 C0 93 DF 41 CA B6 18 7E 6E 1E E9 BB 8D D5 99 F9 A2 10 F4 05 1F CD FD 55 28 8D 97 61 CA 22 C3 21 9E 72 24 76 46 AB 50 50 B0 B2 C7 7F 1D FB 6F 95 45 64 03 61 A2 7C AF CC 59 F3 24 42 E2 1B 7B  

		# Random bytes length (0x10 = 16)
		00 10 

			# Random bytes
			B5 11 F7 8F 84 CE 60 2F 70 11 0C 98 02 54 B1 70 

		# Marker, signature length (0x80 = 128)
		01 00 80 

			# Signature
			29 63 21 CD 66 0B 34 07 43 9E A4 B4 C9 F0 0B 84 6A 3F B5 AF 60 0D F8 25 AF 15 33 39 2D 91 57 24 E6 77 06 3D BF 6D CE AA CC E9 BD CA 10 BB 7D 8C 08 47 E4 B8 CD 5D C8 14 AB 31 FB 41 33 70 45 41 46 00 58 E4 A8 7B C2 3E 9B 53 75 D4 82 F8 B9 B6 56 EA 70 49 B2 DC F0 12 29 CE A1 01 32 4A 7E 3C 8F 97 DE 49 1C 80 6C F0 E2 91 7A 79 3E 29 07 81 9B 04 FC 14 34 A5 79 83 39 7C 58 B4 42 36 A0 6C 

The certificate data in the message is an exact copy of the data decrypted during the initialization step, implying that
this can simply be copied byte-for-byte into the application certificate message.

It's worth noting that the certificate data is always constant, and does not change.

Following the certificate data are 16 random bytes. These random bytes are necessary from a security standpoint 
because without them, the certificate message would always be constant and therefore wouldn't necessarily need 
to be generated by an impersonating software.

At the end of the message is its signature, signed using the typical [RSA signing process](http://en.wikipedia.org/wiki/RSA#Signing_messages).
The process involves computing a hash of the message (in this case, standard SHA-1 with some byte manipulations and other techniques), and then
using the RSA private key and modulus to create a signature of the message. The benefit of having a signature is that since the message is signed with 
the private key, the recipient can use the corresponding public key to retrieve the sender's hash of the message. Then, the recipient can perform the hash
procedure on the message and compare its own computed hash with the sender's hash. If the two are the same, then the recipient can assume that whoever sent the
message is the owner of the private key and, therefore, the person they want to be communicating with.

The RSA signing process involves raising the hash to the private key exponent, modulo the modulus (<strong><em>m<sup>d</sup> mod n</em></strong>, where _m_ is the hash,
_d_ is the private key, and _n_ is the modulus). The first matter of business is to actually compute the private key exponent, since we have every bit of information
about the private key (particularly, the two primes _p_ and _q_) except for the private key exponent itself (see the notes post for the RSA private key information
that was decrypted during the initialization stage). Luckily, this is (relatively) easy to compute:

		p = E7 B2 65 91 1C 64 9C 1B 9A 63 41 AB 67 A5 A1 90 DF 22 54 7F C2 ... [truncated]
		q = E0 16 E8 A5 B2 D7 1D B7 A9 39 B8 5C 35 B7 EB A3 BB DE 58 F2 F3 ... [truncated]

		n = p * q
		phi = (p - 1)(q - 1)
		e = 0x010001 = 65537
		
		d = inverse(e) mod phi

Once the private key is obtained, it's a simple matter of raising the hash to the private key exponent, modulo the modulus. Since the modulus and private key exponent
are both 1024 bits long, the signature should also be 1024 bits long, or 128 bytes.

This final message is then sent to the device.

4\. Handshake Response
---------------------

What follows is a handshake response as captured.

	# Response marker
	02 02 

	# Length of obfuscated decryption key (0x80)
	00 80 

		# Obfuscated decryption key
		3B FA 89 B4 52 F5 13 1A A4 70 EF DC 7D 7E 40 E8 93 DF 1B 90 3F 68 55 69 01 7D 83 5B DD 14 5A 5C FD 0C 18 9A A8 B6 14 E2 06 D9 7A 0B E8 F7 3E 37 EF 4F 8B 26 90 3F 99 B0 DC 2D 9D 08 26 A8 1A 7D 1D F3 B5 67 2D 79 77 12 2E 3B F5 73 51 F0 CF B0 23 0B 42 77 7B 31 4D FC C7 4C DB F4 71 28 FE 30 FF 70 A3 28 1E 35 1B 43 0C B8 8A D4 CA 8D C1 76 B6 6E 06 5F 8C A5 DD 94 2C A9 6F 65 B1 2A 64 29 

	# Length of encrypted response (0x340)
	00 00 03 40 

		# Encrypted response
		EA 16 86 55 D0 69 8C 36 7E 93 C6 A1 B0 F6 FC 62 8E 18 88 D4 FA CA C8 0F BF E2 CC 9D 7F D0 05 C7 70 9D 0C 14 6F 16 AC 84 64 28 CB FA FE CC 3C AA D1 4C 62 9D 6E 19 95 72 F4 82 75 0E CA 7C 90 1D 41 EE C3 EA BB 5E 81 B8 12 91 57 64 E2 22 B3 A5 BF 25 C3 0A 13 1D A7 B0 42 C9 20 A9 A2 ED 8E E7 9F 21 BA CA 95 FF 65 5D BA 45 ED CE 85 7F C7 21 85 9C 0D DE 7B 6A F9 AE 44 D7 F9 B2 9E 48 33 FA BD 8F B6 9C A2 65 74 91 B8 71 5C B6 E9 8F 3C EF F7 EA 46 E0 0E 5B 12 8D 41 44 19 02 49 B8 14 F7 33 42 A1 E0 88 FB 9F 57 50 B9 D8 68 B8 F5 9A EA F8 D8 23 F9 4D DD 09 8E BF CE E3 D4 7A D2 B3 93 8D EB 6E 47 E8 37 5B B7 78 B1 16 54 58 85 B7 26 D6 12 85 90 23 30 D5 4B 3B C0 98 17 FF 94 CD 36 1E 65 DC 9D DE 07 E4 0C 75 EA 86 7B FE 2C F6 C2 1C BF 42 66 26 89 EB 2C E5 A0 86 0E 31 8A 3A BE 32 CC FF 74 FF 10 8C E8 85 81 AC 42 79 93 14 7B 72 43 61 0C 5B 23 48 C5 E8 38 36 69 72 74 AD F2 E3 27 50 DA C2 59 93 C6 C8 11 2D 51 AA DC 41 5F 08 28 18 63 C8 72 8F 83 9B F9 07 3A CC D7 66 F5 D9 B7 2F A9 00 62 5D 2D EF 26 62 C9 17 6B 48 43 5A 18 DB C5 54 D6 CB 87 AC 07 CC 67 31 CC 62 F8 95 DD 29 52 4A 17 99 C8 5E CE 11 37 98 84 6D 12 69 40 EF 1E 1A E5 B8 AC 41 C8 06 76 79 05 EA 7A 13 83 12 73 54 33 20 DA 51 50 8B 4A A4 3B C4 6F 21 FB E7 B7 20 77 CD DE 37 17 4B 75 35 DB 32 90 1E 8B 81 FD E6 79 DC 1F F4 EB 83 6A CE 0A 05 C1 E4 ED 1B 37 10 13 04 99 0C 7E 34 9B AD DA 8A 24 F6 E7 F1 7E EC C1 A1 EF 74 48 B5 92 81 62 C8 B3 94 F1 75 37 6D 16 F7 46 9A DD 8D EF 50 DF 7A F0 19 80 74 FE 7D 83 DF 2C 9E 01 12 B4 1A 97 91 DE 59 7A DA 75 7F 89 F6 47 3A 0A F3 6E E3 F2 D1 B4 C9 95 F6 80 33 44 57 53 1D DB DA DC 0D D0 C5 1A 24 9F 04 0A 5C 88 94 D2 BC 99 08 E2 E9 45 1E AA DA 64 3A C1 DD E5 6A 75 B5 4D 0F 2B 49 4D 51 69 05 DE 22 6A 49 5E E2 5A 2C BC 0E A1 93 3C 3C 6E D7 66 D1 B5 13 8F C9 3F 3E FE 35 ED 49 04 38 DC 8B D3 69 56 FD 77 A1 B9 BA C6 C3 6C 44 CF 38 C9 0F 23 C5 D1 3A 4B A6 08 03 05 4B E6 4D C6 96 74 34 B5 3E 50 6E 07 FB C6 DE 88 9F F2 C4 6C AE 66 DA A1 44 15 16 0F BB 6D 2A DA 86 5A B0 E1 28 C5 9E 40 8F 52 0F 45 AD 1E 6B 8E BE B0 5C 54 8F 71 78 5B F0 7D 3F 11 11 3B 98 6C C4 20 DE 7A 0A 29 68 F5 A0 76 EF 57 C9 B7 C5 BB E3 2F 14 50 21 43 20 B3 69 B1 63 6E BB 62 54 09 C3 CD 48 A0 02 3C F5 02 2C 2A 4D E4 50 AF 74 41 4B D4 08 72 AC 64 71 86 4F 4B 2D 54 77 13 D4 2E 25 0B 72 DE 90 DC 0B 3D 03 17 B2 0C 79 92 08 89 74 82 67 BE DC 5A 7C F8 7A 00 E7 54 2F 39 31 88 35 95 FB A0 1D 98 80 11 16 EB CB 63 FF A0 F6 5D B4 3C 9B 45 64 46 02 AA 85 DC 23 F1 C7 9B 4A A3 A8 41 CE E1 F8 C5 B1 BA 0E 8F 82 3E FE E7 D2 C6 84 23 F6 65 7B 4A 

Evidently, the important part of the message here is the contents of the encrypted response. This key was encrypted using
the software's public key; therefore, it can be decrypted using the corresponding private key. Further transformations
are applied (including some SHA-1 routines) to condense it down to a 16-byte value. This is then used as a decryption key
in the same way `B1 CE 71 1C 1E 1B 46 87 84 A0 84 90 D5 96 22 16` is used as a decryption key during initialization.

Once the response is decrypted, the following data is obtained:

	# Marker (0x01) and length of certificate data (0x026A)
	01 00 00 02 6A 

		# Marker or number of certificates
		02 

			# Certificate 1 - "Zune Device CA 1" (see 1.2 for structure)
			00 00 01 33 01 00 00 00 00 B3 01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 10 5A 75 6E 65 20 44 65 76 69 63 65 20 43 41 20 31 00 01 00 01 00 80 7B 15 9D CE D1 FB 9E 21 17 3E 7D 01 9C 4F 1F 84 71 3D 48 B9 4C F7 4D CB 06 E9 F2 02 27 4F DC 25 39 16 82 41 B3 47 E0 7C B2 02 11 30 6F 26 68 43 D2 1B 01 DB E0 1E E0 25 BC 8B 70 02 DA F0 CB 45 1A 11 2D 2C 5D B7 71 7D FE 45 09 F2 F5 48 7F A7 27 98 A7 02 3F FC 70 37 2E 22 B3 1F 2A 97 78 2A 76 34 54 B1 C0 7B 4E 59 52 A5 15 7F A9 B2 A7 3A 6F E1 73 9C 64 D6 87 80 B9 1B 74 4B BE 75 FC B5 4B 4C 03 EA 8C 31 B7 06 17 21 D1 14 AA C2 4E 5B EC F5 64 0B A5 BB 78 44 1A 1E 49 9F CB A9 D6 5C F9 33 6E A7 D6 84 C2 7F BD EA C3 B3 11 16 AD 3A AF 7D BE 6C 1D 25 19 46 4A AA EA B6 A6 68 44 97 88 B0 6A C6 DD C5 C5 9C 17 69 F2 8D 5D 56 4E AB 74 CC 59 4F F5 6B 63 3E B3 7A C8 53 12 46 EE 2A EF 6B C7 78 34 57 B6 C8 F2 45 DF 9C 4A 29 8A 87 02 12 C4 07 06 FF DB 56 3A FA 98 C8 B1 A6 78 E9 
			
			# Certificate 2 - "Zune Device" (see 1.2 for structure)
			00 00 01 2E 01 00 00 00 00 AE 02 00 00 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 0B 5A 75 6E 65 20 44 65 76 69 63 65 00 01 00 01 00 80 69 69 1E 3F EC EF 51 E8 8C 50 E2 54 02 9A 79 27 2D 07 38 1E B4 A3 E4 20 49 A2 7C E1 42 69 B9 6C 6B 54 91 49 E4 EA 8F FC D8 8B D7 CF 41 4F E2 1F 3F 85 1A 8A 98 E8 6A 03 D2 C6 E2 52 09 35 6D F3 64 C6 BB 18 B0 DD 01 A0 5E 1C 73 A1 E0 D9 14 95 13 AE BB 40 23 C4 5B 8C 9C 65 90 BF C0 08 ED 99 58 A5 9E F0 93 F4 E8 8B 7D 8E 94 38 6D C0 33 DB 13 6A 8C D6 6E 46 75 B1 BA 10 CC 99 09 A9 8D A9 54 42 A3 51 A3 D6 C6 61 55 A0 F4 F5 8B BA ED FA 88 29 2B 26 DC D1 7F 8C DB 11 71 2B 91 08 7B 18 CB 78 4F F8 E0 FA 83 46 A4 98 EE D3 D6 22 47 A4 27 F1 1D 8B 48 E8 CF 37 42 43 06 1D 02 97 CD 7D 75 B1 F9 F9 9C 26 BC BD 62 69 4B BA E3 F2 B4 64 AA B3 34 E5 75 EF AA 52 84 63 D4 BC 22 18 3B 31 05 25 1B C8 79 FC 0E 29 AF 5E 8C 1B 08 F6 96 92 FC 07 37 D4 8B 4D 94 BA 2C 3A 3F E1 6F D8 81 E0 
			
	# Length of software's random bytes
	00 10 

		# Software's random bytes (not random here for the sake of debugging)
		11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 11 
	
	# Length of device's random bytes
	00 10 

		# Device's random bytes
		2A 64 B2 87 01 9F F4 F0 D1 64 82 DE 09 14 AA 3D 
	
	# Marker and length of signature
	01 00 80 

		# Message signature
		08 11 69 E4 D2 FC B9 BC F5 BB C0 43 1E 58 E6 02 51 95 D4 B9 6E AB 6F 75 D3 5E 65 57 E4 56 33 04 76 38 B4 2A EF F7 3B 54 79 74 5A E7 A9 D1 2F 2F 4E 22 F9 86 F7 C9 59 D7 CF 80 AA 66 C2 61 CE A3 AB 19 01 96 B2 08 4B 40 AB 93 A3 A3 B4 A2 EF 7D 3C 72 55 13 62 3E 52 FF FD F3 E7 45 9C 98 5A 93 73 90 9A 57 59 9C 9E 0D 83 AD F3 57 EF A8 76 B0 70 E6 69 F9 DC 47 C4 A0 F6 AC CC 27 F6 41 20 C9 
		
	# Marker and length of CBC-MAC/SHA-256 hash
	01 00 20 

		# CBC-MAC/SHA-256 hash
		F7 7E 47 7A 8E 31 3B 0B 97 D2 61 4C CF 57 5F 6F 38 59 18 70 91 FB AD EA 89 50 BF BA 17 6B BF B5 

	# Extra
	00 00 00 00 00 00 00 

There are two certificates in this message: "Zune Device CA 1" and "Zune Device". The second certificate 
seems to be the primary certificate of the device, and as such, its RSA public key information is used 
to decrypt the signature later on in the message.

Following the certificates are a copy of the random bytes we sent in the application certificate message.
Following those bytes are the device’s 16 random bytes.

Then, a 128-byte signature follows, generated in a fashion similar to our signature in the application
certificate message. That is, it is transformed via a hash function and signed using the device's private key.
It can be verified by using the public key transmitted in the "Zune Device" certificate to decrypt the signature.
Since we can almost already assume that the device that is sending this message is valid, this verification step
can be skipped for the sake of ease of implementation.

Lastly, a 32-byte hash follows. This is a SHA-256 hash of the CBC-MAC calculated of the random bytes in the message. 
Again, for sake of ease of implementation, we can skip generation of this hash for verification, and can instead 
simply copy this 32-byte hash for later use.

5\. Confirmation Message
-----------------------

What follows is a confirmation message as captured.

	# Marker bytes (02 03)
	02 03 

	# Length of message (0x10 = 16)
	00 10 

		# Message
		CD A5 6A 66 68 25 67 9D 99 CE B2 E9 28 E3 9F B9

This format is much shorter and simpler than the other messages. The message is obtained by
applying transformations, encryption, and hash functions to the CBC-MAC/SHA-256 hash found at the end of the
device's handshake response.


