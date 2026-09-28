

# **LaTeX technical report**

**a. The assets, vulnerabilities, risk rankings, and recommended controls.**





**Assets**:

•	Student Record Database: Contains sensitive information about students.

•	Network Infrastructure: Facilitates communication and file transfers between campuses.

•	Staff Computers: Used by staff to access the student records.

**Vulnerabilities**:

	Weak Staff Passwords: Can lead to unauthorized access to sensitive data.

	Outdated Software: Exposes the system to known exploits and vulnerabilities.

	Unencrypted File Transfers: Allows interception of sensitive data during transmission.

**Possible Consequences**:

	Unauthorized access leading to data breaches.

	Service downtime or loss of data integrity.

	Legal implications and damage to institutional reputation.



**b. Anexplanation of the encryption, decryption, and integrity functions, supported by test evidence.**



**1. Encryption Function**

The encryption function I have used in the Python code utilizes the Fernet symmetric encryption from the cryptography library. It transforms plaintext files containing sensitive information into ciphertext, making it unreadable to unauthorized users. Here’s how it works:

•	Key Generation: A symmetric key is generated using Fernet.generate\_key(), which is used for both encryption and decryption.

•	Data Encryption: The plaintext data is read from the file, and then the encrypt() method of the Fernet object is called to encrypt the data using the generated key. The output is a byte string that represents the encrypted file content.

•	Output: The encrypted data is then written to a new file (e.g., encrypted\_student\_records.txt).



**2. Decryption Function**

The decryption function reverses the encryption process, converting ciphertext back into its original plaintext format.

•	Key Loading: The same symmetric key used for encryption is retrieved using load\_key().

•	Data Decryption: The encrypted data is read from the file, and the decrypt() method of the Fernet object is invoked to decrypt the data. The output is the original plaintext.

•	Output: The decrypted data is stored in a new file (e.g., decrypted\_student\_records.txt).



**3. Integrity Function (SHA-256 Hashing)**

To ensure data integrity, the SHA-256 hashing function is implemented. This function computes a unique hash of the file contents, which can be used to verify that the file has not been altered.

•	Hash Calculation: The file is read in chunks, and each chunk is fed into the SHA-256 hash function using the hashlib library. The result is a fixed-size hash that uniquely represents the file's contents.



Test Evidence for Integrity Check:

•	Input: Original file and its corresponding encrypted file.

•	Output: Hash values for both files.

By calculating and comparing the SHA-256 hash of the original file before encryption and the encrypted file after decryption, one can verify the integrity of the data:

•	Before Encryption: Hash of student\_records.txt.

•	After Decryption: Hash of decrypted\_student\_records.txt.

If both hashes are identical, it confirms the integrity of the data throughout the encryption and decryption process.



## **The source code** 



\#!/usr/bin/env python3



"""

Cryptography \& Network Security Exam Toolkit



Functions:

1\. Encrypt a file using Fernet authenticated encryption.

2\. Decrypt the encrypted file.

3\. Verify that decrypted data matches the original.

4\. Calculate SHA-256 and detect later file changes.

5\. Handle missing files and invalid inputs without crashing.



The encryption key must be stored outside the Git repository.

"""



from \_\_future\_\_ import annotations



import argparse

import hashlib

import sys

from pathlib import Path



from cryptography.fernet import Fernet, InvalidToken





def sha256\_file(path: Path) -> str:

&#x20;   """Return the SHA-256 hexadecimal digest of a file."""

&#x20;   digest = hashlib.sha256()



&#x20;   with path.open("rb") as file:

&#x20;       for chunk in iter(lambda: file.read(1024 \* 1024), b""):

&#x20;           digest.update(chunk)



&#x20;   return digest.hexdigest()





def generate\_key(key\_path: Path) -> None:

&#x20;   """Generate a Fernet encryption key."""

&#x20;   if key\_path.exists():

&#x20;       raise FileExistsError(

&#x20;           f"Key already exists: {key\_path}"

&#x20;       )



&#x20;   key\_path.parent.mkdir(parents=True, exist\_ok=True)



&#x20;   key\_path.write\_bytes(Fernet.generate\_key())



&#x20;   # Restrict permissions on systems supporting chmod.

&#x20;   try:

&#x20;       key\_path.chmod(0o600)

&#x20;   except OSError:

&#x20;       pass



&#x20;   print(

&#x20;       f"Encryption key created outside the repository: "

&#x20;       f"{key\_path}"

&#x20;   )





def load\_key(key\_path: Path) -> bytes:

&#x20;   """Load and validate the encryption key."""



&#x20;   if not key\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"Key file not found: {key\_path}"

&#x20;       )



&#x20;   key = key\_path.read\_bytes().strip()



&#x20;   try:

&#x20;       Fernet(key)

&#x20;   except Exception as exc:

&#x20;       raise ValueError(

&#x20;           "Invalid Fernet encryption key."

&#x20;       ) from exc



&#x20;   return key





def encrypt\_file(

&#x20;   input\_path: Path,

&#x20;   output\_path: Path,

&#x20;   key\_path: Path

) -> None:



&#x20;   if not input\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"Input file not found: {input\_path}"

&#x20;       )



&#x20;   key = load\_key(key\_path)



&#x20;   encrypted = Fernet(key).encrypt(

&#x20;       input\_path.read\_bytes()

&#x20;   )



&#x20;   output\_path.parent.mkdir(

&#x20;       parents=True,

&#x20;       exist\_ok=True

&#x20;   )



&#x20;   output\_path.write\_bytes(encrypted)



&#x20;   print(

&#x20;       f"Encrypted: {input\_path} -> {output\_path}"

&#x20;   )





def decrypt\_file(

&#x20;   encrypted\_path: Path,

&#x20;   output\_path: Path,

&#x20;   key\_path: Path,

&#x20;   original\_path: Path | None = None

) -> None:



&#x20;   if not encrypted\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"Encrypted file not found: {encrypted\_path}"

&#x20;       )



&#x20;   key = load\_key(key\_path)



&#x20;   try:

&#x20;       decrypted = Fernet(key).decrypt(

&#x20;           encrypted\_path.read\_bytes()

&#x20;       )



&#x20;   except InvalidToken as exc:

&#x20;       raise ValueError(

&#x20;           "Decryption failed: wrong key or "

&#x20;           "encrypted file was modified."

&#x20;       ) from exc



&#x20;   output\_path.parent.mkdir(

&#x20;       parents=True,

&#x20;       exist\_ok=True

&#x20;   )



&#x20;   output\_path.write\_bytes(decrypted)



&#x20;   print(

&#x20;       f"Decrypted: {encrypted\_path} -> {output\_path}"

&#x20;   )



&#x20;   if original\_path is not None:



&#x20;       if not original\_path.is\_file():

&#x20;           raise FileNotFoundError(

&#x20;               f"Original file not found: {original\_path}"

&#x20;           )



&#x20;       if original\_path.read\_bytes() == decrypted:



&#x20;           print(

&#x20;               "MATCH: decrypted contents are "

&#x20;               "identical to the original file."

&#x20;           )



&#x20;       else:



&#x20;           print(

&#x20;               "MISMATCH: decrypted contents differ "

&#x20;               "from the original file."

&#x20;           )





def write\_hash(

&#x20;   file\_path: Path,

&#x20;   hash\_path: Path

) -> None:



&#x20;   if not file\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"File not found: {file\_path}"

&#x20;       )



&#x20;   digest = sha256\_file(file\_path)



&#x20;   hash\_path.write\_text(

&#x20;       digest + "\\n",

&#x20;       encoding="utf-8"

&#x20;   )



&#x20;   print(f"SHA-256: {digest}")



&#x20;   print(

&#x20;       f"Hash saved to: {hash\_path}"

&#x20;   )





def verify\_hash(

&#x20;   file\_path: Path,

&#x20;   hash\_path: Path

) -> None:



&#x20;   if not file\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"File not found: {file\_path}"

&#x20;       )



&#x20;   if not hash\_path.is\_file():

&#x20;       raise FileNotFoundError(

&#x20;           f"Hash file not found: {hash\_path}"

&#x20;       )



&#x20;   expected = (

&#x20;       hash\_path

&#x20;       .read\_text(encoding="utf-8")

&#x20;       .strip()

&#x20;       .split()\[0]

&#x20;   )



&#x20;   actual = sha256\_file(file\_path)



&#x20;   print(

&#x20;       f"Expected SHA-256: {expected}"

&#x20;   )



&#x20;   print(

&#x20;       f"Actual SHA-256:   {actual}"

&#x20;   )



&#x20;   if actual == expected:



&#x20;       print(

&#x20;           "INTEGRITY OK: the file has not changed."

&#x20;       )



&#x20;   else:



&#x20;       print(

&#x20;           "INTEGRITY FAILED: the file has changed."

&#x20;       )





def build\_parser():



&#x20;   parser = argparse.ArgumentParser(

&#x20;       description=(

&#x20;           "Cryptography and Network Security "

&#x20;           "exam toolkit"

&#x20;       )

&#x20;   )



&#x20;   sub = parser.add\_subparsers(

&#x20;       dest="command",

&#x20;       required=True

&#x20;   )



&#x20;   # Generate encryption key

&#x20;   key = sub.add\_parser(

&#x20;       "generate-key",

&#x20;       help="Generate an encryption key"

&#x20;   )



&#x20;   key.add\_argument(

&#x20;       "--key",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   # Encrypt

&#x20;   enc = sub.add\_parser(

&#x20;       "encrypt",

&#x20;       help="Encrypt a file"

&#x20;   )



&#x20;   enc.add\_argument(

&#x20;       "--input",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   enc.add\_argument(

&#x20;       "--output",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   enc.add\_argument(

&#x20;       "--key",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   # Decrypt

&#x20;   dec = sub.add\_parser(

&#x20;       "decrypt",

&#x20;       help="Decrypt a file and compare it with original"

&#x20;   )



&#x20;   dec.add\_argument(

&#x20;       "--input",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   dec.add\_argument(

&#x20;       "--output",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   dec.add\_argument(

&#x20;       "--key",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   dec.add\_argument(

&#x20;       "--original",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   # SHA-256

&#x20;   hsh = sub.add\_parser(

&#x20;       "hash",

&#x20;       help="Calculate and save SHA-256"

&#x20;   )



&#x20;   hsh.add\_argument(

&#x20;       "--file",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   hsh.add\_argument(

&#x20;       "--hash-file",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   # Verify SHA-256

&#x20;   verify = sub.add\_parser(

&#x20;       "verify",

&#x20;       help="Verify a file against a saved SHA-256"

&#x20;   )



&#x20;   verify.add\_argument(

&#x20;       "--file",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   verify.add\_argument(

&#x20;       "--hash-file",

&#x20;       type=Path,

&#x20;       required=True

&#x20;   )



&#x20;   return parser





def main() -> int:



&#x20;   parser = build\_parser()



&#x20;   args = parser.parse\_args()



&#x20;   try:



&#x20;       if args.command == "generate-key":



&#x20;           generate\_key(args.key)



&#x20;       elif args.command == "encrypt":



&#x20;           encrypt\_file(

&#x20;               args.input,

&#x20;               args.output,

&#x20;               args.key

&#x20;           )



&#x20;       elif args.command == "decrypt":



&#x20;           decrypt\_file(

&#x20;               args.input,

&#x20;               args.output,

&#x20;               args.key,

&#x20;               args.original

&#x20;           )



&#x20;       elif args.command == "hash":



&#x20;           write\_hash(

&#x20;               args.file,

&#x20;               args.hash\_file

&#x20;           )



&#x20;       elif args.command == "verify":



&#x20;           verify\_hash(

&#x20;               args.file,

&#x20;               args.hash\_file

&#x20;           )



&#x20;       return 0



&#x20;   except (

&#x20;       FileNotFoundError,

&#x20;       PermissionError,

&#x20;       ValueError,

&#x20;       FileExistsError

&#x20;   ) as exc:



&#x20;       print(

&#x20;           f"ERROR: {exc}",

&#x20;           file=sys.stderr

&#x20;       )



&#x20;       return 1





if \_\_name\_\_ == "\_\_main\_\_":

&#x20;   raise SystemExit(main())



**c. Thefirewall rules, test procedure, and results for permitted and blocked connections**.



Firewall rules are conditional statements compiled into an Access Control List (ACL) that inspect and regulate network traffic based on parameters like source and destination IP addresses, transport protocols (TCP/UDP), and targeted port numbers. These rules are evaluated sequentially from top to bottom, matching incoming or outgoing packets against specific criteria to execute a PERMIT, DENY, or DROP action. If a packet does not match any explicitly defined criteria, it is automatically discarded by the final Implicit Deny All rule, which serves as the foundational security baseline for the firewall.



The test procedure involves a systematic three-tiered validation process that begins with Layer 3 ICMP probes (ping and traceroute) to verify basic network routing and path availability. It then advances to Layer 4 socket scans using utility tools like Netcat (nc) or Nmap to inject targeted TCP SYN or UDP packets into specific destination ports, directly confirming whether transport-layer access is granted or denied. Finally, the procedure concludes with Layer 7 application handshakes (such as running curl or establishing an SSH session) to guarantee that operational data traffic successfully passes through the security boundary.



The results for permitted and blocked connections are determined by the packet responses received during a connection attempt. Permitted connections successfully complete the network handshake, returning an open or unfiltered status in port scans, delivering a SYN-ACK flag response over TCP, or receiving a standard ICMP Echo Reply. In contrast, blocked connections vary based on whether the firewall drops or rejects the traffic: dropped packets result in a filtered status and connection timeouts due to a complete lack of response, while explicitly rejected packets return a closed status accompanied by a RST-ACK flag or an ICMP "Destination Unreachable" error code.



## **Source code**



\#!/bin/bash



\# Replace these with the values supplied by the assessor.

SERVER\_IP="192.168.10.10"

STAFF\_NET="192.168.20.0/24"

GUEST\_NET="192.168.30.0/24"

SERVICE\_PORT="<ASSESSOR\_PORT>"



\# Block guest network access to the service

sudo iptables -A INPUT \\

&#x20;   -p tcp \\

&#x20;   -s "$GUEST\_NET" \\

&#x20;   -d "$SERVER\_IP" \\

&#x20;   --dport "$SERVICE\_PORT" \\

&#x20;   -j DROP



\# Permit authorized staff access

sudo iptables -A INPUT \\

&#x20;   -p tcp \\

&#x20;   -s "$STAFF\_NET" \\

&#x20;   -d "$SERVER\_IP" \\

&#x20;   --dport "$SERVICE\_PORT" \\

&#x20;   -m conntrack --ctstate NEW,ESTABLISHED \\

&#x20;   -j ACCEPT



\# Block all other inbound access to the service

sudo iptables -A INPUT \\

&#x20;   -p tcp \\

&#x20;   -d "$SERVER\_IP" \\

&#x20;   --dport "$SERVICE\_PORT" \\

&#x20;   -j DROP



echo "Firewall rules applied."



**d. Explain the project structure and how to run the program and reproduce its tests in README.md.**



src/            # Application source code (core logic, firewall modules)

tests/          # Automated test suite (permitted/blocked connection test cases)

config/         # Configuration files (ACL rules, network settings)

&#x20;README.md       # Project documentation



To run the program and reproduce its tests, execute the following commands from the project root directory:



\# 1. Install project dependencies

pip install -r requirements.txt



\# 2. Run the main application

python src/main.py



\# 3. Execute the test suite to reproduce results

pytest tests/













