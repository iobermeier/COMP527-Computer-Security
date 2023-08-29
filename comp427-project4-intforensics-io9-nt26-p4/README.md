![Open in Codespaces](https://classroom.github.com/assets/open-in-codespaces-abfff4d4e15f9e1bd8274d9a39a0befe03a0632bb0f153d0ec72ff541cedbe34.svg)
# Comp427, Spring 2022, Project 4

## Internet and Forensics
This assignment is due **Friday, April 22 at 5 p.m.**

## Student Information
Please also edit _README.md_ and replace your instructor's name and NetID with your own:

_Student1 name_: Isabella Obermeier

_Student1 NetID_: io9

_Student2 name_: Nabillah Tanuwikanda

_Student2 NetID_: nt26

Your NetID is typically your initials and a numeric digit. That's
what we need here.

_If you contacted us in advance and we approved a late submission,
please cut-and-paste the text from that email here._

## Part 1: Exploring Network Traces

#### Problem 1
MAC-----------------IP

00:26:08:e5:66:07 -- 10.0.2.1

04:0c:ce:d8:0f:fa -- 10.0.2.2

8c:a9:82:50:f0:a6 -- 10.0.2.3

#### Problem 2

Since there are only 3 devices on the network, it is thought to be a personal network.

#### Problem 3

(a) Xs4all Internet BV (dl.xs4all.nl)

(b) Active FTP since No.16546 requests various ports using the PORT command

(c) The FTP protocol is vulnerable to anonymous authentication in which anyone may access the platform. Additonally, requesting 'AUTH GSSAPI' escalates security services and gives the user further authentication capabilities. By using Wireshark, we are able to see the unencrypted/plaintext username and password attempts made by the user, exposing further vulnerabilities to the program.

(d) Instead of using FTP, Secure FTP (SFTP) and managed file transfer (MFT) since they both protect files and create a more secure channel. SFTP relies upon secondary authentication whereas MFT streamlines file exchange and protects system integrity.

#### Problem 4

(a) www.evernote.com

(b) Since the only messages sent thus far consist of the handshake protocol to the server, a cipher suite has not yet been chosen.

(c) Cipher Suites (36 suites)

    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA (0xc00a)
    
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA (0xc014)
    
    Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0088)
    
    Cipher Suite: TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA (0x0087)
    
    Cipher Suite: TLS_DHE_RSA_WITH_AES_256_CBC_SHA (0x0039)
    
    Cipher Suite: TLS_DHE_DSS_WITH_AES_256_CBC_SHA (0x0038)
    
    Cipher Suite: TLS_ECDH_RSA_WITH_AES_256_CBC_SHA (0xc00f)
    
    Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA (0xc005)
    
    Cipher Suite: TLS_RSA_WITH_CAMELLIA_256_CBC_SHA (0x0084)
    
    Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
    
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_RC4_128_SHA (0xc007)
    
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA (0xc009)
    
    Cipher Suite: TLS_ECDHE_RSA_WITH_RC4_128_SHA (0xc011)
    
    Cipher Suite: TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (0xc013)
    
    Cipher Suite: TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0045)
    
    Cipher Suite: TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA (0x0044)
    
    Cipher Suite: TLS_DHE_DSS_WITH_RC4_128_SHA (0x0066)
    
    Cipher Suite: TLS_DHE_RSA_WITH_AES_128_CBC_SHA (0x0033)
    
    Cipher Suite: TLS_DHE_DSS_WITH_AES_128_CBC_SHA (0x0032)
    
    Cipher Suite: TLS_ECDH_RSA_WITH_RC4_128_SHA (0xc00c)
    
    Cipher Suite: TLS_ECDH_RSA_WITH_AES_128_CBC_SHA (0xc00e)
    
    Cipher Suite: TLS_ECDH_ECDSA_WITH_RC4_128_SHA (0xc002)
    
    Cipher Suite: TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA (0xc004)
    
    Cipher Suite: TLS_RSA_WITH_SEED_CBC_SHA (0x0096)
    
    Cipher Suite: TLS_RSA_WITH_CAMELLIA_128_CBC_SHA (0x0041)
    
    Cipher Suite: TLS_RSA_WITH_RC4_128_SHA (0x0005)
    
    Cipher Suite: TLS_RSA_WITH_RC4_128_MD5 (0x0004)
    
    Cipher Suite: TLS_RSA_WITH_AES_128_CBC_SHA (0x002f)
    
    Cipher Suite: TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc008)
    
    Cipher Suite: TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA (0xc012)
    
    Cipher Suite: TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016)
    
    Cipher Suite: TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA (0x0013)
    
    Cipher Suite: TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA (0xc00d)
    
    Cipher Suite: TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA (0xc003)
    
    Cipher Suite: SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA (0xfeff)
    
    Cipher Suite: TLS_RSA_WITH_3DES_EDE_CBC_SHA (0x000a)
    
The cipher suites contain a combination of key exchanges, authentication, stream ciphers, and message authentication.
Key exchanges: RSA, Diffie-Hellman Ephemeral (DHE), Elliptic-curve Diffie-Hellman (ECDH), Elliptic-curve DHE (ECDHE)
Authentication: RSA, Elliptic Curve Digital Signature Algorithm (ECDSA), Digital Signature Standard (DSS)
Stream Ciphers: Advanced Encryption Standard (AES), Camellia, Rivest Cipher 4 (RC4), Triple Data Encryption Algorithm (3DES)
Message Authentication: MD5, SHA

For example, the first cipher uses the ECDHE key exchange, the ECDSA authentication, AES 256 cipher with the CBC mode and SHA 1 hash. Each cipher suite is a conglomeration of authentication features that consist of cryptographic algorithms.

(d) The MD5 and SHA1 hashes have been found to be vulnerable to collision attacks and should use SHA3, SHA256, or SHA512 instead. Additonally, using 128 bits for AES and Camellia may be more secure than 16, 32, or 64 bit, but could be updated to a higher bit rate so that exploiting the vulnerabilities takes longer.

(e) The server chooses Cipher Suite: TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)

#### Problem 5

(a) The GET requests made to Facebook show the ajax request that uses a token or cookie for authentication. Since the token/cookie is shown in plaintext during the HTTP protocols, it can be exploited.

(b) A targeted attack could use the plaintext cookie as their own to spoof the authentication process.

(c) While the user is unable to personally encrypt their cookie, they are able to advocate for Facebook to use the HTTPS protocol instead of HTTP.

(d) The user starts at the Facebook home page to complete a series of searches including: z, zak, zaki, zakir, zakir d, zakir dur and sends a message that includes an attachment.


## Part 2: Forensics Report

<!---
Copy and paste the following template for all numbered prompts of the report.
--->

#### Problem 1

During bootup, the status messages give indications to the user of the processes being loaded. The user can see a message, "THEFT DETECTED, ENGAGING SECURITY SYSTEMEXT2-fs error" followed by invalid bitmap outputs(1-bootup-message.png). We can deduce that this is likely a compromised system that we cannot fully load with Live Analysis. After the bootup messages are complete, the interface allows us to choose our country and time zone, but prints a "failed" message with an infinite loop that requires a restart (1-failed-error.png). Upon restarting the machine, we receive the message: "FATAL: No bootable medium found! System halted." (1-fatal-error.png). From this sequence of behaviors, we know that Live Analysis is not possible since bootup will fail.

#### Problem 2

According to the Image Details, the Source OS is Linux. Volume 1 has Puppy Linux, version 2.6.30.5 and Volume 3 has Ubuntu version 9.04, both found within the /etc/issue folder. The only other Linux type found is in volume 3 with the folder /etc/debian_version and lists 5.0 as the version, but it is not located in the issue folder. The other mounted files are both raw files, therefore volume 1 & 3 are the only ones we can assess.

#### Problem 3

Username of the suspect: nefarious (3-username-proof.png)

#### Problem 4

The night of the crime the suspect did have a accomplice (4-Accomplice-found.png). The suspect was talking about needing to do a fast getaway, and the accomplice said I'll be waiting outside of the building. The accomplice is the getaway car driver. This information was found through the seearch of the word 'accomplice'.

#### Problem 5

There is one interesting encrypted file, 'passwords.zip' First we extract 'passwords.zip' and crack its password using the fcrackzip tool to find 5 text files (5-cracked-pass-zip.png). Returning to autopsy, we can choose the 'Unzip contents with password" option and enter the password, 'warrant' to get the contents of the 5 text files. Opening each seperately gives the following passwords: 1-mystery 2-love 3-secretpassword 4-MONKEY 5-jjdMn7vM3wU5tA (5-password5-text.png).

#### Problem 6

Yes, through a keyword search for the projectile, "nerf", there are lots of searches and results found for a Nerf gun including results for "best nerf guns" and browsing hasbro catalogs (6-ebay-results.png and 6-hasbro-url-searches.png).

#### Problem 7
Yes,the following was deleted and found from "all deleted files":
"evil_plan.bmp" (7-removing-files.png)

/3/home/nefarious/.thumbnails/normal/gimp-thumb-2932-22d0c19d 

/3/home/nefarious/password5.txt

/3/home/nefarious/password4.txt

/3/home/nefarious/password3.txt



#### Problem 8

[your answer here]

#### Problem 9

The suspect has a plan where the suspect is shooting something at the Hapless Victim(9-Extra-evidence-1.png). This was obtained from looking through the suspect's thumbnail folder

Obtained from searching the keyword "Nerf" is this chat conversation about the best nerf gun for shooting and how it is modifiable (9-nerf-question.jpeg)
