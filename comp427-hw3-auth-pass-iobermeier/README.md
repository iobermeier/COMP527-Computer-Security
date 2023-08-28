# Comp427 / 541: Homework 3

## Authentication and Passwords

The homework specifications, as well as the corresponding course slide decks,
can be found on the Comp427 Piazza.
This assignment is due **Friday, March 19 at 6 p.m.**

You will do this homework by editing the _README.md_ file. It's in
[MarkDown format](https://guides.github.com/features/mastering-markdown/)
and will be rendered to beautiful HTML when you visit your GitHub repo.

## Student Information

Please also edit _README.md_ and replace your instructor's name and NetID with your own:

_Student name_: Isabella Obermeier

_Student NetID_: io9

Your NetID is typically your initials and a numeric digit. That's
what we need here.

_If you contacted us in advance and we approved a late submission,
please cut-and-paste the text from that email here._

## Problem 1

#### Part A

Using a central sign on can help admins control users across domains rather than handle multiple accounts for a single user. The addition of a token makes signing in convenient for the user since it can be used multiple times without having to log in again. If the user logs out of their account, a new token will need to be administered, therefore adding a second layer of security without hassle for the users and admin.

#### Part B

A single sign on and token can hurt security if the user forgets their password or their account becomes locked since they won't be able to access any of the campus sites. Similarly, if a malicious user knows a user's password, they have unlimited access to all the campus sites, rather than just a few. Similarly, the use of a token can be compromised and give access to all of the campus sites.

#### Part C

If the attacker is controlling site A, it may be able to gain the user's private key and create multiple signatures to send to other sites. If the attacker cannot reach the user's private key, then the attacker can take the signature sent to site A and forward it to other sites for spoofing.

#### Part D

The best to avoid a malicious user from obtaining a user's secret key is to implement encryption methods such as PGP or PKI encryption methods for improved integrity and authentication. Another way to prevent a malicious user from successfully using the obtained digital signature is for websites to include a second verification measure before accepting the signature.

#### Part E

Considering that Mallory has access to the nonces sent by both Alice and Bob as well as the shared secret key, she can either use someone else's nonce or randomly create her own to start a parallel version of the protocol. By acting as a man in the middle attacker, Mallory can simply gather the encryptions sent from other members of the group and redistribute them as she needs them. 

#### Part F

Since we need one shared private key, we want to use a pseudorandom nonce generator to make it more difficult for Mallory to join the conversation. Using the same shared key, we could implement a step counter in the HMAC encryption or require both Alice and Bob's nonces in the encryption. Similarly, if we were allowed to use more than one or generate new private keys for each session (ephemeral Diffie-Hellman), then the reverse channel can use separate keys.

## Problem 2

#### Part A

Since the passwords in the database can have any 8 character combination of 26 lower and uppercase letters as well as 10 numbers, it is possible to have 62^8 passwords. Considering that a brute force attack takes (62^8)/2 guesses and an attacker can guess 4 million hashes per second, the number of guesses it would take = (62^8)/(2*4 million) seconds ~= 45,4875.2 minutes or ~=7,581.254 hours. For the purpose of this exercise, we will round up in case the hash is found in the last few minutes, ie takes 7,582.

#### Part B

Using the calculation from part A, cracking one individual hash per hour requires a 7,582 node botnet.

#### Part C

The stored password would occupy 8 bytes and the hash occupies 32 bytes which needs to be considered for each possible password: (62^8)*(8 bytes+32 bytes) = 8,733,604,223,395,840 bytes.

#### Part D

Since the table stores only the first and last passwords, each consisting of 8bytes, the number of bytes in the table is = 16(N/k)

#### Part E

To represent the same # of passwords, 62^8, the number of bytes needed = 16(62^8)/5000 ~= 698,688,337,871.6672 bytes. For realistic application, we round up to store the amount in the decimal ~=698,688,337,872 bytes.

#### Part F

With the same number of passwords, it would take an attacker (62^8)/2 million chain elements per second ~=30325.01466 hours to construct the table.

#### Part G

Cracking a single password through brute force is about 4 times quicker than constructing a rainbow table due to the computing time required for all possible passwords in the rainbow table. However, considering a long term benefit, computing all possible passwords is much quicker using a rainbow table than a brute force attempt. In terms of storage size, computing a rainbow table is much more space efficient, especially since it can compute outputs for all possible passwords.

#### Part H

Using a secret can make it more difficult to access the hashes and passwords on the server. Rather than using the available rainbow table, a new one needs to be computed using the server secret.

#### Part I

Password salting, randomizing a hash with random data from the user can provide better protection of passwords since none of the hashes should match, even if they are the same password. Using a long enough salt is necessary to ensure it cannot be easily replicated.

#### Part J

In a brute force attack, as was done in part a, we have 62^8 passwords with the number of guesses it would take = (62^8)/(2*180*10^9 hashes per second) ~= 606.5003 seconds or 10.10833 minutes or 0.16847 hours.
