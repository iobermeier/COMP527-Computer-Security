# Comp427 / 541: Web Security Project

## Web Security
The project specifications, as well as the corresponding course slide decks,
can be found on the Comp427 Piazza.

As a reminder, this file, _README.md_, is in
[MarkDown format](https://guides.github.com/features/mastering-markdown/)
and will be rendered to beautiful HTML when you visit your GitHub repo.

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

## Writeup (Part 4): defenses against SQL injection

To further prevent SQL injection, the inputs should be sanitized for certain symbol characters and strip whitespace and newline characters. Sanitizing the inputs can help prevent inputs such as ' or 1=1-- which can grant access to any of the accounts with a given username. Similarly, a better hashing algorithm should be chosen since MD5 has the vulnerability for collision attacks and allows the hash to be compromised. Using SHA-256 is longer and more difficult to crack and (as far as we know) does not include the ability to collision hash, therefore being a better alternative.

## Writeup (Part 4): defenses against XSS

To prevent XSS attacks, I would recommend validating user inputs by doing filters or escaping special characters. The following: < > ( ) ’ ” ; # & should be filtered out to avoid any malicious attack. Also, validating user input by filtering/prohibiting inputs like URL, location, href, search, and script can stop anything unwanted from running an attack. If script is not filtered out, a hacker can easily create a script statement which can lead to stolen information or control of the victim's account. Putting a maximum length limit in the input can also prevent attacks, as some types of attacks require a lengthy code.


## Writeup (Part 4): defenses against CSRF

SameSite flag cookies can be implemented to avoid further CSRF attack. During our test, we were able to obtain cookies from bungle from our HTML document, which ultimately led to a successful attack on the website. Using a SameSite cookie, cookies are only sent when the request is made from the same domain(the original website), therefore no longer permitting random/non-bungle domains to request cookies. Further validation of the CSRF token is necessary depending upon its request method (GET or POST) and whether it is present or omitted. Since we tested against CSRF attacks using xssdefense=0, we should also santize inputs for certain tags, especially script tags to prevent code injection.

