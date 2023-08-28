#Isabella Obermeier
#Decrypt Vigenere Cipher

from collections import Counter

input_lines = []                    #empty array for the lines we want to read
with open('input1.txt', 'r') as input1:     #read the ciphertext
    for lines in input1:            #go through each line
        cipher = list(lines)        #separate the lines into the individual letters
        cipher.pop()                #take off the new line characters
        input_lines.append(cipher)  #add all the lines into one list

letters = []                        #empty array for our letters
for sub in input_lines:             #since we have sublists, we want to make them flat
    for element in sub:
        letters.append(element)     #the list with individual letters is saved in 'letters'

"""
 #Used for testing what the cipher frequency is
first = []; second = []; third = []; fourth = []; fifth = [];  sixth = []; seventh = [] #hold the columns of letters
count = 0
while count < len(letters):         #group the letters into seven columns
    first.append(letters[count])
    second.append(letters[count+1])
    third.append(letters[count+2])
    fourth.append(letters[count+3])
    fifth.append(letters[count+4])
    if count+5 < len(letters):      #since we do not have an even multiple of 7, we need to limit its function here
        sixth.append(letters[count+5])
        seventh.append(letters[count+6])
    count +=7
counter = Counter(fourth)          #get the counter values by replacing the column you want to see
print(counter)
"""

alphabet = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"] #list of alphabet letters
key = ["M", "A", "L", "L", "O", "R", "Y" ] #the computed key

print(key)
#driver code to complete decoding
plainText = []                      #list to hold the decoded letters
let_count = 0                       #counter for cycling through the letters
while let_count < len(letters):
    for i in range(0,7):            #for loop to go through all the letters
        cipher_index = alphabet.index(letters[let_count])      #get the index of the letter to be decoded
        key_index = alphabet.index(key[i])         #find the index value of the key
        plain_index = int (cipher_index) - int (key_index) #subtract the associated values of the key from the cipher
        if plain_index < 0:         #handle if we go beyond the 0 index into negatives (loop back to z)
            plain_index += 26
        
        plainText.append(alphabet[plain_index])      #add the decoded letter to a new list
        let_count = let_count +1    #add a counter to iterate through all the letters of the ciphertext   
        if let_count >= len(letters):   #test that we do not go beyond the letters of the ciphertext since our while does not see the counter until after the for loop runs
            break

#print the completed encoding
print("encoded word is:", ''.join(plainText))
