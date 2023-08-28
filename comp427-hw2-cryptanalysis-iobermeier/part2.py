#Isabella Obermeier
#computations for part2

import statistics
import letterFrequency as let_freq #import the python file
#from collections import Counter

upper_alphabet = ["A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M", "N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z"] #list of uppercase alphabet letters for python file use
lower_alphabet = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z"] #list of lowercase alphabet letters for text file use


######### import data
input_lines = []                   #empty array for the lines we want to read
with open('input2.txt', 'r') as input2:     #read the ciphertext
    for lines in input2:           #go through each line
        plain = list(lines)        #separate the lines into the individual letters
        plain.pop()                #take off the new line characters
        input_lines.append(plain)  #add all the lines into one list

letters = []                        #empty array for our letters
for sub in input_lines:             #since we have sublists, we want to make them flat
    for element in sub:
        letters.append(element)     #the list with individual letters is saved in 'letters'

####### functions
def calc_var(input_list):
    plain_var = []              #list to hold just the variances
    counter = 0
    for character in lower_alphabet:    #cycle through each letter of the alphabet
        counter = input_list.count(character)  #count the occurrence of each letter
        #print(counter)
        freq_var = counter/len(input_list)     #divide the frequency of each by the total letters
        plain_var.append(freq_var)          #store the variances
    pop_var_plaintext = statistics.variance(plain_var)  #calculates the variance from the plaintext
    return pop_var_plaintext


####### qa - population variance of english text
variances = []                  #list to hold just the variances
for letter in upper_alphabet:   #cycle through all the letters to get their variances
    variances.append(let_freq.letterFrequency[letter])    #store just the double values into the list

pop_var_eng = statistics.variance(variances)        #calculates the variance from the dictionary
print("qa - The population variance of English Text: ", pop_var_eng)



####### qb - population variance of letter frequencies in plaintext
print("qb - The population variance of Plaintext: ", calc_var(letters))



####### qc - encrypt plaintext with Vigenere cipher and given key
key = [["y", "z"], ["x", "y", "z"], ["w", "x", "y", "z"], ["v", "w", "x", "y", "z"], ["u", "v", "w", "x", "y", "z"]]
cipherText = []                     #list to hold the encoded letters
key_num = 4                        # the number corresponds to which key we want to use; from 0 to 4
let_count = 0                       #counter for cycling through the letters
while let_count < len(letters):     #while loop to go through all the letters
    for i in range(len(key[key_num])):                              #for loop to iterate over the keys
        plain_index = lower_alphabet.index(letters[let_count])      #get the index of the letter to be encoded
        key_index = lower_alphabet.index(key[key_num][i])           #find the index value of the key
        cipher_index = int (plain_index) + int (key_index)          #add the associated values of the key to the plaintext
        if cipher_index >= 26:       #handle if we go beyond the 26th index (loop back to a)
            cipher_index -= 26
        cipherText.append(lower_alphabet[cipher_index])             #add the encoded letter to a new list
        let_count = let_count +1    #add a counter to iterate through all the letters of the ciphertext
        if let_count >= len(letters):   #test that we do not go beyond the letters of the plaintext since our while does not see the counter until after the for loop runs
            break
#print(key[key_num], "encoded word is:", ''.join(cipherText)) #print the completed encoding
print(key[key_num], "\nqc - The population variance of Cipherext: ", calc_var(cipherText))



####### qd - separate the ciphertext into k lists & calculate frequence and average results
z_ciph = []; y_ciph = []; x_ciph = []; w_ciph = []; v_ciph = []; u_ciph = [] #initialize lists to hold the cipher letters
k=0
while k < len(cipherText):              #go through all the ciphertext
    for g in range(len(key[key_num])):  #go through each letter of the key
        if key[key_num][g] =="z":       #based on the letter of the key, switch between cases
            z_ciph.append(cipherText[k])#append the ciphertext if the correct key encoding
        elif key[key_num][g] =="y":
            y_ciph.append(cipherText[k])
        elif key[key_num][g] =="x":
            x_ciph.append(cipherText[k])
        elif key[key_num][g] =="w":
            w_ciph.append(cipherText[k])
        elif key[key_num][g] =="v":
            v_ciph.append(cipherText[k])
        elif key[key_num][g] =="u":
            u_ciph.append(cipherText[k])
        k=k+1                           #increment through the ciphertext
        if k >= len(letters):   #test that we do not go beyond the letters of the ciphertext since our while does not see the counter until after the for loop runs
            break
#print("z key letters: ", ''.join(z_ciph)); print("y key letters: ", ''.join(y_ciph)); 
if key_num == 0:                        #create another set of switch statements for calculating the mean of frequency variances
    avg_var = (calc_var(z_ciph) + calc_var(y_ciph))/len(key[key_num])   #take the ciphertext for the necessary keys and average based on its length
elif key_num == 1:
    avg_var = (calc_var(z_ciph) + calc_var(y_ciph)+ calc_var(x_ciph))/len(key[key_num])
elif key_num == 2:
    avg_var = (calc_var(z_ciph) + calc_var(y_ciph)+ calc_var(x_ciph) + calc_var(w_ciph))/len(key[key_num])
elif key_num == 3:
    avg_var = (calc_var(z_ciph) + calc_var(y_ciph)+ calc_var(x_ciph)+ calc_var(w_ciph) + calc_var(v_ciph))/len(key[key_num])
elif key_num == 4:
    avg_var = (calc_var(z_ciph) + calc_var(y_ciph)+ calc_var(x_ciph)+ calc_var(w_ciph) + calc_var(v_ciph) + calc_var(u_ciph))/len(key[key_num])   
    ####### qe - using key uvwxyz, recalculate if key length is 2,3,4,5
    for k_length in range(2,6):             #go through lengths of 2-5
        len_attack = (calc_var(z_ciph) + calc_var(y_ciph)+ calc_var(x_ciph)+ calc_var(w_ciph) + calc_var(v_ciph) + calc_var(u_ciph))/k_length #calculate the mean for each length type since our variance is the same for each iteration
        print("qe - The mean of the ", k_length, "variance: ", len_attack)
print("qd - The mean of the split variances: ", avg_var)
