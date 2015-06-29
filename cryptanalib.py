# cryptanalib.py - A series of useful functions for crypto jazz
# by Daniel "unicornFurnace" Crowley

import string
import frequency
import operator

# Polybius square generator. Returns a list of strings of equal
# length, either 5x5 or 6x6 depending on whether extended
# Polybius mode is on. Assumes I/J are represented as one letter
def make_polybius_square(password,extended=False):
   alphabet = string.lowercase
   if extended == True:
      alphabet += string.digits
   else:
      alphabet = string.replace(string.lowercase, 'j', '')
      password = string.replace(password, 'j', 'i')
   if any([x not in alphabet for x in set(password)]):
      return False
   unique_letters = []
   for letter in password:
      if letter not in unique_letters:
         unique_letters.append(letter)
   for letter in unique_letters:
      alphabet = string.replace(alphabet, letter, '')
   for letter in unique_letters[::-1]:
      alphabet = letter + alphabet
   ps = []
   alphabet_len = len(alphabet)
   grid_size = 5 + int(extended) # Not necessary, but looks cleaner
   for index in xrange(0,alphabet_len,grid_size):
      ps.append(alphabet[index:index+grid_size])
   return ps

# Decrypt given a polybius square (such as one generated
# by make_polybius_square() ) and a ciphertext.
def polybius_decrypt(ps, ciphertext):
   ct_len = len(ciphertext)
   if (ct_len % 2) != 0:
      return False
   digraphs = []
   plaintext = ''
   for index in xrange(0,ct_len,2):
      digraphs.append(ciphertext[index:index+2])
   for digraph in digraphs:
      x = int(digraph[0]) - 1
      y = int(digraph[1]) - 1
      plaintext += ps[y][x]
   return plaintext

# Look for repeating blocks
def detect_ecb(ciphertext):
   ciphertext_len = len(ciphertext)
   for blocksize in [32,16,8]:
      if ciphertext_len % blocksize == 0:
         blocks = [ciphertext[offset:offset+blocksize] for offset in xrange(0,ciphertext_len,blocksize)]
         seen = set()
         for block in blocks:
            if block in seen:
               return True, blocksize
            else:
               seen.add(block)
   return False, 0


# PKCS7 padding remove - returns unpadded string if successful,
# returns False if unsuccessful
def pkcs7_padding_remove(text, blocksize):
   last_byte = ord(text[-1:])
   if last_byte > blocksize:
      return False
   if text[-last_byte:] != chr(last_byte)*last_byte:
      return False
   else:
      return text[:-last_byte]

def pkcs7_pad(text, blocksize):
   pad_num = (blocksize - len(text)%blocksize)
   return text+chr(pad_num)*pad_num

# TODO: Byte at a time ecb decryption
def ecb_cp_decrypt(encryption_oracle, random_prefix=False):
   last_len = 0
   bytes_to_boundary = 0
   for length in xrange(1,33):
      cur_len = len(encryption_oracle("A"*length))
      if (cur_len > last_len) and last_len != 0:
         bytes_to_boundary = length
         blocksize = cur_len - last_len
         break
   padding = "A"*bytes_to_boundary
   position_test = encryption_oracle(padding + 'A'*blocksize + 'B'*(blocksize*2) + 'A'*blocksize)
   # TODO: do a real regex - position = regex.find(position_test, '(blockA)(blockB){2}\1')+blocksize*4
   working_block = "A"*blocksize-1
   decrypted_bytes = ''
   correct_byte_block = encryption_oracle(padding+working_block)[position:position+blocksize]
   for char in map(chr,xrange(256)):
      if encryption_oracle(padding+working_block+char)[position:position+blocksize] == correct_byte_block:
         decrypted_bytes += char
         break
   working_block = working_block[:-len(decrypted_bytes)] + decrypted_bytes
   

# TODO: recover earlier states from mersenne twister output
def mersenne_untwister()

# TODO: Given a padding oracle function and ciphertext,
# perform Vaudenay's PO -> DO attack
# TODO: Extend the attack to other forms of padding that
# function similarly to PKCS5/PKCS7
def padding_oracle_decrypt( 
   
# Calculate and return bitwise hamming distance between two strings
def hamming_distance(string1, string2):
   distance = 0
   for char1, char2 in zip(string1, string2):
      for digit1, digit2 in zip('{0:08b}'.format(ord(char1)),'{0:08b}'.format(ord(char2))):
         if digit1 != digit2:
            distance += 1
   return distance



# XOR two strings and return the result
def sxor(string1, string2):
   return ''.join(chr(ord(chr1)^ord(chr2)) for chr1, chr2 in zip(string1,string2))



# generate a character frequency table for a given text
# and charset as list of chars, digraphs, etc
def generate_frequency_table(text,charset):
   freq_table = {}
   text_len = 0
   for char in text:
      if char in charset:
         text_len += 1
   # Gather counts of each character and digraph in charset
   for char in charset:
      freq_table[char] = string.count(text,char)
   # Normalize frequencies with length of text
   for key in freq_table.keys():
      if text_len != 0:
         freq_table[key] /= float(text_len)
      else:
         freq_table[key] = 0
   return freq_table



# Return a list of likely successful single byte XOR decryptions sorted
# by score
def break_single_byte_xor(ciphertext,num_answers=5):
   answers = {}
   ciphertext_len = len(ciphertext)
   for key in xrange(256):
      answer = sxor(ciphertext, chr(key)*ciphertext_len)
      answers[answer] = (detect_plaintext(answer),key)
   return sorted(answers.items(),key=operator.itemgetter(1))[:num_answers]


# Return score for likelihood that string is plaintext
# in specified language as a measure of deviation from
# expected frequency values (lower is better)
def detect_plaintext(candidate_text, pt_lang='english_letters', single_chars_only=False):
   pt_freq_table = frequency.frequency_tables[pt_lang]
   if single_chars_only:
      pt_freq_table_keys = filter(lambda x: len(x)==1,pt_freq_table.keys())
   else:
      pt_freq_table_keys = pt_freq_table.keys()
   candidate_dict = generate_frequency_table(candidate_text, pt_freq_table_keys)
   # generate score as deviation from expected character frequency
   score = 0
   for char in pt_freq_table_keys:
      score += abs(candidate_dict[char]-pt_freq_table[char])
   return score


# Return a list of likely successful decryptions sorted
# by score
# TODO: find the best keysize more intelligently, hamming
# distance seems a bit too dodgy
def break_multi_byte_xor(ciphertext, max_keysize=40, num_answers=5):
   edit_distances = {}
   ciphertext_len = len(ciphertext)
   for keysize in xrange(2,max_keysize+1):
      edit_distances[keysize] = hamming_distance(ciphertext[:keysize],ciphertext[keysize:keysize*2])/1.0/keysize
   best_keysizes = sorted(edit_distances.items(),key=operator.itemgetter(1))[0:num_answers]
   answers = {}
   for best_keysize in best_keysizes:
      ct_chunks = []
      pt_chunks = []
      for offset in xrange(best_keysize[0]):
         ct_chunks.append(ciphertext[offset::best_keysize[0]])
      best_key=''
      for ct_chunk in ct_chunks:
         best_key += chr(break_single_byte_xor(ct_chunk,1)[0][1][1])
      answers[best_key] = sxor(ciphertext,best_key*((len(ciphertext)/best_keysize[0])+1))
   return sorted(answers.values(),key=detect_plaintext)[0]




# TODO: extended euclidian GCD algorithm
def extended_euclid():
   print 'todo'

# TODO: CRT algo
def chinese_remainder_theorem():
   print 'todo'

# TODO: this sucks, add digraph/trigraph detection? word detection?
# consider implementing quipqiup method
# FIXME: Currently this function is broken as frequency tables now
# include digraphs and translating based on mixed single chars and
# digraphs doesn't work as originally written
def break_simple_substitution(ciphertext, pt_lang='english', num_answers=5):
   freq_table = frequency.frequency_tables[pt_lang]
   ciphertext_freq = generate_frequency_table(ciphertext, freq_table.keys())
   ''' Experiments in frequency matching...
   closest_match = ('', 1)
   plaintext_charset = []
   ciphertext_charset = []
   for pt_char, pt_frequency in freq_table.items():
      for ct_char, ct_frequency in ciphertext_freq.items():
         current_match = abs(ct_frequency-pt_frequency)
         if current_match < closest_match[1]:
            closest_match = (ct_char, current_match)
      plaintext_charset += pt_char
      ciphertext_charset += closest_match[0]
      closest_match = ('', 1)
   '''
   #old method - sort tables by frequency and map characters directly
   plaintext_charset = [x[0] for x in sorted(freq_table.items(), key=operator.itemgetter(1), reverse=True)]
   ciphertext_charset = [x[0] for x in sorted(ciphertext_freq.items(), key=operator.itemgetter(1), reverse=True)]
   # 
   answers = []
   candidate_charset = plaintext_charset
   for offset in xrange(len(plaintext_charset)-1):
      candidate_charset[offset],candidate_charset[offset+1] = candidate_charset[offset+1],candidate_charset[offset]
      answers.append(do_simple_substitution(ciphertext, candidate_charset, ciphertext_charset))
      candidate_charset[offset],candidate_charset[offset+1] = candidate_charset[offset+1],candidate_charset[offset]
   return sorted(answers, key=detect_plaintext)[:num_answers]



def do_simple_substitution(ciphertext, pt_charset, ct_charset):
   #translate ciphertext to plaintext using mapping
   return string.translate(ciphertext, string.maketrans(ct_charset, pt_charset))



# Generic shift cipher brute forcer
def break_generic_shift(ciphertext, charset):
   answers = []
   charset_len = len(charset)
   for offset in xrange(charset_len):
      plaintext = ''
      for char in ciphertext:
         if char in charset:
            plaintext += charset[(charset.find(char)+offset)%charset_len]
         else:
            plaintext += char
      answers.append(plaintext)
   return sorted(answers, key=detect_plaintext)[0]

# Call generic shift cipher breaker with lowercase letters 
def break_alpha_shift(ciphertext):
   return break_generic_shift(ciphertext.lower(), string.lowercase)

# Call generic shift cipher breaker with full ASCII range
def break_ascii_shift(ciphertext):
   ascii_set = ''
   for num in xrange(256):
      ascii_set += chr(num)
   return break_generic_shift(ciphertext, ascii_set)

