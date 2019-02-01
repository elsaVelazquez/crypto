#created by Elsa Velazquez
#16.3 second Nonce with 6 leading zeros in python

#referred to the following
#https://www.youtube.com/watch?time_continue=259&v=K_Ac1Ko8-p8
#https://www.udemy.com/build-your-blockchain-az/learn/v4/t/lecture/9657552?start=30

#Group members: Josh Nguyen and Elsa Velazquez



import hashlib
import string


def brute_force_pow():
	proof_test = False
	increment_nonce = 0
	total_tests = 99999999
	seed = 'elve5895-jong5039-'

	while proof_test == False:
		#loop to create the new nonce and test it
		for increment_nonce in xrange(total_tests):
			new_nonce = str(increment_nonce)
			current_nonce = (seed + new_nonce)
			hashed = hashlib.sha256(current_nonce).hexdigest()
			if hashed.startswith('000000'):
				print 'POW mined!  It is :', current_nonce
				print 'Should hash to:  ', hashed
				break
		proof_test = True


brute_force_pow()
