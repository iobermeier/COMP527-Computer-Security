# this is a simple benchmark that just measures how fast our encryption runs
import time
from secrets import randbelow

from tqdm import tqdm

from electionguard.elgamal import (
    elgamal_encrypt,
    ElGamalCiphertext,
    elgamal_keypair_random,
)
from electionguard.chaum_pedersen import (
    make_constant_chaum_pedersen_proof_known_nonce
)
from electionguard.hash import(
    hash_elems
)
from electionguard.group import rand_q, ElementModQ
from electionguard.nonces import Nonces

ballots_num = 100
contests_num = 20
selections_num = 5

keypair = elgamal_keypair_random()
nonces = Nonces(rand_q(), "benchmark-nonces")

total_iterations = ballots_num*contests_num*selections_num
start_time = time.perf_counter()
for i in tqdm(range(0, total_iterations)):
    nonce: ElementModQ = nonces[i]
    message = randbelow(total_iterations)
    ciphertext: ElGamalCiphertext = elgamal_encrypt(message, nonce, keypair.public_key)
    make_constant_chaum_pedersen_proof_known_nonce(ciphertext, message, nonce, keypair.public_key, nonce, hash_elems(message))
end_time = time.perf_counter()
delta_time = end_time - start_time

print(
    "%d ElGamal encryption operates in %.2f seconds\n  = %.5f ballots/sec"
    % (ballots_num*contests_num*selections_num, delta_time, ballots_num / delta_time)
)
