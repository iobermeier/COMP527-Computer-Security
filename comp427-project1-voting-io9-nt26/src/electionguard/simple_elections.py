from typing import Optional, Tuple, List, Dict, Final

from electionguard.chaum_pedersen import (
    ConstantChaumPedersenProofKnownSecretKey,
    make_disjunctive_chaum_pedersen_known_nonce,
    make_constant_chaum_pedersen_proof_known_nonce,
    make_constant_chaum_pedersen_proof_known_secret_key,
)
from electionguard.elgamal import elgamal_encrypt, elgamal_add, ElGamalCiphertext
from electionguard.group import ElementModQ, add_q, rand_range_q
from electionguard.logs import log_error
from electionguard.nonces import Nonces
from electionguard.simple_election_data import (
    CiphertextBallot,
    PlaintextBallot,
    PlaintextSelection,
    CiphertextSelection,
    PrivateElectionContext,
    CiphertextSelectionTally,
    AnyElectionContext,
    PlaintextSelectionWithProof,
    PlaintextBallotWithProofs,
)
from electionguard.utils import list_of_option_to_option_list

PLACEHOLDER_NAME: Final[str] = "PLACEHOLDER"


def encrypt_selection(
    context: AnyElectionContext,
    selection: PlaintextSelection,
    seed_nonce: ElementModQ,
) -> Tuple[CiphertextSelection, ElementModQ]:
    """
    Given a selection and the necessary election context, encrypts the selection and returns the
    encrypted selection plus the encryption nonce. If anything goes wrong, `None` is returned.
    """
    elgamal_encryption = elgamal_encrypt(
        selection.choice, seed_nonce, context.get_public_key()
    )
    chaum_pedersen = make_disjunctive_chaum_pedersen_known_nonce(
        elgamal_encryption,
        selection.choice,
        seed_nonce,
        context.get_public_key(),
        seed_nonce,
        seed_nonce,
    )
    if elgamal_encryption is None:
        return None
    else:
        return (
            CiphertextSelection(selection.name, elgamal_encryption, chaum_pedersen),
            seed_nonce,
        )


def encrypt_ballot(
    context: AnyElectionContext,
    ballot: PlaintextBallot,
    seed_nonce: ElementModQ,
    interpret_ballot: bool = True,
) -> Optional[CiphertextBallot]:
    """
    Given a ballot and the necessary election context, encrypts the ballot and returns the
    ciphertext. If anything goes wrong, `None` is returned. If the number of selections is greater
    than allowed for this ballot style, we call that an "overvoted" ballot. There's no valid
    encryption of that, so we normally "interpret" the ballot first, replacing the votes with an
    undervote (i.e., all selections blank). The `interpret_ballot` flag, if false, overrides this
    behavior, allowing for the creation of malformed ballot encryptions.
    """
    list_of_en = []
    ciphertxts=[]
    id = ballot.ballot_id
    if interpret_ballot is True and ballot.is_overvoted(context.max_votes_cast) is True: #flag is true and too many votes
        for x in range(len(ballot.selections)):
            ballot.selections[x]=PlaintextSelection(ballot.selections[x].name,0)
        for y in range(0,context.max_votes_cast):
            ballot.selections.append(PlaintextSelection(PLACEHOLDER_NAME,1))
    else:       #flag is false
        count = 0
        for i in ballot.selections:
            count+=i.choice
        undervote = context.max_votes_cast - count
        if undervote == 0:
            pass
        else:
            for f in range(0,undervote):
                ballot.selections.append(PlaintextSelection(PLACEHOLDER_NAME,1))
    j = 0
    select_nonce = Nonces(seed_nonce)[0:len(ballot.selections)]
    for m in ballot.selections:
        en_sel = encrypt_selection(context, m, select_nonce[j])
        assert en_sel is not None
        ciphertxts.append(en_sel[0].ciphertext)
        list_of_en.append(en_sel[0])
        j=j+1

    add_nonces = add_q(*select_nonce)
    sum = elgamal_add(*ciphertxts)

    known_nonce = make_constant_chaum_pedersen_proof_known_nonce(
        sum,
        context.max_votes_cast,
        add_nonces,
        context.get_public_key(),
        seed_nonce,
        context.hash_header)
    output=CiphertextBallot(id, list_of_en, known_nonce)
    return output

    # TODO: implement this for part 2, be sure to use your encrypt_selection from part 1.


def encrypt_ballots(
    context: AnyElectionContext, ballots: List[PlaintextBallot], seed_nonce: ElementModQ
) -> Optional[List[CiphertextBallot]]:
    """
    Given a list of ballots and the necessary election context, encrypts the ballots and returns
    a list of the ciphertexts. If anything goes wrong, `None` is returned. This also ensures that
    the nonce seeds are unique for each ballot.
    """
    encrypt_nonce = Nonces(seed_nonce)[0:len(ballots)]
    ballot_count=[]
    i = 0
    for x in ballots:
        each_ballot=encrypt_ballot(context,x,encrypt_nonce[i],True)
        assert each_ballot is not None
        ballot_count.append(each_ballot)
        i=i+1
    if ballot_count is None:
        return None
    else:
        return ballot_count

    # TODO: implement this for part 2. Be sure to use your encrypt_ballot.



def validate_encrypted_selection(
    context: AnyElectionContext, selection: CiphertextSelection
) -> bool:
    """Validates the proof on an encrypted selection. Returns true if everything is good."""
    if (
        selection.zero_or_one_proof.is_valid(
            selection.ciphertext, context.get_public_key(), context.hash_header
        )
        is False
    ):
        return True
    else:
        return False


def validate_encrypted_ballot(
    context: AnyElectionContext, ballot: CiphertextBallot
) -> bool:
    """Validates all the proofs on the encrypted ballot. Returns true if everything is good. add logic(validate all the proofs),proof for checking the ballot. x.name not equal place holder"""
    sum_ciphertext = []
    for x in ballot.selections:
        # if x.name == "PLACEHOLDER":
        #    continue
        # else:
        if (
            validate_encrypted_selection(context,x) is True
        ):
            pass
        else:
            return False
        sum_ciphertext.append(x.ciphertext)
    summed = elgamal_add(*sum_ciphertext)
    if ballot.valid_sum_proof.is_valid(summed, context.get_public_key(), context.hash_header) is True:
        return True
    else:
        return False

    #raise RuntimeError("not implemented yet")
    # TODO: implement this for part 2. Be sure to use your validate_encrypted_selection from part 1.


def decrypt_selection(
    context: PrivateElectionContext,
    selection: CiphertextSelection,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextSelectionWithProof]:
    """
    Given an encrypted selection and the necessary crypto context, decrypts it, returning
    the plaintext selection along with a Chaum-Pedersen proof of its correspondence to the
    ciphertext. The optional seed is used for computing the proof.
    """
    decryption = selection.ciphertext.decrypt(context.keypair.secret_key)

    assert decryption is not None
    actual_dec: int = decryption
    plaintext_text = PlaintextSelection(selection.name, actual_dec)
    proof_test = make_constant_chaum_pedersen_proof_known_secret_key(
        selection.ciphertext,
        actual_dec,
        context.keypair.secret_key,
        seed,
        context.hash_header,
    )
    return PlaintextSelectionWithProof(plaintext_text, proof_test)


def decrypt_ballot(
    context: PrivateElectionContext,
    ballot: CiphertextBallot,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextBallotWithProofs]:
    """
    Given an encrypted ballot and the necessary crypto context, decrypts it. Each
    decryption includes the necessary Chaum-Pedersen decryption proofs as well.
    The optional seed is used for the decryption proofs."""
    dec_ballots=[]
    dec_nonce = Nonces(seed)[0:len(ballot.selections)]
    k = 0
    for x in ballot.selections:
        decrypted_ballot=decrypt_selection(context, x, dec_nonce[k])
        if decrypted_ballot is not None:
            dec_ballots.append(decrypted_ballot)
        k = k+1

    return PlaintextBallotWithProofs(ballot.ballot_id,dec_ballots)

    #raise RuntimeError("not implemented yet")
    # TODO: implement this for part 2. Be sure to use your decrypt_selection from part 1.


def validate_decrypted_selection(
    context: AnyElectionContext,
    plaintext: PlaintextSelectionWithProof,
    ciphertext: CiphertextSelection,
) -> bool:
    """
    Validates that the plaintext is provably generated from the ciphertext. Returns true
    if everything is good.
    """
    return plaintext.decryption_proof.is_valid(
        ciphertext.ciphertext, context.get_public_key(), context.hash_header
    )


def validate_decrypted_ballot(
    context: AnyElectionContext,
    plaintext: PlaintextBallotWithProofs,
    ciphertext: CiphertextBallot,
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext. Returns true if everything is good.   """
    bool_list = []

    for x in range(0,len(plaintext.selections)):
        if(validate_decrypted_selection(context,plaintext.selections[x], ciphertext.selections[x]) is True):
            bool_list.append(True)
        else:
            bool_list.append(False)
            return False
    return True
  
    # TODO: implement this for part 2. Be sure to use your validate_decrypted_selection from part 1.
    #raise RuntimeError("not implemented yet")


def tally_encrypted_ballots(
    context: AnyElectionContext, ballots: List[CiphertextBallot]
) -> List[CiphertextSelectionTally]:
    """Homomorphically accumulates the encrypted ballots, returning list of tallies, one per selection."""
    tally_list: Dict[str, List[ElGamalCiphertext]] = {}

    for single_ballot in ballots:
        for selection_list in single_ballot.selections:
            if not selection_list.name == PLACEHOLDER_NAME:
                if selection_list.name not in tally_list:
                    tally_list[selection_list.name]=[selection_list.ciphertext]
                else:
                    tally_list[selection_list.name].append(selection_list.ciphertext)
    return [
        CiphertextSelectionTally(name, elgamal_add(*tally_list[name]))
        for name in tally_list
    ]
    # TODO: implement this for part 2.


def decrypt_tally(
    context: PrivateElectionContext,
    selection: CiphertextSelectionTally,
    seed: ElementModQ = rand_range_q(1),
) -> Optional[PlaintextSelectionWithProof]:
    """Given an encrypted, tallied selection, and the necessary crypto context, decrypts it,
    returning the plaintext selection along with a Chaum-Pedersen proof of its correspondence to the
    ciphertext. The optional seed is used for computing the proof.
    """

    decryption = selection.total.decrypt(context.keypair.secret_key)
    assert decryption is not None

    actual_dec: int = decryption
    obtain_plaintext=PlaintextSelection(selection.name,actual_dec)

    proof_test = make_constant_chaum_pedersen_proof_known_secret_key(
        selection.total,
        actual_dec,
        context.keypair.secret_key,
        seed,
        context.hash_header,
    )
    return PlaintextSelectionWithProof(obtain_plaintext, proof_test)


    #TODO: implement this for part 2.
    #raise RuntimeError("not implemented yet")


def decrypt_tallies(
    context: PrivateElectionContext,
    tally: List[CiphertextSelectionTally],
    seed: ElementModQ = rand_range_q(1),
) -> Optional[List[PlaintextSelectionWithProof]]:
    """Given a list of encrypted tallies and the necessary crypto context, does the
    decryption on the entire list. The optional seed is used for computing the proofs."""
    tallies=[]
    for x in tally:
        ind_dec=decrypt_tally(context,x,seed)
        assert ind_dec is not None
        tallies.append(ind_dec)
    return tallies

    # TODO: implement this for part 2. Be sure to use decrypt_tally.
    #raise RuntimeError("not implemented yet")


def validate_tally(
    context: AnyElectionContext,
    tally_plaintext: PlaintextSelectionWithProof,
    tally_ciphertext: CiphertextSelectionTally,
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext. Returns true if everything is good."""
    return tally_plaintext.decryption_proof.is_valid(
        tally_ciphertext.total, context.get_public_key(), context.hash_header
    )
    # TODO: implement this for part 2. It's similar to, but not the same as validate_decrypted_ballot.
    #raise RuntimeError("not implemented yet")
    #might be correct?


def validate_tallies(
    context: AnyElectionContext,
    tally_plaintext: List[PlaintextSelectionWithProof],
    tally_ciphertext: List[CiphertextSelectionTally],
) -> bool:
    """Validates that the plaintext is provably generated from the ciphertext for every tally. Returns true if
    everything is good."""
    bool_list = []

    for x in range(0,len(tally_plaintext)):
        if(validate_tally(context,tally_plaintext[x], tally_ciphertext[x]) is True):
            bool_list.append(True)
        else:
            bool_list.append(False)
            return False
    return True

    # TODO: implement this for part 2. Be sure to use validate_tally.
    #raise RuntimeError("not implemented yet")


def tally_plaintext_ballots(
    context: AnyElectionContext, ballots: List[PlaintextBallot]
) -> PlaintextBallot:
    """Given a list of ballots, adds their counters and returns a ballot representing the totals of the contest."""

    # You may find this method to be handy. We use it for some unit tests.

    totals: Dict[str, int] = {}
    for b in ballots:
        for s in b.selections:
            if s.name not in totals:
                totals[s.name] = s.choice
            else:
                totals[s.name] += s.choice

    return PlaintextBallot(
        "TOTALS", [PlaintextSelection(name, totals[name]) for name in context.names]
    )
