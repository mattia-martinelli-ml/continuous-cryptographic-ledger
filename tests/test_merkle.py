from merkle_proof.merkle import build_merkle_root, inclusion_proof, verify_merkle_proof, sha256_hash


def test_sha256_hash_consistency():
    assert sha256_hash("hello").hex() == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"


def test_build_merkle_root_single_leaf():
    leaf = sha256_hash("event")
    assert build_merkle_root([leaf]) == leaf


def test_build_merkle_root_pair():
    leaves = [sha256_hash("a"), sha256_hash("b")]
    root = build_merkle_root(leaves)
    assert isinstance(root, bytes)
    assert len(root) == 32


def test_inclusion_proof_and_verify():
    leaves = [sha256_hash("a"), sha256_hash("b"), sha256_hash("c")]
    index = 1
    proof = inclusion_proof(index, leaves)
    root = build_merkle_root(leaves)
    assert verify_merkle_proof(leaves[index], proof, root)
