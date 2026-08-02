import hashlib

from core.models import TBSCertificateLogEntry, MerkleNode, InclusionProof

def serialize_log_entry(entry: TBSCertificateLogEntry) -> bytes:
    
    parts = [
        str(entry.version),
        entry.issuer,
        entry.subject,
        entry.not_before.isoformat(),
        entry.not_after.isoformat(),
        entry.subject_public_key_info_hash.hex(),  
        str(sorted(entry.extensions.items())),     
    ]
    serialized_string = "|".join(parts)
    return serialized_string.encode("utf-8")

def hash_log_entry(entry: TBSCertificateLogEntry) -> bytes:
    
    serialized = serialize_log_entry(entry)
    return hashlib.sha256(serialized).digest()

def create_leaf(entry: TBSCertificateLogEntry, site_domain: str) -> MerkleNode:
    
    leaf_hash = hash_log_entry(entry)
    return MerkleNode(
        hash_value=leaf_hash,
        is_leaf=True,
        left=None,
        right=None,
        site_id=site_domain,
    )
    
def create_all_leaves(sites: list) -> list[MerkleNode]:
    
    leaves = []
    for site in sites:
        if site.log_entry is None:
            raise ValueError(
                f"Le site '{site.domain}' n'a pas encore de TBSCertificateLogEntry."
            )
        leaf = create_leaf(site.log_entry, site.domain)
        leaves.append(leaf)
    return leaves

def _combine_nodes(left: MerkleNode, right: MerkleNode) -> MerkleNode:
    
    combined = left.hash_value + right.hash_value
    parent_hash = hashlib.sha256(combined).digest()

    return MerkleNode(
        hash_value=parent_hash,
        is_leaf=False,
        left=left,
        right=right,
        site_id=None,  
    )

def build_merkle_tree(leaves: list[MerkleNode]) -> MerkleNode:
   
    if not leaves:
        raise ValueError("Impossible de construire un arbre sans aucune feuille.")

    if len(leaves) == 1:
      
        return leaves[0]

    current_level = leaves

    while len(current_level) > 1:
        next_level = []

        i = 0
        while i < len(current_level):
            if i + 1 < len(current_level):
                
                parent = _combine_nodes(current_level[i], current_level[i + 1])
                next_level.append(parent)
                i += 2
            else:
               
                next_level.append(current_level[i])
                i += 1

        current_level = next_level

    return current_level[0]  
def _find_path_and_siblings(node: MerkleNode, target_site_id: str, path: list) -> bool:
    
    if node.is_leaf:
        return node.site_id == target_site_id

    found_left = _find_path_and_siblings(node.left, target_site_id, path)
    if found_left:
        
        path.append((node.right.hash_value, "RIGHT"))
        return True

    found_right = _find_path_and_siblings(node.right, target_site_id, path)
    if found_right:
       
        path.append((node.left.hash_value, "LEFT"))
        return True

    return False


def _find_leaf_hash(node: MerkleNode, target_site_id: str) -> bytes:

    if node.is_leaf:
        if node.site_id == target_site_id:
            return node.hash_value
        return None

    left_result = _find_leaf_hash(node.left, target_site_id)
    if left_result is not None:
        return left_result
    return _find_leaf_hash(node.right, target_site_id)


def generate_inclusion_proof(root: MerkleNode, site_id: str, tree_size: int) -> InclusionProof:
    
    if root.is_leaf:
        
        if root.site_id != site_id:
            raise ValueError(f"Site '{site_id}' introuvable dans l'arbre.")
        return InclusionProof(
            leaf_index=0,
            leaf_hash=root.hash_value,
            sibling_hashes=[],
            tree_size=tree_size,
        )

    sibling_hashes = []
    found = _find_path_and_siblings(root, site_id, sibling_hashes)

    if not found:
        raise ValueError(f"Site '{site_id}' introuvable dans l'arbre.")

    leaf_hash = _find_leaf_hash(root, site_id)

    return InclusionProof(
        leaf_index=-1,
        leaf_hash=leaf_hash,
        sibling_hashes=sibling_hashes,
        tree_size=tree_size,
    )

def verify_inclusion_proof(proof: InclusionProof, expected_root_hash: bytes) -> bool:
    
    current_hash = proof.leaf_hash

    for sibling_hash, position in proof.sibling_hashes:
        if position == "RIGHT":
            combined = current_hash + sibling_hash
        else:  # "LEFT"
            combined = sibling_hash + current_hash
        current_hash = hashlib.sha256(combined).digest()

    return current_hash == expected_root_hash