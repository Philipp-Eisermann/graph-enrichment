from neo4j_backend import create_relation
from typing import Callable
import main


''' - - - Weakness Chaining - - - '''


# Takes CVE json object and extracts the CWEs it is linked to
# Returns a list of ints that are CWE Ids
def cwe_from_cve(cve_object):
    if cve_object is None:
        return []

    cwe_list = []

    object_weaknesses = cve_object['cve']['weaknesses']

    for weakness in object_weaknesses:
        cwe_id = weakness["description"][0]["value"]
        if not cwe_id[:3] == "CWE":
            print("Error in the CWE format")
        else:
            cwe_list += [int(cwe_id[4:])]

    return cwe_list


# db is the cwe2 Database Object to which the CWE ids queries are sent
# ids is a list of CVE string ids
def simple_cwe_chains_to_neo4j(db, ids):
    # n_matcher = NodeMatcher(node_graph)
    # r_matcher = RelationshipMatcher(node_graph)$
    for i in ids:
        extracted_weaknesses = extract_cwe_related_weaknesses(i, db)

        if not type(extracted_weaknesses) is dict:
            main.unextracted_cwes += [i]
            continue

        posteriors = extracted_weaknesses["CanPrecede"]

        for posterior in posteriors:
            create_relation(i, posterior, "CanPrecede")

        # Similar Code
        antecedents = extracted_weaknesses["CanFollow"]
        # print(antecedants)
        for antecedent in antecedents:
            create_relation(antecedent, i, "CanFollow")


# Takes an integer cwe_id being a CWE ID
# Returns a dictionary for all related weaknesses organised by relationship type
# Is a helper funciton of above simple_cwe_chains
def extract_cwe_related_weaknesses(cwe_id, db):
    id_dict = {"ChildOf": [], "StartsWith": [], "CanPrecede": [], "CanFollow": [], "RequiredBy": [], "Requires": [],
               "PeerOf": [], "CanAlsoBe": []}
    try:
        related_weaknesses_string = db.get(cwe_id).related_weaknesses
        elements = related_weaknesses_string.split("::")

        for element in elements:
            parts = element.split(":")
            if len(parts) >= 3 and parts[0] == "NATURE":
                nature = parts[1]
                cwe_index = parts.index("CWE ID")
                cwe_id = parts[cwe_index + 1]
                id_dict[nature].append(str(cwe_id))  # TODO: verify
    except Exception as e:
        print(f"Error extracting CWE-{cwe_id}: {e}")
        return None

    return id_dict


''' - - - Attack Pattern Chaining - - - '''


# ids is a list of ids which have to be iteratively queried using
# f_query_function(id, (maybe a string), boolean onlyIds), which returns a list of string ids (could be capecs)
# when onlyIds=True. This function returns a list of string ids which were queried with the parameter function,
# sorted by the order of occurrences during the queries
def query_group(ids, f_query_function: Callable[[str, bool], list], relationship=None):
    # from query_cti_objects import get_capecs_by_cwe
    query_dict = {}
    if not ids:
        return []
    for id_ in ids:
        if not relationship:
            queried_ids = f_query_function(id_, True)
        else:
            queried_ids = f_query_function(id_, relationship, True)

        for queried_id in queried_ids:
            if queried_id in query_dict:
                query_dict[queried_id] += 1
            else:
                query_dict[queried_id] = 1
    # TODO: insert a parameter to limit the size of the ret array?
    return sorted(query_dict, key=query_dict.get, reverse=True)


# CVEs in cve_chain should be entire objects
# f_get_capecs_by_cwe(cwe, bool onlyIds) returns the ids of capecs (onlyIds=True) linked to
# the cwe. Is defined in query_cti_objects
# f_get_related_attack_patterns(capec_id, rel, bool onlyIds) returns the ids of capecs (onlyIds=True)
# referenced by the CAPEC with id capec_id with a rel relationship
def cve_to_capec_chain(cve_chain, f_get_capecs_by_cwe: Callable[[str, bool], list] = None,
                       f_get_related_attack_patterns: Callable[[str, str, bool], list] = None):
    if not f_get_capecs_by_cwe or not f_get_related_attack_patterns:
        return

    # We derive the analogous capec chain from the cve_chain
    current_cwes = cwe_from_cve(cve_chain[0])

    capec_chain = [[] for _ in range(len(cve_chain))]
    capec_composite_chain = [[] for _ in range(len(cve_chain))]
    capec_chain[0] = query_group(current_cwes, f_get_capecs_by_cwe)
    capec_composite_chain[0] = capec_chain[0]

    following_capecs = query_group(capec_chain[0], f_get_related_attack_patterns, "x_capec_can_precede_refs")
    for i in range(1, len(cve_chain)):
        current_cwes = cwe_from_cve(cve_chain[i])
        capecs = query_group(current_cwes, f_get_capecs_by_cwe)

        for capec in capecs:
            if capec in following_capecs:
                capec_composite_chain[i].append(capec)
        capec_chain[i] = capecs

        following_capecs = query_group(capecs, f_get_related_attack_patterns, "x_capec_can_precede_refs")

    # TODO: check canFollow and canPrecede relations between CWEs and CAPECs

    return capec_chain, capec_composite_chain


# TODo
def evaluate_chaining_relationships():
    pass
