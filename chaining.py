from neo4j_backend import create_relation


# graph is the Neo4j Graph object to which the chains should be added
# db is the cwe2 Database Object to which the CWE ids queries are sent
def simple_chains_to_neo4j(db, ids):
    # n_matcher = NodeMatcher(node_graph)
    # r_matcher = RelationshipMatcher(node_graph)$
    from main import unextracted_cwes
    
    for i in ids:
        extracted_weaknesses = extract_cwe_related_weaknesses(i, db)

        if not type(extracted_weaknesses) is dict:
            unextracted_cwes += [i]
            continue

        posteriors = extracted_weaknesses["CanPrecede"]

        for posterior in posteriors:
            create_relation(i, posterior, "CanPrecede")

        # Similar Code
        antecedents = extracted_weaknesses["CanFollow"]
        # print(antecedants)
        for antecedent in antecedents:
            create_relation(antecedent, i, "CanFollow")


# Takes CVE json object and extracts the CWEs it is linked to
# Returns a list of ints that are CWE Ids
# The library used to get the CWE is unstable
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


# Takes an integer being a CWE ID
# Returns a dictionary for all related weaknesses organised by relationship type
# Is a helper funciton of chain_cwe
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
                id_dict[nature].append(str(cwe_id))  # TODO: IS THIS GOOD?
    except Exception as e:
        print(f"Error extracting CWE-{cwe_id}: {e}")
        return None

    return id_dict

