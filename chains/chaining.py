from cwe2.database import Database

from py2neo import Graph, Node, Relationship

# Checks if nodes and relation (node1->node2) already exists and only 
# adds to graph (node4j) what is lacking
# node1, node2 are int ids of nodes to be added
# rel_type is a string holding the type of the relation
def create_relation(graph, node_matcher, rel_matcher, node1, node2, rel_type):
    global created_nodes
    src_list = list(node_matcher.match(id=node1))
    trg_list = list(node_matcher.match(id=node2))
    node1_instance = Node(str(node1), id=node1)
    node2_instance = Node(str(node2), id=node2)

    # Does the source node1 already exist?
    if len(src_list) == 0:
        graph.create(node1_instance)
        created_nodes += [node1]

    # Does the target node2 already exist?
    if len(trg_list) == 0:
        graph.create(node2_instance)
        created_nodes += [node2]
    
    # Do src and target node exist, only once each? 
    if len(src_list) > 1 or len(trg_list) > 1:
        print(f"src_list: {src_list}, trg_list: {trg_list}")
        print("Warning: source and/or target nodes are not unique!")
        return

    # Does the relationship already exist?
    rel_id = f"{node1}>{node2}"
    if len(list(rel_matcher.match(id=rel_id))) == 0:
        if len(src_list) == 1:
            node1_instance = src_list[0]
        if len(trg_list) == 1:
            node2_instance = trg_list[0]
            
        relationship_instance = Relationship(node1_instance, rel_type, node2_instance, id=rel_id)
        graph.create(relationship_instance)
        print(f"Created {rel_id}")


# graph is the Neo4j Graph object to which the chains should be added
# db is the cwe2 Database Object to which the queries are sent
def simple_chains_to_neo4j(graph, db, ids):  
    global unextracted_cwes
    n_matcher = NodeMatcher(graph)
    r_matcher = RelationshipMatcher(graph)

    for i in ids:
        extracted_weaknesses = extract_cwe_related_weaknesses(i, db)

        if not type(extracted_weaknesses) is dict:
            unextracted_cwes += [i]
            continue

        posteriors = extracted_weaknesses["CanPrecede"]

        for posterior in posteriors:
            create_relation(graph, n_matcher, r_matcher, i, posterior, "CanPrecede")
        
        # Similar Code 
        antecedants = extracted_weaknesses["CanFollow"]
        print(antecedants)
        for antecedant in antecedants:
            create_relation(graph, n_matcher, r_matcher, antecedant, i, "CanFollow")
            

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


# Global vars
unextracted_cwes = [] # CWEs for which the query was unsuccessful
created_nodes = [] # nodes that were added to neo4j

if __name__ == "__main__":

    # UPLOAD CWE Chains to Neo4J server
    neo4j_uri = "bolt://localhost:7687"  # NEO4J URI
    neo4j_user = "phil"        # NEO4J USERNAME
    neo4j_password = "adminphil"    # NEO4J PASSWORD

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))

    db = Database()
    
    simple_chains_to_neo4j(graph, db, range(0,600))

    print(f"{len(unextracted_cwes)} CWEs could not be extracted.")
    print(f"The following Nodes were added: {created_nodes}")