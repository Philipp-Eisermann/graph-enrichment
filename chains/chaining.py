from cwe2.database import Database

from py2neo import Graph, Node, Relationship

# Takes either a str id or a dictionnary
# Following node types are defined for this network model:
# host, router, cpe, cve
def get_node_label(node):
    if isinstance(node, dict):
        node = str(node["id"]).lower()
    if node.startswith("host"):
        return "host"
    if node.startswith("router"):
        return "router"
    else:
        return node[:3] # either CVE or CPE


# Checks if nodes and relation (node1->node2) already exists and only 
# adds to graph (node4j) what is lacking
# node1, node2 are ids or dictionnaries (need to have "id" field!) of nodes to be added
# rel_type is a string holding the type of the relation
def create_relation(graph, node_matcher, rel_matcher, node1, node2, rel_type):
    global created_nodes
    
    if isinstance(node1, dict):
        node1_instance = Node(get_node_label(node1), **node1)
        src_list = list(node_matcher.match(id=node1["id"]))
        node1_id = node1["id"]
    else:
        node1_instance = Node(get_node_label(node1), id=node1)
        src_list = list(node_matcher.match(id=node1))
        node1_id = node1
    if isinstance(node2, dict):
        node2_instance = Node(get_node_label(node2), **node2)
        trg_list = list(node_matcher.match(id=node2["id"]))
        node2_id = node2["id"]
    else:
        node2_instance = Node(get_node_label(node2), id=node2)
        trg_list = list(node_matcher.match(id=node2))
        node2_id = node2

    # Does the source node1 already exist?
    if len(src_list) == 0:
        graph.create(node1_instance)
        if isinstance(node1, dict):
            created_nodes += [node1["id"]]
        else:
            created_nodes += [node1]

    # Does the target node2 already exist?
    if len(trg_list) == 0:
        graph.create(node2_instance)
        if isinstance(node2, dict):
            created_nodes +=[node2["id"]]
        else:
            created_nodes += [node2]    
    
    # Do src and target node exist, only once each? 
    if len(src_list) > 1 or len(trg_list) > 1:
        print(f"src_list: {src_list}, trg_list: {trg_list}")
        print("Warning: source and/or target nodes are not unique!")
        return

    # Does the relationship already exist?
    rel_id = f"{node1_id}-{rel_type}>{node2_id}"
    if len(list(rel_matcher.match(id=rel_id))) == 0:
        if len(src_list) == 1:
            node1_instance = src_list[0]
        if len(trg_list) == 1:
            node2_instance = trg_list[0]
            
        relationship_instance = Relationship(node1_instance, rel_type, node2_instance, id=rel_id)
        graph.create(relationship_instance)
        #print(f"Created {rel_id}")


# host1 (src) and host2 (trg) can be ids or dicts, but have to be modelled 
# in the graph already! (done in the init step using create_relation())
# exploited_cve is a dict
def create_exploit_relation(graph, node_matcher, rel_matcher, host1, host2, exploited_cve):
    if isinstance(host1, dict):
        src_list = list(node_matcher.match(id=host1["id"]))
        host1_id = host1["id"]
    else:
        src_list = list(node_matcher.match(id=host1))
        host1_id = host1

    if isinstance(host2, dict):
        trg_list = list(node_matcher.match(id=host2["id"]))
        host2_id = host2["id"]
    else:
        trg_list = list(node_matcher.match(id=host2))
        host2_id = host2

    rel_id = f"{host1_id}-exploits({exploited_cve['id']})>{host2_id}"
    
    # Check if relation exists already
    if not len(list(rel_matcher.match(id=rel_id))) == 0:
        return

    if len(src_list) != 1 or len(trg_list) != 1:
        print(f"Relation creation issue! src_list: {src_list}, trg_list: {trg_list}")
        return

    # Design choice explanation: we decide to not link the cpes in the exploitability path
    # for a better overview. Does require looking up responsible cves for each exploit
    relationship_instance = Relationship(src_list[0], exploited_cve["id"], trg_list[0], id=rel_id, cve=exploited_cve["id"],
                                         precondition=exploited_cve["precondition"],postcondition=exploited_cve["postcondition"],
                                         attackVector=exploited_cve["accessVector"])
    graph.create(relationship_instance)


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
        #print(antecedants)
        for antecedant in antecedants:
            create_relation(graph, n_matcher, r_matcher, antecedant, i, "CanFollow")
            

# Takes a host node id and returns a list of dictionnaries
# of all CVE Node() objects that are linked to it (via CPEs)
def get_connected_vulnerabilities(graph, node_matcher, node_id):
    ret_cves = []
    node = node_matcher.match(id=node_id)
    if node:
        query = f"MATCH (n)-[:has]->(related_node) WHERE n.id = \"{node_id}\" RETURN related_node"
        results = graph.run(query)
        cpe_nodes = [result["related_node"] for result in results]
        # TODO: check if CPEs?
        for cpe_node in cpe_nodes:
            results = graph.run(f"MATCH (n)-[:vulnerable_to]->(related_node) WHERE n.id = \"{cpe_node.get('id')}\" RETURN related_node")
            cve_nodes = [result["related_node"] for result in results]
            # TODO: check if CVEs?
            for cve_node in cve_nodes:
                if cve_node not in ret_cves: ret_cves.append(cve_node)
    
    return ret_cves


# Takes a host node id and returns a list of node ids of the
# hosts that are reachable through layer 2
def get_hosts_same_subnet(graph, node_id):
    ret_nodes = []
    
    query = f"MATCH (source)-[r]->(target) WHERE source:router AND target.id = \"{node_id}\" RETURN source.id"
    #query = f"MATCH (n) RETURN n"
    routers = graph.run(query) # contains a list of the router names

    router = routers.evaluate()
    
    while router is not None:
        print(router)
        # Query to get the subnet of the router 
        query = f"MATCH (source)-[r]->(target) WHERE source.id = \"{str(router)}\" AND target.id = \"{node_id}\" RETURN type(r)"
        subnet = graph.run(query).evaluate() # should be unique

        # Get all nodes connected to router which are in the same subnet
        query = f"MATCH (source)-[r:{subnet}]->(target) WHERE source.id = \"{str(router)}\" AND target.id <> \"{node_id}\" RETURN target"
        results = graph.run(query)
        for result in results:
            ret_nodes.append(result)

        router = routers.evaluate()
    
    print(ret_nodes)
    return ret_nodes

# Takes a host node id and returns a list of node ids of the 
# hosts that are reachable through layer 3
def get_hosts_other_subnets(graph, node_id):
    ret_nodes = []
    
    query = f"MATCH (source)-[r]->(target) WHERE source:router AND target.id = \"{node_id}\" RETURN source.id"
    routers = graph.run(query) # contains a list of the router names

    router = routers.evaluate()
    
    while router is not None:
        # Query to get the subnet of the router 
        query = f"MATCH (source)-[r]->(target) WHERE source.id = \"{str(router)}\" AND target.id = \"{node_id}\" RETURN type(r)"
        subnet = graph.run(query).evaluate() # must be unique

        query = f"MATCH (n)-[r]->() WHERE n.id = \"{str(router)}\" RETURN DISTINCT type(r) AS relationship_types"
        iterate_subnets = graph.run(query)
        current_subnet = iterate_subnets.evaluate()
        subnets = [] # will be fed with the sames of the other subnets
        while current_subnet is not None:
            if subnet != current_subnet:
                subnets.append(current_subnet)
            current_subnet = iterate_subnets.evaluate()

        for subnet in subnets:
            # Get all nodes connected to router which are in the other subnet
            query = f"MATCH (source)-[r:{subnet}]->(target) WHERE source.id = \"{str(router)}\" RETURN target"
            
            results = graph.run(query)
            result = results.evaluate()
            while result is not None:
                ret_nodes.append(result)
                result = results.evaluate()
        
        router = routers.evaluate()

    return ret_nodes


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
    id_dict = {"ChildOf": [], "StartsWith": [], "CanPrecede": [], "CanFollow": [], "RequiredBy": [], "Requires": [], "PeerOf": [], "CanAlsoBe": []}
    try: 
        related_weaknesses_string = db.get(cwe_id).related_weaknesses
        elements = related_weaknesses_string.split("::")

        for element in elements:
            parts = element.split(":")
            if len(parts) >= 3 and parts[0] == "NATURE":
                nature = parts[1]
                cwe_index = parts.index("CWE ID")
                cwe_id = parts[cwe_index + 1]
                id_dict[nature].append(str(cwe_id)) # TODO: IS THIS GOOD?
    except Exception as e:
        print(f"Error extracting CWE-{cwe_id}: {e}")
        return None

    return id_dict

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