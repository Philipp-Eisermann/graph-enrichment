import json

from py2neo import Graph, Node, NodeMatcher, RelationshipMatcher

from pytrie import StringTrie

import chaining
import query_nvd
import neo4j_backend
import ag_gen

with open("config.json", 'r') as file:
    config_content = file.read()

config_content = json.loads(config_content)

neo4j_uri = config_content["neo4j_uri"]
neo4j_user = config_content["neo4j_user"]
neo4j_password = config_content["neo4j_password"]

# GLOBAL VARS - - -

graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)

visited_nodes = StringTrie()  # contains mappings hostname:privilege_level

# ! if threaded extension: each thread needs its own current_cpes var, cves to analyse are splitted between threads
# This global array stores the CPEs that are involved for the current cve iteration
current_cpes = []

# Global vars
unextracted_cwes = []  # CWEs for which the query was unsuccessful
created_nodes = []  # nodes that were added to neo4j

# CONFIGS
DEBUG = False
# - - - - - -


# Can be changed into a parsing function
def config_example():
    inventory1 = ["cpe:2.3:a:ati:catalyst_driver:1:2:*:*:*:*:*:*",
                  # "cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*",
                  "cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*"]
    inventory2 = ["cpe:2.3:a:skype_technologies:skype:3.5:*:*:*:*:*:*:*"]
    inventory3 = ["cpe:2.3:a:microsoft:internet_explorer:1:2:3:4:5:*:*:*",
                  "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*"]

    # "cpe:2.3:o:apple:mac_os_x:10.1.3:*:*:*:*:*:*:*"
    # Declare Hosts with respective inventories
    host1 = Node(id="host1")
    for item in inventory1:
        neo4j_backend.create_relation(graph, node_matcher, relation_matcher, host1, Node(id=item), "has")
    ag_gen.find_vulnerabilities(inventory1)

    host2 = Node(id="host2")
    for item in inventory2:
        neo4j_backend.create_relation(graph, node_matcher, relation_matcher, host2, Node(id=item), "has")
    ag_gen.find_vulnerabilities(inventory2)

    host3 = Node(id="host3")
    for item in inventory3:
        neo4j_backend.create_relation(graph, node_matcher, relation_matcher, host3, Node(id=item), "has")
    ag_gen.find_vulnerabilities(inventory3)

    router1 = Node(id="router1")
    neo4j_backend.create_relation(graph, node_matcher, relation_matcher, router1, host1, "subnet1")
    neo4j_backend.create_relation(graph, node_matcher, relation_matcher, router1, host2, "subnet1")
    neo4j_backend.create_relation(graph, node_matcher, relation_matcher, router1, host3, "subnet2")


if __name__ == "__main__":
    # This sets up an example environment with 3 hosts and 1 router
    config_example()

    # draw_attack_paths("host2", 1)
    # When wanting to regenerate the AG starting from a different host, make
    # sure to have deleted all exploits relationships (starting with CVE):
    # match ()-[r]->() where r.precondition IN [0,1,2] delete rs
    