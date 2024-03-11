from termios import CWERASE
import requests

from py2neo.matching import *

from chaining import create_relation, get_connected_vulnerabilities, get_hosts_same_subnet, get_hosts_other_subnets, create_exploit_relation

from py2neo import Graph, Node, Relationship

from pytrie import StringTrie

import json

# Returns the CVE vulnerability object from NVD with the ID cve_id (ex. "CVE-2019-1010218" )
# Returns a json cve object {'cve': {'id': 'CVE-2019-1010218', ...}
# ! Is an api query which takes 5-15 seconds
def query_nvd_cve(cve_id):
    # NVD API base URL
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Construct the API URL with the CVE ID parameter
    api_url = f"{base_url}?cveId={cve_id}"

    try:
        # Send GET request to NVD API
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for any HTTP errors

        # Parse JSON response
        cve_data = response.json()
        #print(cve_data)

        # Check if the response contains CVE data
        if "vulnerabilities" in cve_data:
            # cve_data["vulnerabilities"] returns a list like [{'cve': {'id': 'CVE-2019-1010218', ...}, ...]
            # As we always only query one object, this list is always of size 1
            return cve_data["vulnerabilities"][0]
        else:
            print("No CVE data found for", cve_id)
            return None

    except requests.exceptions.RequestException as e:
        print("Error querying NVD API:", e)
        return None


# Returns a list of CVE objects that are associated to cpe_id in 
# any semantic by the NVD.
# Will return None if the query fails (404 often occurs)
# ! ! CPE has to be version 2.3
def query_nvd_cpe(cpe_id):
    # pretty similar code to query_nvd_cve()
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Construct the API URL with the CVE ID parameter
    api_url = f"{base_url}?cpeName={cpe_id}"

    try:
        # Send GET request to NVD API
        response = requests.get(api_url)
        response.raise_for_status()  # Raise an exception for any HTTP errors

        # Parse JSON response
        cve_data = response.json()

        # Check if the response contains CVE data
        if "vulnerabilities" in cve_data:
            # cve_data["vulnerabilities"] returns a list like 
            # [{'cve': {'id': 'CVE-2019-1010218', ...}, ...]
            # We want to return the whole list of CVE objects
            return cve_data["vulnerabilities"]
        else:
            print("No CVE data found for", cpe_id)
            return None

    except requests.exceptions.RequestException as e:
        #print("Error querying NVD API:", e)
        return None


# Takes inventory list (CPEs) and finds all CVEs for which the 
# vulnerability conditions are fulfilled
def find_vulnerabilities(inventory):
    # First, we generate the list of CVEs that are linked to each
    # component of our inventory
    linked_cves = [] # each object should be unique!
    ids_set = set()
    # Get the inventory list of cpes
    for cpe_id in inventory:
        queried_cves = query_nvd_cpe(cpe_id)
        if queried_cves is None:
            print(f"Didn't extract vulnerabilities linked to: {cpe_id}")
            continue
        for queried_cve in queried_cves:
            if queried_cve['cve']['id'] not in ids_set:
                # Now check if the inventory is vulnerable to this CVE
                if is_vulnerable_to(queried_cve, inventory): # The links are added to the graph here
                    linked_cves.append(queried_cve)
                    ids_set.add(queried_cve['cve']['id'])
            else:
                print("already in it!")

    print(f"{len(ids_set)} meet the vulnerability conditions ")
    return ids_set, linked_cves


# Inventory is a list list of CPEs in the form of strings
# CVE_object is in json format
# Returns a bool indicating whether the inventory matches the 
# vulnerability conditions of the configs in the CVE. 
# Makes calls to link the CVE to the affected CPEs on Neo4j
def is_vulnerable_to(cve_object, inventory):
    if cve_object is None:
        return

    configurations = cve_object['cve']['configurations']
    pre_post_conditions = get_pre_post_conditions(cve_object['cve']['metrics'])
    cve_to_pass = {'id': cve_object['cve']['id'], 'precondition': pre_post_conditions[0],
                   'accessVector': pre_post_conditions[1], 'postcondition': pre_post_conditions[2]}
    
    for configuration in configurations:     
        # Every configuration has a list of nodes (possibly len 1)
        matched_nodes = [match_node(inventory, n) for n in configuration["nodes"]]
        
        if "operator" not in configuration.keys() or configuration["operator"] == "OR":
            if any(matched_nodes):
                link_items_to_cve(cve_to_pass)
                return True
            #return any(matched_nodes)
        elif configuration["operator"] == "AND":
            if all(matched_nodes):
                link_items_to_cve(cve_to_pass)
                return True
            else: return False


# Helper function to matches a CPE definition
def match_node(inventory, node):
    if node["negate"] == True:
            # All listed components are not vulnerable 
            return False
    if node["operator"] == "OR":
        for cpe_match in node["cpeMatch"]:
            if cpe_match["vulnerable"] == False:
                continue
            if match_cpe_criteria(inventory, cpe_match["criteria"]):
                # We stop looking after the first match. But other combinations
                # of items in the inventory could also match, which will only
                # appear after rerunning the script without the matched components
                return True
        return False
    else: # AND opertator
        for cpe_match in node["cpeMatch"]:
            if cpe_match["vulnerable"] == False:
                continue
            if not match_cpe_criteria(inventory, cpe_match["criteria"]):
                return False
        return True


# Inventory is a list of CPEs that form the device inventory
# cpe is a cpe id which was extracted from "criteria" in a 
# configuration node's "cpeMAtch" attribute
def match_cpe_criteria(inventory, cpe):
    global current_cpes
    # ! This function assumes that there are only * after the first *
    # TODO: Cover all possibilities
    for item in inventory:
        star_index = cpe.find("*")
        if star_index != -1:
            cpe = cpe[:star_index]
        if item.startswith(cpe):
            current_cpes.append(item)
            return True
    return False
    
           
#graph, node_matcher, rel_matcher, node1, node2, rel_type
# TODO: For multi-threading - should be synchronized
def link_items_to_cve(cve):
    global graph, node_matcher, relation_matcher, current_cpes
    #print("linked item")
    for cpe in current_cpes:
        create_relation(graph, node_matcher, relation_matcher, cpe, cve, "vulnerable_to")
    current_cpes = []


# Parses CVSS "metrics" part of a CVE json object
# and returns a tuple (int,'N'/'A'/'L',int) 
def get_pre_post_conditions(metrics):
    # Throughout the parsing of CVSS metrics, we add the pre and
    # postconditions
    precondition = -1 # NONE - 0, USER - 1, ROOT - 2
    attackVector = 0 # (N) Network, (A) Adjacent, (L) Local, "accessVector in 2.0"
    postcondition = 0 # NONE - 0, USER - 1, ROOT - 2

    # Check version, prefer version 2
    if "cvssMetricV2" in metrics.keys():
        metrics = metrics["cvssMetricV2"][0]

        # precondition TODO: revisit 
        if metrics["cvssData"]["authentication"] == "MULTIPLE":
            precondition = 2
        elif metrics["cvssData"]["authentication"] == "SINGLE":
            precondition = 1
        elif metrics["cvssData"]["authentication"] == "NONE":
            precondition = 0

        # We want the first letter of the access vector
        attackVector = metrics["cvssData"]["accessVector"][0]

        # postcondition
        if metrics["obtainUserPrivilege"] == True:
            postcondition = 1
        if metrics["obtainAllPrivilege"] == True:
            postcondition = 2
            

    # CVSS V3
    elif "cvssMetricV31" in metrics.keys() or "cvssMetricV30" in metrics.keys():
        if "cvssMetricV31" in metrics.keys():
            metrics = metrics["cvssMetricV31"][0]["cvssData"]
        else:
            metrics = metrics["cvssMetricV30"][0]["cvssData"]

        # precondition
        if metrics["privilegesRequired"] == "HIGH":
            precondition = 2
        elif metrics["privilegesRequired"] == "LOW":
            precondition = 1
        elif metrics["privilegesRequired"] == "NONE":
            precondition = 0

        # Discard physical attacks
        if metrics["attackVector"][0] != 'P':
            attackVector = metrics["attackVector"][0]

        # postcondition
        if metrics["scope"] == "UNCHANGED":
            if (metrics["confidentialityImpact"] == "HIGH" or metrics["confidentialityImpact"] == "LOW") and \
                (metrics["integrityImpact"] == "HIGH" or metrics["integrityImpact"] == "LOW") and \
                (metrics["availabilityImpact"] == "HIGH" or metrics["availabilityImpact"] == "LOW"):
                postcondition = 1
        else:
            if metrics["confidentialityImpact"] == "HIGH" and metrics["integrityImpact"] == "HIGH" and \
            metrics["availabilityImpact"] == "HIGH":
                postcondition = 2
    
    else:
        print(f"Could not find CVSS data, available keys are {metrics.keys()}")
    
    return precondition, attackVector, postcondition


# Adds all outgoing attack paths outgoing start_node 
# - The visited_nodes variable has to be initialized before the
# first call of the function (correct ids and ints to -1)
# - The graph needs: correct connections between host-nodes,
# vulnerabilities need to have their pre_post_condition attribute initialized
# start_node is a string id, privilege an int
def draw_attack_paths(start_node, privilege):
    global graph, node_matcher, relation_matcher, visited_nodes

    print("On host " + start_node + " with priv " + str(privilege))

    # NONE - 0, USER - 1, ROOT - 2
    # Check if the start node belongs to the (node/privilege) we already visited
    if privilege <= 0:
        return
    if start_node in visited_nodes.keys() and visited_nodes[start_node] >= privilege:
        return
    
    nodes_to_visit = {}
    
    # First try to exploit the current node to get root permissions
    if privilege == 1: 
        connected_vulnerabilities = get_connected_vulnerabilities(graph, node_matcher, start_node)
        for vulnerability in connected_vulnerabilities:
            # We don't need to check the accessVector since we
            # are already on the machine

            if vulnerability["precondition"] <= privilege:
                #create_relation(graph, node_matcher, relation_matcher, start_node, vulnerability, "exploits")
                create_exploit_relation(graph, node_matcher, relation_matcher, start_node, start_node, vulnerability)

                if start_node not in nodes_to_visit.keys():
                    nodes_to_visit[start_node] = vulnerability["postcondition"]    
                elif nodes_to_visit[start_node] <= vulnerability["postcondition"]:
                    nodes_to_visit[start_node] = vulnerability["postcondition"]
    
    connected_nodes = get_hosts_same_subnet(graph, start_node)
    print("nodes: " + str(connected_nodes))
    if privilege == 2:
        # Then, try to exploit the machines in the same subnet
        for connected_node in connected_nodes[0]:
            #print(connected_node)
            connected_vulnerabilities = get_connected_vulnerabilities(graph, node_matcher, connected_node['id'])
            print("vulns: " + str(connected_vulnerabilities))
            for vulnerability in connected_vulnerabilities:
                # Check access vector
                if vulnerability["accessVector"] == "A" or vulnerability["accessVector"] == "N":
                    if vulnerability["precondition"] == 0:
                        #create_relation(graph, node_matcher, relation_matcher, start_node, vulnerability, "exploits")
                        print(f"Create rel between {start_node} and {connected_node}, cve {vulnerability}")
                        create_exploit_relation(graph, node_matcher, relation_matcher, start_node, connected_node, vulnerability)
                        
                        if connected_node['id'] not in nodes_to_visit.keys():
                            nodes_to_visit[connected_node['id']] = vulnerability["postcondition"]
                        
        
        # Lastly, try to exploit the machines in connected subnets
        connected_nodes = get_hosts_other_subnets(graph, start_node)
        for connected_node in connected_nodes:
            connected_vulnerabilities = get_connected_vulnerabilities(graph, node_matcher, connected_node)
            for vulnerability in connected_vulnerabilities:
                # Check access vector
                if vulnerability["accessVector"] == "N":
                    if vulnerability["precondition"] == 0:
                        #create_relation(graph, node_matcher, relation_matcher, start_node, vulnerability, "exploits")
                        print(f"Create rel between {start_node} and {connected_node}")
                        create_exploit_relation(graph, node_matcher, relation_matcher, start_node, connected_node, vulnerability)
                        
                        if connected_node['id'] not in nodes_to_visit.keys():
                            nodes_to_visit[connected_node['id']] = vulnerability["postcondition"]
                    

    # Add the start node to the visited nodes
    visited_nodes[start_node] = privilege

    print(nodes_to_visit)

    for node, postcondition in nodes_to_visit.items():
    # We can now continue from the current node with the new privilege 
        draw_attack_paths(node, postcondition)


        
# UPLOAD CWE Chains to Neo4J server
neo4j_uri = "bolt://localhost:7687"  # NEO4J URI
neo4j_user = "phil"        # NEO4J USERNAME
neo4j_password = "adminphil"    # NEO4J PASSWORD

# GLOBAL VARS - - -
graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)

visited_nodes = StringTrie() # contains mappings hostname:privilege_level 

# ! if threaded extension: each thread needs its own current_cpes var, cves to analyse are splitted between threads
# This global array stores the CPEs that are involved for the current cve iteration
current_cpes = []

# Can be changed into a parsing function
def config_example():
    inventory1 = ["cpe:2.3:a:ati:catalyst_driver:1:2:*:*:*:*:*:*",
                 #"cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*",
                 "cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*"]
    inventory2 = ["cpe:2.3:a:skype_technologies:skype:3.5:*:*:*:*:*:*:*"]
    inventory3 = ["cpe:2.3:a:microsoft:internet_explorer:1:2:3:4:5:*:*:*",
                  "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*"]
    
    #"cpe:2.3:o:apple:mac_os_x:10.1.3:*:*:*:*:*:*:*"
    # Declare Hosts with respective inventories
    host1 = Node(id="host1")
    for item in inventory1:
        create_relation(graph, node_matcher, relation_matcher, host1, Node(id=item), "has")
    find_vulnerabilities(inventory1)

    host2 = Node(id="host2")
    for item in inventory2:
        create_relation(graph, node_matcher, relation_matcher, host2, Node(id=item), "has")
    find_vulnerabilities(inventory2)

    host3 = Node(id="host3")
    for item in inventory3:
        create_relation(graph, node_matcher, relation_matcher, host3, Node(id=item), "has")
    find_vulnerabilities(inventory3)

    router1 = Node(id="router1")
    create_relation(graph, node_matcher, relation_matcher, router1, host1, "subnet1")
    create_relation(graph, node_matcher, relation_matcher, router1, host2, "subnet1")
    #create_relation(graph, node_matcher, relation_matcher, router1, host3, "subnet2")

if __name__ == "__main__":
    config_obj = [{"operator":"AND","nodes":
	[{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:8:*:*:*:*:*:*:*","matchCriteriaId":"A52E757F-9B41-43B4-9D67-3FEDACA71283"},
		{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:8.0.6001:*:*:*:*:*:*:*","matchCriteriaId":"5F709B61-F64B-4E8F-80BB-4944485B6125"}
		]
	},
	{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_7:-:*:*:*:*:*:*:*","matchCriteriaId":"E33796DB-4523-4F04-B564-ADF030553D51"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*","matchCriteriaId":"4D3B5E4F-56A6-4696-BBB4-19DF3613D020"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*","matchCriteriaId":"B8A32637-65EC-42C4-A892-0E599562527C"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*","matchCriteriaId":"FFAC3F90-77BF-4F56-A89B-8A3D2D1FC6D6"}
		]
	}]
},
{"operator":"AND","nodes":
	[{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:7:*:*:*:*:*:*:*","matchCriteriaId":"1A33FA7F-BB2A-4C66-B608-72997A2BD1DB"},
		{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:7.0:*:*:*:*:*:*:*","matchCriteriaId":"6BC71FD8-D385-4507-BD14-B75FDD4C79E6"},
		{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:7.00.6000.16441:*:*:*:*:*:*:*","matchCriteriaId":"53D75496-8594-44DB-B5C4-EA3CABD6551A"}
		]
	},
	{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*","matchCriteriaId":"4D3B5E4F-56A6-4696-BBB4-19DF3613D020"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_vista:*:sp2:*:*:*:*:*:*","matchCriteriaId":"0A0D2704-C058-420B-B368-372D1129E914"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*","matchCriteriaId":"FFAC3F90-77BF-4F56-A89B-8A3D2D1FC6D6"}
		]
	}]
},
{"nodes":
	[{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:5.01:sp4:*:*:*:*:*:*","matchCriteriaId":"F3F2A51E-2675-4993-B9C2-F2D176A92857"},
		{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:*:*:*:*:*:*:*","matchCriteriaId":"693D3C1C-E3E4-49DB-9A13-44ADDFF82507"},
		{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:sp1:*:*:*:*:*:*","matchCriteriaId":"D47247A3-7CD7-4D67-9D9B-A94A504DA1BE"}
		]
	}]
},
{"nodes":
	[{"operator":"OR","negate":False,"cpeMatch":
		[{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_2000:*:sp4:*:*:*:*:*:*","matchCriteriaId":"83E7C4A0-78CF-4B56-82BF-EC932BDD8ADF"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_2003_server:*:sp2:*:*:*:*:*:*","matchCriteriaId":"2978BF86-5A1A-438E-B81F-F360D0E30C9C"},
		{"vulnerable":True,"criteria":"cpe:2.3:o:microsoft:windows_xp:-:sp2:x64:*:*:*:*:*","matchCriteriaId":"FFAC3F90-77BF-4F56-A89B-8A3D2D1FC6D6"}
		]
	}]
}]
    
    cve_obj = {'cve': {'id': 'CVE-2019-1010218', 'sourceIdentifier': 'josh@bress.net', 'published': '2019-07-22T18:15:10.917', 'lastModified': '2020-09-30T13:40:18.163', 'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': "Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet."}, {'lang': 'es', 'value': 'El servidor web de Cherokee más reciente de Cherokee Webserver Hasta Versión 1.2.103 (estable actual) está afectado por: Desbordamiento de Búfer - CWE-120. El impacto es: Bloqueo. El componente es: Comando cherokee principal. El vector de ataque es: Sobrescribir argv[0] en una longitud no sana con execl. La versión corregida es: no hay ninguna solución aún.'}], 'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'HIGH', 'baseScore': 7.5, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 3.9, 'impactScore': 3.6}], 'cvssMetricV2': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '2.0', 'vectorString': 'AV:N/AC:L/Au:N/C:N/I:N/A:P', 'accessVector': 'NETWORK', 'accessComplexity': 'LOW', 'authentication': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'PARTIAL', 'baseScore': 5.0}, 'baseSeverity': 'MEDIUM', 'exploitabilityScore': 10.0, 'impactScore': 2.9, 'acInsufInfo': False, 'obtainAllPrivilege': False, 'obtainUserPrivilege': False, 'obtainOtherPrivilege': False, 'userInteractionRequired': False}]}, 'weaknesses': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-787'}]}, {'source': 'josh@bress.net', 'type': 'Secondary', 'description': [{'lang': 'en', 'value': 'CWE-120'}]}], 'configurations': config_obj, 'references': [{'url': 'https://i.imgur.com/PWCCyir.png', 'source': 'josh@bress.net', 'tags': ['Exploit', 'Third Party Advisory']}]}}
    node_obj = {"operator":"OR","negate":False,"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:5.01:sp4:*:*:*:*:*:*","matchCriteriaId":"F3F2A51E-2675-4993-B9C2-F2D176A92857"},{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:*:*:*:*:*:*:*","matchCriteriaId":"693D3C1C-E3E4-49DB-9A13-44ADDFF82507"},{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:sp1:*:*:*:*:*:*","matchCriteriaId":"D47247A3-7CD7-4D67-9D9B-A94A504DA1BE"}]}
    cpe = "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*"
    
    config_example()



    #lol = get_connected_vulnerabilities(graph, node_matcher, "host1")[0]

    #create_exploit_relation(graph, node_matcher, relation_matcher, "host1", "host2", lol)


    #get_hosts_other_subnets(graph, "host3")

    #draw_attack_paths("host2", 1)
    #print(visited_nodes)
    
    #trg_list = list(node_matcher.match(id="host1"))
    #src_list = list(node_matcher.match(id="host2"))
    #relationship_instance = Relationship(src_list[0], "exploits", trg_list[0], id="host2-exploits(CVE-2005-2127)>host1", cve="CVE-2005-2127",
    #                                     precondition=0,postcondition=1,
    #                                     attackVector="N")
    #graph.create(relationship_instance)

    #print(get_connected_vulnerabilities(graph, node_matcher, "host2"))
        
    #print(get_pre_post_conditions(cve_obj["cve"]["metrics"]))

    

