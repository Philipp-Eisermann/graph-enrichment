
from query_nvd import query_nvd_cpe


# Takes inventory list (CPEs) and finds all CVEs for which the
# vulnerability conditions are fulfilled
def find_vulnerabilities(inventory):
    from main import DEBUG
    print(f"Searching vulnerabilities in items of: {inventory}")
    # First, we generate the list of CVEs that are linked to each
    # component of our inventory
    linked_cves = []  # each object should be unique!
    ids_set = set()
    # Get the inventory list of cpes
    for cpe_id in inventory:
        queried_cves = query_nvd_cpe(cpe_id)
        if queried_cves is None:
            if DEBUG:
                print(f"Didn't extract vulnerabilities linked to: {cpe_id}")
            continue
        for queried_cve in queried_cves:
            if queried_cve['cve']['id'] not in ids_set:
                # Now check if the inventory is vulnerable to this CVE
                if is_vulnerable_to(queried_cve, inventory):  # The links are added to the graph here
                    linked_cves.append(queried_cve)
                    ids_set.add(queried_cve['cve']['id'])
            # else:
                # print("already in it!")

    print(f"- {len(ids_set)} meet the vulnerability conditions ")
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
            # return any(matched_nodes)
        elif configuration["operator"] == "AND":
            if all(matched_nodes):
                link_items_to_cve(cve_to_pass)
                return True
            else:
                return False


# Helper function to matches a CPE definition
def match_node(inventory, node):
    if node["negate"]:
        # All listed components are not vulnerable
        return False
    if node["operator"] == "OR":
        for cpe_match in node["cpeMatch"]:
            if not cpe_match["vulnerable"]:
                continue
            if match_cpe_criteria(inventory, cpe_match["criteria"]):
                # We stop looking after the first match. But other combinations
                # of items in the inventory could also match, which will only
                # appear after rerunning the script without the matched components
                return True
        return False
    else:  # AND opertator
        for cpe_match in node["cpeMatch"]:
            if not cpe_match["vulnerable"]:
                continue
            if not match_cpe_criteria(inventory, cpe_match["criteria"]):
                return False
        return True


# Inventory is a list of CPEs that form the device inventory
# cpe is a cpe id which was extracted from "criteria" in a 
# configuration node's "cpeMAtch" attribute
def match_cpe_criteria(inventory, cpe):
    from main import current_cpes
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


# graph, node_matcher, rel_matcher, node1, node2, rel_type
# TODO: For multi-threading - should be synchronized
def link_items_to_cve(cve):
    from neo4j_backend import create_relation
    from main import current_cpes

    # print("linked item")
    for cpe in current_cpes:
        create_relation(cpe, cve, "vulnerable_to")

    current_cpes = []


# Parses CVSS "metrics" part of a CVE json object
# and returns a tuple (int,'N'/'A'/'L',int) 
def get_pre_post_conditions(metrics):
    # Throughout the parsing of CVSS metrics, we add the pre and
    # postconditions
    precondition = -1  # NONE - 0, USER - 1, ROOT - 2
    attackVector = 0  # (N) Network, (A) Adjacent, (L) Local, "accessVector in 2.0"
    postcondition = 0  # NONE - 0, USER - 1, ROOT - 2

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
        if metrics["obtainUserPrivilege"]:
            postcondition = 1
        if metrics["obtainAllPrivilege"]:
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
    from neo4j_backend import get_connected_vulnerabilities, create_exploit_relation, \
        get_hosts_same_subnet, get_hosts_other_subnets

    from main import DEBUG, visited_nodes

    # print("On host " + start_node + " with priv " + str(privilege))

    # NONE - 0, USER - 1, ROOT - 2
    # Check if the start node belongs to the (node/privilege) we already visited
    if privilege <= 0:
        return
    if start_node in visited_nodes.keys() and visited_nodes[start_node] >= privilege:
        return

    nodes_to_visit = {}

    # First try to exploit the current node to get root permissions
    if privilege == 1:
        connected_vulnerabilities = get_connected_vulnerabilities(start_node)
        for vulnerability in connected_vulnerabilities:
            # We don't need to check the accessVector since we
            # are already on the machine

            if vulnerability["precondition"] <= privilege:
                # create_relation(start_node, vulnerability, "exploits")
                create_exploit_relation(start_node, start_node, vulnerability)

                if start_node not in nodes_to_visit.keys():
                    nodes_to_visit[start_node] = vulnerability["postcondition"]
                elif nodes_to_visit[start_node] <= vulnerability["postcondition"]:
                    nodes_to_visit[start_node] = vulnerability["postcondition"]

    connected_nodes = get_hosts_same_subnet(start_node)
    # print("nodes: " + str(connected_nodes))
    if privilege == 2:
        # Then, try to exploit the machines in the same subnet
        for connected_node in connected_nodes[0]:
            # print(connected_node)
            connected_vulnerabilities = get_connected_vulnerabilities(connected_node['id'])
            # print("vulns: " + str(connected_vulnerabilities))
            for vulnerability in connected_vulnerabilities:
                # Check access vector
                if vulnerability["accessVector"] == "A" or vulnerability["accessVector"] == "N":
                    if vulnerability["precondition"] == 0:
                        # create_relation(start_node, vulnerability, "exploits")
                        create_exploit_relation(start_node, connected_node, vulnerability)
                        if DEBUG:
                            print(f"Created rel between {start_node} and {connected_node}, cve {vulnerability}")

                        if connected_node['id'] not in nodes_to_visit.keys():
                            nodes_to_visit[connected_node['id']] = vulnerability["postcondition"]

        # Lastly, try to exploit the machines in connected subnets
        connected_nodes = get_hosts_other_subnets(start_node)
        for connected_node in connected_nodes:
            connected_vulnerabilities = get_connected_vulnerabilities(connected_node)
            for vulnerability in connected_vulnerabilities:
                # Check access vector
                if vulnerability["accessVector"] == "N":
                    if vulnerability["precondition"] == 0:
                        # create_relation(start_node, vulnerability, "exploits")
                        create_exploit_relation(start_node, connected_node, vulnerability)
                        if DEBUG:
                            print(f"Create rel between {start_node} and {connected_node}, cve {vulnerability}")

                        if connected_node['id'] not in nodes_to_visit.keys():
                            nodes_to_visit[connected_node['id']] = vulnerability["postcondition"]

    # Add the start node to the visited nodes
    visited_nodes[start_node] = privilege

    # print(nodes_to_visit)

    for node, postcondition in nodes_to_visit.items():
        # We can now continue from the current node with the new privilege
        draw_attack_paths(node, postcondition)


