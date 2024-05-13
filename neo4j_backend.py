from py2neo import Node, Relationship
import main


# Takes either a str id or a dictionary
# Following node types are defined for this network model:
# host, router, cpe, cve, exploit
def get_node_label(node):
    if isinstance(node, dict):
        if 'standard_id' in node.keys():
            node = node['standard_id']
        else:
            node = node['id']
    node = node.lower()

    if node.startswith("host"):
        return "host"
    if node.startswith("router"):
        return "router"
    if node.startswith("exploit"):
        return "exploit"
    if node.startswith("cve") or node.startswith("cpe"):
        return node[:3]  # either CVE or CPE

    index = node.find('--')
    if index != -1:
        return str(node)[:index] if index != -1 else str(node)
    else:

        return node  # either CVE or CPE


# Node can be either a name (for the label) or a dict
def create_node(node):
    if isinstance(node, dict):
        node_instance = Node(get_node_label(node), **node)
        node_id = node["id"]
    else:
        node_instance = Node(get_node_label(node), id=node)
        node_id = node

    if node_id in main.created_nodes:
        return
    else:
        main.graph.create(node_instance)


# Checks if nodes and relation (node1->node2) already exists and only
# adds to graph (node4j) what is lacking
# node1, node2 are ids or dictionaries (need to have "id" field!) of nodes to be added
# rel_type is a string holding the type of the relation
def create_relation(node1, node2, rel_type):
    # TODO: Simplify - we can use created_nodes instead of node_matching
    if isinstance(node1, dict):
        node1_instance = Node(get_node_label(node1), **node1)
        src_list = list(main.node_matcher.match(id=node1["id"]))
        node1_id = node1["id"]
    else:
        node1_instance = Node(get_node_label(node1), id=node1)
        src_list = list(main.node_matcher.match(id=node1))
        node1_id = node1

    if isinstance(node2, dict):
        node2_instance = Node(get_node_label(node2), **node2)
        trg_list = list(main.node_matcher.match(id=node2["id"]))
        node2_id = node2["id"]
    else:
        node2_instance = Node(get_node_label(node2), id=node2)
        trg_list = list(main.node_matcher.match(id=node2))
        node2_id = node2

    # If the src node does not yet exist
    if len(src_list) == 0:
        main.graph.create(node1_instance)
        if isinstance(node1, dict):
            main.created_nodes += [node1["id"]]
        else:
            main.created_nodes += [node1]

    # If the trg node does not yet exist
    if len(trg_list) == 0:
        main.graph.create(node2_instance)
        if isinstance(node2, dict):
            main.created_nodes += [node2["id"]]
        else:
            main.created_nodes += [node2]

    # Do src and target node exist, only once each?
    if len(src_list) > 1 or len(trg_list) > 1:
        print(f"src_list: {src_list}, trg_list: {trg_list}")
        print("Warning: source and/or target nodes are not unique!")
        return

    # Does the relationship already exist?
    rel_id = f"{node1_id}-{rel_type}>{node2_id}"
    if len(list(main.relation_matcher.match(id=rel_id))) == 0:
        if len(src_list) == 1:
            node1_instance = src_list[0]
        if len(trg_list) == 1:
            node2_instance = trg_list[0]

        relationship_instance = Relationship(node1_instance, rel_type, node2_instance, id=rel_id)
        main.graph.create(relationship_instance)
        # print(f"Created {rel_id}")


# host1 (src) and host2 (trg) can be ids or dicts, but have to be modelled
# in the graph already! (done in the init step using create_relation())
# exploited_cve is a dict
def create_exploit_relation(host1, host2, exploited_cve):
    if isinstance(host1, dict):
        src_list = list(main.node_matcher.match(id=host1["id"]))
        host1_id = host1["id"]
    else:
        src_list = list(main.node_matcher.match(id=host1))
        host1_id = host1

    if isinstance(host2, dict):
        trg_list = list(main.node_matcher.match(id=host2["id"]))
        host2_id = host2["id"]
    else:
        trg_list = list(main.node_matcher.match(id=host2))
        host2_id = host2

    rel_id = f"{host1_id}-exploits({exploited_cve['id']})>{host2_id}"

    # Check if relation exists already
    if not len(list(main.relation_matcher.match(id=rel_id))) == 0:
        return

    if len(src_list) != 1 or len(trg_list) != 1:
        print(f"Relation creation issue! src_list: {src_list}, trg_list: {trg_list}")
        return

    # Design choice explanation: we decide to not link the cpes in the exploitability path
    # for a better overview. Does require looking up responsible cves for each exploit
    relationship_instance = Relationship(src_list[0], exploited_cve["id"], trg_list[0], id=rel_id,
                                         cve=exploited_cve["id"],
                                         precondition=exploited_cve["precondition"],
                                         postcondition=exploited_cve["postcondition"],
                                         attackVector=exploited_cve["accessVector"])
    main.graph.create(relationship_instance)


# same arguments as create_exploit_relation, but creates a exploit
# object holding the involved CPEs
def create_exploit_object_relations(host1, host2, exploited_cve):
    # Create the exploit object
    id_expl = "exploit_" + exploited_cve["id"]
    exploit_dict = {"id": id_expl,
                    "precondition": exploited_cve["precondition"],
                    "postcondition": exploited_cve["postcondition"],
                    "attackVector": exploited_cve["accessVector"],
                    "involvedCPEs": get_involved_cpes(exploited_cve["id"], host1)}
    # Create the two relations
    create_relation(host1, exploit_dict, "exploits")
    create_relation(exploit_dict, host2, "exploits")


# Takes a host node id and returns a list of dictionaries
# of all CVE Node() objects that are linked to it (via CPEs)
def get_connected_vulnerabilities(node_id):
    ret_cves = []
    node = main.node_matcher.match(id=node_id)
    if node:
        cpe_nodes = get_connected_cpes(node_id)
        # TODO: check if CPEs?
        for cpe_node in cpe_nodes:
            results = main.graph.run(
                f"MATCH (n)-[:vulnerable_to]->(related_node) WHERE n.id = \"{cpe_node}\" RETURN related_node")
            cve_nodes = [result["related_node"] for result in results]
            # TODO: check if CVEs?
            for cve_node in cve_nodes:
                if cve_node not in ret_cves:
                    ret_cves.append(cve_node)

    return ret_cves


#
def get_all_vulnerabilities():
    cursor = main.graph.run("MATCH (n:cve) RETURN collect(toString(n.id)) AS idList")
    results = cursor.data()

    # 'results' is a list of dictionaries. Each dictionary corresponds to a record in the result set.
    # Since your query collects IDs into a single list, you expect one record with one field 'idList'.
    if results and 'idList' in results[0]:
        return results[0]['idList']
    else:
        return []


def get_connected_cpes(host):
    results = main.graph.run(f"match (n:host)-[:has]->(f:cpe) where n.id = \"{host}\" return f")
    return [result["f"] for result in results]


# Takes CVE id (vulnerability) and a host id (eg. "host1")
# and returns the cpe.ids that are in the inventory of the
# host and fulfill the vulnerbility conditions of the CVE
def get_involved_cpes(vulnerability, host):
    query = f"MATCH (host)-[:has]->(cpe)-[:vulnerable_to]->(related_node) WHERE related_node.id = \"{vulnerability}\" and host.id = \"{host}\" RETURN cpe"
    results = main.graph.run(query)
    cpe_nodes = [result["cpe"].get('id') for result in results]
    return cpe_nodes


# Helper function for get_connected_vulnerabilities, simple Cypher Query
def get_connected_cpes(node_id):
    query = f"MATCH (n)-[:has]->(related_node) WHERE n.id = \"{node_id}\" RETURN related_node"
    results = main.graph.run(query)
    cpe_nodes = [result["related_node"].get('id') for result in results]
    return cpe_nodes


# Takes a host node id and returns a list of node ids of the
# hosts that are reachable through layer 2
def get_hosts_same_subnet(node_id):
    ret_nodes = []

    query = f"MATCH (source)-[r]->(target) WHERE source:router AND target.id = \"{node_id}\" RETURN source.id"
    # query = f"MATCH (n) RETURN n"
    routers = main.graph.run(query)  # contains a list of the router names

    router = routers.evaluate()

    while router is not None:
        # Query to get the subnet of the router
        query = f"MATCH (source)-[r]->(target) WHERE source.id = \"{str(router)}\" AND target.id = \"{node_id}\" RETURN type(r)"
        subnet = main.graph.run(query).evaluate()  # should be unique

        # Get all nodes connected to router which are in the same subnet
        query = f"MATCH (source)-[r:{subnet}]->(target) WHERE source.id = \"{str(router)}\" AND target.id <> \"{node_id}\" RETURN target"
        results = main.graph.run(query)
        results = [result["target"] for result in results]
        for result in results:
            ret_nodes.append(result)

        router = routers.evaluate()

    return ret_nodes  # [ret_node[0] for ret_node in ret_nodes]


# takes a host node is and returns the list of routers connected
# to it
def get_connected_routers(node_id):
    query = f"MATCH (source)-[r]->(target) WHERE source:router AND target.id = \"{node_id}\" RETURN source.id"
    routers = main.graph.run(query)  # contains a list of the router names

    return [router['source.id'] for router in routers]


# Takes a host node id and returns a mapping (subnet->node_ids) of the
# hosts that are reachable through router in a different subnetwork
def get_hosts_other_subnets(node_id, router):
    ret_nodes = {}

    # Query to get the subnet of router the node is in
    query = f"MATCH (source)-[r]->(target) WHERE source.id = \"{str(router)}\" AND target.id = \"{node_id}\" RETURN type(r)"
    src_subnet = main.graph.run(query).evaluate()  # must be unique

    query = f"MATCH (n)-[r]->() WHERE n.id = \"{str(router)}\" RETURN DISTINCT type(r) AS relationship_types"
    iterate_subnets = main.graph.run(query)
    current_subnet = iterate_subnets.evaluate()
    other_subnets = []  # will be fed with the sames of the other subnets
    while current_subnet is not None:
        if src_subnet != current_subnet:
            other_subnets.append(current_subnet)
        current_subnet = iterate_subnets.evaluate()

    for other_subnet in other_subnets:
        # Get all nodes connected to router which are in the other subnet
        query = f"MATCH (source)-[r:{other_subnet}]->(target) WHERE source.id = \"{str(router)}\" RETURN target"

        nodes_subnet = main.graph.run(query)
        node_subnet = nodes_subnet.evaluate()
        while node_subnet is not None:
            # - loops over each node in subnet
            # -if fire_router is not None:
            # -    blocked_cpes = fire_router.get_blocked_resources(current_subnet, subnet)
            #    connected_cpes = get_connected_cpes(node_subnet)
            #    if set(blocked_cpes).isdisjoint(set(connected_cpes)):
            # only if all the cpes connected to node_subnet are NOT blocked
            # ret_nodes.append(node_subnet)
            # -else:
            # -    ret_nodes.append(node_subnet)

            if other_subnet not in ret_nodes:
                ret_nodes[other_subnet] = [node_subnet]
            else:
                ret_nodes[other_subnet].append(node_subnet)

            node_subnet = nodes_subnet.evaluate()

    # ret_nodes = [ret_node[0] for ret_node in ret_nodes]
    return src_subnet, ret_nodes


def get_all_hosts():
    results = main.graph.query("MATCH (n:host) RETURN n")
    cpe_nodes = [result["related_node"].get('id') for result in results]
    return cpe_nodes


# - - - - - Functions to setup test environments - - - - - -


def add_vulnerabilities(host: str):
    from ag_gen import find_vulnerabilities
    inventory = get_connected_cpes(host)
    find_vulnerabilities(inventory)


# Can be changed into a parsing function
def config_example(searchVuln=False):
    from main import FirewallRouter
    import ag_gen

    # HOSTS
    host_internet = Node(id="host_internet")  # or internet

    inventory1 = [  # "cpe:2.3:a:apache:log4j:2.0:-:*:*:*:*:*:*"
        "cpe:2.3:o:apple:mac_os_x:10.0.0:*:*:*:*:*:*:*",
        "cpe:2.3:a:apple:imovie:6.0.3:*:*:*:*:*:*:*",
        "cpe:2.3:h:apple:m1_mac_mini:-:*:*:*:*:*:*:*"]
    host1 = Node(id="host1")

    inventory2 = ["cpe:2.3:h:amd:a6-9220:-:*:*:*:*:*:*:*",
                  "cpe:2.3:h:amd:ryzen_3_pro_3200g:-:*:*:*:*:*:*:*",
                  "cpe:2.3:h:nvidia:geforce_gtx_1050_ti:-:*:*:*:*:*:*:*",
                  "cpe:2.3:o:microsoft:windows_11:-:*:*:*:*:*:arm64:*"]
    host2 = Node(id="host2")

    inventory_printer = ["cpe:2.3:h:samsung:clp-360_ss062a:-:*:*:*:*:*:*:*"]
    host_printer = Node(id="host_printer")

    # SERVERS
    inventory_web_server = ["cpe:2.3:o:microsoft:windows_server_2022:*:*:*:*:*:*:*:*:*",
                            "cpe:2.3:a:microsoft:.net_framework:3.0:sp2:*:*:*:*:*:*",
                            "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",  # Web Server software
                            "cpe:2.3:a:microsoft:sql_server:2019:*:*:*:*:*:*:*",  # for small-scale DBMS
                            "cpe:2.3:a:symantec:endpoint_protection:*:*:*:*:*:*:*",  # security ?
                            ]
    inventory_mail_server = ["cpe:2.3:o:dell:poweredge_r940_firmware:-:*:*:*:*:*:*:*",
                             "cpe:2.3:o:openbsd:openbsd:8.0:*:*:*:*:*:*:*",
                             "cpe:2.3:a:openbsd:opensmtpd:6.6:*:*:*:*:*:*:*",
                             "cpe:2.3:a:todd_miller:sudo:1.5.8:*:*:*:*:*:*:*"
                             ]
    inventory_dns_server = ["cpe:/o:microsoft:windows_server_2019",
                            "cpe:/a:microsoft:active_directory:2019",
                            "cpe:2.3:a:powerdns:authoritative_server:4.5.4:*:*:*:*:*:*:*",
                            "cpe:2.3:a:apache:http_server:1.3.26:*:*:*:*:*:*:*"]

    inventory_reverse_proxy_server = ["cpe:/o:microsoft:windows_server_2019",
                                      "cpe:/a:microsoft:active_directory:2019",
                                      "cpe:2.3: a:trustwave: modsecurity:2.9.4:*:*:*:*:*:*:*"
                                      "cpe:2.3:o:dell:poweredge_r940_firmware:-:*:*:*:*:*:*:*",
                                      "cpe:2.3:a:apache:http_server:1.3.26:*:*:*:*:*:*:*",
                                      ]

    host_webserver = Node(id="host_webserver")
    host_mailserver = Node(id="host_mailserver")
    host_revproxserver = Node(id="host_reverse_proxy_server")

    dmz_rules = []
    firewall_external = FirewallRouter("router_external", dmz_rules)  # internet <-> DMZ
    router_external = Node(id="router_external")

    create_relation(router_external, host_internet, "internet")

    internal_rules = []
    firewall_internal = FirewallRouter("router_external", internal_rules)  # internet <-> DMZ
    router_internal = Node(id="router_internal")

    # In DMZ
    # (external router)
    for item in inventory_web_server:
        create_relation(host_webserver, Node(id=item), "has")
    create_relation(router_external, host_webserver, "DMZ_ext")
    for item in inventory_mail_server:
        create_relation(host_mailserver, Node(id=item), "has")
    create_relation(router_external, host_mailserver, "DMZ_ext")

    for item in inventory_reverse_proxy_server:
        create_relation(host_revproxserver, Node(id=item), "has")
    create_relation(router_external, host_revproxserver, "DMZ_ext")

    # (internal router)
    create_relation(router_internal, host_revproxserver, "DMZ_int")
    # for item in inventory_mail_server:
    #    create_relation(host_mailserver, Node(id=item), "has")
    # create_relation(router_internal, host_mailserver, "DMZ_int")

    # In work-LAN
    for item in inventory_printer:
        create_relation(host_printer, Node(id=item), "has")
    create_relation(router_internal, host_printer, "LAN")
    for item in inventory1:
        create_relation(host1, Node(id=item), "has")
    create_relation(router_internal, host1, "LAN")

    for item in inventory2:
        create_relation(host2, Node(id=item), "has")
    create_relation(router_internal, host2, "LAN")

    # Search vulns
    if searchVuln:
        ag_gen.find_vulnerabilities(inventory1)
        ag_gen.find_vulnerabilities(inventory2)
        ag_gen.find_vulnerabilities(inventory_printer)
        ag_gen.find_vulnerabilities(inventory_reverse_proxy_server)
        ag_gen.find_vulnerabilities(inventory_web_server)
        ag_gen.find_vulnerabilities(inventory_mail_server)
        ag_gen.find_vulnerabilities(inventory_dns_server)

    return {"router_external": firewall_external, "router_internal": firewall_internal}
