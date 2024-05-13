from py2neo import Node
from pycti import OpenCTIApiClient
import json


# Queries opencti for observable objects that are connected to
# the sdo with stix_id ("id" field of the stix object).
# Returns array of tuples (object, rel_type)
def get_sdo_observables(api_client: OpenCTIApiClient, stix_id):
    stix_relations = api_client.stix_core_relationship.list(
        first=100,
        fromId=stix_id  # "ed71b0c9-0355-4468-8e76-04cb301dd9ca"
    )
    # TODO: observables can also point TO sdos
    # ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Cyber-Observable']

    ret_observables = []
    for relation in stix_relations:
        if 'Stix-Cyber-Observable' in relation["to"]["parent_types"]:
            ret_observables.append(relation["to"])
            # query again for links to sdo? -> some relations form loops!

    stix_relations = api_client.stix_core_relationship.list(
        first=100,
        toId=stix_id  # "ed71b0c9-0355-4468-8e76-04cb301dd9ca"
    )

    #ret_observables = []
    for relation in stix_relations:
        if 'Stix-Cyber-Observable' in relation["from"]["parent_types"]:
            ret_observables.append(relation["from"])
            # query again for links to sdo? -> some relations form loops!

    return ret_observables


# Queries opencti for domain objects that point towards
# vuln objects with cve_id. The function returns an array
# of tuples (object, relation_type, vuln)
def get_cve_sdos(api_client: OpenCTIApiClient, cve_id):
    ''' list of vuln objects with relations for testing:
    CVE-2023-4911, CVE-2019-3396, CVE-2021-42237, CVE-2022-31199, CVE-2021-34523
    CVE-2021-27065, CVE-2023-46604, CVE-2023-1389, CVE-2019-0803, CVE-2012-4792
    CVE-2020-17144, CVE-2015-2545, CVE-2017-11882, CVE-2021-26858, CVE-2021-20016
    CVE-2019-11510, CVE-2022-24521, CVE-2021-26857, CVE-2016-5198, CVE-2019-15107
    CVE-2022-21661, CVE-2013-3660, CVE-2017-0144, CVE-2016-0189, CVE-2021-35394
    CVE-2017-0199
    '''
    # get vulnerability object for stix id
    vulnerability = get_vulnerabilities(api_client, [cve_id])

    if vulnerability:
        vulnerability = vulnerability[0]

    if (not vulnerability) or ("entity_type" not in vulnerability.keys()) or \
            (not vulnerability["entity_type"] == "Vulnerability"):
        # print(f"{cve_id} not a CVE id or no CVE found in the CTI database.")
        return

    opencti_id = vulnerability["id"]  # stix id without entity_type name in front

    stix_relations = api_client.stix_core_relationship.list(
        first=100,
        toId=opencti_id
    )
    if len(stix_relations) >= 99:
        print(f"Warning: Some sdos linked to {vulnerability} may not have been added because of too many instances.")
    ret_objects = []
    # Vulnerability sdos can only be pointed at, are never source of relation
    for relation in stix_relations:
        # from_object = api_client.stix_domain_object.read(
        #    id=relation["from"]["id"]
        # )
        # The relationships point to one of these types:
        # Malware, Campaign, Intrusion Set; infrastructure, coa, tool,
        # threat actor, attack pattern, campaign
        ret_objects.append((relation['from'], relation["relationship_type"], relation['to']))

    return ret_objects


# Returns a list of STIX objects corresponding to the cve_ids (eg. "CVE-2019-1234")
# in the same order as in the list
def get_vulnerabilities(api_client: OpenCTIApiClient, cve_ids: list):
    ret_vulnerabilities = api_client.vulnerability.list(
        first=len(cve_ids),
        filters={"mode": "and", "filters": [{"key": "entity_type", "values": ["Vulnerability"]},
                                            {"key": "name", "values": cve_ids}],
                 "filterGroups": []})
    return ret_vulnerabilities


# Takes a json representation of a stix object (not bundle!!), deletes all properties that
# are nested, except if it belongs to the set of required_properties,
# in which case a string replaces the nested variable set
def remove_nested_properties(json_obj):
    required_properties = {"object_marking_refs"}  # Add other required properties as needed

    cleaned_obj = {}
    for key, value in json_obj.items():
        if isinstance(value, list):
            # only keep the contents of the list that are of primitive type
            cleaned_obj[key] = [item for item in value if isinstance(item, (int, str, float, bool))]
        elif isinstance(value, (int, str, float, bool)):
            cleaned_obj[key] = value
        else:
            cleaned_obj[key] = "-" if key in required_properties else None

    return cleaned_obj


# Creates any STIX domain or relationship object
# Graph - neo4j object for the graph where the object should be added to
# stix_object - the object to be added
def create_instance(node_graph, node_matcher_, rel_matcher, stix_object):
    from neo4j_backend import create_relation, create_node
    # - Returns 0 on successful adding of the object
    # - Returns 1 if the stix_object has a problem
    # - Returns 2 if the object already exists
    # - Returns 3 if relationship object reference is ambiguous
    # - Returns 4 if relationship object points to non-existing object (is caught)
    # In retrospective, 5 error code for this function is excessive.
    print(stix_object.keys())
    try:
        object_type = stix_object.get("type")
    except Exception:
        object_type = stix_object.get("entity_type")

    object_id = stix_object.get("id")

    # TODO: Check validity of Graph object

    # Make sure the STIX object has a type
    if not object_type:
        print("Error: 'type' field is required in the STIX object. (Added nothing)")
        return 1
    # Make sure the STIX object has an ID
    if not object_id:
        print("Error: 'id' field is required in the STIX Object. (Added nothing)")
        return 1

    # Create Relationship
    if object_type == "relationship":
        relationship_type = stix_object['relationship_type']
        if not relationship_type:
            print("Error: no 'relationship_type' field")
            return 1

        # Make sure the STIX ID is not already present in the set of relations -
        relationship_list = list(rel_matcher.match(id=object_id))
        if not len(relationship_list) == 0:
            print("Error: a relationship with the same STIX id was already added to the graph. (Added nothing)")
            return 2

        # - Check if source and target nodes exist -
        # gives all objects (in database) that are pointed to by src pointer
        src_object = stix_object.get("source_ref")
        src_list = list(node_matcher_.match(id=src_object))

        if len(src_list) > 1:
            print("Error: src object ", src_object, " of relation exists multiple times.")
            return 3
        if len(src_list) == 0:
            print("Error: src object ", src_object, " of relation doesn't exist.")
            return 4

        # gives all objects (in database) that are pointed to by target pointer
        trg_object = stix_object.get("target_ref")
        trg_list = list(node_matcher_.match(id=stix_object.get("target_ref")))
        # print(stix_object.get("target_ref"))

        if len(trg_list) > 1:
            print("Error: target object ", trg_object, " of relation exists multiple times.")
            return 3
        if len(trg_list) == 0:
            print("Error: target object ", trg_object, " of relation doesn't exist.")
            return 4

        # create relationship instance
        # relationship_instance = Relationship(src_list[0], relationship_type, trg_list[0], id=object_id)
        # node_graph.create(relationship_instance)
        create_relation(src_list[0], trg_list[0], relationship_type)

    # Create Node
    else:
        # Make sure the STIX ID is not already present in the set of nodes
        id_list = list(node_matcher_.match(id=object_id))
        if not len(id_list) == 0:
            print("Error: a node with the same STIX id was already added to the graph. (Added nothing)")
            return 2

        # the Node() function does not allow to specify neo4j's id attribute
        # the STIX id is therefore inserted as a property to the object
        # node_instance = Node(object_type, **stix_object)
        create_node(Node(object_type, **stix_object))

    print("Added instance successfully")
    return 0


# The function expects stix objects with NO nested properties!
# -> the stix objects have to passed through remove_nested_variables()
def unpack_bundle(node_graph, node_matcher, relation_matcher, bundle):
    relations = []

    # We first add the nodes so there are no issues with the pointers of the
    # relations
    for stix_object in bundle["objects"]:
        # print(stix_object)
        if stix_object["type"] == "relationship":
            relations.append(stix_object)
        else:
            create_instance(node_graph, node_matcher, relation_matcher, stix_object)

    # all observables and domain objects should now have been added
    for stix_object in relations:
        create_instance(node_graph, node_matcher, relation_matcher, stix_object)


# Test function for this class
if __name__ == "__main__":
    with open("config.json", 'r') as file:
        config_content = file.read()

    config_content = json.loads(config_content)

    neo4j_uri = config_content["neo4j_uri"]
    neo4j_user = config_content["neo4j_user"]
    neo4j_password = config_content["neo4j_password"]
    bundle_filename = config_content["bundle_filename"]

    cti_url = config_content["fusioncenter_uri"]
    cti_token = config_content["access_token_f"]

    opencti_api_client = OpenCTIApiClient(cti_url, cti_token)

    #get_cve_sdos(opencti_api_client, "CVE-2021-27065")
    print(get_sdo_observables(opencti_api_client, "ed71b0c9-0355-4468-8e76-04cb301dd9ca"))

    # Get vulnerabilities of graph
    from ag_gen import find_vulnerabilities
    # conda-repo-cli, tornado 6.4

    #vulnerabilities = find_vulnerabilities()


    '''
    # BUNDLE UNPACKING TESTING
    try:
        # Read the contents of the STIX bundle file
        with open(bundle_filepath, 'r') as file:
            json_content = file.read()

        bundle_data = json.loads(json_content)

    except Exception as e:
        print(f"Error parsing STIX bundle: {e}")

    # open bundle: go through all objects in the bundle
    for i in range(len(bundle_data["objects"])):
        # print(len(bundle_data["objects"]))
        bundle_data["objects"][i] = remove_nested_properties(bundle_data["objects"][i])

    # Process the STIX bundle
    # unpack_bundle(graph, node_matcher, relation_matcher, bundle_data)

    
    '''
