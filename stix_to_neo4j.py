from py2neo import Graph, Node, Relationship, NodeMatcher, RelationshipMatcher

from pycti import OpenCTIApiClient
from datetime import datetime
import logging

import os

import json
# import main - for testing
from neo4j_backend import create_relation, create_node



# Queries opencti
def get_indicators_of_vulnerability(opencti_api):
    from main import opencti_url, opencti_token

    vulnerability = opencti_api.vulnerability.read(id="vulnerability--87168880-202e-5bdc-ae1b-7db39a95e9ab")

    print(vulnerability)


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
        #print(stix_object)
        if stix_object["type"] == "relationship":
            relations.append(stix_object)
        else:
            create_instance(node_graph, node_matcher, relation_matcher, stix_object)

    # all observables and domain objects should now have been added
    for stix_object in relations:
        create_instance(node_graph, node_matcher, relation_matcher, stix_object)


def get_vulnerabilities(api_client: OpenCTIApiClient):
    logging.getLogger("pycti").setLevel(logging.WARNING)

    # Initialize OpenCTI API client
    #api_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)

    # Calculate the start date for the year 2023
    start_date = datetime(2023, 1, 1, 0, 0, 0)

    # Define the filters for the query
    filters = [{"key": "created_after", "values": start_date.isoformat()}]

    # [{"created_after": start_date.isoformat(), "entity_type": ["Intrusion-Set"]}]

    # [{"key": "x_mitre_id", "values": ["T1514"]}]

    # Query the number of Intrusion Sets
    intrusion_sets_count = api_client.location.list(
        with_pagination=False,
    )

    print("Number of Intrusion Sets created in 2023: ", intrusion_sets_count)


# Test function for this class
if __name__ == "__main__":

    with open("config.json", 'r') as file:
        config_content = file.read()

    config_content = json.loads(config_content)

    neo4j_uri = config_content["neo4j_uri"]
    neo4j_user = config_content["neo4j_user"]
    neo4j_password = config_content["neo4j_password"]
    bundle_filename = config_content["bundle_filename"]

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
    node_matcher = NodeMatcher(graph)
    relation_matcher = RelationshipMatcher(graph)

    current_directory = os.path.dirname(os.path.realpath(__file__))
    bundle_filepath = os.path.join(current_directory, bundle_filename)

    objects_bundle = []  # defined as list!

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
    unpack_bundle(graph, node_matcher, relation_matcher, bundle_data)
