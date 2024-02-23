from py2neo import Graph, Node, Relationship

from py2neo.matching import *

import stix2
from stix2 import Bundle, Indicator, exceptions, ExternalReference

import os

import json

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
# - Returns 0 on successful adding of the object
# - Returns 1 if the stix_object has a problem
# - Returns 2 if the object already exists
# - Returns 3 if relationship object reference is ambiguous
# - Returns 4 if relationship object points to non-existing object (is caught)
# In retrospective, 5 error code for this function is excessive.
def create_instance(graph, stix_object):
    object_type = stix_object.get("type")
    object_id = stix_object.get("id")
    print(object_id)

    # TODO: Check validity of Graph object

    # TODO: insert this as function parameters ? to not create it each time
    node_matcher = NodeMatcher(graph)
    rel_matcher = RelationshipMatcher(graph)

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

        # Make sure the STIX ID is not already present in the set of relations
        relationship_list = list(rel_matcher.match(id=object_id))
        if not len(relationship_list) == 0:
            print("Error: a relationship with the same STIX id was already added to the graph. (Added nothing)")
            return 2

        # - Check if source and target nodes exist -
        # gives all objects (in database) that are pointed to by src pointer
        src_object = stix_object.get("source_ref")
        src_list = list(node_matcher.match(id=src_object))

        if len(src_list) > 1:
            print("Error: src object ", src_object, " of relation exists multiple times.")
            return 3
        if len(src_list) == 0:
            print("Error: src object ", src_object, " of relation doesn't exist.")
            return 4

        # gives all objects (in database) that are pointed to by target pointer
        trg_object = stix_object.get("target_ref")
        trg_list = list(node_matcher.match(id=stix_object.get("target_ref")))
        # print(stix_object.get("target_ref"))

        if len(trg_list) > 1:
            print("Error: target object ", trg_object, " of relation exists multiple times.")
            return 3
        if len(trg_list) == 0:
            print("Error: target object ", trg_object, " of relation doesn't exist.")
            return 4

        # create relationship instance
        relationship_instance = Relationship(src_list[0], relationship_type, trg_list[0], id=object_id)

        graph.create(relationship_instance)

    # Create Node
    else:
        # Make sure the STIX ID is not already present in the set of nodes
        id_list = list(node_matcher.match(id=object_id))
        if not len(id_list) == 0:
            print("Error: a node with the same STIX id was already added to the graph. (Added nothing)")
            return 2

        # the Node() function does not allow to specify neo4j's id attribute
        # the STIX id is therefore inserted as a property to the object
        node_instance = Node(object_type, **stix_object)

        graph.create(node_instance)

    print("Added instance successfully")
    return 0


# The function expects stix objects with NO nested properties!
# -> the stix objects have to passed through remove_nested_variables()
def unpack_bundle(graph, bundle):
    relations = []


    # We first add the nodes so there are no issues with the pointers of the
    # relations
    for stix_object in bundle["objects"]:
        #print(stix_object)
        if stix_object["type"] == "relationship":
            relations.append(stix_object)
        else:
            create_instance(graph, stix_object)

    # all observables and domain objects should now have been added
    for stix_object in relations:
        create_instance(graph, stix_object)


if __name__ == "__main__":

    neo4j_uri = "bolt://localhost:7687"  # NEO4J URI
    neo4j_user = "phil"        # NEO4J USERNAME
    neo4j_password = "adminphil"    # NEO4J PASSWORD
    bundle_filename = "json_samples/sample_database.json" # FILENAME OF BUNDLE, FROM SAME DIR

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))

    current_directory = os.path.dirname(os.path.realpath(__file__))
    bundle_filepath = os.path.join(current_directory, bundle_filename)

    objects_bundle = [] # defined as list!

    try:
        # Read the contents of the STIX bundle file
        with open(bundle_filepath, 'r') as file:
            json_content = file.read()

        bundle_data = json.loads(json_content)

    except Exception as e:
        print(f"Error parsing STIX bundle: {e}")

    # open bundle: go through all objects in the bundle
    for i in range(len(bundle_data["objects"])):
        #print(len(bundle_data["objects"]))
        bundle_data["objects"][i] = remove_nested_properties(bundle_data["objects"][i])

    # Process the STIX bundle
    unpack_bundle(graph, bundle_data)
