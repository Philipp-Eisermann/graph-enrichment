import json

from py2neo import Graph, Node, NodeMatcher, RelationshipMatcher
from pycti import OpenCTIApiClient

from pytrie import StringTrie

# GLOBAL VARS
# CONFIG FILE PARSING
#import neo4j_backend

# turn off logging
#import urllib3
#urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
#import logging
#logging.basicConfig(level=logging.ERROR)

with open("config.json", 'r') as file:
    config_content = file.read()

config_content = json.loads(config_content)

neo4j_uri = config_content["neo4j_uri"]
neo4j_user = config_content["neo4j_user"]
neo4j_password = config_content["neo4j_password"]

cti_url = config_content["fusioncenter_uri"]
cti_token = config_content["access_token_f"]

opencti_api_client = OpenCTIApiClient(cti_url, cti_token)

graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)

# For attack graph generation
visited_nodes = StringTrie()  # contains mappings hostname:privilege_level

# ! if threaded extension: each thread needs its own current_cpes var,
# cves to analyse are splitted between threads. In neo4j backend stores
# the CPEs that are involved for the current cve iteration
current_cpes = []

# CWE extraction
unextracted_cwes = []  # CWEs for which the query was unsuccessful

# For graph generation
created_nodes = []  # nodes that were added to neo4j

# CONFIGS
DEBUG = False


# - - - - - -


class FirewallRouter:
    def __init__(self, name: str, rules=None):
        self.name = name
        self.rules = rules if rules else {}

    def declare_router_rules(self, rules: dict):
        # TODO: verify that subnets belong to the router
        # in the graph database
        if not rules:
            return
        for subnet_mapping, cpes in rules.items():
            if subnet_mapping in self.rules:
                self.rules[subnet_mapping].extend(cpe for cpe in cpes if cpe not in self.rules[subnet_mapping])
            else:
                self.rules[subnet_mapping] = list(cpes)

    def get_rules(self):
        return self.rules


# Tests get_cve_sdos and get_sdo_observables functions for the enrichment
# of CVE object on the graph
def vuln_enrichment_test():
    global opencti_api_client
    from stix_to_neo4j import get_cve_sdos, get_sdo_observables
    from neo4j_backend import create_relation

    vulnerabilities_id = ["CVE-2019-11510", "CVE-2022-24521", "CVE-2021-26857",
                          "CVE-2016-5198", "CVE-2019-15107", "CVE-2023-4911",
                          "CVE-2019-3396", "CVE-2021-42237", "CVE-2022-31199",
                          "CVE-2021-34523", "CVE-2021-27065"]

    for vuln in vulnerabilities_id:
        sdos = get_cve_sdos(opencti_api_client, vuln)

        if not sdos:
            print("nothhing for " + vuln)
            continue
        for sdo, rela_type, targ_vuln in sdos:
            # targ_vuln and vuln should be the same object
            create_relation(sdo, targ_vuln, rela_type)

            observables = get_sdo_observables(opencti_api_client, sdo["id"])
            print(observables)
    '''
        # Observables Test
        # for i in cve_list:
        #    relations = get_cve_sdos(opencti_api_client, i)
        #    for domain_obj, rel_type, vuln in relations:
        #        observables = get_sdo_observables(opencti_api_client, domain_obj["id"])
        #        if observables:
        #            print(f"For object {domain_obj['id']}: {observables}")

        # get the graphs vulnerability
        vuln_ids = get_all_vulnerabilities()
        for vuln_id in vuln_ids:
            relations = get_cve_sdos(opencti_api_client, vuln_id)
            if not relations:
                print(f"No relations for {vuln_id}")
                continue
            for domain_obj, rel_type, vuln in relations:
                observables = get_sdo_observables(opencti_api_client, domain_obj["id"])
                print(f"For object {vuln_id}: {observables}")
        # create instance on graph
        #exploits_rels = [{'id': 'ed589b17-4f94-4e57-b5d2-defd10fa9d1d', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:29.587Z', 'updated_at': '2024-01-24T16:29:29.587Z', 'standard_id': 'relationship--22aa3e8d-dc13-4742-b23c-3e615cf3e754', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:29.587Z', 'modified': '2024-01-24T16:29:29.587Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': '58f343e8-c690-4728-b0c4-d7adc76141c1', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--f73ba567-0875-538a-af1e-784bf406e55d', 'spec_version': '2.1', 'created_at': '2021-02-28T22:42:37.489Z', 'updated_at': '2022-04-29T04:53:21.514Z', 'name': 'CVE-2020-1054'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '1bef3996-c094-446e-8841-0a8b5ecfbe03', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:17.311Z', 'updated_at': '2024-01-24T16:29:17.311Z', 'standard_id': 'relationship--2bd7cf88-4a3f-42c9-ae53-b9c2191eafbd', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:17.311Z', 'modified': '2024-01-24T16:29:17.311Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': '037aef83-735c-48f4-a62a-ee2503ca9f0b', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--3f43f8b7-0be8-5bb0-b5d0-b84fb70de45b', 'spec_version': '2.1', 'created_at': '2021-02-28T22:42:37.697Z', 'updated_at': '2021-04-16T11:29:19.697Z', 'name': 'CVE-2019-0808'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': 'f042594c-14e4-4497-8d48-3c8c5793fc4e', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:33.850Z', 'updated_at': '2024-01-24T16:29:33.850Z', 'standard_id': 'relationship--393db1f7-3099-457a-9bab-ccf4d18ebf44', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:33.850Z', 'modified': '2024-01-24T16:29:33.850Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': 'bc3e1228-27fc-422a-80ed-a0b516056aa0', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--c2ebf575-7ec1-5938-a435-cd0819d6dadb', 'spec_version': '2.1', 'created_at': '2021-03-20T11:57:52.238Z', 'updated_at': '2024-02-09T13:01:35.481Z', 'name': 'CVE-2021-1732'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '0d9cb891-f13c-40e4-a22d-4e6515d84db1', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:21.410Z', 'updated_at': '2024-01-24T16:29:21.410Z', 'standard_id': 'relationship--4fc4f063-8d2f-4532-be32-d1ac98336c80', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:21.410Z', 'modified': '2024-01-24T16:29:21.410Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': 'db3e8a0f-8f66-4f16-b3a4-eb2c19ba85d7', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--e2a8b8a0-507f-5b31-b7b5-320a6f67fa6f', 'spec_version': '2.1', 'created_at': '2021-02-28T07:34:59.076Z', 'updated_at': '2023-07-06T08:50:55.144Z', 'name': 'CVE-2019-1458'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': 'fd34d544-9285-4b39-b25d-3360401b76d7', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:25.537Z', 'updated_at': '2024-01-24T16:29:25.537Z', 'standard_id': 'relationship--a9fd407e-fc41-47e8-b385-f57f3b6e9a37', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:25.537Z', 'modified': '2024-01-24T16:29:25.537Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': 'dc9e4ddd-6f2c-4a99-a726-10ca8bf1c5da', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--2930fb5d-7db3-5582-bf18-20a25a032e92', 'spec_version': '2.1', 'created_at': '2021-02-28T07:34:32.483Z', 'updated_at': '2022-01-02T05:45:12.064Z', 'name': 'CVE-2020-0674'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '303a3a14-2d19-469c-9bc5-297129d7f047', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:13.179Z', 'updated_at': '2024-01-24T16:29:13.179Z', 'standard_id': 'relationship--f40d47db-ac90-4d49-936e-f5945d9bc8f0', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:13.179Z', 'modified': '2024-01-24T16:29:13.179Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': 'adb75723-4b7c-4278-a691-30c5b479992d', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--e7766bd8-ff16-50cd-980e-feaf558e195a', 'spec_version': '2.1', 'created_at': '2021-02-27T09:46:05.497Z', 'updated_at': '2021-09-27T10:21:37.381Z', 'name': 'CVE-2015-1701'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': 'b6833481-7ac4-495a-ae22-1a67325f62ee', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-01-24T16:29:38.001Z', 'updated_at': '2024-01-24T16:29:38.001Z', 'standard_id': 'relationship--f47edf15-9e8e-4aee-80fa-e376a43f22e4', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-01-24T16:29:38.001Z', 'modified': '2024-01-24T16:29:38.001Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '5b4c1d15-814e-4529-88f4-7357a0eb076e', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0c64033e-5bac-5adf-ac8f-0f98fe0401d9', 'spec_version': '2.1', 'created_at': '2021-02-28T22:43:42.131Z', 'updated_at': '2024-01-24T16:29:09.023Z', 'name': 'Purple Fox'}, 'to': {'id': 'a29b70dd-ee69-416b-a85e-550c0f4c1ed2', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--0f82e11d-7912-5cb6-9d78-c31beb502515', 'spec_version': '2.1', 'created_at': '2021-03-20T14:26:26.190Z', 'updated_at': '2023-12-30T05:58:14.539Z', 'name': 'CVE-2021-26411'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '8094f347-bef8-48bc-b98e-2404ff0661bc', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2022-10-21T16:04:05.345Z', 'updated_at': '2022-10-21T16:04:05.345Z', 'standard_id': 'relationship--7982886c-db2c-4c80-b354-7dc0265c9e61', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2022-10-21T16:04:05.345Z', 'modified': '2022-10-21T16:04:05.345Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '2f004b42-a682-47b9-b2b8-23d1e7fa1667', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0cdc72ad-22b0-5eb7-a4ec-6f67115ec213', 'spec_version': '2.1', 'created_at': '2021-10-18T14:47:29.978Z', 'updated_at': '2022-04-26T08:48:23.026Z', 'name': 'BlackByte'}, 'to': {'id': 'e88ea5bc-737e-42c5-9c28-61dcdf6b90b2', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--23465e57-7973-5628-bea0-2e5ac1cc968b', 'spec_version': '2.1', 'created_at': '2021-03-18T09:34:04.535Z', 'updated_at': '2023-12-30T05:58:14.344Z', 'name': 'CVE-2021-27065'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '6d10ca7c-4b5f-49ee-9da5-9761be8b6e16', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2022-10-21T16:04:04.825Z', 'updated_at': '2022-10-21T16:04:04.825Z', 'standard_id': 'relationship--7e6e58ca-9376-46c7-b5ba-9433fb881e2b', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2022-10-21T16:04:04.825Z', 'modified': '2022-10-21T16:04:04.825Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '2f004b42-a682-47b9-b2b8-23d1e7fa1667', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0cdc72ad-22b0-5eb7-a4ec-6f67115ec213', 'spec_version': '2.1', 'created_at': '2021-10-18T14:47:29.978Z', 'updated_at': '2022-04-26T08:48:23.026Z', 'name': 'BlackByte'}, 'to': {'id': '50b324ee-8819-43c0-9e81-bca50eea35eb', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--dc374f96-51cc-5e02-8b14-2af1bdcc94d1', 'spec_version': '2.1', 'created_at': '2021-03-18T09:34:17.064Z', 'updated_at': '2023-12-30T05:58:15.026Z', 'name': 'CVE-2021-26855'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '3d72f24c-6688-4edb-b5d0-eee8e025f416', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2022-10-21T16:04:06.410Z', 'updated_at': '2022-10-21T16:04:06.410Z', 'standard_id': 'relationship--a6d9b5f4-d49b-4cd4-a4d1-95f8734cbb0a', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2022-10-21T16:04:06.410Z', 'modified': '2022-10-21T16:04:06.410Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '2f004b42-a682-47b9-b2b8-23d1e7fa1667', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0cdc72ad-22b0-5eb7-a4ec-6f67115ec213', 'spec_version': '2.1', 'created_at': '2021-10-18T14:47:29.978Z', 'updated_at': '2022-04-26T08:48:23.026Z', 'name': 'BlackByte'}, 'to': {'id': 'a2fdcef2-7661-4e2f-983d-4f8b5354d23f', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--9d7d5c81-9e39-599e-a6ab-495e25b00c92', 'spec_version': '2.1', 'created_at': '2021-07-15T05:25:39.585Z', 'updated_at': '2023-12-29T05:57:45.185Z', 'name': 'CVE-2021-34473'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': 'cd0f8b87-210a-40cc-9330-b00110a58dc3', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2022-10-21T16:04:05.987Z', 'updated_at': '2022-10-21T16:04:05.987Z', 'standard_id': 'relationship--ab0b5d7f-c1bd-4d81-95ab-dab5bc423fae', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2022-10-21T16:04:05.987Z', 'modified': '2022-10-21T16:04:05.987Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '2f004b42-a682-47b9-b2b8-23d1e7fa1667', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0cdc72ad-22b0-5eb7-a4ec-6f67115ec213', 'spec_version': '2.1', 'created_at': '2021-10-18T14:47:29.978Z', 'updated_at': '2022-04-26T08:48:23.026Z', 'name': 'BlackByte'}, 'to': {'id': '86e26c99-5646-49c4-bd64-ebd2acb7559b', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--d5912f3e-bc6a-5739-b62a-1c7cdc7df1b1', 'spec_version': '2.1', 'created_at': '2021-05-12T05:23:21.751Z', 'updated_at': '2023-07-10T15:53:18.265Z', 'name': 'CVE-2021-31207'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': 'cbc4565f-e3fb-4080-998d-d32ec366d54b', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2022-10-21T16:04:06.821Z', 'updated_at': '2022-10-21T16:04:06.821Z', 'standard_id': 'relationship--e66de350-1707-4fba-838d-cbcf51a0cdad', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2022-10-21T16:04:06.821Z', 'modified': '2022-10-21T16:04:06.821Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': '2f004b42-a682-47b9-b2b8-23d1e7fa1667', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--0cdc72ad-22b0-5eb7-a4ec-6f67115ec213', 'spec_version': '2.1', 'created_at': '2021-10-18T14:47:29.978Z', 'updated_at': '2022-04-26T08:48:23.026Z', 'name': 'BlackByte'}, 'to': {'id': '07cf825b-e307-4ae5-8513-0cde6a734ebe', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--45eb2830-58b3-5286-81d6-e0ec9903ed48', 'spec_version': '2.1', 'created_at': '2021-07-15T05:25:45.758Z', 'updated_at': '2023-12-29T05:57:45.188Z', 'name': 'CVE-2021-34523'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}, {'id': '20c8310d-3527-463b-a14c-8aaf4918168f', 'entity_type': 'exploits', 'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1', 'created_at': '2024-02-05T12:43:11.614Z', 'updated_at': '2024-02-05T12:43:11.614Z', 'standard_id': 'relationship--6efe77d6-6761-4fe9-8865-c62dfb41840e', 'relationship_type': 'exploits', 'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z', 'revoked': False, 'confidence': 100, 'lang': 'en', 'created': '2024-02-05T12:43:11.614Z', 'modified': '2024-02-05T12:43:11.614Z', 'createdBy': None, 'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [], 'from': {'id': 'd8978660-9487-49d0-b837-1883940ccfa1', 'entity_type': 'Malware', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'malware--16fdbde1-1060-5e22-8e70-14d10436c47a', 'spec_version': '2.1', 'created_at': '2021-02-24T08:28:47.913Z', 'updated_at': '2024-04-11T12:07:17.743Z', 'name': 'Mispadu'}, 'to': {'id': 'a509fb11-8971-495e-93ad-f75727362e10', 'entity_type': 'Vulnerability', 'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'], 'standard_id': 'vulnerability--9aad87b6-9f9f-5fca-b6fd-f0627a095b80', 'spec_version': '2.1', 'created_at': '2023-11-14T19:41:21.617Z', 'updated_at': '2024-05-02T13:42:07.871Z', 'name': 'CVE-2023-36025'}, 'createdById': None, 'objectMarkingIds': [], 'objectLabelIds': [], 'externalReferencesIds': []}]
    #cve_list = [exp["to"]["name"] for exp in exploits_rels]
    #print(cve_list)
    #retrel = []
    #for rel in exploits_rels:
    #    print(rel["to"]["name"])

    stix_relations = opencti_api_client.stix_core_relationship.list(
        first=2,
        entity_type="communicates-with"
    )
    '''

if __name__ == "__main__":
    from stix_to_neo4j import get_sdo_observables, get_cve_sdos
    from ag_gen import draw_attack_paths
    import neo4j_backend
    from query_cti_objects import get_related_attack_patterns, get_capecs_by_cwe, query_nvd_cve, get_capec_by_stix_id
    from chaining import cve_to_capec_chain, query_group, cwe_from_cve
    from neo4j_backend import get_all_vulnerabilities, create_relation

    # Routers Test
    routers = neo4j_backend.config_example(True)

    draw_attack_paths("host_internet", 2, routers)

    # for cve_id in cve_ids:
    #    cwes = cwe_from_cve(query_nvd_cve(cve_id))
    #    print(cwes)
    #    print(query_group(cwes, get_capecs_by_cwe))

    #cve_objects = [query_nvd_cve(cve_id) for cve_id in cve_ids]

    #res = cve_to_capec_chain(cve_objects, get_capecs_by_cwe, get_related_attack_patterns)
    '''
    
    # Example usage:
    attack_patterns = get_capecs_by_cwe('1286')

    if attack_patterns:
        for ap in attack_patterns:
            if "x_capec_can_follow_refs" in ap.keys():
                print(ap["x_capec_can_follow_refs"])
            if "x_capec_can_precedes_refs" in ap.keys():
                print(ap["x_capec_can_precedes_refs"])
    else:
        print("0.")

    

    '''   '''
    
    rel = {'id': 'f9fdd15d-0509-4e36-9f86-c22fca1c7754', 'entity_type': 'based-on',
      'parent_types': ['basic-relationship', 'stix-relationship', 'stix-core-relationship'], 'spec_version': '2.1',
      'created_at': '2021-03-09T00:10:35.497Z', 'updated_at': '2021-03-09T00:10:35.497Z',
      'standard_id': 'relationship--000000c0-74ec-4517-a9c9-e0160edca644', 'relationship_type': 'based-on',
      'description': '', 'start_time': '1970-01-01T00:00:00.000Z', 'stop_time': '5138-11-16T09:46:40.000Z',
      'revoked': False, 'confidence': 0, 'lang': 'en', 'created': '2021-02-28T11:02:01.544Z',
      'modified': '2021-02-28T11:02:01.544Z', 'createdBy': {'id': '44fba35b-12b2-4511-8c4f-99a92170812a',
                                                            'standard_id': 'identity--3fd1ed93-897e-5d4c-8713-9a15a2a9070e',
                                                            'entity_type': 'Organization',
                                                            'parent_types': ['Basic-Object', 'Stix-Object',
                                                                             'Stix-Core-Object', 'Stix-Domain-Object',
                                                                             'Identity'], 'spec_version': '2.1',
                                                            'identity_class': 'organization', 'name': 'Thales',
                                                            'description': None, 'roles': None,
                                                            'contact_information': None, 'x_opencti_aliases': None,
                                                            'created': '2021-02-24T08:28:09.397Z',
                                                            'modified': '2024-03-27T17:39:04.723Z', 'objectLabel': [],
                                                            'x_opencti_organization_type': None,
                                                            'x_opencti_reliability': None, 'objectLabelIds': []},
      'objectMarking': [], 'objectOrganization': [], 'objectLabel': [], 'externalReferences': [],
      'from': {'id': 'ed71b0c9-0355-4468-8e76-04cb301dd9ca', 'entity_type': 'Indicator',
               'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
               'standard_id': 'indicator--aed71920-e4b5-52bc-a4b4-d0e296358d88', 'spec_version': '2.1',
               'created_at': '2021-03-08T20:53:26.563Z', 'updated_at': '2021-10-26T20:17:43.047Z',
               'name': '5310be36e9746e2b6bb92b225321a37b43c0b8a2c0eabe84dfe17be41c96b75f'},
      'to': {'id': '34b663cd-cc80-441b-ae64-6fdfb2ebe6ba', 'entity_type': 'StixFile',
             'parent_types': ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Cyber-Observable'],
             'standard_id': 'file--4fcf518d-3cd2-5bb4-88d8-1945bbb7a467', 'spec_version': '2.1',
             'created_at': '2021-03-08T19:38:06.333Z', 'updated_at': '2021-03-08T19:38:06.333Z',
             'observable_value': '5310be36e9746e2b6bb92b225321a37b43c0b8a2c0eabe84dfe17be41c96b75f'},
      'createdById': '44fba35b-12b2-4511-8c4f-99a92170812a', 'objectMarkingIds': [], 'objectLabelIds': [],
      'externalReferencesIds': []}

    #print(retrel)
    #print(get_sdo_observables(opencti_api_client, "3c4860af-40e5-5da1-9deb-da76b24d27fd"))

    
    '''


