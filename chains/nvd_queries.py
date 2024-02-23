from termios import CWERASE
import requests

from cwe2.database import Database

from py2neo import Graph, Node, Relationship

from py2neo.matching import *

import json

# Returns the CVE vulnerabilities from NVD with the ID cve_id (ex. "CVE-2019-1010218" )
# Returns a list of json cves [{'cve': {'id': 'CVE-2019-1010218', ...}, ...], has only 
# one element most of the time 
def query_nvd_for_cveid(cve_id):
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
            return cve_data["vulnerabilities"]
        else:
            print("No CVE data found for", cve_id)
            return None

    except requests.exceptions.RequestException as e:
        print("Error querying NVD API:", e)
        return None

# Takes json object and extracts the CWEs it is linked to
# TODO: Returns a list of ints that are CWE Ids
def cwe_from_cve(cve_object):
    if cve_object is None:
        return []
    
    if len(cve_object) == 1:
        cve_object = cve_object[0]

    cwe_list = []

    object_weaknesses = cve_object['cve']['weaknesses']

    for weakness in object_weaknesses:
        cwe_id = weakness["description"][0]["value"]
        if not cwe_id[:3] == "CWE":
            print("Error")
        else:
            cwe_list += [cwe_id]
        
    return cwe_list

# Takes a neo4j network attack graph and probes if it matches the vulnerability
# conditions declared by the inputted CVE
def is_graph_vulnerable(graph, cve_object):
    if cve_object is None:
        return

    if len(cve_object) == 1:
        cve_object = cve_object[0]

    configurations = cve_object['cve']['configurations']

    for configuration_node in configurations:
        cpe_match = configuration_node["cpeMatch"]
        # - 'negate'?
        if configuration_node["operator"] == "OR":
            # look if graph holds any of the cpes
            for cpe in configuration_node["cpeMatch"]:
                # - 'vulnerable'?
                # regex with criteria 
                cpe["criteria"]
                # if match
                    # add CVE to graph
                    # continue to next node
        
        elif configuration_node["operator"] == "AND":
            for cpe in configuration_node["cpeMatch"]:
                # - 'vulnerable'?
                # regex with criteria
                cpe["criteria"]
                # if not match
                    # continue to next node
            # if all match then add to the graph
            


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

# Checks if nodes and relation (node1->node2) already exists and only 
# adds to graph (node4j) what is lacking
# node1, node2 are int ids of CWE nodes to be added
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
            

unextracted_cwes = [] # CWEs for which the query was unsuccessful
created_nodes = [] # nodes that were added to neo4j

if __name__ == "__main__":
    '''
    # UPLOAD CWE Chains to Neo4J server
    neo4j_uri = "bolt://localhost:7687"  # NEO4J URI
    neo4j_user = "phil"        # NEO4J USERNAME
    neo4j_password = "adminphil"    # NEO4J PASSWORD

    graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))

    db = Database()
    
    simple_chains_to_neo4j(graph, db, range(0,600))

    print(f"{len(unextracted_cwes)} CWEs could not be extracted.")
    print(f"The following Nodes were added: {created_nodes}")

    '''
    #halal = query_nvd_for_cveid("CVE-2010-0302")
    #print(halal)
    halal = {'resultsPerPage': 1, 'startIndex': 0, 'totalResults': 1, 'format': 'NVD_CVE', 'version': '2.0', 'timestamp': '2024-02-23T15:34:22.907', 'vulnerabilities': [{'cve': {'id': 'CVE-2010-0302', 'sourceIdentifier': 'secalert@redhat.com', 'published': '2010-03-05T19:30:00.437', 'lastModified': '2024-02-03T02:22:17.867', 'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': 'Use-after-free vulnerability in the abstract file-descriptor handling interface in the cupsdDoSelect function in scheduler/select.c in the scheduler in cupsd in CUPS before 1.4.4, when kqueue or epoll is used, allows remote attackers to cause a denial of service (daemon crash or hang) via a client disconnection during listing of a large number of print jobs, related to improperly maintaining a reference count. NOTE: some of these details are obtained from third party information. NOTE: this vulnerability exists because of an incomplete fix for CVE-2009-3553.'}, {'lang': 'es', 'value': 'Vulnerabilidad de uso despues de liberacion en el interfaz de gestion de descriptores de fichero en la funcion cupsdDoSelect en  scheduler/select.c en the scheduler en cupsd en CUPS v1.3.7, v1.3.9, v1.3.10, y v1.4.1, cuando se utiliza kqueue o epoll, permite a atacantes remotos producir una denegacion de servicio (caida de demonio o cuelgue) a traves de la desconexion del cliente durante el listado de un gran numero de trabajos de imporesion, relacionados con el inadecuado mantenimiento del numero de referencias. NOTA: Algunos de los detalles fueron obtenidos de terceras partes. NOTA; Esta vulnerabilidad se ha producido por un arreglo incompleto de CVE-2009-3553.'}], 'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'HIGH', 'baseScore': 7.5, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 3.9, 'impactScore': 3.6}], 'cvssMetricV2': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '2.0', 'vectorString': 'AV:N/AC:M/Au:N/C:N/I:N/A:P', 'accessVector': 'NETWORK', 'accessComplexity': 'MEDIUM', 'authentication': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'PARTIAL', 'baseScore': 4.3}, 'baseSeverity': 'MEDIUM', 'exploitabilityScore': 8.6, 'impactScore': 2.9, 'acInsufInfo': False, 'obtainAllPrivilege': False, 'obtainUserPrivilege': False, 'obtainOtherPrivilege': False, 'userInteractionRequired': False}]}, 'weaknesses': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-416'}]}], 'configurations': [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*', 'versionEndExcluding': '1.4.4', 'matchCriteriaId': '9779FF46-9FB1-4F6A-8633-AC5D3FB5A96C'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*', 'versionEndExcluding': '10.5.8', 'matchCriteriaId': '80C038E4-C24D-45E9-8287-C205C0C07809'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*', 'versionStartIncluding': '10.6.0', 'versionEndExcluding': '10.6.4', 'matchCriteriaId': '25512493-BB20-46B2-B40A-74E67F0797B6'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x_server:*:*:*:*:*:*:*:*', 'versionEndExcluding': '10.5.8', 'matchCriteriaId': '7F89C200-D340-4BB4-BC82-C26629184C5C'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x_server:*:*:*:*:*:*:*:*', 'versionStartIncluding': '10.6.0', 'versionEndExcluding': '10.6.4', 'matchCriteriaId': 'CD7461BE-1CAC-46D6-95E6-1B2DFC5A4CCF'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:fedoraproject:fedora:11:*:*:*:*:*:*:*', 'matchCriteriaId': 'B3BB5EDB-520B-4DEF-B06E-65CA13152824'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:6.06:*:*:*:*:*:*:*', 'matchCriteriaId': '454A5D17-B171-4F1F-9E0B-F18D1E5CA9FD'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:8.04:*:*:*:-:*:*:*', 'matchCriteriaId': '7EBFE35C-E243-43D1-883D-4398D71763CC'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:8.10:*:*:*:*:*:*:*', 'matchCriteriaId': '4747CC68-FAF4-482F-929A-9DA6C24CB663'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:9.04:*:*:*:*:*:*:*', 'matchCriteriaId': 'A5D026D0-EF78-438D-BEDD-FC8571F3ACEB'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:9.10:*:*:*:*:*:*:*', 'matchCriteriaId': 'A2BCB73E-27BB-4878-AD9C-90C4F20C25A0'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '1D8B549B-E57B-4DFE-8A13-CAB06B5356B3'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_desktop:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '133AAFA7-AF42-4D7B-8822-AA2E85611BF5'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_eus:5.4:*:*:*:*:*:*:*', 'matchCriteriaId': '4DD6917D-FE03-487F-9F2C-A79B5FCFBC5A'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_server:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '54D669D4-6D7E-449D-80C1-28FA44F06FFE'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_workstation:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': 'D0AC5CD5-6E58-433C-9EB3-6DFE5656463E'}]}]}], 'references': [{'url': 'http://cups.org/articles.php?L596', 'source': 'secalert@redhat.com', 'tags': ['Release Notes']}, {'url': 'http://cups.org/str.php?L3490', 'source': 'secalert@redhat.com', 'tags': ['Release Notes']}, {'url': 'http://lists.apple.com/archives/security-announce/2010//Jun/msg00001.html', 'source': 'secalert@redhat.com', 'tags': ['Mailing List']}, {'url': 'http://lists.fedoraproject.org/pipermail/package-announce/2010-March/037174.html', 'source': 'secalert@redhat.com', 'tags': ['Mailing List']}, {'url': 'http://secunia.com/advisories/38785', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/38927', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/38979', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/40220', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://security.gentoo.org/glsa/glsa-201207-10.xml', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}, {'url': 'http://support.apple.com/kb/HT4188', 'source': 'secalert@redhat.com', 'tags': ['Vendor Advisory']}, {'url': 'http://www.mandriva.com/security/advisories?name=MDVSA-2010:073', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://www.securityfocus.com/bid/38510', 'source': 'secalert@redhat.com', 'tags': ['Broken Link', 'Third Party Advisory', 'VDB Entry']}, {'url': 'http://www.securitytracker.com/id?1024124', 'source': 'secalert@redhat.com', 'tags': ['Broken Link', 'Third Party Advisory', 'VDB Entry']}, {'url': 'http://www.ubuntu.com/usn/USN-906-1', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}, {'url': 'http://www.vupen.com/english/advisories/2010/1481', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'https://bugzilla.redhat.com/show_bug.cgi?id=557775', 'source': 'secalert@redhat.com', 'tags': ['Issue Tracking', 'Patch']}, {'url': 'https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A11216', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'https://rhn.redhat.com/errata/RHSA-2010-0129.html', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}]}}]}
    
    is_graph_vulnerable("", halal["vulnerabilities"])
