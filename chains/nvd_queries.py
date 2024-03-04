from termios import CWERASE
import requests

from py2neo.matching import *

from chaining import create_relation

from py2neo import Graph, Node, Relationship

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
                linked_cves.append(queried_cve)
                ids_set.add(queried_cve['cve']['id'])
            else:
                print("already in it!")

    print(f"Found {len(linked_cves)} CVEs that link to the inventory.")

    # Then, for each CPE, we look if the graph meets the conditions of the
    # CVE to be considered vulnerable 
    for linked_cve in linked_cves:
        if not is_vulnerable_to(linked_cve, inventory):
            # We use the ids_set to keep the exploitable CVEs
            ids_set.remove(linked_cve['cve']['id'])
    
    print(f"{len(ids_set)} meet the vulnerability conditions ")
    return ids_set


# Inventory is a list list of CPEs in the form of strings
# CVE_object is in json format
# Returns a bool indicating whether the inventory matches the 
# vulnerability conditions of the configs in the CVE. 
def is_vulnerable_to(cve_object, inventory):
    if cve_object is None:
        return

    configurations = cve_object['cve']['configurations']
    
    for configuration in configurations: 
        # Every configuration has a list of nodes (possibly len 1)
        matched_nodes = [match_node(inventory, n) for n in configuration["nodes"]]
        # TODO: check negate
        if "operator" not in configuration.keys() or configuration["operator"] == "OR":
            if any(matched_nodes):
                link_items_to_cve(cve_object['cve']['id'])
                return True
            #return any(matched_nodes)
        elif configuration["operator"] == "AND":
            if all(matched_nodes):
                link_items_to_cve(cve_object['cve']['id'])
                return True
            else: return False



def match_node(inventory, node):
    if node["operator"] == "OR":
        for cpe_match in node["cpeMatch"]:
            # TODO: Check "vulnerable" 
            if match_cpe_criteria(inventory, cpe_match["criteria"]):
                # We stop looking after the first match. But other combinations
                # of items in the inventory could also match, which will only
                # appear after rerunning the script without the matched components
                return True
        return False
    else: # AND opertator
        for cpe_match in node["cpeMatch"]:
            # TODO: Check "vulnerable"
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
def link_items_to_cve(cve):
    global graph, node_matcher, relation_matcher, current_cpes
    print("linked item")
    for cpe in current_cpes:
        create_relation(graph, node_matcher, relation_matcher, cpe, cve, "vulnerable_to")
    current_cpes = []


# UPLOAD CWE Chains to Neo4J server
neo4j_uri = "bolt://localhost:7687"  # NEO4J URI
neo4j_user = "phil"        # NEO4J USERNAME
neo4j_password = "adminphil"    # NEO4J PASSWORD

# GLOBAL VARS
graph = Graph(neo4j_uri, auth=(neo4j_user, neo4j_password))
node_matcher = NodeMatcher(graph)
relation_matcher = RelationshipMatcher(graph)

# ! if threaded extension: each thread needs its own current_cpes var
# This global array stores the CPEs that are involved 
current_cpes = []


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
    
    inventory = ["cpe:2.3:o:microsoft:windows_server_2008:*:sp2:x32:*:*:*:*:*",
                 "cpe:2.3:a:skype_technologies:skype:3.6:*:*:*:*:*:*:*",
                 "cpe:2.3:o:microsoft:windows_server_2003:*:sp2:*:*:*:*:*:*",
                 "cpe:2.3:a:microsoft:internet_explorer:7.00.6000.16441:*:*:*:*:*:*:*",
                 "cpe:2.3:a:microsoft:internet_explorer:8.0.6001:2:5:69:*:*:*:*"]
    cve_obj = {'cve': {'id': 'CVE-2019-1010218', 'sourceIdentifier': 'josh@bress.net', 'published': '2019-07-22T18:15:10.917', 'lastModified': '2020-09-30T13:40:18.163', 'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': "Cherokee Webserver Latest Cherokee Web server Upto Version 1.2.103 (Current stable) is affected by: Buffer Overflow - CWE-120. The impact is: Crash. The component is: Main cherokee command. The attack vector is: Overwrite argv[0] to an insane length with execl. The fixed version is: There's no fix yet."}, {'lang': 'es', 'value': 'El servidor web de Cherokee más reciente de Cherokee Webserver Hasta Versión 1.2.103 (estable actual) está afectado por: Desbordamiento de Búfer - CWE-120. El impacto es: Bloqueo. El componente es: Comando cherokee principal. El vector de ataque es: Sobrescribir argv[0] en una longitud no sana con execl. La versión corregida es: no hay ninguna solución aún.'}], 'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'HIGH', 'baseScore': 7.5, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 3.9, 'impactScore': 3.6}], 'cvssMetricV2': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '2.0', 'vectorString': 'AV:N/AC:L/Au:N/C:N/I:N/A:P', 'accessVector': 'NETWORK', 'accessComplexity': 'LOW', 'authentication': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'PARTIAL', 'baseScore': 5.0}, 'baseSeverity': 'MEDIUM', 'exploitabilityScore': 10.0, 'impactScore': 2.9, 'acInsufInfo': False, 'obtainAllPrivilege': False, 'obtainUserPrivilege': False, 'obtainOtherPrivilege': False, 'userInteractionRequired': False}]}, 'weaknesses': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-787'}]}, {'source': 'josh@bress.net', 'type': 'Secondary', 'description': [{'lang': 'en', 'value': 'CWE-120'}]}], 'configurations': config_obj, 'references': [{'url': 'https://i.imgur.com/PWCCyir.png', 'source': 'josh@bress.net', 'tags': ['Exploit', 'Third Party Advisory']}]}}
    node_obj = {"operator":"OR","negate":False,"cpeMatch":[{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:5.01:sp4:*:*:*:*:*:*","matchCriteriaId":"F3F2A51E-2675-4993-B9C2-F2D176A92857"},{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:*:*:*:*:*:*:*","matchCriteriaId":"693D3C1C-E3E4-49DB-9A13-44ADDFF82507"},{"vulnerable":True,"criteria":"cpe:2.3:a:microsoft:internet_explorer:6:sp1:*:*:*:*:*:*","matchCriteriaId":"D47247A3-7CD7-4D67-9D9B-A94A504DA1BE"}]}
    cpe = "cpe:2.3:a:cherokee-project:cherokee_web_server:*:*:*:*:*:*:*:*"
    #print(cve_obj)
    #print(is_vulnerable_to(cve_obj, inventory))
    
    #print(is_vulnerable_to(cve_obj, inventory))

    print(find_vulnerabilities(inventory))

    #cve_instance = {'cve': {'id': 'CVE-2010-0302', 'sourceIdentifier': 'secalert@redhat.com', 'published': '2010-03-05T19:30:00.437', 'lastModified': '2024-02-03T02:22:17.867', 'vulnStatus': 'Analyzed', 'descriptions': [{'lang': 'en', 'value': 'Use-after-free vulnerability in the abstract file-descriptor handling interface in the cupsdDoSelect function in scheduler/select.c in the scheduler in cupsd in CUPS before 1.4.4, when kqueue or epoll is used, allows remote attackers to cause a denial of service (daemon crash or hang) via a client disconnection during listing of a large number of print jobs, related to improperly maintaining a reference count. NOTE: some of these details are obtained from third party information. NOTE: this vulnerability exists because of an incomplete fix for CVE-2009-3553.'}, {'lang': 'es', 'value': 'Vulnerabilidad de uso despues de liberacion en el interfaz de gestion de descriptores de fichero en la funcion cupsdDoSelect en  scheduler/select.c en the scheduler en cupsd en CUPS v1.3.7, v1.3.9, v1.3.10, y v1.4.1, cuando se utiliza kqueue o epoll, permite a atacantes remotos producir una denegacion de servicio (caida de demonio o cuelgue) a traves de la desconexion del cliente durante el listado de un gran numero de trabajos de imporesion, relacionados con el inadecuado mantenimiento del numero de referencias. NOTA: Algunos de los detalles fueron obtenidos de terceras partes. NOTA; Esta vulnerabilidad se ha producido por un arreglo incompleto de CVE-2009-3553.'}], 'metrics': {'cvssMetricV31': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '3.1', 'vectorString': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H', 'attackVector': 'NETWORK', 'attackComplexity': 'LOW', 'privilegesRequired': 'NONE', 'userInteraction': 'NONE', 'scope': 'UNCHANGED', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'HIGH', 'baseScore': 7.5, 'baseSeverity': 'HIGH'}, 'exploitabilityScore': 3.9, 'impactScore': 3.6}], 'cvssMetricV2': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'cvssData': {'version': '2.0', 'vectorString': 'AV:N/AC:M/Au:N/C:N/I:N/A:P', 'accessVector': 'NETWORK', 'accessComplexity': 'MEDIUM', 'authentication': 'NONE', 'confidentialityImpact': 'NONE', 'integrityImpact': 'NONE', 'availabilityImpact': 'PARTIAL', 'baseScore': 4.3}, 'baseSeverity': 'MEDIUM', 'exploitabilityScore': 8.6, 'impactScore': 2.9, 'acInsufInfo': False, 'obtainAllPrivilege': False, 'obtainUserPrivilege': False, 'obtainOtherPrivilege': False, 'userInteractionRequired': False}]}, 'weaknesses': [{'source': 'nvd@nist.gov', 'type': 'Primary', 'description': [{'lang': 'en', 'value': 'CWE-416'}]}], 'configurations': [{'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*', 'versionEndExcluding': '1.4.4', 'matchCriteriaId': '9779FF46-9FB1-4F6A-8633-AC5D3FB5A96C'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*', 'versionEndExcluding': '10.5.8', 'matchCriteriaId': '80C038E4-C24D-45E9-8287-C205C0C07809'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x:*:*:*:*:*:*:*:*', 'versionStartIncluding': '10.6.0', 'versionEndExcluding': '10.6.4', 'matchCriteriaId': '25512493-BB20-46B2-B40A-74E67F0797B6'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x_server:*:*:*:*:*:*:*:*', 'versionEndExcluding': '10.5.8', 'matchCriteriaId': '7F89C200-D340-4BB4-BC82-C26629184C5C'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:apple:mac_os_x_server:*:*:*:*:*:*:*:*', 'versionStartIncluding': '10.6.0', 'versionEndExcluding': '10.6.4', 'matchCriteriaId': 'CD7461BE-1CAC-46D6-95E6-1B2DFC5A4CCF'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:fedoraproject:fedora:11:*:*:*:*:*:*:*', 'matchCriteriaId': 'B3BB5EDB-520B-4DEF-B06E-65CA13152824'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:6.06:*:*:*:*:*:*:*', 'matchCriteriaId': '454A5D17-B171-4F1F-9E0B-F18D1E5CA9FD'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:8.04:*:*:*:-:*:*:*', 'matchCriteriaId': '7EBFE35C-E243-43D1-883D-4398D71763CC'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:8.10:*:*:*:*:*:*:*', 'matchCriteriaId': '4747CC68-FAF4-482F-929A-9DA6C24CB663'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:9.04:*:*:*:*:*:*:*', 'matchCriteriaId': 'A5D026D0-EF78-438D-BEDD-FC8571F3ACEB'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:canonical:ubuntu_linux:9.10:*:*:*:*:*:*:*', 'matchCriteriaId': 'A2BCB73E-27BB-4878-AD9C-90C4F20C25A0'}]}]}, {'nodes': [{'operator': 'OR', 'negate': False, 'cpeMatch': [{'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '1D8B549B-E57B-4DFE-8A13-CAB06B5356B3'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_desktop:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '133AAFA7-AF42-4D7B-8822-AA2E85611BF5'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_eus:5.4:*:*:*:*:*:*:*', 'matchCriteriaId': '4DD6917D-FE03-487F-9F2C-A79B5FCFBC5A'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_server:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': '54D669D4-6D7E-449D-80C1-28FA44F06FFE'}, {'vulnerable': True, 'criteria': 'cpe:2.3:o:redhat:enterprise_linux_workstation:5.0:*:*:*:*:*:*:*', 'matchCriteriaId': 'D0AC5CD5-6E58-433C-9EB3-6DFE5656463E'}]}]}], 'references': [{'url': 'http://cups.org/articles.php?L596', 'source': 'secalert@redhat.com', 'tags': ['Release Notes']}, {'url': 'http://cups.org/str.php?L3490', 'source': 'secalert@redhat.com', 'tags': ['Release Notes']}, {'url': 'http://lists.apple.com/archives/security-announce/2010//Jun/msg00001.html', 'source': 'secalert@redhat.com', 'tags': ['Mailing List']}, {'url': 'http://lists.fedoraproject.org/pipermail/package-announce/2010-March/037174.html', 'source': 'secalert@redhat.com', 'tags': ['Mailing List']}, {'url': 'http://secunia.com/advisories/38785', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/38927', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/38979', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://secunia.com/advisories/40220', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://security.gentoo.org/glsa/glsa-201207-10.xml', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}, {'url': 'http://support.apple.com/kb/HT4188', 'source': 'secalert@redhat.com', 'tags': ['Vendor Advisory']}, {'url': 'http://www.mandriva.com/security/advisories?name=MDVSA-2010:073', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'http://www.securityfocus.com/bid/38510', 'source': 'secalert@redhat.com', 'tags': ['Broken Link', 'Third Party Advisory', 'VDB Entry']}, {'url': 'http://www.securitytracker.com/id?1024124', 'source': 'secalert@redhat.com', 'tags': ['Broken Link', 'Third Party Advisory', 'VDB Entry']}, {'url': 'http://www.ubuntu.com/usn/USN-906-1', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}, {'url': 'http://www.vupen.com/english/advisories/2010/1481', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'https://bugzilla.redhat.com/show_bug.cgi?id=557775', 'source': 'secalert@redhat.com', 'tags': ['Issue Tracking', 'Patch']}, {'url': 'https://oval.cisecurity.org/repository/search/definition/oval%3Aorg.mitre.oval%3Adef%3A11216', 'source': 'secalert@redhat.com', 'tags': ['Broken Link']}, {'url': 'https://rhn.redhat.com/errata/RHSA-2010-0129.html', 'source': 'secalert@redhat.com', 'tags': ['Third Party Advisory']}]}}
    #print(cwe_from_cve(cve_obj))

