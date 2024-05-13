import requests
from main import DEBUG

from stix2 import FileSystemSource, Filter


# Returns the CVE vulnerability object from NVD with the ID cve_id (ex. "CVE-2019-1010218" )
# Returns a json cve object {'cve': {'id': 'CVE-2019-1010218', ...}
# ! Is an api query which can take 5-15 seconds
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

        # Check if the response contains CVE data
        if "vulnerabilities" in cve_data:
            # cve_data["vulnerabilities"] returns a list like [{'cve': {'id': 'CVE-2019-1010218', ...}, ...]
            # As we always only query one object, this list is always of size 1
            return cve_data["vulnerabilities"][0]
        else:
            print("No CVE data found for", cve_id)
            return None

    except requests.exceptions.RequestException as e:
        if DEBUG:
            print("Error querying NVD API:", e)
        return None


# Returns a list of CVE objects that are associated to cpe_id in
# any semantic by the NVD.
# Can return huge amounts of CVEs
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
            if DEBUG:
                print("No CVE data found for ", cpe_id)
            return None

    except requests.exceptions.RequestException as e:
        if DEBUG:
            print("Error querying NVD API for ", cpe_id, ": ", e)
        return None


# Following function query the STIX-encoded CAPEC knowledge base
# https://github.com/mitre/cti/tree/master/capec
fs = FileSystemSource('../cti-extensions/capec/2.1')


# Returns the CAPEC object encoded in STIX with the string number id
# capec_id (ex. '66').
# Is of type AttackPattern
# Code reused from https://github.com/mitre/cti/blob/master/USAGE-CAPEC.md
def get_capec_by_capec_id(capec_id):
    capec_id = "CAPEC-" + capec_id
    filt = [
      Filter('type', '=', 'attack-pattern'),
      Filter('external_references.external_id', '=', capec_id),
      Filter('external_references.source_name', '=', 'capec'),
    ]
    return fs.query(filt)


# Returns the CAPEC object encoded in STIX with the string number id
# stix_id (ex. 'attack-pattern--70c8a212-72da-4a98-a626-e5d38e5416e3').
# Is of type AttackPattern
# Code adapted from get_capec_by_capec_id()
def get_capec_by_stix_id(stix_id):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('id', '=', stix_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    return fs.query(filt)


# Returns the list of CAPEC objects encoded in STIX that have the CWE
# cwe_id (ex.'66') as external reference
def get_capecs_by_cwe(cwe_id, onlyIds=False):
    # TODO: make sure to only capec objects
    filt = [
        Filter("type", "=", "attack-pattern"),
        Filter("external_references.external_id", "=", f"CWE-{cwe_id}"),
        Filter("external_references.source_name", "=", "cwe"),
    ]
    aps = fs.query(filt)
    # we use 0 as index as the first external reference is always the CAPEC ID
    return [ap["external_references"][0]["external_id"] for ap in aps] if onlyIds else aps


# Returns the list of CAPEC objects encoded in STIX that are children of
# the inputted capec_id (ex. '66').
# relationship is the type of link "eg. x_capec_can_precede_refs"
# The CAPEC with id capec_id has a parentOf rel with the returned objects
def get_related_attack_patterns(capec_id, relationship, onlyIds=False):
    # Get the CAPEC object with the specified ID
    capec_object = get_capec_by_capec_id(capec_id)
    if capec_object:
        capec_object[0]
    else:
        return []

    # Extract child CAPEC IDs from the x_capec_child_of_refs property
    related_capec_ids = capec_object.get(relationship, [])

    # Build a filter to retrieve child CAPEC objects
    filt = [
        Filter("type", "=", "attack-pattern"),
        Filter("id", "in", related_capec_ids),
    ]
    aps = fs.query(filt)
    # we use 0 as index as the first external reference is always the CAPEC ID
    return [ap["external_references"][0]["external_id"] for ap in aps] if onlyIds else aps



