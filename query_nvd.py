import requests


# Returns the CVE vulnerability object from NVD with the ID cve_id (ex. "CVE-2019-1010218" )
# Returns a json cve object {'cve': {'id': 'CVE-2019-1010218', ...}
# ! Is an api query which takes 5-15 seconds
def query_nvd_cve(cve_id):
    from main import DEBUG
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
# Will return None if the query fails (404 often occurs)
# ! ! CPE has to be version 2.3
def query_nvd_cpe(cpe_id):
    from main import DEBUG
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

