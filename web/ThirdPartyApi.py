import os
import requests
import json


def get_ip_details_from_abuse_ip(ipAddress):
    api_key_abuseIP = os.getenv('api_key_abuseIP')
    url_check_endpoint_abuseIP = 'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Accept': 'application/json',
        'Key': api_key_abuseIP
    }
    query = {
        'ipAddress': ipAddress,
        'maxAgeInDays': 60
    }
    response = requests.get(url=url_check_endpoint_abuseIP, headers=headers, params=query)
    decoded_response = json.loads(response.text)
    return decoded_response


def get_domain_report(domain):
    api_key_virus_total = os.getenv('api_key_virus_total')
    url_endpoint_for_domain_report_virus_total = 'https://www.virustotal.com/vtapi/v2/domain/report'
    query = {
        'apikey': api_key_virus_total,
        'domain': domain
    }
    response = requests.get(url=url_endpoint_for_domain_report_virus_total, params=query)
    return json.loads(response.text)


def extract_ip_details(ip_json_response):
    if "data" in ip_json_response.keys():
        data_subset = ip_json_response["data"]
        details = {
            "ipaddress": data_subset["ipAddress"],
            "abuseConfidenceScore": data_subset["abuseConfidenceScore"],
            "countryCode": data_subset["countryCode"],
            "domain": data_subset["domain"],
            "numDistinctUsersReportedIp": data_subset["numDistinctUsers"],
            "lastReportedAt": data_subset["lastReportedAt"]}
        return details
    else:
        return {}


def get_domain_sentiment(json_response):
    url_endpoint_for_classification = "https://sentim-api.herokuapp.com/api/v1/"
    headers = {
        'Accept': 'application/json', 'Content-Type': 'application/json'
    }
    alphaMountain = ""
    bitdefender_category = ""
    dr_web_category = ""
    forcepoint = ""
    if 'alphaMountain.ai category' in json_response.keys():
        alphaMountain = json_response["alphaMountain.ai category"].replace("/", " ")
    if 'BitDefender category' in json_response.keys():
        bitdefender_category = str(json_response["BitDefender category"]).replace("/", " ")
    if 'Dr.Web category' in json_response.keys():
        dr_web_category = json_response["Dr.Web category"].replace("/", " ")
    if 'Forcepoint ThreatSeeker category' in json_response.keys():
        forcepoint = json_response["Forcepoint ThreatSeeker category"].replace("/", " ")

    text_to_analyse = alphaMountain + " or" + bitdefender_category + " or" + dr_web_category + " or" + forcepoint
    body = {
        "text": text_to_analyse
    }
    response = requests.post(url_endpoint_for_classification, headers=headers, data=json.dumps(body))
    return json.loads(response.text)["result"]