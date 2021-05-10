import json
from unittest import TestCase
import requests
import os

class Test(TestCase):
    def test_domain_sentiment(self):
        url_endpoint_for_classification = "https://sentim-api.herokuapp.com/api/v1/"
        headers = {
            'Accept': 'application/json', 'Content-Type': 'application/json'
        }
        body = {
            "text": "This is a test"
        }
        response = requests.post(url_endpoint_for_classification, headers=headers, data=json.dumps(body))
        assert response.status_code == 200

    def test_get_ip_details_from_abuse_ip(self):
        api_key_abuseIP = os.getenv('api_key_abuseIP')
        url_check_endpoint_abuseIP = 'https://api.abuseipdb.com/api/v2/check'
        headers = {
            'Accept': 'application/json',
            'Key': api_key_abuseIP
        }
        query = {
            'ipAddress': '8.8.8.8',
            'maxAgeInDays': 60
        }
        response = requests.get(url=url_check_endpoint_abuseIP, headers=headers, params=query)
        assert response.status_code == 200

    def test_get_domain_report(self):
        api_key_virus_total = os.getenv('api_key_virus_total')
        url_endpoint_for_domain_report_virus_total = 'https://www.virustotal.com/vtapi/v2/domain/report'
        query = {
            'apikey': api_key_virus_total,
            'domain': 'google.com'
        }
        response = requests.get(url=url_endpoint_for_domain_report_virus_total, params=query)
        assert response.status_code == 200

    def test_extracting_ip_details_from_bad_request(self):
        json_response = {"test": "test"}
        details = {}
        if "data" in json_response.keys():
            data_subset = json_response["data"]
            details = {
                "ipaddress": data_subset["ipAddress"],
                "abuseConfidenceScore": data_subset["abuseConfidenceScore"],
                "countryCode": data_subset["countryCode"],
                "domain": data_subset["domain"],
                "numDistinctUsersReportedIp": data_subset["numDistinctUsers"],
                "lastReportedAt": data_subset["lastReportedAt"]}
            return details
        else:
            return details
        assertDictEqual(details, {})

    def test_extracting_ip_details_from_good_response(self):
        json_response = {"data": {
            "ipAddress": "ipAddress",
            "abuseConfidenceScore": "abuseConfidenceScore",
            "countryCode": "countryCode",
            "domain": "domain",
            "numDistinctUsers": "numDistinctUsers",
            "lastReportedAt": "lastReportedAt"}
        }
        details = {}
        if "data" in json_response.keys():
            data_subset = json_response["data"]
            details = {
                "ipaddress": data_subset["ipAddress"],
                "abuseConfidenceScore": data_subset["abuseConfidenceScore"],
                "countryCode": data_subset["countryCode"],
                "domain": data_subset["domain"],
                "numDistinctUsersReportedIp": data_subset["numDistinctUsers"],
                "lastReportedAt": data_subset["lastReportedAt"]}
            return details
        else:
            return details
        assertDictEquals(details, {
            "ipaddress": "ipAddress",
            "abuseConfidenceScore": "abuseConfidenceScore",
            "countryCode": "countryCode",
            "domain": "domain",
            "numDistinctUsersReportedIp": "numDistinctUsers",
            "lastReportedAt": "lastReportedAt"})
