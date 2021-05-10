import logging
from datetime import datetime
from flask import Flask, request
from flask_restful import Api, Resource
from pymongo import MongoClient
from ThirdPartyApi import get_domain_report, get_ip_details_from_abuse_ip, get_domain_sentiment, extract_ip_details

app = Flask(__name__)
api = Api(app)

client = MongoClient("mongodb://my_db:27017")
db = client.projectDB
Saved_IPs = db["Saved_IPs"]
domains = db["Domains"]


def does_domain_exist_in_database(domain):
    if domains.count_documents({"Domains": domain}) == 0:
        return False
    else:
        return True


def is_ip_in_database(ip):
    if Saved_IPs.count_documents({"Saved_IPs": ip}) == 0:
        return False
    else:
        return True


def get_domain_sentiment_from_db(domain):
    return domains.find({"Domains": domain, })[0]["Sentiment"]


def get_ip_sentiment_from_db(ip):
    return Saved_IPs.find({"Saved_IPs": ip, })[0]["Details"]


class LookUpDomain(Resource):
    def post(self):
        data = request.get_json()
        domain = data["domain"]
        if not domain:
            return {
                "status": 303,
                "msg": "Supply a valid Domain"
            }

        if not does_domain_exist_in_database(domain):
            try:
                domains.insert_one({"Domains": domain,
                                    "Sentiment": []})
                response = get_domain_report(domain)
                sentiment = get_domain_sentiment(response)
                sentiment["LastUpdated"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                domains.update_one({
                    "Domains": domain
                }, {
                    "$set": {
                        "Sentiment": sentiment,
                    }
                })
                return {
                    "status": 200,
                    "obj": sentiment}
            except Exception as e:
                domains.delete_one({"Domains": domain})
                logging.error(e)
        else:
            return {
                "status": 200,
                "obj": get_domain_sentiment_from_db(domain),
            }


class LookUpIP(Resource):
    def post(self):
        data = request.get_json()
        ip = data["ip"]

        if not ip:
            return {
                "status": 303,
                "msg": "Supply a valid IP address"
            }

        if not is_ip_in_database(ip):
            try:
                Saved_IPs.insert_one({"Saved_IPs": ip,
                                      "Details": {}})
                response = get_ip_details_from_abuse_ip(ip)
                extracted_details = extract_ip_details(response)
                extracted_details["LastUpdated"] = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
                Saved_IPs.update_one({
                    "Saved_IPs": ip
                }, {
                    "$set": {
                        "Details": dict(extracted_details),

                    }
                })
                return {
                    "status": 200,
                    "obj": dict(extracted_details)
                }

            except Exception as e:
                Saved_IPs.delete_one({"Saved_IPs": ip})
                logging.error(e)
        else:
            return {
                "status": 200,
                "obj": get_ip_sentiment_from_db(ip)}

class ClearDatabase(Resource):
    def get(self):
        domains.delete_many({})
        Saved_IPs.delete_many({})
        return {
            "status": 200,
            "obj": "All the data has been cleared"}

api.add_resource(LookUpIP, "/lookupip")
api.add_resource(LookUpDomain, "/lookupdomain")
api.add_resource(ClearDatabase,"/cleardb")

if __name__ == "__main__":
    app.run(host='0.0.0.0', debug=True)
