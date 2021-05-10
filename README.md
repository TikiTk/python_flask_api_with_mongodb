# This application makes a request to 3rd party API then does sentiment analysis on the responses to classify the result 

The python scripts can be ran as standalone scripts or the entire application can be ran using docker.

The following commands can be used to bring up the docker environment

```docker-compose build``` in the root folder for the application followed by ```docker-compose up```

## Dependencies
The application requires a VirusTotal API key and an AbuseIPDB API Key. The can be found at [VirusTotal](https://www.virustotal.com/gui/) and [AbuseIPDB](https://www.abuseipdb.com/)

The API keys should be stored in an ```.env``` file in the root folder of the project.

### Application Endpoints

The application has three endpoints which are:
* GET localhost:5000/cleardb - this clears all data within the database
* POST localhost:5000/lookupip - this checks if a previously reported IP is in the database, otherwise it does a lookup to AbuseIPDB then stores important fields from the response
* POST localhost:5000/lookupdomain - this checks if a previously reported domain is in the database, otherwise it does a lookup to VirusTotal then parses the data for specific fields which it then sends to another 3rd party API for sentiment analysis then stores the result

The request bodies of the POST endpoints require the following payloads for IP lookup and Domain Lookup respectively

Domain lookup ```{"domain":"A-DOMAIN"}```
IP lookup ```{"ip":"A-IPV4 or IPV6 IP}```

With Content-Type set to application/json

