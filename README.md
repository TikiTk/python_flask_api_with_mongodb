# This application makes a request to 3rd party API then does sentiment analysis on the responses to classify the result 

The python scripts can be ran as standalone scripts or the entire application can be ran using docker.

The following commands can be used to bring up the docker environment

```docker-compose build``` in the root folder for the application followed by ```docker-compose up```

## Dependencies
The application requires a VirusTotal API key and an AbuseIPDB API Key. The can be found at [VirusTotal](https://www.virustotal.com/gui/) and [AbuseIPDB](https://www.abuseipdb.com/)

The API keys should be stored in an ```.env``` file in the root folder of the project.
