#!/bin/bash
 
URI='https://www.virustotal.com/vtapi/v2/domain/report?'
KEY="apikey=d8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8"
INPUT=$1
DOMAIN="domain=${INPUT}"
REQ="${URI}${KEY}&${DOMAIN}"
echo "Fetch Request: $REQ"
curl -v --request GET  --url ${REQ}
