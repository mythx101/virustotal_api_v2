#!/usr/bin/env python
#author: Alan Lee
# VTClassifier.py - Use Virustotal Database to classify malware


import json as simplejson
import urllib
import urllib2
import sys
import getopt
import postfile #requires postfile.py to be installed (get from http://code.activestate.com/recipes/146306/)
import time
import os
import requests
import magic

myapikey = 'd8a3b280436173ab539d748127a0c3f22f8eda6a2ed0c41872a667dd943dabf8'
num_detected = 0
num_not_detected = 0
num_not_seen = 0
crdfcount = 0

proxies = { "http://proxy.labs.localsite.sophos:8080", "https://proxy.labs.localsite.sophos:8080" }

class Usage(Exception):
    def __init__(self, msg):
        self.msg = msg

def main(argv=None):

    if argv is None:
        argv = sys.argv
    try:
        try:
            opts, args = getopt.getopt(argv[1:], "r:s:g:l:d:u:v:f:b:n:z:m:", ["rescan=", "submit=", "getreport=", "file=", "dir=", "gurl=", "surl=", "urlfile=", "behav=", "network=", "cluster=", "surl=", "massrescan="])
        except getopt.error, msg:
             raise Usage(msg)

        for opt, arg in opts:
            if opt in ("-r", "--rescan"):
                rescanhash = arg
                rescan(rescanhash)
            elif opt in ("-s", "--submit"):
                submitfile = arg
                submitscan(submitfile)
            elif opt in ("-g", "--getreport"):
                getreporthash = arg
                getreport(getreporthash)
            elif opt in ("-l", "--list"):
                fileloc = arg
                masshashes(fileloc)
            elif opt in ("-d", "--dir"):
                dirloc = arg
                massfiles(dirloc)
            elif opt in ("-u", "--gurl"):
                geturl = arg
                geturlreport(geturl)
            elif opt in ("-f", "--urlfile"):
                geturlfile = arg
                massurl(geturlfile)
            elif opt in ("-z", "--surl"):
                geturlfile = arg
                submitmassurl(geturlfile)
            elif opt in ("-b", "--behav"):
                filebehavhash = arg
                getfilebehav(filebehavhash)
            elif opt in ("-n", "--network"):
                networkhash = arg
                getnetwork(networkhash)
            elif opt in ("-m", "--massrescan"):
                gethashfile = arg
                massrescanhashes(gethashfile)

            
    except Usage, err:
        print >> sys.stderr, err.msg
        print >> sys.stderr, ""
        print >> sys.stderr, "Usage: VTClassifier.py -r [md5/sha2 hash] -- to rescan a file already in Virustotal"
        print >> sys.stderr, "       VTClassifier.py -m [file location] -- to submit a file of hash to rescan in Virustotal"
        print >> sys.stderr, "       VTClassifier.py -s [file location] -- to submit a file to Virustotal"
        print >> sys.stderr, "       VTClassifier.py -g [md5/sha2 hash] -- to get a report from Virustotal"
        print >> sys.stderr, "       VTClassifier.py -l [text file] -- to send a list of md5 hashes to Virustotal"
        print >> sys.stderr, "       VTClassifier.py -d [directory] -- to submit a folder of files to Virustotal"
        print >> sys.stderr, "       VTClassifier.py -u [URL] -- to get a URL report from Virustotal"
        print >> sys.stderr, "       VTClassifier.py -f [text file] -- to send a list of URLs to Virustotal"
        print >> sys.stderr, "       VTClassifier.py -z [text file] -- to submit list of URLs to Virustotal"
        print >> sys.stderr, "       VTClassifier.py -b [md5/sha2 hash] -- get report about behaviour of a file when executed in a sandboxed environment"
        print >> sys.stderr, "       VTClassifier.py -n [md5/sha2 hash] -- get dump of network traffic genenrated by sample when executed"
        return 2

# submit hash to VT for rescan
def rescan (samplehash):
    url = "https://www.virustotal.com/vtapi/v2/file/rescan"
    parameters = {"resource": samplehash, "apikey": myapikey, "proxies": proxies}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)

    try: 
        response = urllib2.urlopen(req)
    except urllib2.HTTPError, e:
        print "HTTP error : " + str(e.code)
    except urllib2.URLError, e:
        print "URL error : " + str(e.reason)
    except httplib.HTTPException, e:
        print "HTTP Exception error"
    except Exception:
        print "Unknown error"
    
    json = response.read()

    #print json

    # parse results from Virustotal
    #process_result(json)

    return;

# submit single file to VT
def submitscan (samplefile):
    host = "www.virustotal.com"
    selector = "https://www.virustotal.com/vtapi/v2/file/scan"
    fields = [("apikey", myapikey)]
    print "Sending " + samplefile + " to Virustotal"
    file_to_send = open(samplefile, "rb").read()
    files = [("file", samplefile, file_to_send)]
    json = postfile.post_multipart(host, selector, fields, files)

    # parse results from Virustotal
    #print json

    try:

        response_dict = simplejson.loads(json)

    	sha256hash = response_dict.get("sha256", {})

    	#write sha256 to text file for later processing

    	f = open("submittedfiles.txt", "a+")
    	f.write(sha256hash+"\n")
    	f.close()

    	f2 = open("submittedfilenames.txt", "a+")
    	f2.write(samplefile+";"+sha256hash+"\n")
    	f2.close()

    except:

        print "Error: Unable to process JSON due to unknown errors"

    return;

# obtain json report from VT with hash submission
def getreport (samplehash):
    url = "https://www.virustotal.com/vtapi/v2/file/report"
    parameters = {"resource": samplehash, "apikey": myapikey, "proxies": proxies}
    data = urllib.urlencode(parameters)
    req = urllib2.Request(url, data)

    try: 
        response = urllib2.urlopen(req)
        print response
    except urllib2.HTTPError, e:
        print "HTTP error : " + str(e.code)
    except urllib2.URLError, e:
        print "URL error : " + str(e.reason)
    except httplib.HTTPException, e:
        print "HTTP Exception error"
    except Exception:
        print "Unknown error"
    
    json = response.read()

    # parse result from Virustotal
    #print json
    process_result(json)

    return;


# obtain file behaviour report from VT with hash submission
def getfilebehav(samplehash):
    url = "https://www.virustotal.com/vtapi/v2/file/behaviour"
    parameters = {"apikey": myapikey, "hash": samplehash, "proxies": proxies}
    response = requests.get(url, params=parameters)
    json_response = response.json()

    try:
        json_response = response.json()
        print json_response
    except urllib2.HTTPError, e:
        print "HTTP error : " + str(e.code)
    except urllib2.URLError, e:
        print "URL error : " + str(e.reason)
    except httplib.HTTPEXception, e:
        print "HTTP Execption error"
    except Exception:
        print "Unknown error"

    #json = response.read()
    #print json
   
# obtain file network report from VT with hash submission
def getnetwork(samplehash):
    url = "https://www.virustotal.com/vtapi/v2/file/network-traffic"
    parameters = {"apikey": myapikey, "hash": samplehash, "proxies": proxies}
    response = requests.get(url, params=parameters)
    

    ms = magic.open(magic.MAGIC_NONE)
    ms.load()
    ms.buffer(response.text)
    #print response.text

    pcap_file = open("dump.pcap", "w")
    pcap_file.write(response.text.encode('utf8'))
    pcap_file.close()
    print "Network dump completed"

def geturlreport (sampleurl):
        url = "https://www.virustotal.com/vtapi/v2/url/report"
        parameters = {"resource": sampleurl, "apikey": myapikey, "proxies": proxies , "allinfo": "true"}
        data = urllib.urlencode(parameters)
        req = urllib2.Request(url, data)

        try: 
            response = urllib2.urlopen(req)
            json = response.read()
            #print json
            process_urlreport(sampleurl, json)
        
        except urllib2.HTTPError, e:
            print "HTTP error : " + str(e.code)
        except urllib2.URLError, e:
            print "URL error : " + str(e.reason)
        except httplib.HTTPException, e:
            print "HTTP Exception error"
        except Exception:
            print "Unknown error"
    
        return;

def process_urlreport(sampleurl, jsonin):
    #print jsonin
    finalresult = ""
    
    try:
        response_dict = simplejson.loads(jsonin)

        responsecode = response_dict.get("response_code", {})
        myurl = response_dict.get("url", {})
        positives = response_dict.get("positives", {})
        url_alive = response_dict.get("additional_info", {}).get("Response code")
        sophos_result = response_dict.get("scans", {}).get("Sophos", {}).get("result")
        first_seen = response_dict.get("first_seen", {})

        #crdf_result = response_dict.get("scans", {}).get("CRDF", {}).get("result")
        #print url_alive

        #print jsonin
        
        if responsecode > 0:
 
            finalresult = myurl + "|" + str(positives) + "|" + str(sophos_result) + "|" + str(url_alive) + "|" + str(first_seen)

            print finalresult

            #if crdf_result == "malicious site": # testing
                #global crdfcount
                #crdfcount += 1
                
            if positives > 0:
                global num_detected
                num_detected += 1
            else:
                global num_not_detected
                num_not_detected += 1
                

            #if positives < 5:
            #    print myurl + " - Not detected"
            #    finalresult += positives
            #else:
            #    print myurl + " - Detected"
            #    finalresult += positives

        elif responsecode == 0:
            print sampleurl.strip() + " - URL is not found in Virustotal"
            finalresult = sampleurl.strip() + "|URL_not_available_on_VT"

            global num_not_seen
            num_not_seen += 1

        # send VT results to text file

        f = open("urlVTresult.txt", "a+")
        f.write(finalresult+"\n")
        f.close()

    except Exception as e:
        print "Unknown error " + str(e)

# process json results obtained
def process_result(jsonin):

    response_dict = simplejson.loads(jsonin)

    responsecode = response_dict.get("response_code", {})
    scandate = response_dict.get("scan_date", {})
    md5hash = response_dict.get("md5", {})
    sha256hash = response_dict.get("sha256", {})
    sha1hash = response_dict.get("sha1", {})
    resource = response_dict.get("resource", {})
    kas_result = response_dict.get("scans", {}).get("Kaspersky", {}).get("result")
    ms_result = response_dict.get("scans", {}).get("Microsoft", {}).get("result")
    trend_result = response_dict.get("scans", {}).get("TrendMicro", {}).get("result")
    antivir_result = response_dict.get("scans", {}).get("AntiVir", {}).get("result")
    fsecure_result = response_dict.get("scans", {}).get("F-Secure", {}).get("result")
    sophos_result = response_dict.get("scans", {}).get("Sophos", {}).get("result")
    mcafee_result = response_dict.get("scans", {}).get("McAfee", {}).get("result")
    malwarebytes_result = response_dict.get("scans", {}).get("Malwarebytes", {}).get("result")
    gdata_result = response_dict.get("scans", {}).get("GData", {}).get("result")
    bitdefender_result = response_dict.get("scans", {}).get("BitDefender", {}).get("result")
    positives = response_dict.get("positives", {})

#    print jsonin
    detected = False
    finalresult = ""
    print ""


    if responsecode > 0:

    	if sha1hash is not None:
    	    print "SHA1: " + sha1hash
    	    finalresult += sha1hash + "|"
	if scandate is not None:
    	    print "ScanDate: " + scandate
    	    finalresult += scandate + "|"
    	if kas_result is not None:
    	    print "Kaspersky: " + kas_result
    	    finalresult += kas_result + "|"
    	    detected = True
    	if ms_result is not None:
    	    print "Microsoft: " + ms_result
    	    finalresult += ms_result + "|"
    	    detected = True
    	if trend_result is not None:
    	    print "Trend Micro: " + trend_result
    	    finalresult += trend_result + "|"
    	    detected = True
    	if antivir_result is not None:
    	    print "Antivir: " + antivir_result
    	    finalresult += antivir_result + "|"
    	    detected = True
    	if fsecure_result is not None:
    	    print "F-Secure: " + fsecure_result
    	    finalresult += fsecure_result + "|"
    	    detected = True
    	if sophos_result is not None:
    	    print "Sophos: " + sophos_result
    	    finalresult += sophos_result + "|"
    	    detected = True
    	if mcafee_result is not None:
    	    print "McAfee: " + mcafee_result
    	    finalresult += mcafee_result + "|"
    	    detected = True
    	if malwarebytes_result is not None:
    	    print "MalwareBytes: " + malwarebytes_result
    	    finalresult += malwarebytes_result + "|"
    	    detected = True
    	if gdata_result is not None:
    	    print "GData: " + gdata_result
    	    finalresult += gdata_result + "|"
    	    detected = True
    	if bitdefender_result is not None:
    	    print "BitDefender: " + bitdefender_result
    	    finalresult += bitdefender_result + "|"
    	    detected = True
        if positives is not None:
    	    print "Positives: " + str(positives)
    	    finalresult += str(positives) + "|"
    	    detected = True

    	if detected is False:
    	    print "Not detected"



    elif responsecode == 0:

        print resource + "- File is not found in Virustotal"
        finalresult = resource + "|" + "File_not_available_on_VT"


    	# send VT results to text file

    f = open("VTresult.txt", "a+")
    f.write(finalresult+"\n")
    f.close()

    return;


# submit hashes in file to VT
def masshashes(flocation):

    start_time = time.time()
    iCounter = 0

    if os.path.isfile(flocation):
        f = open(flocation, "r")
        for line in f:
	    getreport(line)
            iCounter += 1
            #time.sleep(15)

        print ""
        print "All hashes in " + flocation + " are processed!"
        print "File count: " + str(iCounter)

        elapsed_time = time.time() - start_time
        print "Elapsed time: " + str(elapsed_time)

    else:
        print ""
        print "Error: " + flocation + " does not appear to be a valid file"


#submit mass hashes in file to VT for rescan/new results
def massrescanhashes(flocation):

    start_time = time.time()
    iCounter = 0

    if os.path.isfile(flocation):
        f = open(flocation, "r")
        for line in f:
            rescan(line)
            iCounter += 1
            
        print ""
        print "All hashes in " + flocation + " are processed!"
        print "File count: " + str(iCounter)

        elapsed_time = time.time() - start_time
        print "Elapsed time: " + str(elapsed_time)
    else:
        print ""
        print "Error: " + flocation + " does not appear to be a valid file"
                                                                                                                                            
# submit files in folder to VT
def massfiles(dlocation):

    start_time = time.time()
    iCounter = 0

    if os.path.isdir(dlocation):
        for root, subFolders, files in os.walk(dlocation):
            for filename in files:
                fullpath = os.path.join(dlocation, filename)
                iCounter += 1
                print ""
                submitscan(fullpath)

                #time.sleep(2)


        print ""
        print "All files in " + dlocation + " are processed!"
        print "File count: " + str(iCounter)

        elapsed_time = time.time() - start_time
        print "Elapsed time: " + str(elapsed_time)

    else:
        print ""
        print "Error: " + dlocation + " does not appear to be a valid directory"

    return;


def massurl(furl):

    start_time = time.time()
    iCounter = 0
    
    if os.path.isfile(furl):
        f = open(furl, "r")
        for line in f:
	    geturlreport(line)
            iCounter += 1
            #time.sleep(1)

        print ""
        print "All URLs in " + furl + " are processed!"
        print "URL count: " + str(iCounter)
        print "Has Detection: " + str(num_detected)
        print "No Detection: " + str(num_not_detected)
        print "Not seen: " + str(num_not_seen)
        #print "CRDF count: " + str(crdfcount)

        elapsed_time = time.time() - start_time
        print "Elapsed time: " + str(elapsed_time)

    else:
        print ""
        print "Error: " + furl + " does not appear to be a valid file"

def submitmassurl(furl):

    start_time = time.time()
    iCounter = 0
    
    if os.path.isfile(furl):
        f = open(furl, "r")
        for line in f:
	    submiturl(line)
            iCounter += 1
            #time.sleep(5)

        print ""
        print "All URLs in " + furl + " are processed!"
        print "URL count: " + str(iCounter)

        elapsed_time = time.time() - start_time
        print "Elapsed time: " + str(elapsed_time)

    else:
        print ""
        print "Error: " + furl + " does not appear to be a valid file"


# submit single url to VT
def submiturl (sampleurl):
    url = "https://www.virustotal.com/vtapi/v2/url/scan"
    params = {'apikey': myapikey, 'url': sampleurl, 'proxies': proxies , "allinfo": "true"}
    response = requests.post(url, data=params)
    #print(response.json())   
 

if __name__ == "__main__":
    sys.exit(main())
