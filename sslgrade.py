#!/usr/bin/env python3

import sys
import json
import requests
import pprint
import time
import socket

if len(sys.argv) <= 1:
    print("Usage: ./sslgrade.py domain.tld")
    exit(1)

domain = sys.argv[1]

try:
    socket.gethostbyname(domain)
except:
    print("Domain doesn't have DNS record")
    exit(1)

ssllabs_api_url= "https://api.dev.ssllabs.com/api/v2/"

def check_test_status():

    test_status_url = "{}analyze?host={}&publish=off&analyze".format(ssllabs_api_url,domain)
    response = requests.get(test_status_url)

    if response.status_code != 200:
        print('Status:', response.status_code, 'Problem with the request. Exiting.')
        exit()

    data = response.json()

    try:
        status = data['endpoints'][0]['statusMessage']
    except:
        start_test()
        wait_for_test()
        test_result_print()

    if status == "Ready":
        print("There's existing fresh result, start new test anyway?")
        while True:
            answer = input("y/n:  ")
            if answer == "y":
                start_test()
                wait_for_test()
                test_result_print()
                break
            elif answer == "n":
                test_result_print()
                break
            else:
                print("Please enter y/n")
    else:
        wait_for_test()

def start_test():

    test_status_url = "{}analyze?host={}&publish=off&analyze&startNew=on&ignoreMismatch=on".format(ssllabs_api_url,domain)
    response = requests.get(test_status_url)

    if response.status_code == 200:
        return json.loads(response.content.decode('utf-8'))
    else:
        return None


def wait_for_test():

    test_status_url = "{}analyze?host={}&publish=off&analyze".format(ssllabs_api_url,domain)
    response = requests.get(test_status_url)

    if response.status_code != 200:
        print('Status:', response.status_code, 'Problem with the request. Exiting.')
        exit()

    data = response.json()

    error_status = data['status']
    status = data['endpoints'][0]['statusMessage']

    if error_status == "ERROR":
        print("error initializing test. full json response:")
        print("")
        pprint.pprint(data)
        print("")

    print("Waiting for test to finish")
    while status != "Ready":
        time.sleep( 3 )
        response = requests.get(test_status_url)
        data = response.json()
        status = data['endpoints'][0]['statusMessage']

        percentage = data['endpoints'][0]['progress']
        if percentage < 0:
            percentage = "0"

        progress = " Progress: {} %".format(percentage)
        sys.stdout.write('%s\r' % progress)
        sys.stdout.flush()        
        sys.stdout.write("\b")

        response = requests.get(test_status_url)
        data = response.json()
       	status = data['endpoints'][0]['statusMessage']

def test_result_print():


    test_status_url = "{}analyze?host={}&publish=off&analyze".format(ssllabs_api_url,domain)
    response = requests.get(test_status_url)

    if response.status_code != 200:
        print('Status:', response.status_code, 'Problem with the request. Exiting.')
        exit()

    data = response.json()

    grade = data['endpoints'][0]['grade']
    warnings = data['endpoints'][0]['hasWarnings']
    ipaddress = data['endpoints'][0]['ipAddress']

    test_details_url = "{}getEndpointData".format(ssllabs_api_url)
    payload = {'host': domain, 's': ipaddress}
    response = requests.get(test_details_url, params=payload)

    if response.status_code != 200:
        print('Status:', response.status_code, 'Problem with the request. Exiting.')
       	exit()

    data = response.json()

    certchain = data['details']['chain']['issues']
    
    protocols_formatted = ""
    for x in data['details']['protocols']:
        protocols = (x['version']).replace('\b', ' ')
        protocols_formatted += protocols + ' '
   

    print("")
    print("SSL Labs test results for:", domain)
    print("Grade:", grade)
    print("Warnings:", warnings)
    if certchain == 0:
       certchain = "none"
    elif certchain == 2:
       certchain = "incomplete chain"
    elif certchain == 4:
       certchain = "chain contains unrelated or duplicate certificates"
    elif certchain == 8:
       certchain = "the certificates form chain (trusted or not), but the order is incorrect"
    elif certchain == 16:
       certchain = "contains a self-signed certificate"
    elif certchain == 32:
       certchain = "the certificates form a chain, but we could not validate it"
    
    print("Issues in certificate chain:", certchain)
    print("Supported TLS/SSL protocols:", protocols_formatted)

    print("")
    result_cache_url = "https://www.ssllabs.com/ssltest/analyze.html?d={}&fromCache=on".format(domain)
    print(result_cache_url)

    exit(0)

check_test_status()
