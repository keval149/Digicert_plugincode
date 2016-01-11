"""
"""
from flask import current_app

from lemur.plugins.bases import IssuerPlugin
import lemur_digicert as digicert
from lemur_digicert import constants

import requests
import json
import time
import xmltodict
import arrow

from requests import Request, Session
from requests.auth import HTTPBasicAuth




def handle_response(content):
    """
    Helper function for parsing responses from the Verisign API.
    :param content:
    :return: :raise Exception:
    """
    d = xmltodict.parse(content)
    global DIGICERT_ERRORS
    if d.get('Error'):
        status_code = d['Error']['StatusCode']
    elif d.get('Response'):
        status_code = d['Response']['StatusCode']
    if status_code in DIGICERT_ERRORS.keys():
        raise Exception(DIGICERT_ERRORS[status_code])
    return d


class DigicertIssuerPlugin(IssuerPlugin):
    title = 'Digicert'
    slug = 'digicert-issuer'
    description = 'Enables the creation of certificates by the digicert test API.'
    version = digicert.VERSION

    author = 'Keval Doshi'
    author_url = 'PASTE URL HERE'

    def create_certificate(self, csr, issuer_options):
        """
        Creates a Digicert certificate.

        :param csr:
        :param issuer_options:
        :return: :raise Exception:
        """
        
	url = "https://api.digicert.com/enterprise/certificate/ssl"
	print("check 2")
	print issuer_options
	cname = issuer_options["commonName"]
	orgunit = issuer_options["organizationalUnit"]
  	state = issuer_options["state"]
	
	payload = {
      		"type": "private_ssl",
      		"org_unit": issuer_options["organizationalUnit"],
      		"server_type": "Apache",
      		"common_name": "COMMON NAME HERE",
      		"sans": "SANS NAME ",
      		"comments": "DESCRIPTION",
      		"org_name": "ORGANIZATION NAME",
      		"org_addr1": "ADDRESS line 1",
      		"org_addr2": "address line 2",
     		 "org_city": "SAN JOSE",
      		"org_state": "CA",
     		 "org_zip": "PINCODE HERE",
     		 "org_country": "USA",
      		"validity": "NO.OF YEARS",
      		"csr": csr
    	}

   	data = process_options(issuer_options)
	print csr
	#data['csr'] = csr

	key = current_app.config.get("DIGICERT_KEY") #FETCHES THE DIGICERT API KEY FROM CONFIG FILE.
        print key
        acc_id = current_app.config.get("DIGICERT_ACCID")  ##FETCHES THE DIGICERT ACCOUNT ID FROM CONFIG FILE.
        print acc_id
        auth = HTTPBasicAuth(acc_id,key)
    	
	head = {'Content-Type': 'application/vnd.digicert.rest-v1+json'}
        current_app.logger.info("Requesting a new Digicert certificate: {0}".format(data))
	print payload
        
	response = requests.post(url, data=json.dumps(payload), auth=auth, headers=head)
	print response
	requestid = response.json()["request_id"]
	print requestid
	
	url2 = "https://api.digicert.com/request/"+requestid
    	s = Session()
    	req = Request('APPROVE', url2,auth=auth,
        	headers=head
    	)
    	prepped = req.prepare()
    	print prepped
    	print req

    	orderid = s.send(prepped).json()["order_id"]
    	print orderid
	print "Sleeping for 45 seconds ..."
	time.sleep(45)
	
	
	#response = requests.post(url, data=data, auth=auth, headers=head)
        url3 = "https://api.digicert.com/order/"+orderid+"/certificate"
	orderid = requests.get(url3, auth = auth, headers= head).json()["order_id"]
    	print ("order_id is:")
    	print orderid

    	serial = requests.get(url3, auth = auth, headers= head).json()["serial"]
    	print ("serial is:")
    	print serial

    	certificate = requests.get(url3, auth = auth, headers= head).json()["certs"]["certificate"]
    	print ("certificate is:")
    	print certificate

    	intermediate = requests.get(url3, auth = auth, headers= head).json()["certs"]["intermediate"]
    	print ("intermediate is:")
    	print intermediate

    	root = requests.get(url3, auth = auth, headers= head).json()["certs"]["root"]
    	print ("root is:")
    	print root

   	pkcs7 = requests.get(url3, auth = auth, headers= head).json()["certs"]["pkcs7"]
    	print ("pkcs7 is:")
    	print pkcs7

	#cert = handle_response(response.content)['Response']['Certificate']
        return certificate, intermediate,

    @staticmethod
    def create_authority(options):
        """
        Creates an authority, this authority is then used by Lemur to allow a user
        to specify which Certificate Authority they want to sign their certificate.

        :param options:
        :return:
        """
        role = {'username': '', 'password': '', 'name': 'digicert'}
        return constants.DIGICERT_ROOT, "", [role]
