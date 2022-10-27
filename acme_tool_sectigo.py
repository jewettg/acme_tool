#!/usr/bin/env python
# 
# ACME Automation Tool
# 
# Code written by:
#   Greg Jewett, jewettg@austin.utexas.edu, 512-471-9645
# 
# Code maintained by:
#   Greg Jewett, jewettg@austin.utexas.edu, 512-471-9645
#
# This script will interface with the Sectigo/InCommon API to add automated tasks and
# interaction with the ACME functionality.
#
# ---------------------------------------------------------------------------------------
# CHANGE LOG
# 2022-07-06 (GSJ) Initial version, python 3.
# 2022-09-20 (GSJ) Rewrote interface, supporting bulk domains, and restructured 
#                  parameterization. 

# ---------------------------------------------------------------------------------------


# =======================================================================================
# NOTE
# The following files and directories are requires to operate:
# See imports below for details.
# -> requests       - module for REST API / HTTP calls.
# -> re             - Regular Expression method
# -> os             - The operating system module/library
# -> sys            - The system module for Python.
# -> logging        - Import the logging module, configuration in __main__
# -> pathlib        - Import the object-oriented filesystem paths "pathlib"
# -> datetime       - Manipulation of date/time formats and data.
# -> time           - Import time module to allow the script to "sleep"
# -> json           - JSON library for handling of JSON data types.
# -> OpenSSL.crypto - Support for SSL Certificate Decoding.
# -> argparse       - Add support for argument passing, used to determine action to perform.
#
# =======================================================================================

# =======================================================================================
# BEGIN Import modules and dependencies
# =======================================================================================

# The system module for Python, specifically use to get command line arguments.
import sys


# =======================================================================================
# CHECK PYTHON VERSION
# Error out for any Python version earlier than minimum supported version.
# =======================================================================================
minVer = (3,8,8) 
curVer = sys.version_info[0:] 
if curVer < minVer:
    print("Current Python version: {}.{}.{}".format(*curVer+(0,0,)))
    print("ABORT: Expect Python version {}.{}.{}".format(*minVer+(0,0,))+" or better required!")
    sys.exit(1)

# Import Regular Expression method
import re

# The operating system module/library
import os

# Import the logging module, configuration in __main__
import logging

# Import the object-oriented filesystem paths "pathlib"
import pathlib

# Manipulation of date/time formats and data.
import datetime

# Import time module to allow the script to "sleep"
import time

# HTTP requests for API access
import requests
from requests.auth import HTTPBasicAuth
requests.packages.urllib3.disable_warnings()

# JSON library for handling of JSON data types.
import json

# Support for SSL Certificate Decoding.
import OpenSSL.crypto

# Add support for argument passing, used to collect information on what
# action to perform.
import argparse

# =======================================================================================
# END Import modules and dependencies
# =======================================================================================


# =======================================================================================
# BEGIN Functions used by global path variables.
# =======================================================================================
# Get Script Path
def scriptPath():
    return os.path.dirname(os.path.realpath(__file__))

# function to return a string (date/time) stamp, based on format needed.
def dt_stamp(format):
    stamp = datetime.datetime.now()
    if format == "d":
        # current date in ISO (YYYY-MM-DD) format
        return stamp.strftime("%Y-%m-%d")
    if format == "dt":
        # current date/time in ISO format: YYYY-MM-DDTHH:MM:SS.ddddd
        return stamp.isoformat()
    if format == "t":
        # current time in ISO format: HH:MM:SS.ddddd
        return stamp.strftime("%H:%M:%S.%f")
    if format == "fdt":
        # current date and time in format supported by OS for filenames.
        return stamp.strftime("%Y-%m-%d_%H%M%S")

# =======================================================================================
# END Functions used by global path variables.
# =======================================================================================

# =======================================================================================
# BEGIN Required variables and setup
# =======================================================================================

# Logging Metadata
scriptVer = "1.0"
scriptName = "ACME Automation Tool"
logTag = "ACMETOOL"
logName = "acme_tool"
logPath = "/opt/lb-bkups/script_logs/"+logName
minLogLevel = logging.INFO

# =======================================================================================
# END Required setup and global variables
# =======================================================================================



# =======================================================================================
# BEGIN Class Declarations
# =======================================================================================

# Define a class that will hold the request issued, along with status, etc..
# ------------------------------------------------------------------
class ACME_Request:

    # Instance Variables (defined below)
    # -------------------------------------------------------
    #  * account            STR, The account to either list, add, or delete domains from
    #  * domains            LIST, a list of domains to either add or delete.
    #  * what               STR, the list choice ['accounts', 'domains']
    #  * requestStatus      BOOL, are all the checks OK?  Can the request be processed?
    #  * acctList           LIST, all accounts by name
    #  * acctDetail         LIST, all account with all details (domains, id, status, etc..)

    # Class Methods
    # -------------------------------------------------------

    # Set the renewal status and if present, error message.
    def ifCmd(self, cmd):
        return (self.cmd == cmd)


    # Set the renewal status and if present, error message.
    def setReqStatus(self, status):
        if type(status) != bool:
            self.requestStatus = False
        else:
            self.requestStatus = status

    # Return the renewal status
    def getReqStatus(self):
        if hasattr(self, 'requestStatus'):
            if type(self.requestStatus) != bool:
                self.requestStatus = False
            else:
                return self.requestStatus
        else:
            return False

    # Initialization Method   
    # -------------------------------------------------------
    def __init__(self, params):
        self.requestStatus = True
        self.cmd = params.get("cmd", "") 

        if self.cmd == 'add':
            self.domains = params.get("domains", [])
            self.account = params.get("account", "")

        if self.cmd == 'delete':
            self.domains = params.get("domains", [])
            self.account = params.get("account", "")

        if self.cmd == 'list':
            self.what = params.get("what", "")
            self.account = params.get("account", "")
        
        self.acctDetail = dict()
        self.acctList = list()


# Define a credential vault to store and retreive credentials that
# should be destroyed before the program exists, to purge memory.
# ------------------------------------------------------------------
class CredentialVault:
    # Class variables (globals within class, all objects)
    # -------------------------------------------------------
    
    # Instance Variables (defined below)
    # -------------------------------------------------------
    #   * userName       the credential username (if used)
    #   * password       the credential password (if used)
    #   * otherTokens    other token values stored.
 
    # Class Methods
    # -------------------------------------------------------

   # Set the credential username
    def setUser(self, theUser):
        self.userName = theUser
       
   # Set the credential username
    def getUser(self):
        return self.userName
       
    # Set the credential password
    def setPass(self, thePass):
        self.password = thePass
       
    # Set the credential password
    def getPass(self):
        return self.password

    # Set the other stored token .. in dictionary
    def setOther(self, tName, tValue):
        self.otherTokens[tName] = tValue
       
    # Return a "pretty" version of the certificate subject alternative name list.
    def getOther(self, tName):
        return self.otherTokens.get(tName, "")

    def __del__(self):
        self.userName = None
        self.password = None
        self.otherTokens = None
    
    def destroy(self):
        self.userName = None
        self.password = None
        self.otherTokens = None

    # Initialization Method   
    # -------------------------------------------------------
    def __init__(self):
        self.userName = ""
        self.password = ""
        self.otherTokens = dict()


# =======================================================================================
# END Class Declarations
# =======================================================================================


# =======================================================================================
# BEGIN Functions Declarations
# =======================================================================================

# Validate FQDN / Common Name
# ---------------------------------------------------------
def validate_fqdn(fqdn):    
    if len(fqdn) > 255 or len(fqdn) < 1:
        return False
    if fqdn[-1] == ".":
        fqdn = fqdn[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in fqdn.split("."))


# Test and Validate if provided string is valid JSON data.
# ---------------------------------------------------------
def validateJSON(someData):
    try:
        json.loads(someData)
    except:
        return False
    else:
        return True
    

# Test API Response
# Assuming API response is from python "requests" module
# Try to get a status code, if successful, and body is not 
# blank and decodable, then succeed, else fail.
# ---------------------------------------------------------
def testResponse(respStr, 
                 successCode=200,
                 successResp=True,
                 failResp=False):
    
    respStr = str(respStr)
    if "status_code" in respStr and str(successCode) in respStr:
        return successResp
    elif ("code" in respStr or "status" in respStr) and str(successCode) in respStr:
        return successResp
    elif "Response" in respStr and str(successCode) in respStr:
        return successResp
    else:
        return failResp


# Setup and configure the logging system.
# -------------------------------------------------------
def setupLogging(logPath, logName, minLogLevel=logging.info, logTag="",
                 scriptName=logName, scriptVer="1.0", screenOut=False):
                 
    logFile = logPath+"/"+logName+"_"+dt_stamp('d')+".log"
    levelOut = {50:"CRITICAL", 40:"ERROR", 30:"WARNING", 20:"INFO", 10:"DEBUG", 0:"NOTSET" }

    # Check if the logPath exists, if not create it.
    pathlib.Path(logPath).mkdir(parents=True, exist_ok=True)

    if screenOut:
        handlers = [logging.FileHandler(filename=logFile, mode='a'),
                    logging.StreamHandler(sys.stdout) ]
    else:
        handlers = [logging.FileHandler(filename=logFile, mode='a') ]

    logTag = (logTag if len(logTag) > 0 else re.sub("[^A-Z0-9]", "", re.sub("[a-z]", '', scriptName))[0:5]) 
 
    # Create the logging instance
    doLog = logging
    doLog.basicConfig(level=minLogLevel,
                      format="%(asctime)s %(levelname)-8s ("+logTag+") %(message)s",
                      handlers = handlers,
                      force=True)

    # Write out a log header
    doLog.info("----------------------------------------------------------------------")
    doLog.info(scriptName+"    v"+scriptVer)
    doLog.info("----------------------------------------------------------------------")
    doLog.info("Log Start: "+dt_stamp('d')+" "+dt_stamp('t'))
    doLog.info("Writing script log data to: "+logFile)

    doLog.info("Minimum logging level will be set to: "+levelOut.get(minLogLevel, "UNKNOWN"))
    doLog.disable(level=(minLogLevel-10))
    return doLog


# =======================================================================================
# END Functions Declarations
# =======================================================================================


# =======================================================================================
# BEGIN Process supplied parameters
# =======================================================================================
def process_parameters(certCreds):
    doLog.info("Processing request parameters...")
    scriptDesc = ("This is an automation tool for the Sectigo/InCommon API to add automation "
                  "and interactive functionality for utilizing ACME management." )

    aParser = argparse.ArgumentParser(  description = scriptDesc,
                                        epilog="Please contact Greg Jewett for support; jewettg@austin.utexas.edu",
                                        add_help = True,
                                        allow_abbrev=False)

    subParsers = aParser.add_subparsers(help='sub-command help',
                                        required = True,
                                        dest='cmd')

    # ---------------------------------------------------------------------------------------
    # BEGIN SUB-COMMAND: ADD domain(s) to ACME account
    # ---------------------------------------------------------------------------------------
    addParser = subParsers.add_parser("add", help="Add domain(s) to specific ACME account.  Use 'add -h' to list of parameters")

    # PARAMETER:  Domain(s) to add to an ACME account.
    # ------------------------------------------------------------------------
    addParser.add_argument( "-d",
                            action = "append",
                            dest = "domains",
                            help = "The domains(s) that will be added. Specify multiple times to add multiple domains.",
                            required = True)

    # PARAMETER:  Domain(s) to delete to an ACME account.
    # ------------------------------------------------------------------------
    addParser.add_argument( "-a",
                            action = "store",
                            type = str,
                            dest = "account",
                            help = "The ACME account name to add the domain(s).",
                            required = True)
    # ---------------------------------------------------------------------------------------
    # END SUB-COMMAND: ADD domain(s) to ACME account
    # ---------------------------------------------------------------------------------------


    # ---------------------------------------------------------------------------------------
    # BEGIN SUB-COMMAND: LIST all domains  or accounts
    # ---------------------------------------------------------------------------------------
    listParser = subParsers.add_parser("list", help="List all defined accounts or domains for a specific account. Use 'list -h' to list of parameters.")

    # PARAMETER:  Domain(s) to add to an ACME account.
    # ------------------------------------------------------------------------
    listParser.add_argument( "-w",
                             action = "store",
                             dest = "what",
                             choices=['accounts', 'domains'],
                             help = "List available ACME accounts, IDs, statuses, and contact emails OR domains",
                             required = True)

    listParser.add_argument( "-a",
                             action = "store",
                             dest = "account",
                             help = "If domains is specified, this is required to know the account to list the domains.",
                             default = "UNDEFINED",
                             required = False)
    # ---------------------------------------------------------------------------------------
    # END SUB-COMMAND: LIST all tests
    # ---------------------------------------------------------------------------------------


    # ---------------------------------------------------------------------------------------
    # BEGIN SUB-COMMAND: DELETE a test based on test_id
    # ---------------------------------------------------------------------------------------
    delParser = subParsers.add_parser("delete", help="Delete a domains from an ACME account.  Use 'delete -h' to list of parameters")

    # PARAMETER:  Domain(s) to delete from an ACME account.
    # ------------------------------------------------------------------------
    delParser.add_argument( "-d",
                            action = "append",
                            dest = "domains",
                            help = "The domains(s) that will be deleted. Specify multiple times to delete multiple domains.",
                            required = True)

    # PARAMETER:  The ACME account to delete the domain(s) from. 
    # ------------------------------------------------------------------------
    delParser.add_argument( "-a",
                            action = "store",
                            type = str,
                            dest = "account",
                            help = "The ACME account name to delete the domain(s).",
                            required = True)
    # ---------------------------------------------------------------------------------------
    # END SUB-COMMAND: DELETE a test based on test_id
    # ---------------------------------------------------------------------------------------



    # Check to see if any parameters were provided, as there are some that are required.
    # If none provided, then output the help section.
    # ------------------------------------------------------------------------
    if len(sys.argv) < 2:
        aParser.print_help()
        sys.exit(1)

    cmdParser = vars(aParser.parse_args())
    theRequest = ACME_Request(cmdParser)

    # ---------------------------------------------------------------------------------------
    # Query the Sectigo API for a list of ACME accounts, listing all accounts.
    # This is used in various sections, which domains are assigned to which account and the 
    # the ACME account id.
    # ---------------------------------------------------------------------------------------
    doLog.info("Querying Sectigo for all available accounts and associated domains.")
    if theRequest.getReqStatus():
        cpURL = "https://cert-manager.com/api/acme/v1/account"
        headers = { "content-type" : "application/json",
                    "login":  certCreds.getUser(),
                    "password": certCreds.getPass(),
                    "customerUri": certCreds.getOther('uri') }
        postData = {"position": "0",
                    "size": "200",
                    "organizationId": certCreds.getOther('orgid')}
        apiResponse = requests.get(cpURL, headers=headers, verify=False, params=postData)
        if testResponse(apiResponse):
            theRequest.acctDetail = json.loads(apiResponse.text)
            theRequest.acctList = [aAcct.get("name") for aAcct in theRequest.acctDetail]
            doLog.info("Successful query, "+str(len(theRequest.acctList))+" accounts returned.")
        else:
            doLog.warning("Query failed: "+str(apiResponse.status_code)+"; "+str(apiResponse))
            theRequest.setReqStatus(False)


    # Process the parameters and valid input.
    # ------------------------------------------------------------------------
    doLog.info("COMMAND RECEIVED: "+theRequest.cmd)
    theParams = theRequest.__dict__
    for aParam in theParams.keys():
        if aParam not in ['requestStatus', 'acctList', 'acctDetail']:
            doLog.info("PARAMETER: "+str(aParam)+" --> "+str(theParams.get(aParam)))


    if theRequest.cmd in ['add', 'delete']:
        # Validate the list of domain(s)
        for aDomain in theRequest.domains:
            if not validate_fqdn(aDomain):
                doLog.error("The FQDN/Domain: "+str(aDomain)+" is invalid.  Please specify a valid FQDN/domain.")
                theRequest.setReqStatus(False)
                break
        
        if theRequest.account not in theRequest.acctList:
            doLog.error("The account: "+str(theRequest.account)+" was not found. Use 'list accounts' for a valid list of accounts.")
            theRequest.setReqStatus(False)
                        

    if theRequest.cmd == 'list':        
        if theRequest.what == 'domains':        
            if theRequest.account == "UNDEFINED":
                doLog.error("When list domains (-w domains), you must specify an account (-a option).")
                theRequest.setReqStatus(False)
            if theRequest.account not in theRequest.acctList:
                doLog.error("The account: "+str(theRequest.account)+" was not found.  Use 'list accounts' for a valid list of accounts.")
                theRequest.setReqStatus(False)


    # return the parameters and the boolean if all validation passed.
    return theRequest

# =======================================================================================
# END Process supplied parameters
# =======================================================================================



# =======================================================================================
# BEGIN Performing the requested functions.
# =======================================================================================
def process_request(theRequest, certCreds):

    # LIST:  domains or accounts?
    # ---------------------------------------------------------------------------------------
    if theRequest.cmd in ['list']:        
        if theRequest.what == 'accounts':
            # List ACME accounts previously queried.
            # -------------------------------------------------------------        
            for aAcct in theRequest.acctDetail:
                oData = ("{id:<10}{name:<40}{status:<10}{contacts:<40}").format(**aAcct)
                doLog.info(oData)

        if theRequest.what == 'domains':
            # List domains for specified account.
            # -------------------------------------------------------------
            for aAcct in theRequest.acctDetail:
                if aAcct.get('name') == theRequest.account:
                    domainList = [aDomain.get('name') for aDomain in aAcct.get('domains',[])]
            doLog.info("ACME Account: "+theRequest.account+"; domains found: "+str(len(domainList)))
            for i in range(0,len(domainList)):
                doLog.info(f"{(i+1):>5}  {domainList[i]:<40}")




    # ADD: add a domain to a specified account
    # ---------------------------------------------------------------------------------------
    if theRequest.cmd in ['add']:
        doLog.info("Processing domain list for account: "+theRequest.account)
        
        # We already know the "account" is valid, tested in previous code.
        # Get the account detail for specified account
        aAcct = [aAcct for aAcct in theRequest.acctDetail if aAcct.get('name') == theRequest.account][0]
        accountID = aAcct.get('id')
        verifyDomains = [aDomain.get('name') for aDomain in aAcct.get('domains',[])]
        
        # Is any of the domains already in the account?  If so, skip, else process.
        addList = list()
        for aDomain in theRequest.domains:
            if aDomain in verifyDomains:
                doLog.warning("SKIPPING: "+str(aDomain)+" already in account "+str(theRequest.account)+"; ID: "+str(accountID))
            else:
                doLog.info("ADDING: "+str(aDomain)+" to account "+str(theRequest.account)+"; ID: "+str(accountID))
                addList.append({'name': aDomain})

        if not len(addList) > 0:
            doLog.warning("All domains already in the account, nothing to do!")
            theRequest.setReqStatus(False)
                

        # Perform a Sectigo API call to add a domain to a specific ACME account
        # ---------------------------------------------------------------------------------------
        if theRequest.getReqStatus():
            doLog.info("Sending ADD request to Sectigo API ...")
            cpURL = "https://cert-manager.com/api/acme/v1/account/"+str(accountID)+"/domains"
            headers = { "content-type" : "application/json",
                        "login":  certCreds.getUser(),
                        "password": certCreds.getPass(),
                        "customerUri": certCreds.getOther('uri') }
            postData = {"domains": addList}
            apiResponse = requests.post(cpURL, headers=headers, verify=False, json=postData)

            if testResponse(apiResponse):
                skippedDomains = json.loads(apiResponse.text).get('notAddedDomains', [])
                if len(skippedDomains) > 0:
                    # Domain was not added to the account, because the domain was not previous part of the approved 
                    # organization level domain list.  Need to add to domain to organization domain list and retry.
                    doLog.warning("Several domains not added, due to being part of approved organization level domain list.")
                    for aDomain in skippedDomains:
                        cpURL = "https://cert-manager.com/api/domain/v1"
                        headers = { "content-type" : "application/json",
                                    "login":  certCreds.getUser(),
                                    "password": certCreds.getPass(),
                                    "customerUri": certCreds.getOther('uri') }
                        postData = {"name": aDomain,
                                    "description": "Add by automation; itsy-esm; "+dt_stamp('d'),
                                    "active": "true",
                                    "delegations":[{"orgId":certCreds.getOther('orgid'),"certTypes":["SSL"]}]}
                        apiResponse = requests.post(cpURL, headers=headers, verify=False, json=postData)

                        if testResponse(apiResponse,successCode=201):
                            doLog.info("SUCCESS: Domain  "+str(aDomain)+ " add to organization domain list.")
                        else:
                            doLog.error("FAILURE: Domain  "+str(aDomain)+ " add to organization domain list.")
                            theRequest.setReqStatus(False)        
                else:
                    doLog.info("Request succeeded, all domains were added.")

                # No errors added to organization domain list, retrying to add domains to ACME account.
                if theRequest.getReqStatus():
                    retryList = [{"name": aDomain} for aDomain in skippedDomains]

                    doLog.info("Sending RETRY ADD request to Sectigo API ...")
                    cpURL = "https://cert-manager.com/api/acme/v1/account/"+str(accountID)+"/domains"
                    headers = { "content-type" : "application/json",
                                "login":  certCreds.getUser(),
                                "password": certCreds.getPass(),
                                "customerUri": certCreds.getOther('uri') }
                    postData = {"domains": retryList}
                    apiResponse = requests.post(cpURL, headers=headers, verify=False, json=postData)

                    if testResponse(apiResponse):
                        skippedDomains = json.loads(apiResponse.text).get('notAddedDomains', [])
                        if len(skippedDomains) > 0:
                            theRequest.setReqStatus(False)
                            for aDomain in skippedDomains:
                                doLog.error("FAILURE: Retry attempt to add domain: "+str(aDomain))
                        else:
                            doLog.info("SUCCESS: Domains were added to the account.")           
            else:
                theRequest.setReqStatus(False)
                doLog.error("FAILURE: The REST API call to add domains.")
                if validateJSON (apiResponse.text):
                    doLog.warning("API call failed: "+str(apiResponse.status_code)+"; "+str(apiResponse.text))


    if theRequest.cmd in ['delete']:
        doLog.info("Processing domain list for account: "+theRequest.account)
        
        # We already know the "account" is valid, tested in previous code.
        # Get the account detail for specified account
        aAcct = [aAcct for aAcct in theRequest.acctDetail if aAcct.get('name') == theRequest.account][0]
        accountID = aAcct.get('id')
        verifyDomains = [aDomain.get('name') for aDomain in aAcct.get('domains',[])]
        
        # Is any of the domains already in the account?  If so, skip, else process.
        deleteList = list()
        for aDomain in theRequest.domains:
            if aDomain in verifyDomains:
                doLog.warning("DELETING: "+str(aDomain)+" from account "+str(theRequest.account)+"; ID: "+str(accountID))
                deleteList.append({'name': aDomain})
            else:
                doLog.info("SKIPPING: "+str(aDomain)+" not found in account "+str(theRequest.account)+"; ID: "+str(accountID))

        if not len(deleteList) > 0:
            doLog.warning("None of the domains where found with in the account, nothing to do!")
            theRequest.setReqStatus(False)



        # Perform a Sectigo API call to add a domain to a specific ACME account
        # ---------------------------------------------------------------------------------------
        if theRequest.getReqStatus():
            doLog.info("Sending DELETE request to Sectigo API ...")
            cpURL = "https://cert-manager.com/api/acme/v1/account/"+str(accountID)+"/domains"
            headers = { "content-type" : "application/json",
                        "login":  certCreds.getUser(),
                        "password": certCreds.getPass(),
                        "customerUri": certCreds.getOther('uri') }
            postData = {"domains": deleteList}
            apiResponse = requests.delete(cpURL, headers=headers, verify=False, json=postData)
            if testResponse(apiResponse):
                skippedDomains = json.loads(apiResponse.text).get('notRemovedDomains', [])
                if len(skippedDomains) > 0: 
                    theRequest.setReqStatus(False)
                    doLog.error("Several domains were NOT deleted, this is not expected and could be due to other RESTI API issues.")
                    for aDomain in skippedDomains:
                        doLog.error("FAILURE: Delete domain: "+str(aDomain))
                else:
                    doLog.info("SUCCESS: Domains were deleted from the account.") 
            else:
                theRequest.setReqStatus(False)
                doLog.warning("FAILURE: The REST API call to remove domains from "+theRequest.account)
                if validateJSON (apiResponse.text):
                    doLog.warning("API call failed: "+str(apiResponse.status_code)+"; "+str(apiResponse.text))


    # =======================================================================================
    # END Performing the requested functions.
    # =======================================================================================


    # Destroy the local copies of credentials.
    # ---------------------------------------------------------------------------------------
    certCreds.destroy()

# =======================================================================================
# END processing parameters and performing the requested functions.
# =======================================================================================





# =======================================================================================
# BEGIN Script
# =======================================================================================

if __name__ == '__main__':
    # Setup logging, instance is global, can be used by all functions.
    doLog = setupLogging(logPath, logName, minLogLevel, logTag, scriptName, scriptVer, screenOut=True)

    # ---------------------------------------------------------------------------------------
    # BEGIN Fetch credentials for the InCommon / Sectigo API access
    # You can hardcode your credential here (not recommended) or replace the following code
    # with your REST API calls to fetch credentials from a 1Password, Ansible Vault, LastPass,
    # or other credential management tool.  
    # The Python class CredentialVault() will work to store those credentials and allow their
    # use throughout the script.  It will then destroy the class instance at script conclusion.
    #
    # In the UT Austin implementtion of "Stache", our credential management system,
    # there are three fields in an entry.  The entry called "secret" contains a JSON
    # structure like the following:  
    #
    # {"username": "xxx", "password": "xxx", "orgId": "xxx", "customerUri": "InCommon"}
    # 
    # ---------------------------------------------------------------------------------------
    certCreds = CredentialVault()
    doLog.info("Obtaining proper credentials.")
    try:
        cpURL = "xxxx"
        headers = {"KEY": "xxxx"}
        queryResponse = requests.get(cpURL, headers=headers, verify=False, timeout=3)
        queryResponse.raise_for_status()

    except requests.exceptions.HTTPError as errh:
        doLog.error("Credential retrieval from Stache failed, for InCommon / Sectigo API access.  Aborting.")
        doLog.error("HTTP Error: "+str(errh))
        sys.exit(1)
    except requests.exceptions.ConnectionError as errc:
        doLog.error("Credential retrieval from Stache failed, for InCommon / Sectigo API access.  Aborting.")
        doLog.error("Error Connecting: "+str(errc))
        sys.exit(1)
    except requests.exceptions.Timeout as errt:
        doLog.error("Credential retrieval from Stache failed, for InCommon / Sectigo API access.  Aborting.")
        doLog.error("Timeout Error: "+str(errt))
        sys.exit(1)
    except requests.exceptions.RequestException as err:
        doLog.error("Credential retrieval from Stache failed, for InCommon / Sectigo API access.  Aborting.")
        doLog.error("UNKNOWN Error: "+str(err))
        raise SystemExit
    else: 
        if queryResponse.status_code < 400:
            apiResponse = json.loads(queryResponse.text)['secret']
            certCreds.setUser(json.loads(str(apiResponse))['username'])
            certCreds.setPass(json.loads(str(apiResponse))['password'])
            certCreds.setOther('uri', json.loads(str(apiResponse))['customerUri'])
            certCreds.setOther('orgid', json.loads(str(apiResponse))['orgId'])
        else:
            doLog.error("Credential retrieval from Stache failed, for InCommon / Sectigo API access.  Aborting.")
            sys.exit(1)
    # ---------------------------------------------------------------------------------------
    # END Fetch credentials for the InCommon / Sectigo API access
    # ---------------------------------------------------------------------------------------

    theRequest = process_parameters(certCreds)  # Returns class ACME_Request.
    if theRequest.getReqStatus():
        process_request(theRequest, certCreds)    

    # Shutdown the logger.
    doLog.shutdown()
# =======================================================================================
# END Script
# =======================================================================================
