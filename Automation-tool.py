#! usr/bin/etc python3
import csv
import argparse
from socketserver import DatagramRequestHandler
import retirejs
import requests
import re
from termcolor import colored, cprint
from python_hosts import Hosts, HostsEntry
from bs4 import BeautifulSoup
import nmap
import urllib3
import os

os.system('color')
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
responce_headers= {}
# hosts from etc/host file
hosts = Hosts(path=Hosts.determine_hosts_path())
# Dictionary containing all the detected version
Versions_scripts = {}
Versions_apache = {}
ssl_results = {}
ssh_results = {}
versions = {}
responces = {}

def pocsaver(host, port, vuln_method, responce):
    """
    Description : Save snippets in a list
    Param host : Host on which vulnerability was verified
    host type: string
    Param port: Port on which vulnerability was verified
    port type: string
    Param vuln_method: This is a tag which is unique of every detection method, can be used to know for which vulnerability the snippet was taken
    vuln_method type: string 
    """
    if host not in responces.keys():
        responces[host] = {}
        responces[host][port] = {}
        responces[host][port][vuln_method] = responce
    elif port not in responces[host].keys():
        responces[host][port] = {}
        responces[host][port][vuln_method] = responce
    elif vuln_method not in responces[host][port].keys():
        responces[host][port][vuln_method] = responce

def pocloader(file):
    for i in responces:
        file.write("\n++++++++++++++++++++++++++++++++++++++++"+i+"++++++++++++++++++++++++++++++++++++++++"+"\n")
        for j in responces[i]:
            for k in responces[i][j]:
                file.write("----------------------------------------------------------\nPort = "+j+"\nDetection Method = "+k+"\nResponce:\n"+responces[i][j][k]+"\n")

def mysql_verifier(title, TechDetails, hostlist, port):
    status = False
    msg = ""
    if 'detected version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'detected version \S+', TechDetails).group(0))
        print("Detected mysql Version from technical details is "+detected_version.group(0))
    elif 'oracle mysql version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'oracle mysql version \S+', TechDetails).group(0))
        print("Detected mysql Version from technical details is "+detected_version.group(0))
    elif 'installed version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'Installed version: \S+', TechDetails).group(0))
        print("Detected mysql Version from technical details is "+detected_version.group(0))
    else:
        msg = "Version not detected from CSV"
        return status, msg
    if detected_version:
        for i in hostlist:
            if i+":"+port in versions.keys():
                if detected_version.group(0) in versions[i+":"+port]:
                    status = True
                    print("Verified mysql version on the host is "+versions[i+":"+port])
                    msg = "sql version verified"
                    pocsaver(i, port, "sql-version", versions[i+":"+port])
                    break
                else:
                    msg = "Verified mysql version on the host is "+versions[i+":"+port]
            else:
                result, msg = version_scanner(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    else:
                        if detected_version.group(0) in result[i+":"+port]:
                            status = True
                            print("Verified mysql version on the host is "+result[i+":"+port])
                            msg = "sql version verified"
                            pocsaver(i, port, "sql-version", result[i+":"+port])
                            break
                        else:
                            msg = "Verified mysql version on the host is "+result[i+":"+port]
                except:
                    msg = "unknown error occurred"
        return status, msg
    
def ssh_script_verifier(title, TechDetails, hostlist, port):
    status = False
    msg = ""
    if "diffie-hellman" in title.lower():
        for i in hostlist:
            if i+":"+port in ssh_results.keys():
                if "ssh2-enum-algos" in ssh_results[i+":"+port].keys():
                    if "diffie-hellman-group1-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group14-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group14-sha256" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group16-sha512" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group18-sha512" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group-exchange-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group-exchange-sha256" in ssh_results[i+":"+port]["ssh2-enum-algos"]:
                        status = True
                        msg = "diffie-hellman ssh verified"
                        pocsaver(i, port, "ssh2-enum-algos", ssh_results[i+":"+port]["ssh2-enum-algos"])
                        break

                    else:
                        msg = "DHE algos not present"
                else:
                    msg = "ssh2-enum-algos script not executed"
            else:
                result,msg = ssh_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssh2-enum-algos" in result[i+":"+port].keys():
                        if "diffie-hellman-group1-sha1" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group14-sha1" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group14-sha256" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group16-sha512" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group18-sha512" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group-exchange-sha1" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group-exchange-sha256" in result[i+":"+port]["ssh2-enum-algos"]:
                            status = True
                            msg = "diffie-hellman ssh verified"
                            pocsaver(i, port, "ssh2-enum-algos", result[i+":"+port]["ssh2-enum-algos"])
                            break
                        else:
                            msg = "DHE algos not present"
                    else:
                        msg = "ssh2-enum-algos script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "weak encryption algorithm" in title.lower():
        for i in hostlist:
            if i+":"+port in ssh_results.keys():
                if "ssh2-enum-algos" in ssh_results[i+":"+port].keys():
                    if "aes256-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "aes192-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "aes128-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "cast128-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "blowfish-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "3des-cbc" in ssh_results[i+":"+port]["ssh2-enum-algos"]:
                        status = True
                        msg = "weak encryption algorithm ssh verified"
                        pocsaver(i, port, "ssh2-enum-algos", ssh_results[i+":"+port]["ssh2-enum-algos"])
                        break

                    else:
                        msg = "weak encryption algorithm not present"
                else:
                    msg = "ssh2-enum-algos script not executed"
            else:
                result,msg = ssh_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssh2-enum-algos" in result[i+":"+port].keys():
                        if "aes256-cbc" in result[i+":"+port]["ssh2-enum-algos"] or "aes192-cbc" in result[i+":"+port]["ssh2-enum-algos"] or "aes128-cbc" in result[i+":"+port]["ssh2-enum-algos"] or "cast128-cbc" in result[i+":"+port]["ssh2-enum-algos"] or "blowfish-cbc" in result[i+":"+port]["ssh2-enum-algos"] or "3des-cbc" in result[i+":"+port]["ssh2-enum-algos"]:
                            status = True
                            msg = "weak encryption algorithm ssh verified"
                            pocsaver(i, port, "ssh2-enum-algos", result[i+":"+port]["ssh2-enum-algos"])
                            break

                        else:
                            msg = "weak encryption algorithm not present"
                    else:
                        msg = "ssh2-enum-algos script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "weak host key algorithm" in title.lower():
        for i in hostlist:
            if i+":"+port in ssh_results.keys():
                if "ssh2-enum-algos" in ssh_results[i+":"+port].keys():
                    if "ssh-dss" in ssh_results[i+":"+port]["ssh2-enum-algos"]:
                        status = True
                        msg = "weak host key algorithm ssh verified"
                        pocsaver(i, port, "ssh2-enum-algos", ssh_results[i+":"+port]["ssh2-enum-algos"])
                        break

                    else:
                        msg = "weak host key algorithm not present"
                else:
                    msg = "ssh2-enum-algos script not executed"
            else:
                result,msg = ssh_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssh2-enum-algos" in result[i+":"+port].keys():
                        if "ssh-dss" in result[i+":"+port]["ssh2-enum-algos"]:
                            status = True
                            msg = "weak host key algorithm ssh verified"
                            pocsaver(i, port, "ssh2-enum-algos", result[i+":"+port]["ssh2-enum-algos"])
                            break

                        else:
                            msg = "weak host key algorithm not present"
                    else:
                        msg = "ssh2-enum-algos script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "weak key exchange" in title.lower():
        for i in hostlist:
            if i+":"+port in ssh_results.keys():
                if "ssh2-enum-algos" in ssh_results[i+":"+port].keys():
                    if "diffie-hellman-group-exchange-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group1-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "gss-gex-sha1" in ssh_results[i+":"+port]["ssh2-enum-algos"]:
                        status = True
                        msg = "weak key exchange ssh verified"
                        pocsaver(i, port, "ssh2-enum-algos", ssh_results[i+":"+port]["ssh2-enum-algos"])
                        break

                    else:
                        msg = "weak key exchange not present"
                else:
                    msg = "ssh2-enum-algos script not executed"
            else:
                result,msg = ssh_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssh2-enum-algos" in result[i+":"+port].keys():
                        if "diffie-hellman-group-exchange-sha1" in result[i+":"+port]["ssh2-enum-algos"] or "diffie-hellman-group1-sha1" in result[i+":"+port]["ssh2-enum-algos"] or "gss-gex-sha1" in result[i+":"+port]["ssh2-enum-algos"]:
                            status = True
                            msg = "weak key exchange ssh verified"
                            pocsaver(i, port, "ssh2-enum-algos", result[i+":"+port]["ssh2-enum-algos"])
                            break

                        else:
                            msg = "weak key exchange not present"
                    else:
                        msg = "ssh2-enum-algos script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "weak mac algorithm" in title.lower():
        for i in hostlist:
            if i+":"+port in ssh_results.keys():
                if "ssh2-enum-algos" in ssh_results[i+":"+port].keys():
                    if "hmac-md5" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-96" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-96-etm@openssh.com" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-etm@openssh.com" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "hmac-sha1-96" in ssh_results[i+":"+port]["ssh2-enum-algos"] or "hmac-sha1-96-etm@openssh.com" in ssh_results[i+":"+port]["ssh2-enum-algos"]:
                        status = True
                        msg = "weak mac algorithm ssh verified"
                        pocsaver(i, port, "ssh2-enum-algos", ssh_results[i+":"+port]["ssh2-enum-algos"])
                        break

                    else:
                        msg = "weak mac algorithm not present"
                else:
                    msg = "ssh2-enum-algos script not executed"
            else:
                result,msg = ssh_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssh2-enum-algos" in result[i+":"+port].keys():
                        if "hmac-md5" in result[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-96" in result[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-96-etm@openssh.com" in result[i+":"+port]["ssh2-enum-algos"] or "hmac-md5-etm@openssh.com" in result[i+":"+port]["ssh2-enum-algos"] or "hmac-sha1-96" in result[i+":"+port]["ssh2-enum-algos"] or "hmac-sha1-96-etm@openssh.com" in result[i+":"+port]["ssh2-enum-algos"]:
                            status = True
                            msg = "weak mac algorithm ssh verified"
                            pocsaver(i, port, "ssh2-enum-algos", result[i+":"+port]["ssh2-enum-algos"])
                            break                       
                        else:
                            msg = "weak mac algorithm not present"
                    else:
                        msg = "ssh2-enum-algos script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    else:
        msg = "this was not detected for ssh"
        return status,msg
    
def asp_error(title, Target, port, hostlist):
    status = False
    msg = ""
    for i in hostlist:
        if "443" in port:
            url = "https://"+i+Target
        else:
            url = "http://"+i+":"+port+Target
        try:
            request = requests.get(url,verify=False, timeout=5)
            if "<b>Version Information:</b>" in request.text and "<b> Description: </b>" in request.text and ("Exception" in request.text or "ASP.NET is configured to show verbose error" in request.text):
                status = True
                msg = "ASP error message found"
                pocsaver(i, port, "asp-error", request.text)
        except requests.exceptions.ConnectionError:
            msg = "Failed to establish connection"
    return status, msg

def source_map(title, Target, port, hostlist):
    status = False
    msg = ""
    for i in hostlist:
        try:
            if "443" in port:
                url = "https://"+i+Target
                request = requests.get(url, verify=False, timeout=5)
            else:
                url = "http://"+i+":"+port+Target
                request = requests.get(url, timeout=5)
            if "version" in request.text.lower() and "file" in request.text.lower() and "mappings" in request.text.lower():
                status = True
                msg = "Source map is getting disclosed"
                pocsaver(i, port, "source-map-disclosure", str(request.text.encode("utf-8")))
        except requests.exceptions.ConnectionError: 
            msg = "Failed to esablish connection"
    return status, msg


        

def cors_verifier(title, Target, hostlist, port):
    status = False
    msg = ""
    for i in hostlist:
        if "443" in port:
            url = "https://"+i+Target
        else:
            url = "http://"+i+":"+port+Target
        if url in responce_headers.keys():
            if "Cross-Origin Resource Sharing (CORS) policy permits any origin (Cookies Permitted)" in title:
                if "access-control-allow-credentials" in responce_headers[url].keys():
                    if 'true' in responce_headers[url]["access-control-allow-credentials"].lower():
                        msg = "CORS permits any origin"
                        status = True
                        pocsaver(i, port, "cors-cookies-permitted", responce_headers[url]["access-control-allow-credentials"] )
                        return status, msg
                    else:
                        msg = "access-control-allow-credentials is false"
                else:
                    msg = "'access-control-allow-credentials' header not present in responce"
            if "Cross-Origin Resource Sharing (CORS) policy permits HTTP origin for HTTPS application" in title or "HTML5 Cross Origin Resource Sharing (CORS) policy permits HTTP origin for HTTPS application" in title:
                if "access-control-allow-origin" in responce_headers[url].keys():
                    if 'http://www.example.com' in responce_headers[url]["access-control-allow-origin"].lower():
                        msg = "Cors permits HTTP origin verified"
                        status = True
                        pocsaver(i, port, "cors-http-origin", responce_headers[url]["access-control-allow-origin"])
                        return status, msg
                    else:
                        msg = "access-control-allow-origin is"+responce_headers[url]["access-control-allow-origin"]
                else:
                    msg = "'access-control-allow-origin' header not present in responce"
            if "Cross-Origin Resource Sharing (CORS) policy permits wildcard domains" in title or "HTML5 Cross Origin Resource Sharing (CORS) policy permits wildcard domains" in title or "HTML5 cross-origin resource sharing (Wildcard *)" in title:
                if "access-control-allow-origin" in responce_headers[url].keys():
                    if 'http://www.example.com' in responce_headers[url]["access-control-allow-origin"].lower() or '*' in responce_headers[url]["access-control-allow-origin"]:
                        msg = "CORS permits HTTP origin wildcard verified"
                        status = True
                        pocsaver(i, port, "cors-wildcard", responce_headers[url]["access-control-allow-origin"])
                        return status, msg
                    else:
                        msg = "access-control-allow-origin is"+responce_headers[url]["access-control-allow-origin"]
                else:
                    msg = "'access-control-allow-origin' header not present in responce"
        else:
            try:
                headers = {'Origin': 'http://www.example.com'}
                request = requests.get(url, verify=False, headers=headers, timeout=5)
                responce_headers[url] = request.headers
                if "Cross-Origin Resource Sharing (CORS) policy permits any origin (Cookies Permitted)" in title:
                    if "access-control-allow-credentials" in request.headers.keys():
                        if 'true' in request.headers["access-control-allow-credentials"].lower():
                            msg = "CORS permits cookies"
                            status = True
                            pocsaver(i, port, "cors-cookies-permitted", request.headers["access-control-allow-credentials"])
                            return status, msg
                        else:
                            msg = "access-control-allow-credentials is false"
                    else:
                        msg = "'access-control-allow-credentials' header not present in responce"
                if "Cross-Origin Resource Sharing (CORS) policy permits wildcard domains" in title or "HTML5 Cross Origin Resource Sharing (CORS) policy permits wildcard domains" in title or "HTML5 cross-origin resource sharing (Wildcard *)" in title:
                    if "access-control-allow-origin" in request.headers.keys():
                        if 'http://www.example.com' in request.headers["access-control-allow-origin"].lower() or '*' in request.headers["access-control-allow-origin"]:
                            msg = "Cors permits HTTP origin wildcard verified"
                            status = True
                            pocsaver(i, port, "cors-wildcard", request.headers["access-control-allow-origin"])
                            return status, msg
                        else:
                            msg = "access-control-allow-origin is"+request.headers["access-control-allow-origin"]
                    else:
                        msg = "'access-control-allow-origin' header not present in responce"
                if "Cross-Origin Resource Sharing (CORS) policy permits HTTP origin for HTTPS application" in title or "HTML5 Cross Origin Resource Sharing (CORS) policy permits HTTP origin for HTTPS application" in title:
                    HostUrl = "http://"+i
                    headers = {'Origin': HostUrl}
                    request = requests.get(url, verify=False, headers=headers, timeout=5)
                    if "access-control-allow-origin" in request.headers.keys():
                        if HostUrl in request.headers["access-control-allow-origin"].lower():
                            msg = "Cors permits HTTP origin verified"
                            status = True
                            pocsaver(i, port, "cors-http-origin", request.headers["access-control-allow-origin"])
                            return status, msg
                        else:
                            msg = "access-control-allow-origin is"+request.headers["access-control-allow-origin"]
                    else:
                        msg = "'access-control-allow-origin' header not present in responce"
                

            except requests.exceptions.ConnectionError: 
                msg = "Failed to esablish connection"
    return status, msg

def javascript_sri(title, techdetails, port):
    Status = False
    sri_scripts = re.findall(r'(?<=\n\| )http\S+', techdetails)
    hostList = re.findall(r'(?<=\|\sNo\s\s\|\s)http\S+', techdetails)
    for i in hostList:
       request = requests.get(i,verify=False, timeout=5)
       soup = BeautifulSoup(request.text, 'html.parser')
       
    
        
        

def jscript_verifier(title, techdetails, hostlist, port):
    vers = {}
    Status = False
    msg = ""
    current_comp = re.search(r'(?<=\*\*Current) \S+ (?=Version:\*\*)', techdetails)
    current_version = re.search(r'(?<=Version:\*\* )\d+\.\d+\.\d+', techdetails)
    library_url = re.search(r'(?<=\*\*Pages that import the vulnerable library:\*\*\n\n\[\[)\S+(?=\]\])', techdetails)
    if library_url:
        host = re.search(r'\S+:\/\/[^\/]+', library_url.group(0))
    if current_comp and current_version and library_url and host:
        current_comp = current_comp.group(0).lower().replace(" ","")
        if library_url.group(0) in Versions_scripts.keys():
            if current_comp in Versions_scripts[library_url.group(0)].keys():
                if current_version.group(0) in Versions_scripts[library_url.group(0)][current_comp]:
                    #print("Verified from dictionary")
                    Status = True
                    msg = "Vulnerable component verified"

                else:
                    "not found in dictionary"
            else:
                msg = "This vulnerable component was not detected on the page"
        else:
            try:
                request = requests.get(library_url.group(0),verify=False, timeout=5)
                soup = BeautifulSoup(request.text, 'html.parser')
                for link in soup.find_all('script'):
                        if link.get('src'):
                            if link.get('src').startswith('/'):
                                script_url = host.group(0)+link.get('src')
                            elif link.get('src').startswith('../'):
                                script_url = host.group(0)+"/"+link.get('src')
                            else:
                                if not link.get('src').startswith("http"):
                                    script_url = "https://"+link.get('src')
                                else:
                                    script_url = link.get('src')
                                #print(link.get('src'))
                            #print(f"Script url is : {script_url}")
                            script_scan = retirejs.scan_endpoint(script_url)
                            #print(script_scan)
                            for components in script_scan:
                                vers[components['component'].lower()] = str(components['version'])
                                if components['component'].lower() in current_comp and str(components['version']) in current_version.group(0):
                                    Status = True
                                    msg = "Vulnerable component verified"
                                    request = requests.get(script_url, verify=False, timeout=5)
                                    pocname = "vulnerable-script = "+script_url
                                    pocsaver(str(host.group(0)), port, str(pocname) , str(request.text.encode("utf-8")))
                                    #print("Verified")

            except requests.exceptions.ConnectionError:
                #print("failed to establish connection")
                pass
            except Exception as a:
                pass
            print(vers)
            if any(vers):
                Versions_scripts[library_url.group(0)] = vers
    else:
        msg = "There was an error finding details from Technical details column"
    return Status, msg


def jscript_test():
    a = retirejs.scan_endpoint("https://iinetworks.com/core/assets/vendor/jquery/jquery.min.js?v=3.6.3")
    for comp in a:
        print(f"{comp['component']} has version = {comp['version']} ")
            

def version_verifier(title, TechDetails, hostlist, port):
    status = False
    msg = ""
    if "detected version (" in TechDetails.lower():
        detected_version = re.search(r"(?<=\()\d+\.\d+\.\d+(?=\))", TechDetails)
    if "jboss_enterprise_application_platform" in TechDetails.lower():
        detected_version = re.search(r"(?<=version\s)\S+", TechDetails)
    if "zookeeper" in TechDetails.lower():
        detected_version = re.search(r"(?<=version\s)\d+\.\d+\.\d+", TechDetails)
    if "zookeeper" in title.lower() and "installed version:" in TechDetails.lower():
        detected_version = re.search(r"(?<=version:\s)\d+\.\d+\.\d+", TechDetails)
    if "jetty" in TechDetails.lower():
        detected_version = re.search(r"(?<=version\s)\d+\.\d+\.\d+\.\d+", TechDetails)
    if "elasticsearch" in TechDetails.lower():
        detected_version = re.search(r"(?<=version\s)\d+\.\d+\.\d+", TechDetails)
    if detected_version:
        for i in hostlist:
            if i+":"+port in versions.keys():
                if detected_version.group(0) in versions[i+":"+port]:
                    status = True
                    print("Verified version is "+versions[i+":"+port])
                    msg = "version verified"
                    pocsaver(i, port, "version-vuln", versions[i+":"+port])
                    break
                else:
                    msg = "Verified version is "+versions[i+":"+port]
            else:
                result, msg = version_scanner(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    else:
                        if detected_version.group(0) in result[i+":"+port]:
                            status = True
                            print("verified version is "+result[i+":"+port])
                            msg = "version verified"
                            pocsaver(i, port, "version-vuln", result[i+":"+port])
                            break
                        else:
                            msg = "Verified version is "+result[i+":"+port]
                except:
                    msg = "unknown error occurred"
    else:
        msg = "Vulnerability not detected in Technical details"
    print(msg)
    return status, msg



def ssh_verifier(title, TechDetails, hostlist, port):

    status = False
    msg = ""
    if 'detected version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'detected version \S+', TechDetails).group(0))
        print("Detected ssh Version from techncial-details column is "+detected_version.group(0))
    elif 'openbsd openssh version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'openssh version \S+', TechDetails).group(0))
        print("Detected ssh Version from techncial-details column is "+detected_version.group(0))
    elif 'installed version' in TechDetails.lower():
        detected_version = re.search(r'\d\S+', re.search(r'Installed version: \S+', TechDetails).group(0))
        print("Detected ssh Version from techncial-details column is "+detected_version.group(0))
    else:
        if not detected_version: 
            msg = "version not identified from CSV"
        else:
            msg = "problem with techdetails of this vulnerability"
    if detected_version:
        for i in hostlist:
            if i+":"+port in versions.keys():
                if detected_version.group(0) in versions[i+":"+port]:
                    status = True
                    print("Verified ssh version is "+versions[i+":"+port])
                    msg = "openssh version verified"
                    pocsaver(i, port, "ssh-version", versions[i+":"+port])
                    break
                else:
                    msg = "Verified ssh version is "+versions[i+":"+port]
            else:
                result, msg = version_scanner(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    else:
                        if detected_version.group(0) in result[i+":"+port]:
                            status = True
                            print("Verified ssh version is "+result[i+":"+port])
                            msg = "openssh version verified"
                            pocsaver(i, port, "ssh-version", result[i+":"+port])
                            break
                        else:
                            msg = "Verified ssh version is "+result[i+":"+port]
                except Exception as error:
                    msg = "unknown error occurred:"+str(error)
    return status, msg

def version_scanner(host, port):
    msg = ''
    host = str(host)
    nm = nmap.PortScanner()
    result = {}
    nm.scan(hosts= str(host),ports=port, arguments='--resolve-all -sV -Pn')
    try:
        for hs in nm.all_hosts():
            if "filtered" in nm[hs]['tcp'][int(port)]['state']:
                msg = "port is filtered"
                print(msg)
                pass
            else:
                msg = ""
                versions[hs+':'+port] = nm[hs]['tcp'][int(port)]['version']
                result[hs+':'+port] = nm[hs]['tcp'][int(port)]['version']
                versions[host+':'+port] = nm[hs]['tcp'][int(port)]['version']
                result[host+':'+port] = nm[hs]['tcp'][int(port)]['version']
        if "port is filtered" in msg:
            result[hs+':'+port] = None
            result[host+':'+port] = None
    except KeyError as error:
        result[hs+':'+port] = None
        result[host+':'+port] = None
        msg = "Sorry, the value '"+str(error)+"' is missing"
    return result, msg
    
def ssl_vulns(title, TechDetails, hostlist, port):
    # Too much redundant code, can be optimised
    status = False
    msg = ""
    if 'diffie-hellman' in title.lower() and "'dhe' cipher suites" in TechDetails.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "diffie-hellman verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break

                    else:
                        msg = "DHE ciphers not present"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_128_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "diffie-hellman verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg= "DHE ciphers not present"
                    else:
                        msg = "ssl-enum-ciphers script not executed"
                except Exception as a:
                    print("Error: ")
                    print(a)
        return status, msg



    elif 'ssl/tls' in title.lower() and 'deprecated tlsv1.0' in title.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "TLSv1.0" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLSv1.1" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "TLSv1.0 Verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break
                    else:
                        msg = "It doesnt have TLSv1 ciphers"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "TLSv1.0" in result[i+":"+port]["ssl-enum-ciphers"] or "TLSv1.1" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "TLSv1.0 Verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg = "It doesnt have TLSv1 ciphers"
                    else:
                        msg = "ssl-enum-ciphers script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif 'ssl/tls' in title.lower() and 'deprecated sslv2' in title.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "SSLv2" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "SSLv3" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "SSLv3 Verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break
                    else:
                        msg = "It doesnt have SSLv3 ciphers"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "SSLv2" in result[i+":"+port]["ssl-enum-ciphers"] or "SSLv3" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "SSLv3 Verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg = "It doesnt have SSLv3 ciphers"
                    else:
                        msg = "ssl-enum-ciphers script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg

    elif 'ssl/tls' in title.lower() and 'server temporary key size' in TechDetails.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-dh-params" in ssl_results[i+":"+port].keys():
                    key_size = re.search(r"\d+",re.search(r"Key Length:.\d+",ssl_results[i+":"+port]["ssl-dh-params"]).group(0))
                    print(key_size.group(0))
                    print("\n")
                    if int(key_size.group(0)) < 2048:
                        status = True
                        msg = "SSL Key Size Verified"
                        pocsaver(i, port, "ssl-dh-params", ssl_results[i+":"+port]["ssl-dh-params"])
                        break
                    else:
                        msg = "key size is more than 2048"
                else:
                    msg = "ssl-dh-params script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-dh-params" in result[i+":"+port].keys():
                        key_size = re.search(r"\d+",re.search(r"Key Length:.\d+",result[i+":"+port]["ssl-dh-params"]).group(0))
                        print(key_size.group(0))
                        print("\n")
                        if int(key_size.group(0)) < 2048:
                            status = True
                            msg = "SSL Key Size Verified"
                            pocsaver(i, port, "ssl-dh-params", result[i+":"+port]["ssl-dh-params"])
                            break
                        else:
                            msg = "key size is more than 2048"
                    else:
                        msg = "ssl-cert script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
        
    elif "'vulnerable' cipher suites" in TechDetails.lower() and 'sweet32' in TechDetails.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "SWEET32" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "sweet32 verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break
                    else:
                        msg = "It doesnt have Sweet32"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "SWEET32" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "sweet32 verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg = "It doesnt have Sweet32"
                    else:
                        msg = "ssl-enum-ciphers script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "'weak' cipher suites" in TechDetails.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "TLS_RSA_WITH_RC4_128_MD5" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_RSA_WITH_RC4_128_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"] or "TLS_RSA_WITH_SEED_CBC_SHA" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "weak ciphers verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break
                    else:
                        msg = "It doesnt have weak ciphers"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "TLS_RSA_WITH_RC4_128_MD5" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_RSA_WITH_RC4_128_SHA" in result[i+":"+port]["ssl-enum-ciphers"] or "TLS_RSA_WITH_SEED_CBC_SHA" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "weak ciphers verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg = "It doesnt have weak ciphers"
                    else:
                        msg = "ssl-enum-ciphers script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "(POODLE)" in title:
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-poodle" in ssl_results[i+":"+port].keys():
                    status = True
                    msg = "poodle verified"
                    pocsaver(i, port, "ssl-poodle", ssl_results[i+":"+port]["ssl-poodle"])
                    break
                else:
                    msg = "ssl-poodle not present"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-poodle" in result[i+":"+port].keys():
                        status = True
                        msg = "poodle verified"
                        pocsaver(i, port, "ssl-poodle", result[i+":"+port]["ssl-poodle"])
                        break
                    else:
                        msg = "ssl-poodle not present"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif "openssl ccs man" in title.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-ccs-injection" in ssl_results[i+":"+port].keys():
                    status = True
                    msg = "ccs injection verified"
                    pocsaver(i, port, "ssl-ccs-injection", ssl_results[i+":"+port]["ssl-poodle"])
                    break
                else:
                    msg = "ssl-ccs-injection not present"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-ccs-injection" in result[i+":"+port].keys():
                        status = True
                        msg = "ssl-ccs-injection verified"
                        pocsaver(i, port, "ssl-ccs-injection", result[i+":"+port]["ssl-poodle"])
                        break
                    else:
                        msg = "ssl-ccs-injection not present"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif 'ssl/tls' in title.lower() and 'weak signature algorithm' in title.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-cert" in ssl_results[i+":"+port].keys():
                    if "sha1WithRSAEncryption" in ssl_results[i+":"+port]["ssl-cert"]:
                        status = True
                        msg = "weak signature algorithm verified"
                        pocsaver(i, port, "ssl-cert", ssl_results[i+":"+port]["ssl-cert"])
                        break
                else:
                    msg = "ssl-cert script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-cert" in result[i+":"+port].keys():
                        if "sha1WithRSAEncryption" in result[i+":"+port]["ssl-cert"]:
                            status = True
                            msg = "weak signature algorithm verified"
                            pocsaver(i, port, "ssl-cert", result[i+":"+port]["ssl-cert"])
                            break
                    else:
                        msg = "ssl-cert script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg
    elif 'ssl/tls' in title.lower() and 'crime' in title.lower():
        for i in hostlist:
            if i+":"+port in ssl_results.keys():
                if "ssl-enum-ciphers" in ssl_results[i+":"+port].keys():
                    if "DEFLATE" in ssl_results[i+":"+port]["ssl-enum-ciphers"]:
                        status = True
                        msg = "CRIME verified"
                        pocsaver(i, port, "ssl-enum-ciphers", ssl_results[i+":"+port]["ssl-enum-ciphers"])
                        break
                    else:
                        msg = "It doesnt have CRIME vulnerability"
                else:
                    msg = "ssl-enum-ciphers script not executed"
            else:
                result,msg = ssl_scan(i, port)
                try:
                    if result[i+":"+port] is None:
                        print(msg)
                    elif "ssl-enum-ciphers" in result[i+":"+port].keys():
                        if "DEFLATE" in result[i+":"+port]["ssl-enum-ciphers"]:
                            status = True
                            msg = "CRIME verified"
                            pocsaver(i, port, "ssl-enum-ciphers", result[i+":"+port]["ssl-enum-ciphers"])
                            break
                        else:
                            msg = "It doesnt have CRIME vulnerability"
                    else:
                     msg = "ssl-enum-ciphers script not executed"
                except:
                    msg = "unknown error occurred"
        return status, msg

    else:
        msg = "this was not detected"
        return status,msg
    
def ssh_scan(host, port):
    msg = ''
    nm = nmap.PortScanner()
    result = {}
    nm.scan(hosts= host,ports=port, arguments='--resolve-all --script ssh2-enum-algos -Pn')
    #print(nm._scan_result['scan'][host]['tcp'][443]['script'])
    try:
        for hs in nm.all_hosts():
            if "filtered" in nm[hs]['tcp'][int(port)]['state']:
                msg = "port is filtered"
                print(msg)
                pass
            else:
                msg = ""
                ssh_results[hs+':'+port] = nm[hs]['tcp'][int(port)]['script']
                result[hs+':'+port] = nm[hs]['tcp'][int(port)]['script']
                ssh_results[host+':'+port] = nm[hs]['tcp'][int(port)]['script']
                result[host+':'+port] = nm[hs]['tcp'][int(port)]['script']
        if "port is filtered" in msg:
            result[host+':'+port] = None
            result[hs+':'+port] = None
    except KeyError as error:
        result[hs+':'+port] = None
        result[host+':'+port] = None
        msg = "Sorry, the value '"+str(error)+"' is missing"
    return result, msg

def ssl_scan(host, port):
    msg = ''
    nm = nmap.PortScanner()
    result = {}
    nm.scan(hosts= host,ports=port, arguments='--resolve-all --script ssl-* -Pn')
    #print(nm._scan_result['scan'][host]['tcp'][443]['script'])
    try:
        for hs in nm.all_hosts():
            if "filtered" in nm[hs]['tcp'][int(port)]['state']:
                msg = "port is filtered"
                print(msg)
                pass
            else:
                msg = ""
                ssl_results[hs+':'+port] = nm[hs]['tcp'][int(port)]['script']
                result[hs+':'+port] = nm[hs]['tcp'][int(port)]['script']
                ssl_results[host+':'+port] = nm[hs]['tcp'][int(port)]['script']
                result[host+':'+port] = nm[hs]['tcp'][int(port)]['script']
        if "port is filtered" in msg:
            result[host+':'+port] = None
            result[hs+':'+port] = None
    except KeyError as error:
        result[host+':'+port] = None
        result[hs+':'+port] = None
        msg = "Sorry, the value '"+str(error)+"' is missing"
    return result, msg
        
    #if nm['54.229.221.84']['tcp'][443]['script']['ssl-date']:
     #   print("ssl-date")

def parse_host(host):
    """
    Description = Function finds hosts on the besis of hostnames and returns a list of hosts
    Param host: hostname provided by appcheck
    host type: string
    Return = all_addresses(list or Hostentry object), Hostresolve(Bool)
    all_address = list of resolved addresses
    Hostresolve = whether the host was resolved from etc/host file or not, because object itself doesnt
    contain the list of addresses, .address has to be appended at the end of every object  
    """

    Hostslist = []

    if "ec2" in host and "amazonaws" in host:
        match = re.search("\d+-\d+-\d+-\d+\.", host)
        if match:
            Hostslist.append(re.search('\d+\.\d+\.\d+\.\d+', match.group(0).replace('-','.')).group(0))
        else:
            Hostslist.append(host)
    elif hosts.exists(names=[host]): 
      hostall = hosts.find_all_matching(name=host)
      # This for is redundant, can be removed in future versions
      for i in (hostall):
          Hostslist.append(i.address)
    else:   
        Hostslist.append(host)
    return Hostslist


# Function - Checks status of Apache and Tomcat version vulnerabilities
def check_status(host , port, Techdetails, Title):
    # Version detected by appcheck
    detected_version = re.search(r'\d\.\d\.\d+', Techdetails)
    # Status is initially set to false
    status = False
    comment = ""
    # If the version for this host is already detected and stored in dictionary
    if not detected_version:
        comment = "Version not detected from Techdetails"
        return status, comment
    else:
    # Condition to check Tomcat Version
        print("Detected tomcat version from technical details columns is "+detected_version.group(0))
        if ('detected version' in Techdetails and 'tomcat' in Title.lower()) or 'tomcat version' in Techdetails:
            if host+':'+port in Versions_apache.keys():
                if 'tomcat' in Versions_apache[host+':'+port].keys():
                    if detected_version.group(0) == Versions_apache[host+':'+port]['tomcat']:
                        status = True
                        comment = Versions_apache[host+':'+port]['tomcat']+'tomcat Version verified'
                    else:
                        status = False
                        comment = "verified tomcat version is "+Versions_apache[host+':'+port]['tomcat']
                    return status, comment
                else:
                    Hostlist = parse_host(host)
                    comment = ''
                    for i in range(len(Hostlist)):
                        # check for the real version on the host
                        verified_version, comment = check_version_tomcat(Hostlist[i],port)
                        print('verified tomcat version is = '+verified_version+'\n')
                        # Confition to check if detected version is same as appcheck version
                        if verified_version == detected_version.group(0):
                                status = True
                                comment = 'Verified tomcat vulnerability on host '+host
                                Versions_apache[host+':'+port]['tomcat'] = verified_version
                                break
                        else:
                            result, comment = version_scanner(i, port)
                            try:
                                if result[i+":"+port] is None:
                                    print(comment)
                                else:
                                    print(result[i+":"+port])
                                    if detected_version.group(0) in result[i+":"+port]:
                                        status = True
                                        print("verified version is "+result[i+":"+port])
                                        comment = "version verified"
                                        pocsaver(i, port, "TOMCAT-version-vuln", result[i+":"+port])
                                        Versions_apache[host+':'+port]['tomcat'] = result[i+":"+port]
                                        break

                                    else:
                                        Versions_apache[host+':'+port]['tomcat'] = verified_version
                            except:
                                comment = "unknown error occurred"
                    return status, comment
            else:
                Hostlist = parse_host(host)
                for i in range(len(Hostlist)):
                    # check for the real version on the host
                    verified_version, comment = check_version_tomcat(Hostlist[i],port)
                    print('verified tomcat version is = '+verified_version+'\n')
                    # Confition to check if detected version is same as appcheck version
                    if verified_version == detected_version.group(0):
                            status = True
                            comment = 'Verified on host'+host
                            Versions_apache[host+':'+port] = {}
                            Versions_apache[host+':'+port]['tomcat'] = verified_version
                            break
                    else:
                        Versions_apache[host+':'+port] = {}
                        Versions_apache[host+':'+port]['tomcat'] = verified_version
                return status, comment
        # Condition to check Apache version      
        else:
             # if hostname resolution is present in etc/host file
            if host+':'+port in Versions_apache.keys():
                if 'apache' in Versions_apache[host+':'+port].keys():
                    if detected_version.group(0) == Versions_apache[host+':'+port]['apache']:
                        status = True
                        comment = Versions_apache[host+':'+port]['apache']+' Version verified from dictionary'
                    else:
                        status = False
                        comment = "verified apache version is "+Versions_apache[host+':'+port]['apache']
                    return status, comment
                else:
                    Hostlist = parse_host(host)
                    comment = ''
                    for i in range(len(Hostlist)):
                        # check for the real version on the host
                        verified_version, comment = check_version_apache(Hostlist[i],port)
                        print('verified apache version is = '+verified_version+'\n')
                        # Confition to check if detected version is same as appcheck version
                        if verified_version == detected_version.group(0):
                                status = True
                                comment = 'Verified on host'+host
                                Versions_apache[host+':'+port]['apache'] = verified_version
                                break
                        else:
                            result, comment = version_scanner(i, port)
                            try:
                                if result[i+":"+port] is None:
                                    print(comment)
                                else:
                                    print(result[i+":"+port])
                                    if detected_version.group(0) in result[i+":"+port]:
                                        status = True
                                        print("verified version is "+result[i+":"+port])
                                        comment = "version verified"
                                        pocsaver(i, port, "apache-version-vuln", result[i+":"+port])
                                        Versions_apache[host+':'+port]['apache'] = result[i+":"+port]
                                        break

                                    else:
                                        Versions_apache[host+':'+port]['apache'] = verified_version
                            except:
                                comment = "unknown error occurred"
                    return status, comment
            else:
                Hostlist = parse_host(host)
                comment = ''
                for i in range(len(Hostlist)):
                    # check for the real version on the host
                    verified_version, comment = check_version_apache(Hostlist[i],port)
                    print('verified apache version is = '+verified_version+'\n')
                    # Confition to check if detected version is same as appcheck version
                    if verified_version == detected_version.group(0):
                            status = True
                            comment = 'Verified on host'+host
                            Versions_apache[host+':'+port] = {}
                            Versions_apache[host+':'+port]['apache'] = verified_version
                            break
                    else:
                        Versions_apache[host+':'+port] = {}
                        Versions_apache[host+':'+port]['apache'] = verified_version
                return status, comment
        

def Cookie_Checker(hostlist, port, target, issecure):
    msg = ''
    Secure = True
    Httponly = True
    try:
        for host in hostlist:
            target_url = re.search(r'\S+', target)
            if not target_url:
                msg = "Target not present in CSV"
            else:
                cookie = re.search(r'(?<=cookie\.)\S+(?=\])', target)
                if not cookie:
                    msg = "cookie not found in CSV - Target"
                    return Secure, msg
                else:
                    print("-------------------------")
                    print(f"cookie in csv is {cookie.group(0)} on {host}")
                    if port == "443":
                        url = "https://"+host+":"+port+target_url.group(0)
                        request = requests.get(url,verify=False, cookies = None, timeout=5)
                    else:
                        url = "http://"+host+":"+port+target_url.group(0)
                        request = requests.get(url, cookies = None, timeout=5)
                    if cookie.group(0) in request.cookies.keys():
                        for cooks in request.cookies:
                                if cooks.name == cookie.group(0):
                                    if issecure:
                                        if cooks.secure:
                                            msg = f"Secure flag is there on {cooks.name} and host {host}"
                                            pocsaver(host, port, f"Cookie-secure-present, cookie: {cooks.name}", request.headers['Set-Cookie'])
                                        else:
                                            msg = f"Secure flag is missing on cookie = {cooks.name} and host {host}"
                                            Secure = False
                                            pocsaver(host, port, f"Cookie-secure-missing, cookie: {cooks.name}", request.headers['Set-Cookie'])
                                    else:
                                        if "HttpOnly" in cooks._rest.keys():
                                            msg = f"Htpponly is present on {cooks.name}"
                                            pocsaver(host, port, f"Cookie-httponly-present, cookie: {cooks.name}", request.headers['Set-Cookie'])
                                        else:
                                            msg = f"HttpOnly is missing on {cooks.name} and host {host}"
                                            Httponly = False
                                            pocsaver(host, port, f"Cookie-httponly-missing, cookie: {cooks.name}", request.headers['Set-Cookie'])  
                    else:
                        msg = f"cookie {cookie.group(0)} is missing from  the responce"
                        #print(f"cookie {cookie.group(0)} is missing, have a look at all the present cookies:")
                        #print(request.cookies.keys())                 
    except KeyError:
        msg = "Key error occured"
    except AttributeError:
        msg = "Attribute error"
    except KeyboardInterrupt:
        raise SystemExit
    except requests.exceptions.ConnectionError:
        msg = "Failed to esablish connection"
    except Exception as error:
        msg = "unknown error:"+str(error) 
    print(msg)
    if issecure:
        return Secure, msg
    else:
        return Httponly, msg
    

# Function - Checks Apache version from server header
def check_version_apache(host, port):
    if port == "443":
        url = 'https://'+host+':'+port+'/404'
    else:
        url = 'http://'+host+':'+port+'/404'
    comment = ""
    version = "0"
    for i in range(3):
        try:
            if port == "443":
                request = requests.get(url,verify=False, timeout=5)
            else:
                request = requests.get(url, timeout=5)
            if 'Server' in request.headers.keys():
                print(request.headers['server'])
                Version_detected = re.search(r'[aA]pache.\d\.\d\.\d+',request.headers['server'])
                if not Version_detected:
                    comment = 'version not detected for host: '+host
                # Server header is present and version is also detected
                else:
                    match = re.search(r'\d\.\d\.\d+', Version_detected.group(0))
                    pocsaver(host , port, "apache-server-header", Version_detected.group(0))
                    version = match.group(0)
                    break
            # If server header is not present in response
            else:
                comment = "Server header not present"
        except requests.exceptions.ConnectionError:
            comment = "Failed to esablish connection"
        except Exception as error:
            comment = "unknown error:"+str(error)
    return version, comment
    
def check_version_tomcat(host,port):
    if port == "443":
        url = 'https://'+host+':'+port+'/404'
    else:
        url = 'http://'+host+':'+port+'/404'
    comment = ""
    version = "0"
    
    for i in range(3):
        try:
            if port == "443":
                request = requests.get(url,verify=False, timeout=5)
            else:
                request = requests.get(url, timeout=5)
            Apache_tomcat = re.search(r'[aA]pache [tT]omcat.\d\.\d\.\d+',request.text)
            if Apache_tomcat:
                Apache_tomcat_version = re.search(r'\d\.\d\.\d+', Apache_tomcat.group(0))
                pocsaver(host , port, "tomcat-version", Apache_tomcat.group(0))
                version = Apache_tomcat_version.group(0)
                break
            else:
                comment = 'tomcat version not detected'
        except requests.exceptions.ConnectionError: 
            comment = "Failed to esablish connection"
        except Exception as error:
            comment = "unknown error:"+str(error)
    return version, comment

def DecisionMaker(status, Unconfirmed):
    NewStatus = ""
    if status:
        if Unconfirmed:
            NewStatus = 'confirmed'
            cprint(NewStatus, "green")
        else:
            NewStatus = 'unfixed'
            cprint(NewStatus, "green")
    else:
        cprint("Not verified", "red")
    return NewStatus



def main():
    # Declare the argparser objects description and create an object
    parser = argparse.ArgumentParser(description='version checker')
    
    # Add arguments
    parser.add_argument('-f','--filepath', help='provide filepath here', required=True)
    parser.add_argument('-s','--savefile', help='provide filepath for the POC file here', required=True)

    # Create a dictionary to store values passed in argument parser
    arguments_dict = vars(parser.parse_args())
    Unconfirmed = False
    if "unconfirmed" in arguments_dict['filepath']:
        Unconfirmed = True
    if "/" in arguments_dict['filepath'] or "\\" in arguments_dict['filepath']:
        file_name = re.search(r'(?<=[/\\])[^/\\]+.csv', arguments_dict['filepath'])
        newfile_name = "Verified-"+file_name.group(0)
        newfile = arguments_dict['filepath'].replace(file_name.group(0),newfile_name)
    else:
        newfile = "Verified-"+arguments_dict['filepath']
    with open(arguments_dict['filepath'], 'r', newline='') as csvfile, open (newfile, 'w', newline='') as writerfile, open(arguments_dict['savefile'], 'w') as outputfile:
        reader = csv.DictReader(csvfile)
        writer = csv.writer(writerfile,  dialect='excel')
        headers = ["Last Verified", "Impact", "Probability", "Title", "Host", "Port", "Target", "Technical Details", "Appcheck URL", "Status", "Notes", "Comment"]
        writer.writerow(headers)
        for row in reader:
            status, comment, new_status = '', '', row['Status']
            if "security headers report" in row["Title"].lower():
                if Unconfirmed:
                    new_status = 'confirmed'
                else:
                    new_status = 'unfixed'

            if "Stack Trace Detected: ASP.NET Stack Trace" in row["Title"] or "ASP .NET Verbose Error Reporting Enabled" in row["Title"]:
                print(row["Title"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = asp_error(row['Title'], row['Target'],row["Port"], hostlist)
                new_status = DecisionMaker(status, Unconfirmed)
            if "source map disclosure" in row["Title"].lower():
                print(row["Title"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = source_map(row['Title'], row['Target'],row["Port"], hostlist)
                new_status = DecisionMaker(status, Unconfirmed)

            if "cross-origin resource sharing" in row["Title"].lower() or "cross origin resource sharing" in row["Title"].lower():
                print(row["Title"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = cors_verifier(row['Title'], row['Target'], hostlist, row['Port'])
                new_status = DecisionMaker(status, Unconfirmed)

            if ('nginx' not in row['Title'].lower() and 'mysql' not in row['Title'].lower() and 'jetty' not in row["Title"].lower() and 'jboss' not in row["Title"].lower() and 'zookeeper' not in row["Title"].lower() and 'jquery' not in row["Title"].lower()) and (('detected version' in row["Technical Details"].lower() and ('apache' in row["Technical Details"].lower() or 'tomcat' in row["Technical Details"].lower())) or 'tomcat version' in row["Technical Details"] or 'detected version (' in row["Technical Details"]): 
                print(row["Title"]+"\n")
                status, comment = check_status(row["Host"], row["Port"], row["Technical Details"], row["Title"])
                new_status = DecisionMaker(status, Unconfirmed)
            
                #print("Tech details - "+row["Technical Details"]+"\n")
                

            if ("nginx" in row["Title"].lower() and "detected version (" in row["Technical Details"].lower()) or ("jboss_enterprise_application_platform" in row["Technical Details"].lower() and "jboss" in row["Title"].lower()) or ("zookeeper" in row["Technical Details"].lower() or "zookeeper" in row["Title"].lower()) or ("jetty" in row["Technical Details"] or "elasticsearch" in row["Technical Details"]) :
                print(row["Technical Details"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = version_verifier(row['Title'], row['Technical Details'], hostlist, row['Port'])
                new_status = DecisionMaker(status, Unconfirmed)
            

            if ('diffie-hellman' in row['Title'].lower() and 'ssl' in row['Title'].lower()) or ('ssl/tls' in row['Title'].lower()):
                print(row['Title']+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = ssl_vulns(row['Title'], row['Technical Details'], hostlist, row['Port'])
                #print(row['Technical Details'].lower())
                new_status = DecisionMaker(status, Unconfirmed)
            
                #print("Tech details - "+row["Technical Details"]+"\n")
            if 'openbsd' in row['Title'].lower() or 'openssh' in row["Title"].lower() or 'open shh' in row["Title"].lower() and ('detected version' in row["Technical Details"].lower() or 'openbsd' in row["Technical Details"].lower() or 'installed version' in row["Technical Details"].lower()):
                print(row["Technical Details"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = ssh_verifier(row['Title'], row['Technical Details'], hostlist, row['Port'])
                new_status = DecisionMaker(status, Unconfirmed)
            if 'tomcat' not in row["Title"].lower() and ('mysql' in row["Title"].lower() or 'microsoft sql' in row["Title"].lower() or ('mysql' in row["Technical Details"].lower() or 'microsoft sql' in row["Technical Details"].lower())):
                print(row["Technical Details"]+"\n")
                hostlist = parse_host(row["Host"])
                status, comment = mysql_verifier(row['Title'], row['Technical Details'], hostlist, row['Port'])
                new_status = DecisionMaker(status, Unconfirmed)
            if ('diffie-hellman' in row['Title'].lower() or "weak host key" in row['Title'].lower() or 'weak key exchange' in row['Title'].lower() or "weak encryption algorithm" in row['Title'].lower() or "weak host key" in row['Title'].lower() or "weak mac algorithm" in row['Title'].lower()) and 'ssh' in row['Title'].lower():
                hostlist = parse_host(row["Host"])
                status, comment = ssh_script_verifier(row['Title'], row['Technical Details'], hostlist, row['Port'])
                new_status = DecisionMaker(status, Unconfirmed)
            if 'cookie without httponly flag set' in row['Title'].lower() or "missing `httponly` cookie attribute" in row["Title"].lower():
                hostlist = parse_host(row["Host"])
                httponly, comment = Cookie_Checker(hostlist, row["Port"], row["Target"], False)
                if not httponly:
                    if Unconfirmed:
                        new_status = 'confirmed'
                    else:
                        new_status = 'unfixed'
            if 'ssl cookie without secure flag set' in row['Title'].lower() or "ssl/tls: missing `secure` cookie" in row["Title"].lower():
                hostlist = parse_host(row["Host"])
                secure, comment = Cookie_Checker(hostlist, row["Port"], row["Target"], True)
                if not secure:
                    if Unconfirmed:
                        new_status = 'confirmed'
                    else:
                        new_status = 'unfixed'

            if row["Title"].lower().startswith('outdated') and "appcheck analysed" in row["Technical Details"].lower():
                hostlist = parse_host(row["Host"])
                status, comment = jscript_verifier(row['Title'], row['Technical Details'], hostlist, row['Port'])
                print(row["Title"])
                new_status = DecisionMaker(status, Unconfirmed)
            #if "Cross-Domain JavaScript (Missing SRI)" in row["Title"]:
            #    print(row['Title']+"\n")
             #   javascript_sri(row['Title'], row['Technical Details'], row['Port'])
                
            writer.writerow([row["Last Verified"], row["Impact"], row["Probability"], row["Title"], row["Host"], row["Port"], row["Target"], row["Technical Details"], row["Appcheck URL"], new_status , row["Notes"], comment])
            #allrows.append([row["Last Verified"], row["Impact"], row["Probability"], row["Title"], row["Host"], row["Port"], row["Target"], row["Technical Details"], row["Appcheck URL"], new_status , row["Notes"], comment])
        pocloader(outputfile)
        #headers = ["Last Verified", "Impact", "Probability", "Title", "Host", "Port", "Target", "Technical Details", "Appcheck URL", "Status", "Notes", "Comment"]
        #writer.writerow(headers)
        #writer.writerows(allrows)

if __name__ == "__main__":
    # If the script is run directly.
    # Run the main method.
    #check_libraries("https://beta.isiopensions.com/Homepage")
    main()
