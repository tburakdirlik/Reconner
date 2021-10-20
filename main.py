from colorama import Fore
from termcolor import colored
import socket
from IPy import IP
from threading import Thread, Lock
from queue import Queue
from urllib.error import HTTPError
import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin
import optparse
import whois
import os
import sys

def banner ():

    print(colored("######################################################################################################################",'yellow'))
    print(colored("#                        ____  ________________  _   __   _____ _________    _   ___   ____________                  #",'yellow'))
    print(colored("#                       / __ \/ ____/ ____/ __ \/ | / /  / ___// ____/   |  / | / / | / / ____/ __ \                 #",'yellow'))
    print(colored("#                      / /_/ / __/ / /   / / / /  |/ /   \__ \/ /   / /| | /  |/ /  |/ / __/ / /_/ /                 #",'yellow'))
    print(colored("#                     / _, _/ /___/ /___/ /_/ / /|  /   ___/ / /___/ ___ |/ /|  / /|  / /___/ _, _/                  #",'yellow'))
    print(colored("#                    /_/ |_/_____/\____/\____/_/ |_/   /____/\____/_/  |_/_/ |_/_/ |_/_____/_/ |_|                   #",'yellow'))
    print(colored("######################################################################################################################",'yellow'))
    print(colored("#                                                   USER GUIDE                                                       #",'yellow'))
    print(colored("#    WHOIS USAGE                                                                                                     #",'yellow'))
    print(colored("#        python3 main.py --whois <url>                                                                                #",'yellow'))
    print(colored("#    PORT SCANNER USAGE                                                                                              #",'yellow'))
    print(colored("#        python3 main.py -t <target> -p <port>                                                                       #",'yellow'))
    print(colored("#        python3 main.py -t <target> -P <port1, port2>                                                               #",'yellow'))
    print(colored("#        python3 main.py -t <target> -p <port1,port2,port3>                                                          #",'yellow'))
    print(colored("#    XSS SCANNER USAGE                                                                                               #",'yellow'))
    print(colored("#        python3 main.py -t http://testphp.vulnweb.com --wordList payload.txt                                        #",'yellow'))
    print(colored("#    SUBDOMAIN SCANNER USAGE                                                                                         #",'yellow'))
    print(colored("#        python3 main.py --domain <domain> --wordList subdomain.txt --thread <thread count> --protocol https         #",'yellow'))
    print(colored("#        AVAILABLE SUBDOMAIN DICTIONARIES                                                                            #",'yellow'))
    print(colored("#            subdomains.txt, subdomains-100.txt, subdomains-1000.txt, subdomains-10000.txt,                          #",'yellow'))
    print(colored("#            subdomainscommon500.txt, subdomainscommon1000.txt, suffixes.txt                                         #",'yellow'))
    print(colored("#    DIRECTORY TRAVERSAL VULLNERABILITY SCANNER USAGE                                                                #",'yellow'))
    print(colored("#        python3 main.py --dirdiscover http://192.168.127.178/bWAPP/directory_traversal_1.php?page=../etc/passwd     #",'yellow'))
    print(colored("#        FOR HELP -->python3 main.py --userguide help    or  python3 main.py. --help                                 #",'yellow'))
    print(colored("######################################################################################################################",'yellow'))

def scan_port(ipaddress, port):
    try:
        # socket descriptor,
        sck = socket.socket()  # socket library allows us to make a connection over internet
        sck.settimeout(0.1)
        # some ports will take a longer time to connect to and some ports will take less time to connect
        # this is (0.1) a price to want to pay in order to scan the target faster
        sck.connect((ipaddress, port))
        try:

            portInfo = sck.recv(1024)  # 1024 byte           #below for  clean output

            service = socket.getservbyport(port)

            print(Fore.BLUE + str(port) + '/tcp' + ' : ' + "OPEN " +  str(service)+ "   " +str(portInfo.decode().strip()))

        except:
            print(Fore.BLUE + str(port) +"/tcp" +  " : " +   "OPEN " )

    except:
        pass

def convert_ip(ip):  # this functon about converting domain name to ip address so that
    # usage of program will be allowed with domain name or ip, without any error
    try:
        IP(ip)
        return (ip)
    except ValueError:
        return socket.gethostbyname(ip)

def portScanMain():

    if (inputs.ip and inputs.portRange):
        new_ip = convert_ip(inputs.ip)
        print('\n\n' + '[--> Scanning Target] ' + str(new_ip))

        for port in range(int(portRange[0]), int(portRange[1])):
            scan_port(new_ip, port)

    if (inputs.ip and inputs.givenPorts):
        new_ip = convert_ip(inputs.ip)
        print('\n\n' + '[--> Scanning Target] ' + str(new_ip))

        for port in givenPorts:
            scan_port(new_ip, int(port))
#-----------------------------------------------------------------------------------------------------------------------
#SUBDOMAIN SCANNER
q = Queue()
list_lock = Lock()
discovered_domains = []

global protocol
def scan_subdomains(domain):
    global q

    while True:
        # get the subdomain from the queue
        subdomain = q.get()
        # scan the subdomain

        if protocol == "http":

            url = f"http://{subdomain}.{domain}"

        if protocol == "https":

            url = f"https://{subdomain}.{domain}"

        try:
            requests.get(url)
        except requests.ConnectionError:
            pass
        else:
            print("[+] Discovered subdomain:", url)
            # add the subdomain to the global list
            with list_lock:
                discovered_domains.append(url)

        q.task_done()

def subdomainMain(domain, n_threads, subdomains):
    global q

    for subdomain in subdomains:
        q.put(subdomain)

    for t in range(n_threads):

        worker = Thread(target=scan_subdomains, args=(domain,))
        # daemon thread means a thread that will end when the main thread ends
        worker.daemon = True
        worker.start()

def mainSubdomainCaller(num_threads):
    subdomainMain(domain=domain, n_threads=num_threads, subdomains=open(wordlist).read().splitlines())
    q.join()
    print("Total " + str(len(discovered_domains)) + " subdomain found")
    ask = input("If you want to save found subdomains press 's', otherwise press any character :")
    if ask == "s":
        textfile = open("SubdomainsOutput.txt", "w")
        for element in discovered_domains:
            textfile.write(element + "\n")
        textfile.close()
        print('Results saved in this locate: ', os.path.dirname(os.path.abspath("SubdomainsOutput.txt")))
#-----------------------------------------------------------------------------------------------------------------------

def dirTraversalVulnCheck():
    errorNum = 0
    # target_url = "http://192.168.127.178/bWAPP/directory_traversal_1.php?page=../../../etc/passwd"
    DICT = open("directoryTraversal.txt").read().splitlines()
    for dir in DICT:
        dirTravel = target_url + "/" + dir

        try:
            #print("\rTRYING PATH : " + dirTravel, end="")
            response = requests.get(dirTravel)
            if (response.status_code) == (requests.codes.ok):

                if (response.text != ""):

                    print("\nPOSSIBLE DIRECTORY TRAVERSAL VULLNERABILITY AT THIS PATH : " + dirTravel, end="")
                    # if "HTTP" in response.text:
                    #   print("SAID FOUNDED")

        except requests.exceptions.ConnectionError:
            print("CONNECTION ERROR")
            errorNum += 1
            if errorNum == 2:
                print("PLEASE CHECK YOUR INTERNET CONNECTION OR THAT GIVE YOU WEB ADDRESS")
                break

        except HTTPError as e:
            print("\rHTTP CODE " + str(e.code) + "FOR THIS PATH :" + dirTravel, end="")
#-----------------------------------------------------------------------------------------------------------------------

def get_all_forms(url):
    """Given a `url`, it returns all forms from the HTML content"""
    soup = bs(requests.get(url).content, "html.parser")
    return soup.find_all("form")


def get_form_details(form):
     #extracts all possible useful information about an HTML `form`

    details = {}
    # get the form action (target url)
    action = form.attrs.get("action").lower()
    # get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()
    # get all the input details such as type and name
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        inputs.append({"type": input_type, "name": input_name})
    # put everything to the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details


def submit_form(form_details, url, value):

    # construct the full URL (if the url provided in action is relative)
    target_url = urljoin(url, form_details["action"])
    # get the inputs
    inputs = form_details["inputs"]
    data = {}
    for input in inputs:
        # replace all text and search values with `value`
        if input["type"] == "text" or input["type"] == "search":
            input["value"] = value
        input_name = input.get("name")
        input_value = input.get("value")
        if input_name and input_value:
            # if input name and value are not None,
            # then add them to the data of form submission
            data[input_name] = input_value

    if form_details["method"] == "post":
        return requests.post(target_url, data=data)
    else:
        # GET request
        return requests.get(target_url, params=data)

runningPayloads = []

def scan_xss(url, js_script):

    forms = get_all_forms(url)

    is_vulnerable = False
    # iterate over all forms
    for form in forms:
        form_details = get_form_details(form)
        content = submit_form(form_details, url, js_script).content.decode()
        if js_script in content:
            print(f"[+] {js_script} XSS Detected on {url}")
            runningPayloads.append(js_script)
            is_vulnerable = True
        if len(runningPayloads) == 5:
            inp = input("Xss vullnerability already detected if you want to quit press q, otherwise press any character : ")
            if inp == "q":
                textfile = open("RunningPayloadsOutput.txt", "w")
                for element in runningPayloads:
                    textfile.write(element + "\n")
                textfile.close()
                print('Results saved in this locate: ', os.path.dirname(os.path.abspath("RunningPayloadsOutput.txt")))
                sys.exit()

    return is_vulnerable

def xssMainCaller(js_script,url):

    js_script = open(js_script).read().splitlines()

    for payload in js_script:
        print(scan_xss(url, payload))
#-----------------------------------------------------------------------------------------------------------------------

def is_registered(domain_name):
    try:
        w = whois.whois(domain_name)
    except Exception:
        return False
    else:
        return bool(w.domain_name)

def whoIsMain(domain):
    #domain = input("Give a domain name address")

    print(domain, "is registered" if is_registered(domain) else "is not registered")
    if is_registered(domain):
        whois_info = whois.whois(domain)

        print("Domain registrar:", whois_info.registrar)
        print("WHOIS server:", whois_info.whois_server)
        print("Domain creation date:", whois_info.creation_date)
        print("Expiration date:", whois_info.expiration_date)

        print(whois_info)

if __name__ == "__main__":

    parse_object = optparse.OptionParser()
    parse_object.add_option("-t", dest="ip", help="Please enter the ip or web address")
    parse_object.add_option("-p", dest="givenPorts", help="Please enter the ports")
    parse_object.add_option("-P", dest="portRange", help="Please enter the port range")

    parse_object.add_option("--wordList", dest="wordList", help="Plese give a wordlist")
    parse_object.add_option("--thread", dest="thread", help="Plese give a thread number")
    parse_object.add_option("--domain", dest="domain", help="Please give domain name without protocol (e.g without 'http://' or 'https://')")
    parse_object.add_option("--protocol", dest="protocol", help="Plese give a protocol type as http pr https")

    parse_object.add_option("--dirdiscover", dest="dirdiscover", help="PLease give a url that you want to scan directory vullnerability")

    parse_object.add_option("--whois", dest="whois", help="Plese give a domain name registration informations")
    parse_object.add_option("--userguide", dest="userguide")

    (inputs, arguments) = parse_object.parse_args()

    if inputs.userguide:
        banner()
###
    ip = inputs.ip
    givenPorts = str(inputs.givenPorts).split(',')
    portRange = str(inputs.portRange).split(',')

    if ip and (givenPorts or portRange):
        portScanMain()
    '''
    USAGE
    python3 main.py -t <target> -p <port>                    
    python3 main.py -t <target> -p <port1,port2,port3>       
    python3 main.py -t <target> -P <port1, port2>           
    '''
###

###
    wordlist = inputs.wordList
    thread = inputs.thread
    domain = inputs.domain
    protocol = inputs.protocol
    if wordlist and thread and domain and protocol:
       mainSubdomainCaller(int(thread))

    '''
    USAGE
    python3 main.py --domain facebook.com --wordList subdomains.txt --thread 100 --protocol https 
    python3 main.py --domain <domain> --wordList <wordlist file> --thread <thread count> --protocol https 
    '''
###

###
    target_url = inputs.dirdiscover
    if target_url:
        dirTraversalVulnCheck()
    '''
    USAGE 
    python3 main.py --dirdiscover http://192.168.127.155/bWAPP/directory_traversal_1.php?page=message.txt
    python3 main.py --dirdiscover http://192.168.127.178/bWAPP/directory_traversal_1.php?page=../../../etc/passwd
    '''
###

###
    if inputs.ip and inputs.wordList:
        url = inputs.ip
        js_script = inputs.wordList
        xssMainCaller(js_script, url)
        '''
        USAGE
        python3 main.py -t http://testphp.vulnweb.com --wordList payload.txt 
        '''
###
##
    if inputs.whois:
        whoIsMain(inputs.whois)
        '''
        USAGE 
        python3 main.py -whois <url>
        '''
##
