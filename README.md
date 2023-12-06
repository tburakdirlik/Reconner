REQUIREMENTS

    pip install -r requirements.txt

PORT SCANNER USAGE
    
    python3 main.py -t <target> -p <port>                    
    python3 main.py -t <target> -p <port1,port2,port3>       
    python3 main.py -t <target> -P <port1, port2>            
    
SUBDOMAIN SCANNER USAGE
    
    python3 main.py --domain facebook.com --wordList subdomains.txt --thread 100 --protocol https 
    python3 main.py --domain <domain> --wordList subdomain.txt --thread <thread count> --protocol https 
    
DIRECTORY TRAVERSAL VULLNERABILITY SCANNER USAGE
    
    python3 main.py --dirdiscover http://192.168.127.155/bWAPP/directory_traversal_1.php?page=message.txt
    python3 main.py --dirdiscover http://192.168.127.178/bWAPP/directory_traversal_1.php?page=../../../etc/passwd
    
XSS SCANNER USAGE
    
    python3 main.py -t http://testphp.vulnweb.com --wordList payload.txt 
    
WHOIS USAGE

    python3 main.py --whois <url>

if you encounter an errpr like this  

    └─# python main.py --domain facebook.com --wordList subdomains.txt --thread 100 --protocol https 
    Traceback (most recent call last):
      File "/home/kali/reconner/Reconner/main.py", line 4, in <module>
        from IPy import IP
      File "/usr/local/lib/python3.11/dist-packages/IPy.py", line 1025, in <module>
        class IPSet(collections.MutableSet):
                ^^^^^^^^^^^^^^^^^^^^^^
    AttributeError: module 'collections' has no attribute 'MutableSet'
                                                                                                                                                                                                                                            
Upgrade your IPy 

    pip install --upgrade IPy

Examples

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/1.png)

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/2.png)

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/3.png)

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/4.png)

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/5.png)

![Alt text](https://github.com/tburakdirlik/Reconner/blob/main/bin/6.png)
