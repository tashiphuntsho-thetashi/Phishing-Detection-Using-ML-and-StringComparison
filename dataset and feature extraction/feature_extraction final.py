
import requests
import urllib
from urllib.request import urlopen
from urllib.parse import urlparse
from bs4 import BeautifulSoup 
import re
import whois 
import datetime 
import time
import socket
import pandas as pd 
import numpy as np
# 1 to 18
def character_count(url):
    nb_dots = url.count(".")
    nb_hyphen = url.count('-')
    nb_at = url.count('@')
    nb_qm = url.count("?")
    nb_and = url.count('&')
    nb_or = url.count("|")
    nb_un_score = url.count("_")
    nb_percent = url.count("%")
    nb_slash = url.count("\\") + url.count("/")
    nb_star = url.count("*")
    nb_colon = url.count(":")
    nb_comma = url.count(",")
    nb_semi_colon = url.count(";")
    nb_dollar = url.count("$")
    nb_space = url.count(" ")
    nb_www = url.count('www')
    nb_com = url.count('.com')
    nb_tilde = url.count('~')
    return ([nb_dots,nb_hyphen,nb_at,nb_qm,nb_and,nb_or,nb_un_score,nb_percent,\
     nb_slash,nb_star , nb_colon , nb_comma,nb_semi_colon, nb_dollar, nb_space,nb_www,nb_com, nb_tilde])
# 19
def url_length(url):
    return len(url)
# 20
def ratio_digits_url(url):
    try:
        digits = [x for x in url if x.isdigit()]
        ratio = np.round(len(digits)/len(url),5)
        return (ratio)
    except: 
        return 0
# 21
def ratio_digits_host(url):
    try: 
        domain = urlparse(url).netloc
        digits = [x for x in domain if x.isdigit()]
        ratio = np.round(len(digits)/len(domain),5)
        return ratio    

    except:
        return 0
    
# 22
def web_traffic(url):
    try:
        rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
        rank= int(rank)
        return rank
    except:
        return 0
# 23
def ippresent(url):
    domain = urlparse(url).netloc
    try:
        ip = socket.gethostbyname(domain)
        return 1
    except:
        return 0
# 24
def prefixSuffix(url):
    if '-' in urlparse(url).netloc:
        return 1           
    else:
        return 0 

# 25
def https_token(url):
    if re.findall(r"^https://", url):
        return 1
    else:
        return 0
# 26
def domainAge(url):
    try:
        domain_name = urlparse(url).netloc
    
        whois_response = whois.whois(domain_name)
        creation_date = whois_response.creation_date
        creation_date = creation_date[0].date()
        today = datetime.date.today()
        days = (today - creation_date).days
        return days
    except:
        return 0
# 27
def dns_record(url):
    domain_name = urlparse(url).netloc
    try:    
        rec = whois.whois(domain_name)
        return 1
    except:
        return 0       
shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
                      r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
                      r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
                      r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
                      r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
                      r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
                      r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
                      r"tr\.im|link\.zip\.net"
# 28 tiny url
def tinyURL(url):
    match=re.search(shortening_services,url)
    if match:
        return 1
    else:
        return 0
# 29 redirection
def redirection(url):
  pos = url.rfind('//')
  if pos > 6:
    if pos > 7:
      return 1
    else:
      return 0
  else:
    return 0
# 30 Depth of url
def getDepth(url):
  s = urlparse(url).path.split('/')
  depth = 0
  for j in range(len(s)):
    if len(s[j]) != 0:
      depth = depth+1
  return depth
# 31 protocol count of url
def get_protocol_count(url):
    http_count = url.count('http')
    https_count = url.count('https')
    http_count = http_count - https_count #correcting the miscount of https as http
    return (http_count + https_count)
# 32 protocol of url 
def get_protocol(url):
    protocol = urlparse(url)
    if(protocol.scheme == 'http'):
        return 1
    else:
        return 0
# 33 special character count
def get_special_char_count(url):
    count = 0
    special_characters = [';','+=','_','?','=','&','[',']']
    for each_letter in url:
        if each_letter in special_characters:
            count = count + 1
    return count
# 34 length hostname
def len_hostname(url):
    len_hname = len(urlparse(url).netloc)
    return len_hname

def feature_extraction(url):
    feature =[character_count(url),[url_length(url)],[len_hostname(url)], [ratio_digits_url(url)],[ratio_digits_host(url)],[web_traffic(url)],\
    [ippresent(url)],[prefixSuffix(url)],[https_token(url)],[domainAge(url)],[dns_record(url)],\
    [tinyURL(url)],[redirection(url)],[getDepth(url)],[get_protocol(url)],[get_protocol_count(url)],[get_special_char_count(url)]]     
    feature = [j for i in feature for j in i]
    return feature

