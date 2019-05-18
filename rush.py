#!/usr/bin/python2
# RushScan - Web Application Scanner
# Copyright (c)2019 - Afrizal F.A - ICWR-TECH
# Just For Testing And Education Web Application

import re, sys, requests

print """
 ____            _     ____
|  _ \\ _   _ ___| |__ / ___|  ___ __ _ _ __
| |_) | | | / __| '_ \\\\___ \\ / __/ _` | '_ \\
|  _ <| |_| \__ \ | | |___) | (_| (_| | | | |
|_| \\_\\\\__,_|___/_| |_|____/ \\___\\__,_|_| |_|

Copyright (c)2019 - Afrizal F.A - ICWR-TECH
"""

target=sys.argv[1]
user_agent="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"
str_cms=open("lib/str_cms.rush", "r").read()
linker_str="""href=\"(.+?)\"^^href=\'(.+?)\'""".split("^^")
konten_str="""src=\"(.+?)\"^^src=\'(.+?)\'""".split("^^")
print "[*] Scanning : " + target
konten=requests.get(url=target, headers={"User-Agent" : user_agent}, allow_redirects=True).content
cek=""

print "\n[*] Scanning CMS\n"
pisah_cms=str_cms.split("^^^")
cms_detect=""
for key in pisah_cms :
    cms_value=key.split("^")
    konten_cms=requests.get(url=target + "/robots.txt", headers={"User-Agent" : user_agent}, allow_redirects=True).content
    if re.search(cms_value[0], konten_cms) :
        cms_detect=cms_value[1]
        print "[+] CMS : " + cms_value[1]
        print "\n[*] Scanning Sensitive " + cms_detect + " Plugins"
        list_plugins=open(cms_value[2], "r").read().split("^^^")
        p_detect=""
        for p_key in list_plugins :
            s_plugins=p_key.split("^")
            cek_plugins=requests.get(url=target + s_plugins[0], headers={"User-Agent" : user_agent}, allow_redirects=True)
            if cek_plugins.status_code == 200 :
                print "\n[+] Find Plugins : " + s_plugins[1]
                print "[+] Reference : " + s_plugins[2]
        if not p_detect :
            print "\n[+] Not Detect Plugins"

if not cms_detect :
    print "[-] CMS Not Detected"

print "\n[*] Scanning Content\n"
for x_linker in linker_str :
    result_f=""
    str_link=re.findall(x_linker, konten)
    for link_f in str_link :
        result_f=link_f
        if re.match(target, link_f) :
            if re.match("http://", link_f) or re.match("https://", link_f) :
                print "[+] Content : " + link_f.replace("///", "/")
        else :
            if re.match("http://", link_f) or re.match("https://", link_f) :
                print "[+] Content : " + link_f.replace("///", "/")
            else :
                e_link_f_raw=target + "/" + link_f
                e_link_f=e_link_f_raw.replace("///", "/")
                print "[+] Content : " + e_link_f

    if not result_f :
        print "[-] Content Not Detected"

print "\n[*] Scanning URL\n"
for x_konten in linker_str :
    result_l=""
    str_link=re.findall(x_konten, konten)
    for link in str_link :
        result_l=link
        if re.match(target, result_l) :
            if re.match("http://", link) or re.match("https://", link) :
                print "[+] Find URL : " + link.replace("///", "/")
        else :
            if re.match("http://", link) or re.match("https://", link) :
                print "[+] Find URL : " + link.replace("///", "/")
            else :
                e_link_raw=target + "/" + link
                e_link=e_link_raw.replace("///", "/")
                print "[+] Find URL : " + e_link

    if not result_l :
        print "[-] URL Not Detected"
