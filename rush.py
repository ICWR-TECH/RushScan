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
action_str="""action=\"(.+?)\"^^action=\'(.+?)\'""".split("^^")
p_str="""name=\"(.+?)\"^^name=\'(.+?)\'""".split("^^")
pyld_xss="<!-- XSS -->"
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
        print "[+] CMS : " + cms_value[2]
        print "\n[*] Scanning Sensitive " + cms_detect + " Plugins"
        list_plugins=open(cms_value[1], "r").read().split("^^^")
        p_detect=""
        for p_key in list_plugins :
            s_plugins=p_key.split("^")
            cek_plugins=requests.get(url=target + s_plugins[0], headers={"User-Agent" : user_agent}, allow_redirects=True)
            if cek_plugins.status_code == 200 :
                p_detect="find"
                print "\n[+] Find Plugins : " + s_plugins[1]
                print "[+] Reference : " + s_plugins[2]
        if not p_detect :
            print "\n[-] Not Detect Plugins"

if not cms_detect :
    print "[-] CMS Not Detected"

result_f=""
print "\n[*] Scanning Content\n"
for x_linker in linker_str :
    str_link=re.findall(x_linker, konten)
    for link_f in str_link :
        result_f=link_f
        if re.match(target, link_f) :
            if re.match("http://", link_f) or re.match("https://", link_f) :
                print "[+] Find Content : " + link_f.replace("///", "/")
        else :
            if re.match("http://", link_f) or re.match("https://", link_f) :
                print "[+] Find Content : " + link_f.replace("///", "/")
            else :
                e_link_f_raw=target + "/" + link_f
                e_link_f=e_link_f_raw.replace("///", "/")
                print "[+] Find Content : " + e_link_f

if not result_f :
    print "[-] Content Not Detected"

result_l=""
print "\n[*] Scanning URL\n"
for x_konten in linker_str :
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

result_a=""
link_a=""
print "\n[*] Scanning Action URL\n"
for x_action in action_str :
    str_link=re.findall(x_action, konten)
    for link in str_link :
        result_a=link
        if re.match(target, result_a) :
            if re.match("http://", link) or re.match("https://", link) :
                link_a+=link.replace("///", "/") + "\n"
                print "[+] Find Action URL : " + link.replace("///", "/")
        else :
            if re.match("http://", link) or re.match("https://", link) :
                link_a+=link.replace("///", "/") + "\n"
                print "[+] Find Action URL : " + link.replace("///", "/")
            else :
                a_link_raw=target + "/" + link
                a_link=e_link_raw.replace("///", "/")
                link_a+=a_link + "\n"
                print "[+] Find Action URL : " + a_link

if not result_a :
    print "[-] Action URL Not Detected"

x_s=""
xg_x=""
print "\n[*] Detect Parameter\n"
for x_str in p_str :
    m_param=re.findall(x_str, konten)
    xp={ "" : ""}
    xg=""
    for m_p in m_param :
        dict={ m_p : pyld_xss }
        x_s = { m_p : pyld_xss }
        xg_x=m_p + "=" + pyld_xss
        xg+="&" + m_p + "=" + pyld_xss
        xp.update(dict)
        print "[+] Find : " + m_p
        req_post=requests.post(url=target, data=x_s, headers={"User-Agent" : user_agent}, allow_redirects=True).content
        if re.search(pyld_xss, req_post) :
            print "[+] Vulnerability In Parameter \"" + x_s[m_p] + "\""
            ask=raw_input("Type \"exit\" For Exit : ")
            if ask == "exit" :
                exit
        else :
            print "[-] Failed Trying XSS ( POST ) Parameter : " + m_p
        xss_get=target + "/?" + str(m_p) + "=" + x_s[m_p]
        req_get=requests.post(url=xss_get, headers={"User-Agent" : user_agent}, allow_redirects=True).content
        if re.search(pyld_xss, req_get) :
            print "[+] Vulnerability Parameter \"" + m_p + "\" In URL : " + xss_get
            ask=raw_input("Type \"exit\" For Exit : ")
            if ask == "exit" :
                exit
        else :
            print "[*] Failed Trying XSS ( GET ) Parameter " + str(m_p) + " : " + xss_get

print "\n[*] Trying All Parameter Post Data\n"
if re.search(pyld_xss, requests.post(url=target, data=xp, headers={"User-Agent" : user_agent}, allow_redirects=True).content) :
    print "[+] Find POST Request Xss In : " + target
else :
    print "[-] Not Find POST Request Xss"

print "\n[*] Trying All Parameter GET\n"
if re.search(pyld_xss, requests.get(url=target + "?" + xg_x + xg, headers={"User-Agent" : user_agent}, allow_redirects=True).content) :
    print "[+] Find GET Request Xss In : " + target
else :
    print "[-] Not Find GET Request Xss"

if not x_s :
    print "\n[-] Parameter Not Found\n"

link_act=link_a.split("\n")
if link_a :
    for l_act in link_act :
        if not l_act :
            continue
        print "\n[*] Trying All Parameter POST in URL : " + l_act + "\n"
        if re.search(pyld_xss, requests.post(url=l_act, data=xp, headers={"User-Agent" : user_agent}, allow_redirects=True).content) :
            print "[+] Find POST Request Xss In : " + l_act
            ask=raw_input("Type \"exit\" For Exit : ")
            if ask == "exit" :
                exit
        else :
            print "[-] Not Find POST Request Xss"

        print "\n[*] Trying All Parameter GET in URL : " + l_act + "\n"
        if re.search(pyld_xss, requests.get(url=l_act + "?" + xg_x + xg, headers={"User-Agent" : user_agent}, allow_redirects=True).content) :
            print "[+] Find GET Request Xss In : " + target
            ask=raw_input("Type \"exit\" For Exit : ")
            if ask == "exit" :
                exit
        else :
            print "[-] Not Find GET Request Xss"
