#!/usr/bin/env python
# -*- coding: utf-8 -*-
# @Time    : 2017/6/23 下午1:54
# @Author  : Komi
# @File    : struts2_hunt.py
# @Project : POC-T
# @Ver:    : 0.1
# Referer   https://threathunter.org/topic/594a9f0fde1d70c20885ccd5

import time
import re
import urlparse
import httplib, urllib, urllib2

ERROR_KEYS = ['Struts Problem Report','org.apache.struts2','struts.devMode','struts-tags',
              'There is no Action mapped for namespace']

# check suffix :.do,.action
def checkBySuffix(info):
    if info['code'] == 404:
        return False
    html = info['html']
    matchs_action = re.findall(r"""(['"]{1})(/?((?:(?!\1|\n|http(s)?://).)+)\.action)(\?(?:(?!\1).)*)?\1""", html,
                        re.IGNORECASE)

    matchs_do = re.findall(r"""(['"]{1})(/?((?:(?!\1|\n|http(s)?://).)+)\.do)(\?(?:(?!\1).)*)?\1""", html,
                        re.IGNORECASE)

    if len(matchs_do)+len(matchs_action)> 0 and (".action" in str(matchs_action) or ".do" in str(matchs_do)):
        return True
    else:
        return False

# check devMode page
def checkDevMode(url):
    target_url = url+"/struts/webconsole.html"
    info = gethtml(target_url)

    if info['code'] == 200 and "Welcome to the OGNL console" in info['html']:
        return True
    else:
        return False

# check Error Messages.
def checActionsErrors(url):
    test_tmpurls = []

    test_tmpurls.append(url+"/?actionErrors=1111")
    test_tmpurls.append(url+"/tmp2017.action")
    test_tmpurls.append(url + "/tmp2017.do")
    test_tmpurls.append(url + "/system/index!testme.action")
    test_tmpurls.append(url + "/system/index!testme.do")

    for test_url in test_tmpurls:
        info = gethtml(test_url)
        for error_message in ERROR_KEYS:
            if error_message in info['html'] and info['code'] == 500:
                print "[+] found error_message:",error_message
                return True
    return False

# check CheckboxInterceptor.
def checkCheckBox(url):
    # url = "https://www.vuln.org/?keyword=aaa&loginname=admin&password=888"
    """
        https://www.vuln.org/?__checkbox_keyword=aaa&loginname=admin&password=888
        https://www.vuln.org/?keyword=aaa&__checkbox_loginname=admin&password=888
        https://www.vuln.org/?keyword=aaa&loginname=admin&__checkbox_password=888
        em:
           http://wsbs.wgj.sh.gov.cn/shwgj_zwdt/core/web/welcome/index!search.action

    """
    for match in re.finditer(r"((\A|[?&])(?P<parameter>[^_]\w*)=)(?P<value>[^&#]+)", url):

        info = gethtml(url.replace(match.group('parameter'), "__checkbox_"+match.group('parameter')))
        check_key = 'name="{}"'.format(match.group('parameter'))
        check_value = 'value="false"'

        html = info['html']
        matchs_inputTags = re.findall(r"""<\s*input[^>]*>""", html,re.IGNORECASE)
        for input_tag in matchs_inputTags:
            if check_key in input_tag and check_value in input_tag:
                return True

    return False
# 给 2 个测试站，没有找到好的实现思路
# 初步想法: 对比三次请求返回的文本大小差异,超时请求况,文本是否保护request_locale来做决策
#
# https://eservices.customs.gov.hk/MSOS/wsrh/001s0?request_locale=en_US
# https://ctc.camds.org/camds/mainpage.action?request_locale=zh_CN
# https://ctc.camds.org/camds/mainpage.action?request_locale=en_US
# http://www.quamnet.com/newsUScontent.action?request_locale=zh_CN&articleId=3436914

def checkl18n(target):

    info_orgi = gethtml(target)
    time.sleep(0.5)
    info_zhCN = gethtml(target+"?"+'request_locale=zh_CN')
    time.sleep(0.5)
    info_enUS = gethtml(target+"?"+ 'request_locale=en_US')
    time.sleep(0.5)

    if "request_locale=zh_CN" in info_orgi['html'] and "request_locale=en_US" in info_orgi['html']:
        return True

    if abs(len(info_zhCN['html']) - len(info_enUS['html'])) > 1024:
        return True

    return False

def gethtml(url):
    try:
        request = urllib2.Request(url)
        request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:21.0) Gecko/20100101 Firefox/21.0')
        request.add_header('Accept-Language', 'en-us;q=0.5,en;q=0.3')
        request.add_header('Referer', request.get_full_url())
        u = urllib2.urlopen(request , timeout = 3)
        content = u.read()
        try:
            content = content.encode("utf-8")
        except:
            content = content.decode('gbk','ignore').encode("utf-8",'ignore')
        return {"html":content,"code":u.code,"url":u.geturl()}
    except urllib2.HTTPError,e:
        try:
            return {"html":e.read(),"code":e.code,"url":e.geturl()}
        except:
            return {"html":'',"code":e.code,"url":e.geturl()}
    except:
        return {"html":"","code":404, "url":url}

def poc(target):
    if not target.lower().startswith('http://') and not target.lower().startswith('https://'):
        target = 'http://' + target

    target = urlparse.urlparse(target).scheme + "://" + urlparse.urlparse(target).netloc

    html = gethtml(target)


    if checkDevMode(target):
        return "[success] %s is struts2! [checkDevMode]" % target

    if checkBySuffix(html):
        return "[success] %s is struts2! [checkBySuffix]" % target

    if checActionsErrors(target):
        return "[success] %s is struts2! [checActionsErrors]" % target

    if checkCheckBox(target):
        return "[success] %s is struts2! [checkCheckBox]" % target

    if checkl18n(target):
        return "[success] %s is struts2! [checkl18n]" % target

    return False
