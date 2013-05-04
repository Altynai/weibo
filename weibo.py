#!/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import json
import urllib2
import urllib
import base64
import cookielib
import rsa
import binascii
import logging
from bs4 import BeautifulSoup

cookiejar = cookielib.LWPCookieJar()  
cookie_support = urllib2.HTTPCookieProcessor(cookiejar)  
opener = urllib2.build_opener(cookie_support, urllib2.HTTPHandler)  
urllib2.install_opener(opener) 

loggerformat ='line:%(lineno)d %(asctime)s %(filename)s %(levelname)s %(message)s'

logging.basicConfig(format = loggerformat,
				filename = 'weibo.log',
				filemode = 'w')

pagemax = 20 	# 最多抓取粉丝/关注的页面数
catchmax = 600 	# 最多抓取粉丝/关注的数量

class weibo(object):
	"""
	模拟登录新浪微博，获得cookie
	1.GET请求得到weibo server随机产生的servertime，nonce等字段
	2.根据首页js分析出加密方式
	3.发送带完整FORM的POST
	"""

	def __init__(self, email, password):
		"""
		配置logger，同时输出到控制台和weibo.log
		"""
		self.uid = None
		self.loginpath = 'http://login.sina.com.cn'
		self.path = 'http://weibo.com'
		self.email = email
		self.password = password

		self.logger = logging.getLogger()
		self.logger.setLevel(logging.DEBUG)

		sh = logging.StreamHandler()  
		sh.setLevel(logging.DEBUG)
		global loggerformat
		sh.setFormatter(logging.Formatter(loggerformat))  
		self.logger.addHandler(sh)  

	def getservertimeandnonce(self, email):
		"""
		模拟成浏览器
		访问/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=email&rsakt=mod&client=ssologin.js(v1.4.5)
		获得servertime，nonce和rsakv
		"""

		path = '/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=%s&rsakt=mod&client=ssologin.js(v1.4.5)' % email
		request = urllib2.Request(self.loginpath + path)

		# request.add_header('Accept','text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
		# request.add_header('Accept-Charset','GBK,utf-8;q=0.7,*;q=0.3')
		# request.add_header('Accept-Encoding','gzip,deflate,sdch')
		# request.add_header('Accept-Language','zh-CN,zh;q=0.8')
		# request.add_header('Cache-Control','max-age=0')
		# request.add_header('Connection','keep-alive')
		# request.add_header('User-Agent', 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.64 Safari/537.31')
		
		response = urllib2.urlopen(request)
		responsecontent = response.read()
		regex = re.compile('\((.*)\)')
		responsecontent = regex.findall(responsecontent)[0]

		resultdict = {}
		self.logger.info('getservertimeandnonce结果，' + responsecontent)
		namelist = ['servertime', 'nonce', 'pubkey', 'rsakv']
		try:
			jsondata = json.loads(responsecontent)
			for name in namelist:
				self.logger.info('%s -> %s' % (name, jsondata.get(name)))
				resultdict.setdefault(name, jsondata.get(name))

			return resultdict
		except Exception, e:
			return None

	def encryptEmail(self, email):
	    """
	    Google结果：
	    先将quote进行urlcode转码，再进行base64编码，如果模拟登陆使用还需要进行一次urlcode转码
	    """

	    email = urllib2.quote(email)
	    email = base64.encodestring(email)[:-1]
	    return email

	def encryptPassword(self, password, resultdict):
	    """
	    Google结果：
	    先创建一个rsa公钥，公钥的两个参数新浪微博都给了固定值，不过给的都是16进制的字符串
	    第一个是登录第一步中的pubkey，第二个是js加密文件中的‘10001’。
		这两个值需要先从16进制转换成10进制，不过也可以写死在代码里。这里就把10001直接写死为65537。
		通过rsa加密后转换成16进制
	    """

	    pubkey = resultdict['pubkey']
	    servertime = resultdict['servertime']
	    nonce = resultdict['nonce']
	    rsaPublickey = int(pubkey, 16)
	    key = rsa.PublicKey(rsaPublickey, 65537)
	    message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)
	    password = rsa.encrypt(message, key)
	    password = binascii.b2a_hex(password)
	    return password

	def login(self):
		"""
		POST加密过的邮箱和密码，测试登陆是否成功
		登录成功后自动GET跳转链接，保存Cookie
		return 登陆是否成功
		"""

		resultdict = self.getservertimeandnonce(self.email)
		if resultdict == None:
			self.logger.error('获取servertime，nonce等信息失败\n')
			return False

		newemail = self.encryptEmail(self.email)
		newpassword = self.encryptPassword(self.password, resultdict)
		resultdict.setdefault('su', newemail)
		resultdict.setdefault('sp', newpassword)

		bodys = {
			'entry': 'weibo',
			'gateway': '1',
			'from': '',
			'savestate': '7',
			'userticket': '1',
			'ssosimplelogin': '1',
			'vsnf': '1',
			'vsnval': '',
			'su': resultdict['su'],
			'service': 'miniblog',
			'servertime': resultdict['servertime'],
			'nonce': resultdict['nonce'],
			'pwencode': 'rsa2',
			'sp': resultdict['sp'],
			'encoding': 'UTF-8',
			'prelt': '115',
			'rsakv' : resultdict['rsakv'],
			'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
			'returntype': 'META'
		}

		headers = {
			'Connection':'keep-alive',
			'Cache-Control':'max-age=0',
			'Accept':'text/html:application/xhtml+xml:application/xml;q=0.9:*/*;q=0.8',
			'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.31 (KHTML: like Gecko) Chrome/26.0.1410.64 Safari/537.31',
			'Content-Type':'application/x-www-form-urlencoded',
			'Referer':'http://weibo.com/a/download',
			'Accept-Encoding':'gzip:deflate:sdch',
			'Accept-Language':'zh-CN:zh;q=0.8',
			'Accept-Charset':'GBK,utf-8;q=0.7,*;q=0.3',
		}

		path = '/sso/login.php?client=ssologin.js(v1.4.5)'
		request = urllib2.Request(url = self.loginpath + path, data = urllib.urlencode(bodys), headers = headers)
		response = urllib2.urlopen(request)
		responsecontent = response.read()

		regex = re.compile('location.replace\("(.*)"\)')
		nextlink = regex.findall(responsecontent)[0]
		self.logger.info('跳转链接，' + nextlink)

		if responsecontent.find('retcode=0') == -1:
			self.logger.error('登录失败')
			return False
		else:
			self.logger.info('登录成功')
			request = urllib2.Request(url = nextlink, headers = headers)
			responsecontent = urllib2.urlopen(request).read()
			regex = re.compile('\((.*)\)')
			jsondata = json.loads(regex.findall(responsecontent)[0])
			self.uid = jsondata.get('userinfo').get('uniqueid')
			self.logger.info('当前登录微博id ' + self.uid)
			return True


	def send(self, text):
		"""
		发送微博
		return 是否发送成功
		"""

		data = {
			'text': text,
			'pic_id':'',
			'rank':'0',
			'rankid':'',
			'_surl':'',
			'location':'',
			'module':'topquick',
			'_t':'0',
		}
		headers = {
			'Accept':'*/*',
			'Accept-Charset':'GBK,utf-8;q=0.7,*;q=0.3',
			'Accept-Encoding':'gzip,deflate,sdch',
			'Accept-Language':'zh-CN,zh;q=0.8',
			'Connection':'keep-alive',
			'Content-Type':'application/x-www-form-urlencoded',
			'Origin':'http://weibo.com',
			'Referer':'http://weibo.com/minipublish?uid=2164187874',
			'X-Requested-With':'XMLHttpRequest',
			'User-Agent':'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.31 (KHTML, like Gecko) Chrome/26.0.1410.64 Safari/537.31'
		}
		path = '/aj/mblog/add?_wv=5'

		request = urllib2.Request(url = self.path + path, data = urllib.urlencode(data), headers = headers)
		response = urllib2.urlopen(request)
		responsecontent = response.read()
		self.logger.info('登录结果 ' + responsecontent)

		result = json.loads(responsecontent)
		code = result.get('code')
		if code == '100000':
			self.logger.info('发送微博成功')
			return True
		else:
			self.logger.error('发送失败 '+ result.get('msg'))
			return False

	def getlist(self, url, regex):
		"""
		根据URL的原网页代码，正则匹配出有用的信息
		用于匹配出(fans_uid, fans_name)和(follows_uid, follows_name)
		return [(uid1, name1), (uid2, name2)....]
		"""
		request = urllib2.Request(url)
		response = urllib2.urlopen(request)
		html = response.read()
		return regex.findall(html)

	def fans(self, uid = "-1"):
		"""
		根据uid查看其粉丝列表，默认查看当前账号的粉丝列表
		return [(fans1_uid, fans1_name),(fans2_uid, fans2_name), ....]
		"""

		if uid == "-1" or uid == self.uid:
			uid = self.uid
			urlformat = 'http://weibo.com/%s/myfans?page=%d'
			regex = r'usercard=\\"id=(\d*)\\" title=\\"(.*?)\\"'
		else:
			urlformat = 'http://weibo.com/%s/fans?page=%d'
			regex = r'action-type=\\"itemClick\\" action-data=\\"uid=(\d*)&fnick=(.*?)&sex=[mf]'
		regex = re.compile(regex)
		page = 1
		fanslist = []
		catched = 0
		global pagemax, catchmax
		while page <= pagemax and catched <= catchmax:
			url = urlformat % (uid, page)
			pagelist = self.getlist(url, regex)
			if len(pagelist) == 0:
				break
			pagecount = len(pagelist)
			catched += pagecount
			self.logger.info('%s 粉丝第%d页结果，共%d个' % (uid, page, pagecount))
			for faninfo in pagelist:
				fanslist.append(faninfo)
			page += 1
		return fanslist

	def follows(self, uid = "-1"):
		"""
		根据uid查看其关注列表，默认查看当前账号的关注列表
		return [(follow1_uid, follow1_name),(follow2_uid, follow2_name), ....]
		"""
		if uid == "-1" or uid == self.uid:
			uid = self.uid
			urlformat = 'http://weibo.com/%s/myfollow?page=%d'
			regex = r'usercard=\\"id=(\d*)\\" alt=\\"(.*?)\\"'
		else:
			urlformat = 'http://weibo.com/%s/follow?page=%d'
			regex = r'action-type=\\"itemClick\\" action-data=\\"uid=(\d*)&fnick=(.*?)&sex=[mf]'

		regex = re.compile(regex)
		page = 1
		followslist = []
		catched = 0
		global pagemax, catchmax

		# 标记第一页的第一个id，请求可能重复，例如
		# 某个用户有1,2,...,10页关注
		# 当请求page=11时，返回的其实是第1页数据
		markedid = None

		while page <= pagemax and catched <= catchmax:
			url = urlformat % (uid, page)
			pagelist = self.getlist(url, regex)
			if len(pagelist) == 0:
				break
			pagecount = len(pagelist)
			catched += pagecount

			if page == 1:
				markedid = pagelist[0][0]
			# 发生重复的情况
			if page != 1 and pagelist[0][0] == markedid:
				break
			
			self.logger.info('%s 关注第%d页结果，共%d个' % (uid, page, pagecount))
			for followinfo in pagelist:
				followslist.append(followinfo)
			page += 1
		return followslist


	def tagstring(self, html, tagname, classname):
		"""
		在html中，从类似<tagname class=classname>文本</tagname>
		的tag中提取'文本',tag可能有多个，只提取文本，并合并
		return [string1, string2....]
		"""
		strings = []
		for tag in BeautifulSoup(html).find_all(tagname, class_ = classname):
			strings.append(''.join([str(x) for x in tag.stripped_strings]))
		return strings


	def news(self, page = 1):
		"""
		获得当前登录用户的第page页新鲜事
		return json格式的新鲜事，如下：
		[
			{'nickname0' : nickname0, 'text0' : text0},						<-- 原创微博

			{'nickname0' : nickname0, 'text0' : text0,
			 'nickname1' : nickname1, 'text1' : text1},						<-- 转发微博
			...
		]

		"""
		request = urllib2.Request('http://weibo.com/u/%s?page=%d' % (self.uid, page))
		response = urllib2.urlopen(request)
		html = response.read()
		regex = re.compile(r'<script>STK && STK.pageletM && STK.pageletM.view\((.*?)\)<\/script>')
		# 先获得新鲜事主体
		newscontent = None
		for script in regex.findall(html):
			if script.find('"pid":"pl_content_homeFeed"') != -1:
				newscontent = script
				break
		# 新鲜事主体
		html = json.loads(newscontent).get('html')
		soup = BeautifulSoup(html)

		# sys.stdout = open('temp.html', 'w')
		jsondata = []
		for new in soup.find_all('div', class_ = 'WB_feed_type SW_fun S_line2'):
			newcontent = str(new)
			# 原创微博
			if newcontent.find('isforward') == -1:
				nickname0 = self.tagstring(newcontent, 'div', 'WB_info')[0]
				text0 = self.tagstring(newcontent, 'div', 'WB_text')[0]
				d = dict()
				d.setdefault('nickname0', nickname0)
				print 
				d.setdefault('text0', text0)
				jsondata.append(d)
			# 转发微博
			else:
				nickname = self.tagstring(newcontent, 'div', 'WB_info')
				text = self.tagstring(newcontent, 'div', 'WB_text')
				d = dict()
				for i in xrange(2):
					d.setdefault('nickname%d' % i, nickname[i])
					d.setdefault('text%d' % i, text[i])
				jsondata.append(d)
		print json.dumps(jsondata, indent = 4, separators = (',', ':'))


#----------------------测试部分----------------------#
def testmyfans(wb):
	fans = wb.fans()
	sys.stdout = open('myfans.txt', 'w')
	for fan in fans:
		print fan[0], fan[1]

def testotherfans(wb, uid):
	fans = wb.fans(uid)
	sys.stdout = open('otherfans.txt', 'w')
	for fan in fans:
		print fan[0], fan[1]

def testmyfollows(wb):
	follows = wb.follows()
	sys.stdout = open('myfollows.txt', 'w')
	for follow in follows:
		print follow[0], follow[1]

def testotherfollows(wb, uid):
	follows = wb.follows(uid)
	sys.stdout = open('otherfollows.txt', 'w')
	for follow in follows:
		print follow[0], follow[1]

def testnews(wb, page = 1):
	wb.news(page)

def test():
	email = 'xxx@qq.com'
	password = 'xxx'
	wb = weibo(email, password)
	# 测试登录
	wb.login()
	
	# 测试发微博
	# wb.send("test at ~~ @fity有点喜欢多动症 ")
	
	# 测试获得自己粉丝列表
	# testmyfans(wb)

	# 测试获得自己关注列表
	# testmyfollows(wb)

	# 测试别人粉丝列表
	# testotherfans(wb, '1915548291')

	# 测试别人粉丝列表
	# testotherfollows(wb, '1915548291')

	# 测试新鲜事（第1页）
	testnews(wb)

if __name__ == '__main__':
	test()
