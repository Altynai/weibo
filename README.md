一个作业
=====

1.  登录  
1.  发微博
1.  根据uid看粉丝、关注列表（有基本的可修改的限制，默认抓最多抓20页，最多600条，避免粉丝/关注很多数据。。。。）
1.  查看某页的新鲜事列表

***网上有很多相关的文章，主要的而且可以说是唯一的问题就是微博对密码的加密方式，
以前是`sha`同时加`servertime`和`nonce`做干扰，现在又变成rsa了，以后又变的话这代码就得改了***

过程
=====
1.  POST邮箱密码之前，先GET这个[链接](http://login.sina.com.cn/sso/prelogin.php?entry=sso&callback=sinaSSOController.preloginCallBack&su=youremail&rsakt=mod&client=ssologin.js\(v1.4.5\))，其中`su=youremail`，`js(v1.4.5)`这个版本号会不定期改变，实际当天版本可参考登录页源码
1.  得到`servertime`，`nonce`和`rsakv`值
1.  对email，password加密，就是POST请求头的`su`和`sp`字段，记得要伪装的像个浏览器的样子
1.  得到的response是个跳转链接，其中带个`retcode`，`0`表示登录成功，其他都是失败
1.  GET那个跳转链接，保存Cookie
1.  然后就可以抓数据了

其他
=====
1.  发请求可以用`urllib2`，加上`cookielib`，这样可以自动记录Cookie
1.  新浪对密码的加密方式不定期会变，最近是rsa
1.  关于加密方式的来源，Google吧，或者具体详情可以见[这里](http://login.sina.com.cn/js/sso/ssologin.js)搜`nonce`即可，大概917行的样子
1.  Python2.7 [rsa扩展库](https://pypi.python.org/pypi/rsa/3.1.1)
1.  发微博采用**快速微博**模式，只考虑文本