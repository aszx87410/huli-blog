---
title: '自己修改佈景主題'
date: 2014-04-19 12:58
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other]
---
我一直以為logdown的佈景主題是付費的用戶才可以換
但昨天發現好像免費版的用戶也可以，於是就把每個佈景主題都換過一次
最後發現Octopress這個theme我滿喜歡的
但缺點就是它顯示code的版面我不喜歡，沒有margin讓我很不習慣
在顯示code的方面我還是喜歡原來的那個版面

但是logdown很棒的就是可以拿現有的佈景自己改一改客製化來用
於是我就去原有的版面（its-compiling）裡的css檔找跟code有關的css
[http://cdn-theme.logdown.io/its-compiling/stylesheets/screen.css](http://cdn-theme.logdown.io/its-compiling/stylesheets/screen.css)

然後通通複製出來貼到Octopress上面，自己加一段css覆蓋掉原本的
但margin還是沒有出來，於是自己用chrome的檢查元素功能看一看改一改之後
最後終於變得跟原本的有八九成像了

順便note一下code

``` css
figure.code pre{
	background-color:#ffc
}
pre,code{
	font-family:Menlo,Monaco,"Andale Mono","lucida console","Courier New",monospace
}
pre{
	font-size:14px;
	border:1px solid #d9d9d9;
	padding:.5em;
	overflow:auto
}

code{
	background-color:#ececec;
	color:#d14;
	font-size:85%;
	text-shadow:0 1px 0 rgba(255,255,255,0.9);
	border:1px solid #d9d9d9;
	padding:0.15em 0.3em
}
.figure-code{
	margin:20px 0
}
.figure-code figcaption{
	background-color:#e6e6e6;
	font:85%/2.25 Menlo,Monaco,"Andale Mono","lucida console","Courier New",monospace;
	text-indent:0.5em;
	text-shadow:0 1px 0 rgba(255,255,255,0.9);
	-webkit-border-radius:0.25em 0.25em 0 0;
	-moz-border-radius:0.25em 0.25em 0 0;
	-ms-border-radius:0.25em 0.25em 0 0;
	-o-border-radius:0.25em 0.25em 0 0;
	border-radius:0.25em 0.25em 0 0;
	-webkit-box-shadow:inset 0 0 0 1px #d9d9d9;
	-moz-box-shadow:inset 0 0 0 1px #d9d9d9;
	box-shadow:inset 0 0 0 1px #d9d9d9
}
.highlight{
    background:#ffc;
}
.gist .highlight *::selection, figure.code .highlight *::selection{
	background:#d9d9d9;
	text-shadow:#ffc 0 1px;
}
```