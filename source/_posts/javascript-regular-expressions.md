---
title: '[Javascript] 正規表達式'
date: 2014-04-05 22:54
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,frontend]
---
今天剛好有人來問我這個我又不太會
上網查了點資料之後動手做一下，有比較熟悉一點
趕快寫篇文章記錄一下心得
js的正規表達式要用`/..../`包起來
例如說要驗證一個數字 `/\d/`

而`^`是代表字串的開頭，`$`是代表字串的結尾
`\d`是數字，`+`是代表一個以上，`{2}`則是指定要出現兩次的意思
用`()`刮起來就是記憶單位，就是以後可以被讀取出來的部分
前面加上`?:`就是代表不想被記憶
後面加上`?`就代表是可選擇的單位

如果我們想要驗證一個電話並且抓出他的區碼、號碼跟分機
（號碼限定8碼）
``` javascript

var tel = "02-12345678#123";
var pattern = /^(0\d+)-(\d{8})(?:(?:#)(\d+))?$/; 
document.writeln(pattern.test(tel))
var result = pattern.exec(tel);
for(i=1;i<result.length;i++){
	document.writeln(i+":"+result[i]);
}

```


參考資料：
[JS]正規表示法(Regular expressions)
http://syunguo.blogspot.tw/2013/04/jsregular-expressions.html

[javascript] 正規化表示法速查表
http://felixhuang.pixnet.net/blog/post/23673013-%5Bjavascript%5D-%E6%AD%A3%E8%A6%8F%E5%8C%96%E8%A1%A8%E7%A4%BA%E6%B3%95%E9%80%9F%E6%9F%A5%E8%A1%A8

正規表達式模式的編寫
https://developer.mozilla.org/zh-TW/docs/Core_JavaScript_1.5_%E6%95%99%E5%AD%B8/%E6%AD%A3%E8%A6%8F%E8%A1%A8%E9%81%94%E5%BC%8F%E6%A8%A1%E5%BC%8F%E7%9A%84%E7%B7%A8%E5%AF%AB

