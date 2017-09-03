---
title: '[jQuery] 讓jquery plugin多國語言'
date: 2014-07-23 11:23
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,frontend]
---
最近在研究怎麼讓jquery套件支援多國語言
就是我可能有一個jquery叫做hello_world，用的時候只要
`$(".title").hello_world();`就可以顯示一個"你好"的文字
那我現在如果想讓這個套件支援多國語言，要怎麼做呢？

很簡單可以想到的一種作法就是傳一個語言的參數進去
例如說：`$(".title").hello_world({lang:"en"});`
接著在plugin裡面依據傳進來的參數決定好要顯示哪種語言即可

第二種作法我覺得更好一點
是參考[jquery easy ui](https://code.google.com/p/transmission-control/source/browse/trunk/script/easyui/locale/easyui-lang-zh_TW.js?r=14)的作法

假如你今天想要英文版的plugin，你就include一個en.js就好
`<script src="locale/en.js"></script>`
那這是怎麼做到的呢？
``` javascript en.js
if($.fn.hello_world){
		var hello_world = $.fn.hello_world;
		hello_world.i18n = {
			hello:"hello"
		};
	}
```
用語言檔(en.js)把原本plugin裡面的變數換掉
``` javascript hello_world.js
....(前略)
$.fn.hello_world.i18n = {
    hello:"你好"
}
```
在plugin裡面要用到這個文字的地方就用`$.fn.hello_world.i18n.hello`存取即可
如此以來就可以藉由引入不同的語言檔，實現多國語言