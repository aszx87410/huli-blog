---
title: '[心得] Hubot, 一套 bot framework'
date: 2016-01-09 12:35
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other,bot]
---
第一次知道 hubot 是因為看到[湾区日报是如何运作的？](https://wanqu.co/blog/2015-05-24-behind-the-scenes.html)這篇文章，裡面不斷推薦 hubot 很好用很好用，好奇之下就去找來看。

先來簡短描述 hubot 到底是什麼
[hubot](https://hubot.github.com/)是一套 github 開源出來的機器人框架
這是什麼意思呢？
就是 hubot 幫你開好一些 API, 一些 interface，然後你可以自己實作腳本或是 adapter
hubot 的擴充性因為有這兩點所以變得很高，第一是你可以去找別人下載好的腳本來執行
例如說自動 deploy，自動回話什麼的；那 adapter 就是去串接各個服務
例如說你如果用 slack adapter，你機器人對外的溝通介面就是 slack；也有 qq adapter，就變成利用 qq 溝通

這也是為什麼我會說 hubot 是一套框架，他扮演的角色你可以看成這樣：

>slack <---> adapter <---> hubot <---> script

slack 可以換成任何可以輸出入的介面，像是簡訊、電子郵件、slack、line 等等
前提是你要實作好 adapter在這兩者之間溝通

其實寫到這邊我越來越喜歡 hubot，為什麼呢？因為他的架構讓開發者可以很快速的切換各種場景
像是我有稍微研究過 slack bot 的實作，其實就是串一下 slack api 然後自己實現一些邏輯
這樣會碰到的困難是，假設今天我要在 qq 上也實作相同的功能，怎麼辦？就要自己重寫一遍
但如果透過 hubot 的架構，只要把 adapter 抽換掉就好

接著就來寫一篇簡單的教學/心得文吧

## 安裝
請參考官方教學：[Getting Started With Hubot](https://hubot.github.com/docs/)
實際在裝的時候碰到的困難是出現：`UNMET PEER DEPENDENCY yo@>=1.0.0`錯誤
解法可以看這裡：https://github.com/yeoman/generator-angular/issues/1192
但我自己是沒解掉，用 nvm 把 node 退回 v0.12 就順利裝起來了
接著只要執行 `bin/hubot`，跑的起來就代表你弄好了

## 裝上 slack adapter
https://github.com/slackhq/hubot-slack
在同一個資料夾底下`npm install hubot-slack --save`
在裝的同時可以先去 slack 新增 app，選擇 hubot
弄好之後就會拿到一個 token
執行這段指令，把 token 換成自己的，就可以跑起來了
`HUBOT_SLACK_TOKEN=xoxb-1234-5678-91011-00e4dd ./bin/hubot --adapter slack`

## 寫 script
可是跑起來以後其實一點用都沒有，因為你還沒有指定腳本
我覺得 [hubot 的文件](https://hubot.github.com/docs/scripting/)寫的滿不錯的
先在`scripts`資料夾底下建立一個`script.js`，然後開始寫簡單的程式碼，例如說：
``` javascript
module.exports = function(robot){
	robot.respond(/hello/, function(res){
		res.send('world');
	});
}
```
結果如下圖：
![螢幕快照 2016-01-11 上午12.49.14.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/417258/UKXNh9pPTCywaMNnENuF_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-01-11%20%E4%B8%8A%E5%8D%8812.49.14.jpg)

這樣就是一個簡單的 bot 了！
但要成為一個真的實用的機器人，有兩個必備條件
1. 要可以抓到一些參數
2. 送 http request

馬上來示範一下怎麼達成：
``` javascript
module.exports = function(robot){
	robot.respond(/check (.*)/, function(response){
		var content = response.match[1];
		if(content.indexOf('http')<0){
			return response.send('不是一個正確的網址喔，你是不是忘記加 http 呢？');
		}
		robot.http(content).get()(function(err, res, body){
			if(err){
				return response.send(err);
			}
			response.send(res.statusCode+'');
		})
	});
}
```
![螢幕快照 2016-01-11 上午1.15.59.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/417258/FFIsAz0TDWW0Kz7CORh3_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-01-11%20%E4%B8%8A%E5%8D%881.15.59.jpg)

這邊一個值得注意點的是 callback function 的設計有點奇怪
一般來說都是包在`get`裡面，可是這邊的設計卻包在外面
原本是 coffee script，我還想說怎麼拿到的結果那麼奇怪
後來才知道原來用 javascript 是要這樣寫

簡單的應用差不多是這樣
更複雜的可以自己搭配任何 nodejs 的 library
要接不同地方把 adapter 改掉即可，超級容易
最後講一下一個小缺點，那就是寫 script 的時候超級難 debug
```
[Mon Jan 11 2016 01:14:08 GMT+0800 (CST)] ERROR TypeError: undefined is not a function
  at SlackBot.send (/Users/mac/Documents/nodejs/myhubot/node_modules/hubot-slack/src/slack.coffee:229:47, <js>:278:19)
  at runAdapterSend (/Users/mac/Documents/nodejs/myhubot/node_modules/hubot/src/response.coffee:82:34, <js>:87:50)
  at allDone (/Users/mac/Documents/nodejs/myhubot/node_modules/hubot/src/middleware.coffee:41:37, <js>:32:16)
  at /Users/mac/Documents/nodejs/myhubot/node_modules/hubot/node_modules/async/lib/async.js:274:13
  at Object.async.eachSeries (/Users/mac/Documents/nodejs/myhubot/node_modules/hubot/node_modules/async/lib/async.js:142:20)
  at Object.async.reduce (/Users/mac/Documents/nodejs/myhubot/node_modules/hubot/node_modules/async/lib/async.js:268:15)
  at /Users/mac/Documents/nodejs/myhubot/node_modules/hubot/src/middleware.coffee:46:7, <js>:35:22
  at process._tickCallback (node.js:355:11)
```
後來發現好像是 `response.send` 一定要帶字串，帶數字或是 json object 都不行，都會出錯
