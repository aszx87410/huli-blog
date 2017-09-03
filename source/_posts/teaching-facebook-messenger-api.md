---
title: '[教學] Facebook Messenger API'
date: 2016-04-13 21:24
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [tutorial,facebook api]
---
今天 Facebook 公開了 [Messenger Platform ](https://developers.facebook.com/docs/messenger-platform)，可以利用 Facebook Messenger 這個平台做溝通
意思就是，終於可以在 Facebook 上面做一個機器人啦！

其實 [Facebook 的官方教學](https://developers.facebook.com/docs/messenger-platform/quickstart)已經寫的很詳細了，但這邊我還是自己整理過一次之後 po 個心得好了
<!-- more -->


## 步驟1：開一個 facebook 應用程式
![螢幕快照 2016-04-13 下午9.27.22.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/709641/5JVUEQwBTjmifdOgUGp1_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-04-13%20%E4%B8%8B%E5%8D%889.27.22.jpg)

## 步驟2：開一個粉絲專頁
因為 messenger api 目前只能接粉絲專頁，所以沒有的話要先開一個

## 步驟3：進到 Facebook App 的設定頁面
頁面會長這樣，然後左邊那一排的下面會有`Messenger`這個 tab，點下去
![螢幕快照 2016-04-13 下午9.28.55.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/709641/y3hUNQlSN6FprVZrKY5f_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-04-13%20%E4%B8%8B%E5%8D%889.28.55.jpg)

## 步驟4：開始 coding
進入到這個步驟以後，就要設定跟 api 相關的東西了
主要有這幾個步驟
1. 產生粉絲專頁 token
2. 填入 webhook 網址
3. 把 App 跟粉絲專頁綁在一起
4. 大功告成

程式碼的部份，簡單可以分為三個部分

第一個部分是驗證，也就是官方教學講到的這段程式碼：

``` javascript
app.get('/webhook/', function (req, res) {
  if (req.query['hub.verify_token'] === '<validation_token>') {
    res.send(req.query['hub.challenge']);
  }
  res.send('Error, wrong validation token');
})
```
這段就是你在設定`webhook`網址的時候，facebook 會發一個 request 給你，看看 response 是不是正確的
如果不正確的話，那就沒辦法進入下一階段了

第二個部分就是收到訊息的 api

``` javascript
app.post('/webhook/', function (req, res) {
  messaging_events = req.body.entry[0].messaging; //所有訊息
  for (i = 0; i < messaging_events.length; i++) { // 遍歷毎一則
    event = req.body.entry[0].messaging[i]; 
    sender = event.sender.id; // 誰發的訊息
    if (event.message && event.message.text) {
      text = event.message.text;
      // Handle a text message from this sender
    }
  }
  res.sendStatus(200);
});
```
facebook 的官方範例寫的很不錯，把該給的都給了
就是：`sender`跟`text`這兩個東西

第三個部分是發送訊息

``` javascript
var token = "<page_access_token>";

function sendTextMessage(sender, text) {
  messageData = {
    text:text
  }
  request({
    url: 'https://graph.facebook.com/v2.6/me/messages',
    qs: {access_token:token},
    method: 'POST',
    json: {
      recipient: {id:sender},
      message: messageData,
    }
  }, function(error, response, body) {
    if (error) {
      console.log('Error sending message: ', error);
    } else if (response.body.error) {
      console.log('Error: ', response.body.error);
    }
  });
}
```
這邊會用到的是前面所生成的粉絲專頁的 `token`

結合以上三種，其實一個簡單的聊天機器人就出來了
這邊我有提供簡易範例，下載下來之後按照指示就可以使用了
https://github.com/aszx87410/fb-bot

## 步驟5：設定 webhook
![螢幕快照 2016-04-13 下午9.48.03.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/709641/5vS5yZc2T8m8oPBiiK4f_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-04-13%20%E4%B8%8B%E5%8D%889.48.03.jpg)

最困難的部份來了，在這個步驟你要提供兩個東西
1. callback url
2. verify token

verify token 驗證用的，看心情隨便填就好
callback url 則是我們上面寫的那個小程式在的地方
這邊有要求「一定要是 https」

我是用 [CloudFlare](https://www.cloudflare.com/) 很快的弄了一個
是免費的 https 方案裡面比較有名的

弄好之後，你應該會有個網址，例如說「https://huli.tw/fb-bot/webhook」
就把這網址填上去即可
下面幾個事件也記得全都打勾

填完之後它會用你下面填的 verify token 去驗證
驗證成功才會幫你新增

## 步驟6：把 App 跟粉絲專頁綁在一起

```
curl -ik -X POST "https://graph.facebook.com/v2.6/me/subscribed_apps?access_token=<token>"
```

把`token`換成自己粉絲專頁的`token`，執行一下會跟你說`{"success":true}`
這一步很重要，因為沒有這一步的話，你在粉絲專頁怎麼打字，都不會有人回你
還有，我每次 server 重開的時候都會重新執行一次，不然也會沒反應

## 步驟6：去粉絲專頁測試
![螢幕快照 2016-04-13 下午9.22.31.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/709641/puaOG8UnQ6lR2NK5KGIh_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-04-13%20%E4%B8%8B%E5%8D%889.22.31.jpg)
用自己帳號發訊息，順利的話就可以看到回覆了
如果發現不能發訊息，那應該是因為你是以管理者身分，調成「以訪客身分檢視」就可以了

如果你發現發了訊息但沒有回應，那可能是
1. 程式壞了，開始快樂的 debug 吧
2. 沒有執行 `步驟6`

## 總結
在串 messenger api 的時候其實滿快的
因為官方文件寫的真的不錯，很快就可以上手
其中花我最多時間的就是弄一個 https 的 domain
第二個會出錯的點是 app 去 subscribe 粉絲專頁那邊
這邊如果沒有執行，那你的 webhook 就不會有反應

近期 github 上面應該會湧入一堆相關專案吧XD
之後有 hubot adapter 的話，開發上應該會變得更方便
延伸閱讀：[[心得] Hubot, 一套 bot framework](http://huli.logdown.com/posts/417258-hubot-a-bot-framework)