---
title: '[教學] Line BOT API'
date: 2016-04-26 21:05
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [bot,backend]
---
繼上一篇 Facebook 的教學之後，這一次輪到 Line 了
可以先參考[官方文件](https://developers.line.me/bot-api/getting-started-with-bot-api-trial)
基本上你必須先申請一個試用帳號，試用帳號有名額限制，沒申請的要趕快喔！
相關消息可參考：[開放平台資源，LINE 提供 1 萬個免費「BOT API 試用」帳號申請](http://technews.tw/2016/04/07/line-begins-providing-10000-bot-api-trial-accounts-prior-to-opening-up-access-to-messaging-api/)

# 前置作業
1. 跟臉書一樣，你要有一個 https 的 server，或許你可以考慮用 [heroku](https://heroku.com/)
2. Channel ID	
3. Channel Secret
4. MID

後三個的值你可以在開發者後台找到：
![螢幕快照 2016-04-26 下午9.11.33.jpg](http://user-image.logdown.io/user/7013/blog/6977/post/726082/rjbtYj9DTxKCzyYj7VSP_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202016-04-26%20%E4%B8%8B%E5%8D%889.11.33.jpg)

接著，就是開始串 API 的時間了

# 接收訊息

其實接收訊息很簡單，line 發過來的內容會長這樣
result 是個陣列，裡面每一個 object 代表一則訊息

``` js
{ result: 
   [ { content: [Object],
       createdTime: 1461674869099,
       eventType: '138311609000106303',
       from: 'u206d25c2ea6bd87c17655609a1c37cb8',
       fromChannel: 1341301815,
       id: 'WB1519-3390674233',
       to: [Object],
       toChannel: 1462591242 } ] }
```

這邊值得注意的是，你以為`from`就是發送訊息的人的id嗎？錯！
有沒有注意到這邊有個 `content` 的 key？
print 出來之後，你會發現內容是這樣：

```js
{ 
  toType: 1,
  createdTime: 1461675694090,
  from: 'uccec910deec23d175d03272cf7887599',
  location: null,
  id: '4229056802695',
  to: [ 'ud0bbc01bd7b10902d371f0865cf68505' ],
  text: '安安',
  contentMetadata: { AT_RECV_MODE: '2', SKIP_BADGE_COUNT: 'true' },
  deliveredTime: 0,
  contentType: 1,
  seq: null 
}
```

這邊的 `from` 才是你要的那個，而不是上面那個
務必注意這一點，因為就是這一點花了我半天 debug QQ

綜合以上兩點，可以寫出一段簡單的程式碼：

```js
app.post('/callback', (req, res) => {
  const result = req.body.result;
  for(let i=0; i<result.length; i++){
    const data = result[i]['content'];
    console.log('receive: ', data);
    sendTextMessage(data.from, data.text);
  }
});
```

這邊其實是簡略版，我只在意它發過來的訊息跟是誰發過來的
照官方文件，其實你應該要處理 1. 驗證 跟 2. 事件類型
例如說你被加好友的時候，其實也會收到一個 request
但這邊只是簡易教學，有興趣的話可以自己參考官方文件


# 發送訊息
承上，我們寫了個 `sendTextMessage(data.from, data.text);` 的函式
這邊就要來實作它

```js
function sendTextMessage(sender, text) {

  const data = {
    to: [sender],
    toChannel: 1383378250,
    eventType: '138311608800106203',
    content: {
      contentType: 1,
      toType: 1,
      text: text
    }
  };

  console.log('send: ', data);

  request({
    url: LINE_API,
    headers: {
      'Content-Type': 'application/json; charset=UTF-8',
      'X-Line-ChannelID': CHANNEL_ID,
      'X-Line-ChannelSecret': CHANNEL_SERECT,
      'X-Line-Trusted-User-With-ACL': MID
    },
    method: 'POST',
    body: JSON.stringify(data) 
  }, function(error, response, body) {
    if (error) {
      console.log('Error sending message: ', error);
    } else if (response.body.error) {
      console.log('Error: ', response.body.error);
    }
    console.log('send response: ', body);
  });
}
```

其實也沒什麼難度，就一樣發個 request 而已
值得注意的點大概是：

1. header 的 content type 要設
2. header 的那三個值記得設
3. toChannel 跟 eventType 寫死就好

就這樣，就可以發送訊息了

# 結論
綜合以上兩點，其實就完成一個簡單的「echo 機器人」了
你講什麼它就講什麼
最後照例附上完整範例程式碼：https://github.com/aszx87410/line-bot

