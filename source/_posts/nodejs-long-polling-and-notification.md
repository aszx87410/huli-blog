---
title: '[Node.js] long polling and notification'
date: 2015-07-01 10:25
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---
最近需要一個小功能
例如說我server現在處理一些事情，我希望完成以後前端頁面可以跳出通知，跟user講說某件事情完成了
套個socket.io也是可以，只是我覺得這樣的一個小功能應該可以用別的方法來做
於是就找了一下在node.js上面如何實作long polling

這兩篇有介紹了幾種server跟client之間持續拿資料的方式
[WebSocket 通訊協定簡介：比較 Polling、Long-Polling 與 Streaming 的運作原理](http://blogger.gtwang.org/2014/01/websocket-protocol.html)
[Browser 與 Server 持續同步的作法介紹 (Polling, Comet, Long Polling, WebSocket)](http://josephj.com/entry.php?id=358)

client端的實作很簡單，其實就是ajax完成以後再發一次ajax，就這樣而已
``` javascript
var count = 0;
function polling(){
	count++;
	if(count>=100){
		return;
	}
	$.ajax({
		url: '/longPolling',
		success: function(response) {

			console.log(response);
			
		},
		complete:function(){
			polling();
		}
	})
}

polling();
```

會加上`count`是因為我有時候在測的時候server可能會關掉重開，這時候如果沒加這個，就會看到client瘋狂一直發request

``` javascript
var longPollingRoute = function(request, response, next){

	var start = new Date();
	var ret = {
		list: []
	};

	var defaultRes = JSON.stringify(ret);

	function polling(req, res){
		var date = new Date();

		//超過20秒
		if(parseInt(date - start) > 20000) {
			res.writeHead(200, {'Content-Type': 'text/plain'});
			res.end(defaultRes);
			return false;
		}

		//do something, 例如說去資料庫拿資料
		var hasData = getSomething();
		if(hasData){

			//把資料送回client
			res.writeHead(200, {'Content-Type': 'text/plain'});
			ret.list = list;
			res.write(JSON.stringify(ret));
			res.end();
			ret.list = [];
			return false;
		}

		//10秒鐘重複抓一次
		setTimeout(function(){ 
			polling(request, response) 
		}, 10000);
	}
 
	polling(request, response);	
}

router.route('/longPolling').get(longPollingRoute);
```

跟我貼的參考資料不一樣的點大概只差在抓取時間，範例上的`getTime()`會出現未定義函式的錯誤
所以我就用了別的方法來達成這件事情

秒數可以設置成常數，之後會比較好改一點

現在已經可以讓server跟client同步了，接下來就是發通知的部分了
這裏直接採用比較新的瀏覽器內建支援的通知API

``` javascript
function notify(msg){

	if(!("Notification" in window)){
    alert(msg);
  }else if (Notification.permission === "granted") {
    var notification = new Notification(msg);
  	setTimeout(notification.close.bind(notification), 3000);
  }else if(Notification.permission !== 'denied') {
    Notification.requestPermission(function (permission) {
      if (permission === "granted") {
        var notification = new Notification(msg);
  			setTimeout(notification.close.bind(notification), 3000);
      }
    });
  }
}
```

這樣就會看到你螢幕的右上角有個可愛的通知了
只是這邊我有碰到一個問題，我在發完通知以後會refresh現在的page
應該是因為這樣的緣故，所以通知就不會自動關掉了，不知道有沒有什麼好的解法？

ref:
[Long Polling in node.js](http://blog.shian.tw/long-polling-in-node-js.html)
[Notification](https://developer.mozilla.org/en-US/docs/Web/API/notification)