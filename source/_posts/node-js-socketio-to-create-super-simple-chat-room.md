---
title: '[Node.js] 利用socket.io打造超簡易聊天室'
date: 2015-04-20 16:11
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---
最近在研究node.js，由於它是單線程的，所以適合的場景是：連接數多，但是每個連接做的事情都不會佔用大量資源。
在這樣的前提之下，聊天室就是一個很好的範例，可以同時容納很多人，但每個人做的事情（發送訊息）都很快速就可以完成。
而`socket.io`就是一套可以同時使用在server跟client的library，而且使用方法非常簡單

http://socket.io/get-started/chat/
這是官方的基本教學，看著這個做其實很快就可以上手
只是我有碰到一些問題，所以後來拿這份範例去改了一下，加了一些新功能

先來介紹一下怎麼使用socket.io
直接看code或許會比較容易明瞭
``` javascript app.js
io.on('connection', function(socket){
	//新user
		socket.on('add user',function(msg){
		socket.username = msg;
		console.log("new user:"+msg+" logged.");
		io.emit('add user',{
			username: socket.username
		});
	});
});
```

在有新的client連入的時候，就會執行到`connection`的callback function，會傳入一個`socket`，可以利用這個socket跟這個client溝通

而`socket.on`就是新增一個監聽事件，就像jQuery的`$('#btn').on('click',function(...))`那樣
在上面的程式碼中，我們新增了一個`add user`的事件，等待client端觸發。而這個事件是有新使用者連進來的時候，會傳入它的username，在這邊把這個資訊附加在`socket`上面，識別這個使用者。

而`io.emit`就是送出資料給所有連線的client，`add user`則是事件名稱，第二個參數是要送出的資料

針對上面這段server的code，如果寫在client(html)上面，大致上會長這樣
``` javascript index.html
var socket = io();
var name = prompt("請輸入暱稱","guest");

socket.emit("add user",name);

socket.on('add user',function(data){
  appendMessage(data.username+"已加入");
});
```
在用戶輸入name以後，利用`socket.emit`傳訊息給server，觸發server的`socket.on('add user',...)`
接著再監聽`add user`事件，每當server傳通知來說有新的使用者連入的時候，就在畫面上新增資訊

在這邊要特別提一下
有一種作法是，在client的操作都直接呈現結果，例如說你發送訊息，就直接`$(#msg).append(msg)`之類的；另外一種作法是，一律監聽從socket發送過來的事件，再去做處理。

第一種作法在server端的時候，我們原本用的是`io.emit`發送訊息，但是在這邊不能這樣用
為什麼？因為會造成重複操作
1.使用者aa輸入訊息：你好
2.送出訊息
3.畫面呈現出：你好
4.使用者aa收到socket的事件，有人傳送訊息：你好
5.新增訊息
6.畫面呈現出：你好 你好

所以在server端的時候，要避免發送訊息給「自己」
在實作上面是`socket.broadcast.emit(...)`，就可以發送訊息給「除了自己之外的所有socket」
而`io.emit`則是直接送給所有的socket

我一開始在測試的時候，用了`socket.broadcast.emit(...)`，html裡面又沒有直接呈現操作的結果，害我一直很疑惑，為什麼socket永遠收不到server傳來的事件....不管傳什麼訊息就沒有回傳回來

反正簡單來說就是，
要發送事件用`socket.emit`或是`io.emit(server端)`，要接收事件用`socket.on`，就是這麼簡單
你只要自己定義一些事件名稱跟寫收到事件後要執行的code即可

這邊是一個小範例
可以發送訊息，可以取暱稱，可以通知說誰誰誰加入或離開
還滿陽春的，但是我想應該足夠幫助對於socket.io的理解了
想要更多功能的範例可參考[官方範例](https://github.com/Automattic/socket.io/tree/master/examples/chat)
demo：http://floating-mesa-9431.herokuapp.com/
原始碼：https://github.com/aszx87410/nodejs_simple_chatroom

