---
layout: note
title: "Closure 記憶體陷阱"
date: 2026-02-02 20:34:59
---
今天 Bun 的作者 Jarred Sumner 在推特上發了個文，説對於跑很久的 Claude code session 來說，底下的改動可以省掉 1GB 的記憶體：

Before： => controller.abort
After：controller.abort.bind(controller)

從原本的 function 換成了 bind 的用法，為什麼這樣就可以呢？或是換個方式問，為什麼原本的寫法會吃比較多記憶體？

在原文附圖的註解裡就有寫原因了，說原本用 closure 的寫法，會把整個 scope 記住，而這個 scope 有 request body 跟其他大的物件，所以在結束以前，這些被包住的東西都沒辦法被 GC，就會一直佔空間。

而修改後的做法沒有 closure 了，所以不會記住那些無關的東西。

這個問題其實在我的書[《JavaScript 重修就好》](https://www.tenlong.com.tw/products/9786267757048)裡面就有提過了，有書的同學可以打開翻到 4-44，講 closure 可能造成的潛在問題，我給了這樣的案例：

```
function createWebSocketHandler {
  let socket = new WebSocket("wss://example.com/chat");
  let messages = [];
  socket.onmessage = function(event) {
    messages.push(event.data);
  };
  return {
    sendMessage: function(text) {
      socket.send(text);
    },
    closeConnection: function {
      socket.close;
      socket.onmessage = null;
      socket = null;
    }
  };
}
const chatHandler = createWebSocketHandler;
chatHandler.sendMessage("Hello, world!");
chatHandler.closeConnection;
```

在關閉連線時，我們將 socket close，然後把有用到 messages 的 onmessage 清掉，也把 socket 整個清掉，看起來沒人用到 messages 了，就想說安全，既然沒人用到那就可以被 GC 了。

但這是在使用 closure 時會產生的錯覺，那就是「只有我有用到的東西才會被記住」。事實上，closure 才沒有在管你使用與否，只要是同一個 scope 的東西就全部記了下來。

因此，儘管 sendMessage 與 closeConnection 這兩個函式沒有用到 messages， 它依然被引用了。所以就算把 socket.onmessage 給清除，messages 的記憶體空間還是沒辦法被回收。

重點只有一個，就是 closure 是整個 scope 都會記著，被記住的東西就不會被 GC 了。這恰巧也是 Claude code 碰到的問題，沒有察覺到那個被回傳的 function 會記住整個 scope。

然後這也跟 AI 寫 code 一點關係都沒有，一堆人類也會寫出這樣的 code，況且現在人跟 AI 誰寫得比較好還很難說呢，尤其是對那些非工程師來說。

這個案例是人是 AI 都有可能犯錯，但如果是其他案例，當有人責怪 AI 怎麼寫出這種爛 code 的時候，AI 說不定會想跳出來抱怨：「我才不會犯這種錯呢，這一定是人類寫的」。

補充文章：<https://x.com/jarredsumner/status/2017825694731145388>
