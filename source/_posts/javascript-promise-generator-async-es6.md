---
title: '[Javascript] Promise, generator, async與ES6'
date: 2015-08-26 17:04
catalog: true
tags: [JavaScript,Front-end]
categories:
  - JavaScript
---
在Javascript裡面，有一個超級重要的概念就是非同步，這也是剛入門的時候最容易搞混、忘記的觀念
ES6原生支援了`Promise`，搭配`Generator`使用效果更佳，而ES7甚至支援了`async`的語法
我覺得這算是一個演進的過程，讓程式架構越來越好、可讀性越來越高
所以要講解這些新的東西，就先從最基本的callback開始吧

<!-- more -->


現在假設我們有三個api
第一個是抓取文章列表的api
```json
[
  {
    "title": "文章1",
    "id": 1
  },
  {
    "title": "文章2",
    "id": 2
  },
  {
    "title": "文章3",
    "id": 3
  }
]
```

第二個是給文章id, 抓取文章內容的api
```javascript
{
  "authorId": 5,
  "content": "content",
  "timestamp": "2015-08-26"
}
```

第三個是給作者id, 返回作者資訊的api
```javascript
{
  "email": "aszx87410@gmail.com",
  "name": "huli",
  "id": 5
}
```

現在想要達成的功能是：**抓取最新的一篇文章的作者信箱**
流程就是：抓文章列表->抓文章資訊->抓作者
實作成code就像這樣
``` javascript
getArticleList(function(articles){
	getArticle(articles[0].id, function(article){
    	getAuthor(article.authorId, function(author){
        	alert(author.email);
        })
    })
})

function getAuthor(id, callback){
    $.ajax("http://beta.json-generator.com/api/json/get/E105pDLh",{
    	author: id
    }).done(function(result){
    	callback(result);
    })
}

function getArticle(id, callback){
    $.ajax("http://beta.json-generator.com/api/json/get/EkI02vUn",{
    	id: id
    }).done(function(result){
    	callback(result);
    })
}

function getArticleList(callback){
	$.ajax(
    "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
    .done(function(result){
        callback(result);
    });
}
```
或可參考線上範例：[用callback實做](http://jsfiddle.net/ddam2mof/2/)

相信這樣子的code大家應該都不陌生，但是這樣會有一個缺點
就是我們俗稱的callback hell，這樣一層一層一層的實在是有點醜
那該怎麼辦呢？有種東西叫做`Promise`，就這樣出現了
先來個實際範例再來講解吧！

``` javascript
getArticleList().then(function(articles){
	return getArticle(articles[0].id);
}).then(function(article){
    return getAuthor(article.authorId);
}).then(function(author){
	alert(author.email);
});

function getAuthor(id){
    return new Promise(function(resolve, reject){
        $.ajax("http://beta.json-generator.com/api/json/get/E105pDLh",{
            author: id
        }).done(function(result){
            resolve(result);
        })
    });
}

function getArticle(id){
    return new Promise(function(resolve, reject){
        $.ajax("http://beta.json-generator.com/api/json/get/EkI02vUn",{
            id: id
        }).done(function(result){
            resolve(result);
        })
    });
}

function getArticleList(){
    return new Promise(function(resolve, reject){
       $.ajax(
        "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
        .done(function(result){
            resolve(result);
        }); 
    });
}
```
線上範例：[用Promise實做](http://jsfiddle.net/ddam2mof/3/)
`Promise`是一個物件，有三種狀態，等待中（pending）、完成（resolve or fulfilled）跟失敗（reject）
在上面的範例中，我們把那三個函數的callback function拿掉了，取而代之的是返回一個Promise物件
原本應該是`callback`要出現的地方，變成了`resolve`
這樣有什麼好處呢？看我們最上面呼叫這些函式的地方，原本的callback hell不見了，被我們壓平了
如果看的不是很懂，就先從最基本的，呼叫一個Promise開始
``` javascript
getArticleList().then(function(articles){
  console.log(articles);
});

function getArticleList(){
    return new Promise(function(resolve, reject){
       $.ajax(
        "http://beta.json-generator.com/api/json/get/Ey8JqwIh")
        .done(function(result){
            resolve(result);
        }); 
    });
}
```

你可以在Promise物件後面加上`.then`，就會是這個Promise跑完之後的結果
假如在`then`裡面return另一個`Promise`物件，就可以不斷串接使用
像是這樣
```javascript
getArticleList().then(function(articles){
	return getArticle(articles[0].id);
}).then(function(article){
    return getAuthor(article);
});
```

有了Promise的這個特性，就可以避免掉callback hell
如果我們加上ES6的arrow function，甚至可以簡化成這樣

``` javascript
getArticleList()
.then(articles => getArticle(articles[0].id))
.then(article => getAuthor(article.authorId))
.then(author => {
	alert(author.email);
});
```
[線上範例 Promise+arrow function](http://jsfiddle.net/aszx87410/ddam2mof/4/)

單純運用Promise的範例就到這邊為止，其實到這邊語法已經滿簡單的了，而且有了arrow function以後，可讀性有變得比較好，但是看到一堆`then`總是覺得有點礙眼

那接下來還有什麼呢？
ES6裡面多了一個Generator，如果不知道的話可參考我的上一篇文章[[Javascript] ES6 Generator基礎](http://huli.logdown.com/posts/292331-javascript-es6-generator-foundation)
接著就要利用Generator的特性，來寫出超級像同步但其實是非同步的程式碼
``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}

var gen = run();
gen.next().value.then(function(r1){
  gen.next(r1).value.then(function(r2){
      gen.next(r2).value.then(function(r3){
        gen.next(r3);
        console.log("done");
      })
  })
});
```
[完整版線上範例 Promise + Generator](http://jsfiddle.net/aszx87410/ddam2mof/5/)

仔細看`run`這個generator，利用`yield`的特性，會先執行右邊的程式碼，等待下一次的呼叫並且賦值給左邊
所以我們可以在`getArticleList()`裡面的`then`事件呼叫`gen.next(r1)`，就會把回傳值丟給`articles`這個變數
如果覺得這樣有點難懂，可以先換成只有一層的
```javascript
function* run(){
  var articles = yield getArticleList();
  console.log(articles); 
}

var gen = run();

//第一次呼叫，會執行到getArticleList()，會回傳一個Promise
gen.next().value.then(function(r1){

  //第一個Promise結束後，把r1丟回給generator，讓articles = getArticleList()的回傳值
  gen.next(r1);
  console.log('done');
});
```

讓我們再回來看看上面那段程式碼的上半部
``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}
```
有沒有覺得，跟同步的程式碼很像？只要把`yield`拿掉的話，根本就一模一樣對吧！
這就是generator的精髓所在了：用很像同步的語法，但其實是非同步

那再來看看下半部
``` javascript
var gen = run();
gen.next().value.then(function(r1){
  gen.next(r1).value.then(function(r2){
      gen.next(r2).value.then(function(r3){
        gen.next(r3);
        console.log("done");
      })
  })
});
```
很容易可以發現下半部的語法很固定，並且容易找出規律
而且根本就是個遞迴
所以可以用一個函式包住，處理更多general的case
``` javascript
function* run(){
  var articles = yield getArticleList();
  var article = yield getArticle(articles[0].id);
  var author = yield getAuthor(article.authorId);
  alert(author.email);  
}

function runGenerator(){
	var gen = run();
    
    function go(result){
        if(result.done) return;
        result.value.then(function(r){
        	go(gen.next(r));
        });
    }
    
    go(gen.next());
}

runGenerator();
```
[完整版線上範例 Promise + Generator + 遞迴](http://jsfiddle.net/aszx87410/ddam2mof/6/)
tj做的[co模組](https://github.com/tj/co)就是在做差不多的事情，只是做得更多了
但原理跟我們上面寫的`runGenerator`很類似，就是把一個generator包起來寫一個自動執行器

最後，終於要講到標題上的最後一個東西了：async
這是什麼？先來看code
```
async function run(){
  var articles = await getArticleList();
  var article = await getArticle(articles[0].id);
  var author = await getAuthor(article.authorId);
  alert(author.email);  
}
```
[完整版線上範例 async(沒辦法跑)](http://jsfiddle.net/aszx87410/ddam2mof/7/)
(jsfiddle支援度沒那麼高，所以沒辦法跑這段code)

這段code跟之前的差別在於
1. `function* gen()`變成`async function run()`
2. `yield`變成`await`
就這兩個點而已
然後你會發現，就這樣就結束了
不必用其他模組，不必自己寫遞迴執行器
這就是`async`的語法，其實就是把那些自動執行寫好而已，但是這樣的語法讓我們方便許多
而其實這個語法是在`ES7`才有計畫引入的，QQ

好消息是，我們上面有關ES6的code都是通過[babel](https://babeljs.io/)這個library轉換成ES5的語法
而他有個[實驗性功能](https://babeljs.io/docs/usage/experimental/)的地方，其中就有包含`async`
而`async`是在`stage 2`，**NOTE: Stage 2 and above are enabled by default.**
什麼參數都不用調整就自動幫你開啟了，真是可喜可賀

當初剛接觸ES6時，一下子接觸到一堆眼花撩亂的東西，每個再繼續深入下去都是一門學問
而且我在之前都是純粹用callback（因為層級不多所以還好），偶爾用一下`async`（node的library，跟上面的不一樣）
所以我覺得最好了解的方式，就是從最基礎的callback開始，慢慢進步到promise，再進步到generator，最後才是async
才能懂得為什麼會有這些東西的出現

如果有哪些地方有講錯，還麻煩留個言或是寄信給我
感謝

ref:
[ECMAScript 6 入门 异步操作](http://es6.ruanyifeng.com/#docs/async)
[JavaScript Promises](http://www.html5rocks.com/zh/tutorials/es6/promises/)
[拥抱Generator，告别异步回调](https://cnodejs.org/topic/542953d42ca9451e1bf3c251)
[深入浅出ES6（三）：生成器 Generators](http://www.infoq.com/cn/articles/es6-in-depth-generators)
