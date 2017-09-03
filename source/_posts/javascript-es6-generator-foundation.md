---
title: '[Javascript] ES6 Generator基礎'
date: 2015-08-24 18:29
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,frontend]
---
最近趁著有些時間研究了一下ES6，有個很重要的東西叫做`Generator`，但是這概念對我來說超級陌生
所以我覺得沒有很好上手，研究過一些資料以後終於搞懂是在做什麼
寫篇文章跟大家分享

首先，Generator這東西之所以會不好上手，是因為
##一個指令做兩件事情
只要記住這個原則，Generator就沒有那麼困難了
```javascript
function *get_counter(){
  let i = 1;
  while(true){
    yield i;
    i++;
  }
}

var counter = get_counter();
console.log(counter.next().value);//1
console.log(counter.next().value);//2
console.log(counter.next().value);//3
console.log(counter.next().value);//4
```

一個簡單的計數器，在這邊可以很簡單的先想說，`yield`這個指令就是把東西丟出去
這邊應該滿好理解，但是generator難懂的地方就在於，除了把東西丟出去，還可以丟東西進來

```javascript
function *get_adder(){
  let total = 0;
  while(true){
    console.log("before yield");
    total+=yield total;
    console.log("after yield, total:"+total);
  }
}

var adder = get_adder();
console.log(adder.next().value);
/*
before yield
0
*/
console.log(adder.next(100).value);
/*
after yield, total:100
before yield
100
*/
```

在執行第一次`next()`的時候，會先跑到`console.log("before yield");`，這很好懂
接著會先執行`yield total`，會先把total丟出去，所以會輸出0
接下來呢？還記得剛剛說過 `yield`除了丟值，還可以接受值，所以丟完以後，現在會等下一個值丟進來
於是程式就停住了，執行完第一次之後，會停留在輸出0的地方

接著執行第二次`next()`，我們把100傳進去，於是**上一次**的yield在等待的值就傳入了，會執行
`total+=100;`，然後輸出`after yield, total:100`
每呼叫一次next，都會跑到`yield輸出值`的地方！所以接著會跑到`before yield`然後把total，也就是100丟出去
接著等待下一個值

用比較好懂的方式，就是把`yield`拆成兩個指令
```javascript
function *get_adder(){
  let total = 0;
  while(true){
    console.log("before yield");
    output(total);
    total+=input();
    console.log("after yield, total:"+total);
  }
}
```
每次`next()`的時候都會執行到`output`的地方
`input`則是會等待外面傳值進來

再來看一個範例
```javascript
function *gen(){
  let arr = [];
  while(true){
    arr.push(yield arr);
  }
}

var name = gen();
console.log(name.next('init').value);//[]
console.log(name.next('nick').value);//["nick"]
console.log(name.next('peter').value);//["nick","peter"]
```
可以注意到的是，第一次的`next()`無論有沒有傳值其實都一樣
為什麼呢？還記得剛才提過，generator最重要的概念是：每次next()都會執行到yield丟值出去的地方
然後yield這個指令分成兩個步驟，**先丟東西出去，再等東西進來**。
所以第一次的next()，跑到yield的第一個步驟就結束了，等第二次的next()傳東西進來

差不多就這樣了
重要的兩個概念就是：
1. yield其實是兩個動作的合體：丟東西出去->等東西進來
2. 每次next()都會跑到yield丟東西出來的那個步驟


ref:
[拥抱Generator，告别异步回调](https://cnodejs.org/topic/542953d42ca9451e1bf3c251)
[ES6 Generators 基礎教學](http://andyyou.logdown.com/posts/276655-es6-generators-teaching)