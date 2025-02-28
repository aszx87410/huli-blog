---
layout: post
title: '[Javascript] redux 的 middleware 詳解'
date: 2015-09-03 15:45
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [JavaScript,Front-end,Redux,React] 
categories:
  - React
---
之前寫了[一篇文章](http://huli.logdown.com/posts/294037-javascript-redux-basic-tutorial)簡單的筆記一下自己在看redux的心得，在這邊還是要再次推薦官方文件，因為寫的超級清楚。

但是之前在看官方文件的時候，middleware的地方沒有完全看懂，看到後面就霧煞煞了
這次重看了一遍官方文件講middleware跟非同步操作的地方，邊看邊做筆記，總算是把middleware的實作原理弄懂了
依照慣例分享一下心得


官方文件很棒的點就是這篇不只教你怎麼用，還從頭講起，讓你知道為什麼middleware會是現在這樣的形式。
<!-- more -->

#正文
你在看了某些教學文章之後覺得redux實在是太棒了，於是開始採用redux做自己的產品
可是此時此刻你突然想要做一個功能：logging，你想記錄每個action，以及執行action完以後store的改變
該怎麼做呢？先從最簡單的方法開始吧！

##第一次嘗試：最直覺的方法
假設我們原本dispatch action的code是這樣寫
```javascript
store.dispatch(addTodo('Use Redux'));
```
我們可以直接改成
```javascript
let action = addTodo('Use Redux');

console.log('dispatching', action);
store.dispatch(action);
console.log('next state', store.getState());
```

##第二次嘗試：包成函式
但是第一種方法大家都知道不能這樣，因為程式裡面一定不只一個地方需要做這件事情
那接下來怎麼辦呢？把它包成函式吧
```javascript
function dispatchAndLog(store, action) {
  console.log('dispatching', action);
  store.dispatch(action);
  console.log('next state', store.getState());
}
dispatchAndLog(store, addTodo('Use Redux'));
```
可是這樣子，你每個需要dispatch的地方都要import這個函式，有沒有更好的作法呢？

##第三次嘗試：Monkeypatching
什麼是`Monkeypatch`？大家可以自己估狗一下
大意就是：在runtime的時候把某個東西換掉
就像是你可以在你的chrome devtool裡面寫
```javascript
console.log = function(text){
  alert(text);
}
```
這樣子原本會在console裡面出現的訊息，就會全部用alert顯示了
那用在這裡我們要怎麼用呢？
```javascript
//先把原本的存起來，因為之後會用到
let next = store.dispatch;

//覆蓋掉現在的
store.dispatch = function dispatchAndLog(action) {
  console.log('dispatching', action);
  
  //執行
  next(action);
  console.log('next state', store.getState());
  return;
};

//呼叫方式跟之前一樣
store.dispatch(addTodo('Use Redux'));
```
這樣子的話，原本的code完全不用更動，你只要在程式剛開始的地方把`store.dispatch`換掉就好了
實在是輕鬆又愉快，但是我們很快就碰到了一個新的問題
>如果我現在想要一個錯誤回報的機制怎麼辦？當dispatch出錯的時候，我想把錯誤傳回server

嗯...好問題
我們可以把這兩個想做的事情獨立成兩個function，差不多像是這樣
``` javascript
function patchStoreToAddLogging(store) {
  let next = store.dispatch;
  store.dispatch = function dispatchAndLog(action) {
    console.log('dispatching', action);
    next(action);
    console.log('next state', store.getState());
    return;
  };
}

function patchStoreToAddCrashReporting(store) {
  let next = store.dispatch;
  store.dispatch = function dispatchAndReportErrors(action) {
    try {
      next(action);
    } catch (err) {
      console.error('Caught an exception!', err);
      Raven.captureException(err, {
        extra: {
          action,
          state: store.getState()
        }
      });
      throw err;
    }
  };
}

patchStoreToAddLogging(store);
patchStoreToAddCrashReporting(store);
```
剛開始讀到這段的時候我就有點暈了，不太懂為什麼這樣子可以
後面的不是會把前面的`store.dispatch`覆蓋掉嗎？後來再看幾次終於看懂，精髓就在於那個`let next = store.dispatch;`
上面code的行為大概會是這樣：
1. 執行第一個函式`patchStoreToAddLogging(store);`
2. 現在的dispatch（redux真正發送action的函式）被保存起來
3. `store.dispatch`被換掉，換成`dispatchAndLog`這個函式，這個函式的行為會是：做紀錄並且呼叫原本的dispatch
4. 執行第二個函式`patchStoreToAddCrashReporting(store);`
5. 現在的dispatch（注意，已經變成dispatchAndLog這個函式了）被保存起來
6. `store.dispatch`被換掉，換成`dispatchAndReportErrors`這個函式，這個函式的行為會是：做紀錄並且呼叫原本的dispatc

好，接著若是我們呼叫`dispatch(..)`，看一下流程會怎麼走
1. 因為剛剛被換掉，所以執行`dispatchAndReportErrors`
2. 執行`next(action)`，而`next`就是之前保存的dispatch，就是`dispatchAndLog`
3. 執行`dispatchAndLog`
4. 做紀錄，然後執行`next(action)`，而`next`就是之前保存的dispatch，就是最原始的dispatch
5. 執行最原始的dispatch，執行完畢以後跳回`dispatchAndLog`這個function
6. 回到`dispatchAndLog`，印出改變後的state
7. 回到`patchStoreToAddCrashReporting`，因為都沒有錯誤，所以不做任何事
8. 結束

這樣子就達成我們middleware最重要的功能，可以讓action經過一層又一層的中間件，最後抵達store
但是這樣子還是不夠好

##第四次嘗試：把Monkeypatching藏起來
之前我們都是直接把`store.dispatch`換掉，那如果我們不要直接換掉，而是傳回一個function，會發生什麼事？
```javascript
function logger(store) {
  let next = store.dispatch;

  // 之前的:
  // store.dispatch = function dispatchAndLog(action) {

  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```
假設我們的`crashReporter`也改成這種形式，那我們就可以
```javascript
store.dispatcher = logger(store);
store.dispatcher = crashReporter(store);
```
其實只是把`store.dispatcher`抽出來，獨立在function外面而已
但這樣做的好處就是，我們可以這樣
```javascript
function applyMiddlewareByMonkeypatching(store, middlewares) 
  // Transform dispatch function with each middleware.
  middlewares.forEach(middleware =>
    store.dispatch = middleware(store)
  );
}
applyMiddlewareByMonkeypatching(store, [logger, crashReporter]);
```
但是這樣子其實只是把monkeypatch的地方抽出來而已，實際上還是在
下一步，我們要把monkeypatch這個方法徹底移除掉

##第五次嘗試：把monkeypatching移除掉
為什麼我們要override `dispatch`？
有一個很重要的因素就是，這樣才能不斷呼叫之前的`dispatch`
```javascript
function logger(store) {
  // 這行超重要，有了這行才能達成chaining
  let next = store.dispatch;

  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```
如果少了那重要的一行，那就無法達成chaining的效果
但其實除了這樣子寫，我們還有另外一個方法可以用
我們可以接收一個`next`的參數，達到相同目的
官方文件接著有點講太快了，咻咻咻就直接把最重要的一個部分講完
我這邊試著把進度放慢，講更多細節的東西，其實就是差在`currying`這個概念

繼續剛剛講的，我們可以接收一個`next`的參數，就會變成這樣
```javascript
function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```
可以看到跟之前長得很像，只是原本的next是放在裡面，現在變成參數傳進來
那我們在使用的時候就變成
```javascript
let dispatch = store.dispatch;
dispatch = crashReporter(store, dispatch);
dispatch = logger(store, dispatch);
dispatch(addTodo('Use Redux'));

function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}

function crashReport(store, next) {
  return function dispatchAndReportErrors(action) {
    try {
      return next(action);
    } catch (err) {
      console.error('Caught an exception!', err);
      throw err;
    }
  };
}
```
差別在於函式裡面的`let next = store.dispatch;`被拿掉了
我們的middleware函式`logger`跟`crashReport`變得更乾淨了點
改成這樣之後，把我們原本的`applyMiddleware`也改掉，讓它符合新的寫法
```
function applyMiddleware(store, middlewares) {

  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store,dispatch)
  );

  return Object.assign({}, store, { dispatch });
}

//呼叫的方式一模一樣，只是差別在於這個function現在會回傳一個store
applyMiddleware(store, [logger, crashReporter]);
```
接著我們回來看官方給的文件跟範例，跟現在我們寫的有哪邊不一樣
第一個點是，`logger`跟`crashReport`我們是傳入兩個參數，但是官方的實現只傳入了一個
用了一種叫做`currying`的技巧
什麼是`currying`？就是把多個參數的函數切成很多只有一個參數的函數
直接看範例比較了解：
```javascript
function max(a,b){
	return a>b?a:b;
}
max(1,5);

function maxCurrying(a){
	return function inner(b){
	  return a>b?a:b;
	}
}
maxCurrying(1)(5);
```
有了基本概念以後，就可以把我們剛剛的`logger`函式也做這樣的改變
```javascript
//可以跟原來的比較，發現只是多一層函數包住而已
function logger(store) {
  return function wrapDispatchToAddLogging(next) {
    return function dispatchAndLog(action) {
      console.log('dispatching', action);
      let result = next(action);
      console.log('next state', store.getState());
      return result;
    };
  }
}

//ES6的寫法
const logger = store => next => action => {
  console.log('dispatching', action);
  let result = next(action);
  console.log('next state', store.getState());
  return result;
};

//原來的
function logger(store, next) {
  return function dispatchAndLog(action) {
    console.log('dispatching', action);
    let result = next(action);
    console.log('next state', store.getState());
    return result;
  };
}
```

在我當初看官方文件的時候，最困擾我的就是這一段
因為之前很少用這種function回傳function又回傳function的寫法
所以一下子被弄得頭昏眼花
於是只好先找出不要那麼多層函數的方法，然後了解`currying`之後再去了解原本的code
對我來說這樣子會比較容易啦，不然一下子跳太快

`applyMiddleware`就可以改成這樣
```javascript
function applyMiddleware(store, middlewares) {
  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store)(dispatch) //差在這裡而已
  );
  return Object.assign({}, store, { dispatch });
}

//原來的
function applyMiddleware(store, middlewares) {

  let dispatch = store.dispatch;
  middlewares.forEach(middleware =>
    dispatch = middleware(store,dispatch) //差在這裡而已
  );

  return Object.assign({}, store, { dispatch });
}

```
其實做到這邊，就已經跟`redux`本身的實現有個八分像了
事實上middleware的寫法其實就是`redux`要求的寫法
最後來看一下官方提供的用法要怎麼用
```javascript
import { createStore, combineReducers, applyMiddleware } from 'redux';

// applyMiddleware takes createStore() and returns
// a function with a compatible API.
// 注意到這邊，我們剛剛的寫法是：applyMiddleware(store, [logger, crashReporter]);
// 這邊做了currying，所以把兩個參數變成兩個函數
// 本來我們是傳進陣列，這邊把陣列拿掉了，只要依序傳進去就好
let createStoreWithMiddleware = applyMiddleware(
  logger,
  crashReporter
)(createStore);

// Use it like you would use createStore()
let todoApp = combineReducers(reducers);

//用createStoreWithMiddleware取代原本的createStore
let store = createStoreWithMiddleware(todoApp);
```

##總結
在看官方文件的時候，一直到前面都還看得懂，只是一下突然跳到`currying`那邊
因為對這個概念比較陌生，所以就暈頭轉向了
後來下定決心一定要看懂，重新看一次之後，一行一行去理解是什麼意思、流程怎麼跑
之後就比較清楚了

這邊大幅度參考官方範例，code也是直接抄來的，只是有做了一點小改變所以在這邊說明
像是官方範例的`applyMiddleware`裡面，其實前面都有
```javascript
middlewares = middlewares.slice();
middlewares.reverse();
```
`reverse()`是因為執行順序的關係，`slice()`是複製這個array
但是為什麼要複製我就不知道了，是因為不要改到原本的參數嗎？

總之，希望這篇文章能幫助到一些跟我一樣迷惑的初學者
最後還是要推薦大家去看官方文件
如果有哪邊寫錯，還麻煩留言或是寄信跟我說，感謝大家


