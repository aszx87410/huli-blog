---
layout: post
title: '[Javascript] redux 簡介'
date: 2015-09-01 18:35
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [javascript,frontend,redux]
---
最近這陣子最夯的前端技術應該就是[redux](https://github.com/rackt/redux)了
趁著比較有空的時候，看了一堆文件跟教學，算是對`redux`有了一點小小心得
在這邊幫自己做個筆記，也試著用自己的話解釋一下這個東西
話說其實官方文件我覺得寫得不錯，而且中文翻譯版也不錯，很多東西都講得深入淺出，很推薦去看一下
<!-- more -->

適合閱讀這篇文章的人：
1. 對redux有興趣
2. 知道React在幹嘛
3. 知道flux基本概念

不適合閱讀這篇文章的人：
1. 不知道react跟flux在幹嘛（可以先去補完這方面知識再回來看）

#既然你已經懂flux了，就直接切入正題吧！
flux裡面有幾個重要的概念：`action`、`action creator`、`dispatcher`、`store`、`view`
![](https://facebook.github.io/flux/img/flux-simple-f8-diagram-explained-1300w.png)

##Action
先從action開始，我們知道在`flux`的架構裡面，`action`是**唯一**可以改變`store`裡面的數據的方法
`redux`跟`flux`在這方面比較不一樣的點是，
`flux`是經由`Action creator`直接建立`action`並且`dispatch`出去，像是
``` javascript
var addItem = function(item) {
  Dispatcher.dispatch({
    type: ActionTypes.ADD_ITEM,
    item: item
  });
}
ActionCreator.addItem(..);
```
但是在`redux`裡面，`ActionCreator`只會產生一個純粹的javascript object
你要自己dispatch出去

``` javascript
function addTodo(text) {
  return {
    type: ADD_TODO,
    text
  };
}
store.dispatch(addTodo(text));
```

而且跟`flux`的差別是，dispatch這個動作是用`store`來達成
把原本的`Dispatcher`這個東西拿掉了

再來，`redux`裡面**只有一個store**
這一點也跟`flux`滿不一樣的，那這時候可能會有疑問說：只有一個store，把所有資料都放在這邊，不會很雜亂嗎？
接著就要引入一個`redux`裡面很重要的概念：`reduce`

##reduce
什麼是`reduce`？其實很簡單，就是`(previousState, action) => newState`
給你現在的狀態跟要執行的動作，傳回一個新的狀態
例如說我們現在要新增一個todo的item
``` javascript
function addTodos(state, action) {
	return [...state, {
    text: action.text,
    completed: false
  }];
}
```
之前的狀態->新增一筆資料->新的狀態
這就像是一個狀態機，只要保證input跟action一樣，就能保證輸出的結果永遠都一樣
例如f(1)=1的話，永遠不會出現f(1)=2的情形
給一個狀態跟操作->改變資料->傳回新的狀態

而在這邊值得注意點的是，為什麼不寫成
```javascript
function addTodos(state, action) {
	return state.push({
  	text: action.text,
    completed: false
  })
}
```
##Immutable State
這是之前`React`有提過的概念：**Immutable State**
就是說store裡面的數據，是不可改變的，你不能直接對它做編輯
你能做的就只有把整個state都換掉
為什麼要這樣做？
這跟`React`有一點關係，還記得一個很重要的概念嗎？**always re-render**
但其實如果數據沒有改變的話，根本就不需要重新render
`React`裡面有一個function是`shouldComponentUpdate`
你可以直接寫成：
```javascript
shouldComponentUpdate: function(nextProps, nextState) {
  return this.props !== nextProps;
}
```
如果上個狀態跟現在的狀態不相等的話，才需要update

先假設我們的state現在是可以編輯的，來看看會發生什麼事
```javascript
var prevState = {name:"yo"}
var newState = prevState;
newState.name = "new"
prevState===newState //true
```
在這個情形底下，因為`===`只會比較這兩個變數所指向的記憶體位置是否一樣，所以回傳了`true`
所以每當我們要改變state的時候，就要重新new一份
```javascript
var prevState = {name:"yo"}
var newState = {name:"new"};
prevState===newState //false
```

以上是只有一筆資料的簡單情形，如果資料很多怎麼辦？
每次都重新new一份不是很浪費空間嗎？
所以可以採用一種更好的做法，對於沒有變動的地方，就直接使用；有變動的地方再new一份
應該會長得有點像這樣
```javascript
var prevState = {
	todos: [1,2,3],
	name: "peter"
}

var newState = {
	todos: prevState.todos,
	name: "new"
}

prevState.todos===newState.todos//true
prevState==newState //false
```

那我們在實做的時候，有幾種方法可以選擇
1. [React.addons.update](https://facebook.github.io/react/docs/update.html)
2. [Immutable.js](https://facebook.github.io/immutable-js/)
3. [ES7的object spread](https://github.com/sebmarkbage/ecmascript-rest-spread)

但其實不可改變的state這個概念只是推薦用法，你不這樣用，想要改變它也是可以
只是可能有些[很酷的功能](https://github.com/gaearon/redux-devtools)沒有辦法使用而已

##再回到reducer
還記得store裡面儲存了整個app的state，然後會切割不同部分，交給不同的`reducer`去處理，最後再統一結果
所以結構上面還是相當良好的
大家可以直接看官方文檔裡面的這段code
```javascript
function todos(state = [], action) {
  switch (action.type) {
  case ADD_TODO:
    return [...state, {
      text: action.text,
      completed: false
    }];
  case COMPLETE_TODO:
    return [
      ...state.slice(0, action.index),
      Object.assign({}, state[action.index], {
        completed: true
      }),
      ...state.slice(action.index + 1)
    ];
  default:
    return state;
  }
}

function visibilityFilter(state = SHOW_ALL, action) {
  switch (action.type) {
  case SET_VISIBILITY_FILTER:
    return action.filter;
  default:
    return state;
  }
}

function todoApp(state = {}, action) {
  return {
    visibilityFilter: visibilityFilter(state.visibilityFilter, action),
    todos: todos(state.todos, action)
  };
}
```
`todoApp`就是整個store，然後切割成`visibilityFilter`跟`todos`兩個reducer
分別對自己所關心的state做出反應，回傳新的state
這份code用了大量的ES6，所以看redux的好處就是還可以順便學習ES6

其實redux的一些特性到這邊講得差不多了
就跟flux滿像的，就action creator -> 發action -> store接到action -> 分配給reducer -> 產生新的state
view那邊就subscribe state的變化，這點跟之前flux一樣
接著要講一個redux比較不一樣的點

##Middleware
有接觸過`express`的人相信對middleware不會太陌生，在`redux`裡面的middleware指的是
從action到store的這段路程當中，可以經過很多middleware
action -> middleware1 -> middleware2 -> store
這樣的好處是什麼呢？
1. 可以很輕鬆地log
2. 非同步API!!

redux在middleware裡面非同步API的實作我沒有看得很懂，不過大概可以講一下概念
原本的action是指一個Plain Javascript Object，就是長得像這個樣子
```
{
  type: "ADD_TODO"
}
```

那現在如果action變成一個function呢？
就可以寫一個專門處理function的middleware
只要碰到是function，就立刻執行
那假如今天這個function是一個去遠端拿資料的操作
```javascript
//action creator
function receiveResult(result){
  return {
    type: "RECEIVE_RESULT",
    result: result
  }
}

function get(){
  return function(){
    API.get(function(result){
      store.dispatch(receiveResult(result));
    }
  }
}
store.dispatch(getSomething());
```
middleware在處理到的時候，就會執行這個function，而function執行完會dispatch一個action
詳細的說明可以看我最下面附的參考資料，或是直接參考官方文件
因為官方文件真的寫得很不錯

原本在`flux`的架構裡面，沒有很明確指定說怎麼做非同步的api呼叫
但是在`redux`給了我們明確解答： **就是發action**

##與React的結合
最後稍微提一下怎麼跟React做結合
`redux`提供了`Provider`，讓你把`store`注入到你的react元件裡面去
所以在root的地方必須這樣做
```javascript
let store = createStore(todoApp);

let rootElement = document.getElementById('root');
React.render(
  <Provider store={store}>
    {() => <App />}
  </Provider>,
  rootElement
);
```
在個別元件的地方，用`connect`這個指定這個元件要接收哪些state
如果沒有指定的話，就會接收到整個store的state，也就是這整個應用程式的state

在看`redux`的時候，只要有`flux`的基礎，就會發現兩者有滿多地方類似
而`redux`簡化了一些步驟，引進一些`flux`原本沒有的東西，但是核心思想還是差不多的，就是「單向資料流」
`redux`的sample code也很棒，分成幾個範例，一個叫做`real world`的範例最完整
裡面應用了`react-router`與`github api`，實際示範如何與這些東西做搭配
只要能熟悉這個範例，相信採用`redux`來開發SPA會還滿得心應手的

最後，再次推薦官方文件
下面列出我在寫這篇文之前看過的一些文章，有興趣的可以看看

ref:
[Redux 初步尝试](http://segmentfault.com/a/1190000003482243)
[还在纠结 Flux 或 Relay，或许 Redux 更适合你](https://ruby-china.org/topics/26944)
[Redux basic tutorial](http://segmentfault.com/a/1190000003033033)
[Redux 中文文档](http://camsong.github.io/redux-in-chinese/index.html)
[redux-promise](https://github.com/acdlite/redux-promise)
[redux-tutorial](https://github.com/happypoulp/redux-tutorial)
[Redux 核心概念](http://www.jianshu.com/p/3334467e4b32)
[Thunk 函数的含义和用法](http://www.ruanyifeng.com/blog/2015/05/thunk.html)
[Functional JavaScript Mini Book](http://blog.oyanglul.us/javascript/functional-javascript.html)
[Redux 入門](http://rhadow.github.io/2015/07/30/beginner-redux/)
[The React.js Way: Flux Architecture with Immutable.js](https://blog.risingstack.com/the-react-js-way-flux-architecture-with-immutable-js/)
[react - Advanced Performance](https://facebook.github.io/react/docs/advanced-performance.html)
[gaearon/normalizr](https://github.com/gaearon/normalizr)
