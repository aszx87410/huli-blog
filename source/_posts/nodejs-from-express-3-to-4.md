---
title: '[Node.js] 從express 3到4'
date: 2015-04-21 10:39
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---
去年買了一本書，[不一樣的 Node.js](http://www.books.com.tw/products/0010635109)
但最近才開始仔細看這本書，而書中第八章「親手打造blog系統」是用express 3完成的
但是目前最新版已經到4了，而且其中變動的部分還滿多的，所以就用這篇文章來記錄一下，在看著書中範例學習時，應該如何讓它在express 4上面也能運行。

首先，在裝express的地方，請用 `npm install express -g`裝最新版的express
再來，你會發現如果你直接打`express blog-sysyem`會發現找不到express這個command
那是因為express 4把這個部分移到`express-generator`裡面了，所以要下`npm install express-generator -g`
就可以照書中的指令，`express blog-system`去建立一個專案

當你要把這個專案跑起來的時候，書上寫的是`node app.js`，但在express 4裡面改成`DEBUG=blog-system npm start`才能執行，在windows下則是`set DEBUG=blog-system & npm start`

上面流程可參考官方範例：[Express application generator](http://expressjs.com/starter/generator.html)

接下來的流程都按照書上做就好，指令都一樣
接著會碰到不一樣的地方是書中8-10頁，新增cookie-based Session功能的地方
因為express4把一堆東西都抽出來，所以我們要用的話要自己加回去，首先在`package.json`的`dependencies`裡面新增`"cookie-session":"*"`，就跟新增`mongoose`一樣，再來記得執行`npm install`安裝套件

接著在`app.js`裡面，最上方一堆宣告的地方加上`var cookieSession = require('cookie-session');`
然後在20行左右加入使用cookieSession的程式碼即可

``` javascript app.js
// uncomment after placing your favicon in /public
//app.use(favicon(__dirname + '/public/favicon.ico'));
app.use(logger('dev'));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(cookieSession({ //新增這個片段而已 提供上下文比較好對照
  key: 'node',
  secret: 'HelloExpressSESSION'
}));
app.use(express.static(path.join(__dirname, 'public')));
```

而在router的地方也有了一點小改變
原本在書中的範例，全部的router都寫在`app.js`裡面，不覺得日後有點難維護嗎？
而在express 4自動生成的檔案裡面，可以看到有幾行值得關注
``` javascript app.js
var routes = require('./routes/index');
var users = require('./routes/users');

app.use('/', routes);
app.use('/users', users);
```

``` javascript routes/index.js
var express = require('express');
var router = express.Router();

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

module.exports = router;
```

``` javascript routes/users.js
var express = require('express');
var router = express.Router();

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

module.exports = router;
```

所以只要到`localhost/`，就會依據`index.js`裡面的規則
到`localhost/users/`，就會依據`users.js`裡面的規則

例如說，若是把`users.js`改成
``` javascript routes/users.js
var express = require('express');
var router = express.Router();

/* GET users listing. */
router.get('/', function(req, res, next) {
  res.send('respond with a resource');
});

//新增register事件
router.get('/register',function(req, res, next){
	res.send("register!");
});

module.exports = router;
```

訪問`localhost/users/register`的時候就會出現`register!`的字樣
這樣子的結構，讓你在寫RESTful架構的時候可以更方便的去操作
只要在users.js裡面新增new/edit等等的router即可

而在這邊我們先跟隨著書中範例走，首先`app.js`不用做任何改變，只要改變`routes/index.js`即可
然後還要新增一個`routes/user.js`的檔案（不要跟`users.js`搞混，沒有任何關係）

``` javascript routes/index.js
var express = require('express');
var router = express.Router();

var user = require('./user');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

router.get('/register',user.register);
router.get('/signin',user.signin);
router.get('/signout',user.signout);
router.get('/forget',user.forget);
router.get('/add_article',user.add_article);
router.get('/profile',user.profile);
router.get('/modify/:id',user.modify);
router.get('/message/:id',user.message);

module.exports = router;
```

``` javascript routes/user.js
exports.register = function(req, res){
	res.send('This is register page.');
}

exports.signin = function(req, res){
	res.send('This is signin page.');
}

exports.signout = function(req, res){
	res.send('This is signout page.');
}

exports.forget = function(req, res){
	res.send('This is forget page.');
}

exports.add_article = function(req, res){
	res.send('This is add_article page.');
}

exports.profile = function(req, res){
	res.send('This is profile page.');
}

exports.modify = function(req, res){
	res.send('This is modify page.');
}

exports.message = function(req, res){
	res.send('This is message page.');
}
```

就完成了書中的router

接下來要實際建立我們的view，這邊也與書中範例不太一樣
當我們打開`views/index.jade`的時候，發現有一行`extends layout`
``` javascript views/layout.jade
doctype html
html
  head
    title= title
    link(rel='stylesheet', href='/stylesheets/style.css')
  body
    block content
```
`layout.jade`已經把一些基本的元素都填好了，所以我們不必每新增一個檔案就自己輸入一次，直接用這份code就好，所以才有`extends layout`

參考書上程式碼，把layout.jade重複的地方扣掉以後，就是index.jade裡面應該要有的程式碼
``` javascript views/index.jade
extends layout

block content
  div(style='float:left')
    a(href='/') Home

  div(style='float:right')
    if(username && authenticated)
      a(href='/signout', style='margin:10px;') Sign out
      a(href='/add_article', style='margin:10px;') Add Article
      a(href='/profile', style="margin:10px;") Profile
      span #{username}
    else
      a(href='/signin', style='margin:10px;') Log In
      a(href='/signup', style='margin:10px;') Register
      a(href='/forget', style="margin:10px;") Forget password
  div(style='padding:50px;')
    h1= title
```

`routes/index.js`就照著書中那樣改即可，就可以看到我們建立好的頁面

下一步是建立註冊頁面
跟剛剛建立index的流程其實差不多，我就不再贅述了
中間碰到一些小問題的話，看錯誤頁面應該都可以成功debug

接著是新增`apis/login`提供登入功能，一樣照著書上做即可
要注意的是範例中有一行`res.redirect('register');`應該是`res.redirect('/register');`才對
而之後登出、忘記密碼的頁面都看著書上照做就好

最後是處理跟資料庫有關的事情
而這些繁瑣的流程都照著書上一步一步來就好
基本上就是連接資料庫、建立model、新增view跟action
一直重複這些動作，把發表文章、文章瀏覽等等的頁面完成

後面的流程基本上都大同小異，而且照著書上做應該都不會有問題，我就不贅述了
這篇主要是記錄一些可能會碰到的問題，僅此而已

另外，書中的這份範例有些功能沒有寫到，像是註冊/登入/忘記密碼都沒有，或許是想讓讀者自行更改完成吧
程式碼的結構也有點亂，很多相似的部分可以抽出來，減少不必要的重複程式碼
或許以後哪天有空，再來寫一篇結構比較好的blog範例教學文
