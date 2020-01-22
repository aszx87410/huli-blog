---
title: webpack 新手教學之淺談模組化與 snowpack
catalog: true
header-img: /img/header_img/article-bg.png
date: 2020-01-21 16:41:17
subtitle:
tags: [webpack]
categories:
  - Front-end
---

## 前言

在我的部落格裡面，其實很少有工具類的教學文章。一來是因為這種工具類文章都大同小異，二來是我生性懶惰，許多手把手教學都需要鉅細靡遺外加豐富截圖，實在是不適合我。

但這次會來寫這個題目，是因為我覺得 webpack 是個新手不容易懂，就算懂了也不一定是真的懂的工具。或是換句話說，它是常常被誤解的一個工具。

這並不是 webpack 本身的問題，而是現在許多新手切入前端都直接從 React 或是 Vue 開始，而且都使用了他們各自提供的 CLI 工具，等到要客製化一些設定時才注意到：「阿，原來有個東西叫做 webpack」。

CLI 工具帶來了方便性，優點是讓新手能夠快速上手，不用去管那些繁瑣的設定；而缺點就是若是新手沒有意識到背後那些工具，等到哪一天工具壞了、不能用了或是有地方需要修改，就是噩夢的開始。

為了讓這種情況減少，我才決定寫這篇文章，希望從源頭帶大家認識 webpack 這項工具以及模組化的概念。你必須先知道什麼是模組，才能理解什麼是 webpack。

開頭我想先透過幾個問題讓大家思考自己對模組化以及 webpack 是否熟悉：

1. 為什麼很多專案（例如說 React）在部署前都要先 build？這個步驟在幹嘛你知道嗎？
2. 你知道 `require/module.exports` 與 `import/export` 的差別嗎？
3. 你知道 import 與 export 這兩個語法在瀏覽器上面不是隨便就能使用嗎？
4. 你知道為什麼要用 webpack 嗎？
5. 你知道 webpack 為什麼要有 loader 嗎？

這些問題應該會在讀這篇文章時慢慢有點靈感，在最後面時會幫大家解答。

<!-- more -->

## 模組化

相信大家應該都聽過模組這個詞，英文叫做 module，這邊先舉個簡單的例子。

例如說你的手機，螢幕壞掉了可以只換螢幕，相機壞掉了就換相機，電池壞掉了換電池。你可能會想說：「咦，那不然呢？」

你有想過為什麼可以這樣換嗎？因為螢幕跟相機是兩個完全獨立開來的功能，互不干擾也沒有相依性，所以換螢幕不會讓相機功能壞掉，反之亦然。這其實就是模組化的概念，螢幕是一個模組，只負責顯示資訊這項功能，而相機又是另外一個模組，負責拍照。透過手機的軟體把螢幕與相機整合起來，讓相機捕捉到的畫面在螢幕上顯示。

若是沒有模組化的概念，一整台手機就真的是一整台，每個功能都互相綁在一起，相機壞掉了，就要把整台手機都換掉，沒辦法只換相機。

如果以程式碼來講，大概會像這樣子：

``` js
import 相機
import 螢幕
import AA電池
import sim卡

Phone.start(相機, 螢幕, AA電池, sim卡)
```

模組化的好處之一就是方便抽換，若是今天要用別家的電池，就只要把電池那邊改掉就好了，其他地方都不用動：

``` js
import 相機
import 螢幕
import BB 電池
import sim卡

Phone.start(相機, 螢幕, BB 電池, sim卡)
```

寫程式的時候也是這樣子的，我們常常會用到許多系統內建的模組或者是別人寫的模組，以 Node.js 為例，可以使用內建的 `os` 模組，來獲取作業系統相關的資訊，例如說作業系統是哪個平台：

``` js
var os = require('os')
console.log(os.platform()) // darwin
```

在這邊我們使用了 `require` 將系統內建的 os 模組引入進來，並且呼叫 `os.platform()` 來取得資訊。


這就是在程式裡面最基礎的模組的使用。有了這個概念之後，我們可以把範圍縮小，來談談在 Node.js 裡面模組化是怎麼運作的。（我認為要理解模組化這個概念，對 Node.js 有基本的理解是很重要的，若是你完全不會的話很建議去學一點點，至少知道它在幹嘛）

## Node.js 的模組

前面已經有提到在 Node.js 裡面我們可以使用 `require` 把內建模組給引入。那如果我們想要自己做一個模組該怎麼辦呢？用 `module.exports` 這個語法就可以達成。

例如說我們有個 `utils.js`，裡面有一個會常常用到的計算價格的函式 `calculate`：

``` js
// utils.js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}

module.exports = calculate // 把這個函式 export 出去
```

那我們在另外一個檔案 `main.js`，就可以使用 `require` 這個語法來引入：

``` js
// main.js
var calculate = require('./utils')
console.log(calculate(30)) // 9
```

我們在 `utils.js` 裡面 `module.exports` 什麼，在其他地方用 `require('./utils')` 就會引入什麼。所以你可以把 `var calculate = require('./utils')` 想成 `var calculate = （utils.js 裡的）module.exports`。

再來看一個範例，我們把 `utils.js` 輸出的東西改成一個物件：

``` js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}
  
module.exports = {
  cal: calculate,
  name: 'hello'
} // 把這個物件 export 出去
```

在 `main.js` 裡面，就一樣可以拿到這個物件：

``` js
var obj = require('./utils')
console.log(obj.cal(30)) // 9
console.log(obj.name) // hello
```

這就是在 Node.js 裡面最基本的模組使用的概念，用 `module.exports` 把東西導出，用 `require` 把模組引入。

上面所講的這一套模組機制，其實並不在 JavaScript 的規範裡面，而是一套叫做「CommonJS」的標準。

看到這邊相信應該有些人開始有點頭痛了，想說「蛤？這是什麼意思？」

大家設想一個情境就知道了。

讓我們先回到 ES6 出現之前，在那個年代 JavaScript 本身並沒有規範任何與模組相關的使用機制。

這時候大家就可以天馬行空提出自己的想法，例如說 A 可能會覺得那不如這樣寫：

``` js
// utils.js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}
  
out = {
  cal: calculate,
  name: 'hello'
}

// main.js
var obj = include('./utils')
console.log(obj.cal(30)) // 9
console.log(obj.name) // hello
```

要輸出模組的時候用 `out`，要引入的時候用 `include`。

而 B 也可以說這樣比較好：

``` js
// utils.js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}
  
EXP = {
  cal: calculate,
  name: 'hello'
}

// main.js
var obj = in('./utils')
console.log(obj.cal(30)) // 9
console.log(obj.name) // hello
```

要輸出模組的時候用 `EXP`，要引入的時候用 `in`。

所以 A 發想出來的規範就叫做 A 標準，B 的就叫 B 標準，這兩個標準都可以達成模組化，但是語法跟背後實作不一樣。而 CommonJS 就只是其中一個標準而已，這個標準就是在輸出模組時用 `module.exports`，引入時用 `require`。

而後來 CommonJS 這個標準被 Node.js 所採用，所以才會有我們現在看到的這種形式。

有注意到上面我們一直在講 Node.js 嗎？

那瀏覽器呢？抱歉，瀏覽器原生不支援這個東西。所以你在瀏覽器上面，沒辦法用 `module.exports`，也沒辦法用 `require`。

有些人會說：「你騙人！那為什麼我公司的專案用了這些也可以跑在瀏覽器上」，呵呵，我沒騙人，瀏覽器原生不支援沒錯，但你可以借助其他工具來達成這個目的（對，你現在知道為什麼要用 webpack 了吧）。

不過在介紹工具以前，我們先來試著自己解決看看這個問題。

## 手動加入 CommonJS 支援

在 CommonJS 模組標準裡面，最重要的就是兩個：

1. `module.exports`
2. `require`

前面有提到過：

我們在 `utils.js` 裡面 `module.exports` 什麼，在其他地方用 `require('./utils')` 就會引入什麼。所以可以把 `var calculate = require('./utils')` 想成 `var calculate = （utils.js 裡的）module.exports`。

因此，我們可以試著加入一些程式碼，讓 `require('./utils.js)` 回傳的東西就是 `utils.js` 裡的 `module.exports`，就大功告成了。

第一步，先把原本 main.js 的內容用一個叫做 main 的 function 包住，並且傳入 require：

``` js
function main(require) {
  var obj = require('./utils')
  console.log(obj.cal(30)) // 9
  console.log(obj.name) // hello
}
```

再來我們也把 utils.js 的內容包住，因為 utils.js 沒有使用到 require，所以我們改成傳進去一個參數 module，會變成這樣：

``` js
function main(require) {
  var obj = require('./utils')
  console.log(obj.cal(30))
  console.log(obj.name)
}
  
function utils(module) {
  function calculate(n) { 
    return ((n * 100 + 20 - 4)) % 10 + 3
  }
    
  module.exports = {
    cal: calculate,
    name: 'hello'
  }
}
```

以上只是用兩個 function 把原本的兩個檔案包起來並且傳入參數而已。

接著我們可以在外面宣告一個變數 `m`，並且傳進去 utils 裡面然後呼叫：

``` js
function main(require) {
  var obj = require('./utils')
  console.log(obj.cal(30))
  console.log(obj.name)
}
  
function utils(module) {
  function calculate(n) { 
    return ((n * 100 + 20 - 4)) % 10 + 3
  }
    
  module.exports = {
    cal: calculate,
    name: 'hello'
  }
}
  
// 加入這兩行
var m = {}
utils(m)
```

這樣在呼叫完 utils 函式以後，`m.exports` 就是我們在 `utils` 函式裡面所輸出的東西，也就是 main 裡面的 require 呼叫之後應該回傳的內容。

所以最後一步，就是呼叫 main 函式並且傳入一個 `require` 的參數：

``` js
function main(require) {
  var obj = require('./utils')
  console.log(obj.cal(30))
  console.log(obj.name)
}

function utils(module) {
  function calculate(n) { 
    return ((n * 100 + 20 - 4)) % 10 + 3
  }
    
  module.exports = {
    cal: calculate,
    name: 'hello'
  }
}

var m = {}
utils(m)
  
// 加入底下這幾行
function r() {
  // 回傳我們所需要的 m.exports
  return m.exports
}
main(r)
```

這樣子就大功告成了，就可以把在 `utils` 裡面所輸出的 `module.exports` 丟給 main，並且在 `require('utils.js')` 的時候回傳。直接把上面這一整段程式碼貼到瀏覽器上面，真的能夠順利執行了！

上面這段程式碼只是大致上示範一下原理而已，原理基本上就是：

1. 把檔案包成 function 並且接收 `module` 以及 `require` 等參數
2. 在外面呼叫 function，傳入一個物件以及函式 require

不過實際上當然沒有那麼簡單，因為還有很多問題要解決，例如說：

1. 相依性，例如說 A 依賴於 B，B 又依賴於 C，載入順序就必須是： C->B->A
2. 載入多個模組，我們上面傳給 main 的函式只會回傳 utils 的 module.exports，但是應該要支援多個 require，所以 require 裡面要根據參數來決定回傳什麼
3. 快取，當一個 module 被載入多次的時候應該要能夠快取起來

大概知道原理以後，我們就來看看現成的工具該如何使用。

## browserify 介紹

前端的世界很簡單，說穿了就是一句話：

> 不支援的東西，寫工具自己支援就好了

Babel 如此，webpack 如此，PostCSS 也是如此，都是藉由工具來實現瀏覽器原生不支援的功能。

在 2011 年的時候，[browserify](http://browserify.org/) 出現了。而官網上的第一句話就已經描述了它的用途：

> Browserify lets you require('modules') in the browser by bundling up all of your dependencies.

簡單來說，就是讓你在瀏覽器上面使用 require。

可以在 terminal 上面使用以下指令，來打包我們剛剛那兩個檔案 main.js 與 utils.js：

```
npx browserify main.js -o bundle.js
```


傳入的第一個參數是所謂的入口點（entry point），就代表主要要執行的檔案。舉例來說，我們稍早在示範時都是用 `node main.js` 來執行，表示要執行的檔案其實是 main.js，因此 main.js 就是入口點。

然後產生的 bundle.js 內容如下：

``` js
(
  function e(t, n, r) {
    function s(o, u) {
      if (!n[o]) {
        if (!t[o]) {
          var a = typeof require == "function" && require;
          if (!u && a) return a(o, !0);
          if (i) return i(o, !0);
          var f = new Error("Cannot find module '" + o + "'");
          throw f.code = "MODULE_NOT_FOUND", f
        }
        var l = n[o] = {
          exports: {}
        };
        t[o][0].call(l.exports, function(e) {
          var n = t[o][1][e];
          return s(n ? n : e)
        }, l, l.exports, e, t, n, r)
      }
      return n[o].exports
    }
    var i = typeof require == "function" && require;
    for (var o = 0; o < r.length; o++) s(r[o]);
    return s
  })({
  1: [function(require, module, exports) {
    function calculate(n) {
      return ((n * 100 + 20 - 4)) % 10 + 3 // 計算價格公式
    }

    module.exports = {
      cal: calculate,
      name: 'hello'
    } // 把這個物件 export 出去
  }, {}],
  2: [function(require, module, exports) {
    var obj = require('./utils')
    console.log(obj.cal(30)) // 9
    console.log(obj.name) // hello
  }, {
    "./utils": 1
  }]
}, {}, [2]);
```

看不懂很正常，因為這是經過壓縮後的版本，但其實核心概念就是：「把你的程式碼用一個 function 包住，提供一個叫做 require 的 function 以及一個叫做 module 的物件給你使用」，說穿了跟我們上面做的事情差不多啦，只是更嚴謹了一些。

如果你真的很想看懂在幹嘛，我參考了原始碼：[browser-pack/prelude.js](https://github.com/browserify/browser-pack/blob/master/prelude.js)，把上面那段打包出來的程式碼還原了一下並且加上註解，為了方便閱讀也更動了順序，也把一些額外的檢查跟功能拿掉了。

成果如下（請注意，底下為了教學目的只留下最核心的功能，其餘程式碼都拿掉了）：

``` js
// 跟我們做的事情一樣，把檔案包成一個 function，傳入 require, modules
function utils(require, module) {
  function calculate(n) {
    return ((n * 100 + 20 - 4)) % 10 + 3
  }
  
  module.exports = {
    cal: calculate,
    name: 'hello'
  }
}
  
// 跟我們做的事情一樣，把檔案包成一個 function，傳入 require, modules
function main(require, module) {
  var obj = require('./utils')
  console.log(obj.cal(30))
  console.log(obj.name) 
}
  
/*
  定義一個叫做 modules 的物件，裡面把 module 換成數字編號
  陣列的第一個參數就是上面包好的 function，第二個參數則是相依性需要的 module 以及編號
  例如說： {
    "./utils": 1
  }
  代表說當我呼叫 require("./utils") 的時候，其實就是要載入編號為 1 的 module
*/
var modules = {
  1: [utils, {}],
  2: [main, {
    "./utils": 1
  }]
}

/*
  函式詳細內容可以見底下，第一個參數就是 modules
  第二個參數是 cache（先不管）
  第三個參數則是入口點，就像是 C 語言裡面的 main function 那樣
  以我們的範例來說，就是 main.js 這個檔案，也就是編號為 2 的 module
*/
outer(modules, {}, [2])
 
/* 
  底下程式碼來自：https://github.com/browserify/browser-pack/blob/master/prelude.js
  為了方便理解核心功能，有經過刪改
*/
function outer(modules, cache, entry) {
  /*
    順序執行 entry，在我們的例子 entry 只有一個
    所以可以簡單想成是：newRequire(2)
  */
  for (var i = 0; i < entry.length; i++) {
    newRequire(entry[i]);
  }
  
  /*
    核心程式碼在下面
    以我們的例子而言，name 會是 2
  */
  function newRequire(name) {
    //先從 cache 裡面找這個 module 的內容，找不到的話載入 module 並且放入 cache
    if (!cache[name]) {
      // 找不到要載入的 module，拋出錯誤
      if (!modules[name]) {
        var err = new Error('Cannot find module \'' + name + '\'');
        err.code = 'MODULE_NOT_FOUND';
        throw err;
      }

      /*
        宣告一個物件來儲存 module export 出來的東西
        並且一併放到 cache 裡面
      */
      var m = cache[name] = {
        exports:{}
      };

      /*
        核心功能就是底下這四行
        呼叫我們最前面定義的那個包好的 function，並且傳入 require 以及 module
        在 require 裡面會根據 modules 的內容找到要引入的 id
        以 require('./utils') 為例
        modules[2][1]['./utils'] 是 1，就會去載入 id 為 1 的 module 並且回傳
      */
      modules[name][0].call(m.exports, function(x){
          var id = modules[name][1][x];
          // 載入 module 並且回傳
          return newRequire(id ? id : x);
      }, m);
    }

    // 找到的話就直接回傳 module.exports
    return cache[name].exports
  }
}
```

原本的程式碼因為要考慮其他更多種情況所以比較複雜一些，只留下核心的模組功能差不多就長得像上面那樣。看不懂沒有關係，畢竟這是比較偏新手向的文章，只要稍微看過去就好。

你只要知道一個重點就行了：

> 瀏覽器原生並不支援 CommonJS（require 與 module.exports），一定要透過工具才能在瀏覽器上面使用。

上面提到的「工具」，我們已經介紹 browserify 了，但還有一個更有名的。

對，就是 webpack！

## 初探 webpack

剛才我們使用 browserify 的時候，使用了這個指令來指定入口點與打包出來的檔案名稱：

```
npx browserify main.js -o bundle.js
```

而 webpack 本質上與 browserify 相似，只是需要把這些變成設定檔。我們可以新增一個 `webpack.config.js`：

```
module.exports = {
  entry: './main.js',
  output: {
    path: __dirname,
    filename: 'webpack_bundle.js'
  }
}
```

仔細觀察就會發現這其實跟使用 browserify 時要設定的選項是一樣的，入口點以及輸出的檔案名稱以及路徑（__dirname 代表跟 config 檔同一個目錄）。

接著在 terminal 上面執行這幾行指令，簡單來說就是先安裝 webpack 然後執行 webpack：

```
npm init -y
npm install webpack webpack-cli --save-dev
npx webpack --config webpack.config.js
```

![](/img/mods/webpack.png)

接著就會看到目錄下多了一個 `webpack_bundle.js`，內容也是完全看不懂的東西。這是因為 webpack 有兩個模式，production 與 development，預設是前者。production 代表在生產環境下使用，所以會自動幫你壓縮以及優化。

在開發的時候通常會使用 development 這個模式，打包的速度較快。更改的方式很簡單，改變設定檔即可：

``` js
module.exports = {
  mode: 'development',
  entry: './main.js',
  output: {
    path: __dirname,
    filename: 'webpack_bundle.js'
  }
}
```

存檔以後再執行一次 `npx webpack --config webpack.config.js`，結果如下：

``` js
/******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, { enumerable: true, get: getter });
/******/ 		}
/******/ 	};
/******/
/******/ 	// define __esModule on exports
/******/ 	__webpack_require__.r = function(exports) {
/******/ 		if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 			Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 		}
/******/ 		Object.defineProperty(exports, '__esModule', { value: true });
/******/ 	};
/******/
/******/ 	// create a fake namespace object
/******/ 	// mode & 1: value is a module id, require it
/******/ 	// mode & 2: merge all properties of value into the ns
/******/ 	// mode & 4: return value when already ns object
/******/ 	// mode & 8|1: behave like require
/******/ 	__webpack_require__.t = function(value, mode) {
/******/ 		if(mode & 1) value = __webpack_require__(value);
/******/ 		if(mode & 8) return value;
/******/ 		if((mode & 4) && typeof value === 'object' && value && value.__esModule) return value;
/******/ 		var ns = Object.create(null);
/******/ 		__webpack_require__.r(ns);
/******/ 		Object.defineProperty(ns, 'default', { enumerable: true, value: value });
/******/ 		if(mode & 2 && typeof value != 'string') for(var key in value) __webpack_require__.d(ns, key, function(key) { return value[key]; }.bind(null, key));
/******/ 		return ns;
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = "./main.js");
/******/ })
/************************************************************************/
/******/ ({

/***/ "./main.js":
/*!*****************!*\
  !*** ./main.js ***!
  \*****************/
/*! no static exports found */
/***/ (function(module, exports, __webpack_require__) {

eval("var obj = __webpack_require__(/*! ./utils */ \"./utils.js\")\nconsole.log(obj.cal(30)) // 9\nconsole.log(obj.name) // hello\n\n\n//# sourceURL=webpack:///./main.js?");

/***/ }),

/***/ "./utils.js":
/*!******************!*\
  !*** ./utils.js ***!
  \******************/
/*! no static exports found */
/***/ (function(module, exports) {

eval("function calculate(n) { \n  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式\n}\n  \nmodule.exports = {\n  cal: calculate,\n  name: 'hello'\n} // 把這個物件 export 出去\n\n//# sourceURL=webpack:///./utils.js?");

/***/ })

/******/ });
```

跟 browserify 一樣，你把上面這整串貼到瀏覽器的 console 去，一樣可以正常執行並輸出結果。上面的程式碼不用細看，大致上滑過去就好，但你滑過去的時候就會發現有許多東西跟 browserify 打包出來的程式碼類似。

好，看到這邊相信大家已經知道了兩個重點：

1. webpack 與 browserify 類似
2. 要在瀏覽器上面使用 CommonJS 的模組機制，就必須使用工具先把程式碼打包才能做到

而第二點就是必須使用 webpack 的理由。

這時你可能會想問一個問題：

> 可是我們公司沒有用 require，而是用 ES6 的 import 與 export，這個瀏覽器不是支援了嗎？那為什麼需要 webpack？

問得很好，看到這邊可以先起身喝個水，下半場要開始了。

## ES6 的標準化模組

前面有提到在 ES6 出現以前，JavaScript 並沒有一個標準的模組化規範。Node.js 支援 CommonJS，所以才可以用`require`跟`module.exports`，但是瀏覽器原生沒有支援，所以才需要像是 browserify 以及 webpack 這種工具。

而 ES6 出來之後，終於有了正式的規範，就是大家常看到的 import 與 export，我們可以把之前的 main.js 與 utils.js 改成 import 與 export 的形式：

``` js
// main.js
import obj from './utils'
console.log(obj.cal(30))
console.log(obj.name)

//utils.js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}
  
export default {
  cal: calculate,
  name: 'hello'
}
```

雖然說這是 ES6 的標準，但其實支援度還不是很好。

若是你在 Node.js 上面試圖執行 `node main.js`，會直接噴給你一個 `SyntaxError: Unexpected identifier` 的錯誤，因為 Node.js 不認識 `import` 這個語法。

想要在 Node.js 上面使用 import 與 export 的話有兩個方法，第一個方法是把副檔名從 .js 換成 .mjs，然後在使用 node 時加上一個 flag：`node --experimental-modules main.mjs`。

![](/img/mods/es.png)

順帶一提，這是 Node.js 版本 < 13 時的狀況，如果是最新的 13 版本以上，只要把檔名改成 mjs 就好，詳情可以參考：[Node.js v13.7.0 Documentation: ECMAScript Modules](https://nodejs.org/dist/latest-v13.x/docs/api/esm.html#esm_enabling)。

第二個方法就是大名鼎鼎的 babel 啦，靠著 babel 幫我們把 ES6 的語法轉成 ES5，可以直接使用在 babel 官網上提供的[簡易線上轉換器](https://babeljs.io/repl#?browsers=&build=&builtIns=false&spec=false&loose=false&code_lz=JYWwDg9gTgLgBBARgKzgMyhEcDkA6AegFcZgAbAZxwCgBjCAOwojIFM8yIBzACiWTy0AhmR4BmAAwBKKXUbM2HbnxR4GQkK1lA&debug=false&forceAllTransforms=false&shippedProposals=false&circleciRepo=&evaluate=true&fileSize=false&timeTravel=false&sourceType=module&lineWrap=false&presets=es2015%2Creact%2Cstage-2&prettier=false&targets=&version=7.8.3&externalPlugins=)，把 `main.js` 的內容從 import 轉成 require：

![](/img/mods/babel.png)

上面講的都是 Node.js 的使用，那瀏覽器呢？

可以先來試試看什麼都不要改變，一樣只有 `main.js` 與 `utils.js`，然後新增一個 index.html，內容如下：

``` html
<html>
<head>
  <script src="./main.js"></script>
</head>
<body>
</body>
</html>
```

打開之後會看到 devtool 的 console 吐了這樣一個錯誤：

`Uncaught SyntaxError: Cannot use import statement outside a module`

跟 Node.js 類似，若是想要使用 import 與 export，都必須以 module 的形式來執行，所以要在 script 標籤加上 type：

``` html
<html>
<head>
  <script src="./main.js" type="module"></script>
</head>
<body>
</body>
</html>
```

接著再次打開頁面，會發現還是有一個錯誤：

```
Access to script at 'file:///Users/huli/w_test/main.js' from origin 'null'
has been blocked by CORS policy: Cross origin requests are only supported for protocol schemes:
http, data, chrome, chrome-extension, https.
```

因為我目前打開 index.html 是直接點兩下打開，所以其實是開檔案而已，網址開頭會是 `file:///`。若是要使用 import 的話，必須要用伺服器的方式開啟才行。可以在同一個目錄底下輸入這行指令，簡單跑一個 file server：

```
python -m SimpleHTTPServer 8080
```

接著就可以打開：http://localhost:8080。

很不巧地，這次又出現了一個錯誤：`GET http://localhost:8080/utils net::ERR_ABORTED 404 (File not found)`

要把 main.js 裡的 `import obj from './utils'` 改成：`import obj from './utils.js'` 才行，要明確指定是要引入 .js 這個檔案。

改完之後重新整理，就可以在 console 上面看到正確的結果了！底下是完整的程式碼，只有三個檔案而已：

main.js

``` js
import obj from './utils.js'
console.log(obj.cal(30))
console.log(obj.name)
```

utils.js

``` js
function calculate(n) { 
  return ((n * 100 + 20 - 4)) % 10 + 3  // 計算價格公式
}
  
export default {
  cal: calculate,
  name: 'hello'
}
```

index.html

``` js
<html>
<head>
  <script src="./main.js" type="module"></script>
</head>
<body>
</body>
</html>
```

到這裡為止一切看似順利，好像沒什麼問題。在網頁上只要把引入的標籤多一個 `type="module"` 就可以跑起來了，很棒啊。

事情是沒有那麼簡單的。

第一個問題，瀏覽器支援度。

其實這個問題說大不大說小不小，端看貴公司有沒有要支援 IE，因為各大瀏覽器都有支援 import 與 export，可是 IE 沒有。

第二個問題，我想要使用 npm 上面其他人寫的套件的話怎麼辦？

在 Node.js 裡面沒有這個問題，因為你一定會在資料夾底下先裝好 `node_modules`，可是網頁呢？難道要把整個 `node_modules` 資料夾一起傳上去嗎？

還有一個問題是當你在 import 的時候，路徑要怎麼寫？難道要寫明是：`import pad from './node_modules/pad-left/index.js'` 這樣嗎？這是可維護性相當差的一個寫法，若是模組的入口點變了，你就必須改寫所有 import 的地方。

這個問題其實是相當麻煩的，因為在開發時通常都會用到其他人寫好的模組，若是沒辦法很方便地去支援引入這些模組，會造成很多不便利。

還記得我前面說過的話嗎？

「前端的世界很簡單，不支援的東西，寫工具自己支援就好了。」，這邊要稍微修改一下，變成：「前端的世界很簡單，不支援或是支援度很差的東西，寫工具自己支援就好了」。

就是因為瀏覽器原生的模組機制會碰到許多問題（相容性、無法兼容 npm 等等），所以我們才需要一個額外的工具。

而這個工具，就是 webpack。

## 再探 webpack

為了來體驗 webpack 的強大之處，我們先隨便找一個套件來安裝：

```
npm install pad-left
```

接著在 main.js 裡面引入套件並且使用：

``` js
import obj from './utils.js'
import pad from 'pad-left'
console.log(obj.cal(30))
console.log(pad('4', 4, 0))
```

然後一樣按照之前教過的流程打包檔案，config 檔之前已經寫過了，所以直接下指令就好：

```
npx webpack --config webpack.config.js
```

接著打開 index.html，更改引入的 script，因為有 webpack 的關係所以不需要 `type=module` 了：

``` html
<html>
<head>
  <script src="./webpack_bundle.js"></script>
</head>
<body>
</body>
</html>
```

最後打開 index.html，看到 console 上面出現 9 跟 0004 這兩個輸出，就代表有打包成功了。

所以使用 webpack 的好處之一，就是我們能把使用 npm 安裝的模組一併打包，就跟打包自己寫的模組一樣，不需要多做其他事情。這件事是原生的瀏覽器沒辦法做到的。

我們之所以需要 webpack，就是因為原生的瀏覽器模組功能跟支援度都沒那麼完整。

不過呢，其實 webpack 的強大之處不只這樣而已。打開 [webpack 官網](https://webpack.js.org/)，會看到這張圖：

![](/img/mods/web.png)

webpack 最厲害的地方在於它把「模組化」這個概念延伸了。我們剛剛在談論模組化的時候，都只有討論 JavaScript，討論程式上的模組。但 webpack 把「任何資源」都視成一個模組。

圖片是模組，所以你可以 `import Image from './assets/banner.png'`；CSS 是模組，你可以 `import styles from 'style.css'`，只要是任何資源都可以 import 進來使用。

這已經跟 JavaScript 與 ES6 一點關係都沒有了，這完全是 webpack 自己的延伸，在瀏覽器上面你是沒有辦法這樣使用的。

為了要支援這樣的功能，webpack 定義了許多 loader（載入器），不同的資源有不同的 loader，要透過 loader 處理才能把資源載入。而這個 loader 也是它強大的地方。

例如說你可以用 scss loader 載入 scss 的檔案，在引入資源的時候就會幫你順便編譯成 CSS，所以你不用自己做這件事。JS 也是一樣，你可以寫最新最潮的語法，然後在載入時用 babel-loader 把 ES10 的語法轉成 ES5。

這種資源的引入以及轉換，才是 webpack 最強大的地方。

還記得你在寫 React 的時候，把 import 圖片跟 CSS 當作吃飯喝水一樣嗎？好像這樣是很稀鬆平常的事。

你能夠寫出這種語法而且被支援，都是因為底層有 webpack 在幫你做處理，都是因為有 image loader 跟 css loader 特別處理你的 import。這不是瀏覽器原生就支援的東西，而是 webpack 的模組系統幫你做的事。

再者，掌握了資源的打包這一段之後，webpack 就可以藉由 loader 以及 plugin 做更多有趣的事，例如說：

1. 在載入 JS 的時候順便做 uglify
2. 在載入 CSS 的時候順便做 minify
3. 把打包出來的檔名順便加上 hash
4. 根據不同頁面打包不同的檔案，就不用一次載入全部 JS
5. 支援動態引入 JS，有需要的時候才載入

webpack 的教學就到這邊了，我沒有打算繼續深講，再講下去就比較偏向工具的使用了。我寫這篇最主要的目的只是想讓你知道：

1. 為什麼要用 webpack？
2. 不用 webpack 的話會怎樣？
3. webpack 與 ES6 定義的標準模組有什麼差別？
4. webpack 的最基礎使用（寫設定檔與打包 JS）

## Snowpack

前面我們有提到使用 webpack 的原因之一是原生的瀏覽器沒辦法打包 npm 安裝的模組，而 webpack 除了解決這個問題之外，還順便擴展了「模組」的定義，任何資源都可以視為一個模組，搭配強大的 loader 與 plugin 系統也可以做出更多有趣的事。

而近期剛好出了另外一個 library：[Snowpack](https://www.snowpack.dev/)，標榜的就是不需要打包就能夠在瀏覽器上面跑，而原理十分簡單，其實就是幫你把 `node_modules` 安裝的模組整理了一下，放到另一個叫做 `web_modules` 的資料夾，要引入的時候去那邊引入就好了。

不過並不是每個模組都可以這樣，必須模組本身有支援標準的 ESM module 才行。像我們剛剛所使用的`pad-left` 就沒有，所以沒有辦法搭配 Snowpack 使用，因此我們等等會再裝一個有支援的 `mathjs` 來試試看。

我們立刻來體驗一下吧，先把 Snowpack 跟 mathjs 裝起來：

```
npm install --save-dev snowpack
npm install mathjs
```

接著執行 Snowpack，讓它把模組整理好：

```
npx snowpack
```

執行完之後，就會看到多了一個 `web_modules` 的資料夾，底下有兩個檔案：`import-map.json` 與 `mathjs.js`

接著我們更新一下 main.js：

``` js
import obj from './utils.js'
import {pi} from './web_modules/mathjs.js' // 從 web_modules 資料夾引入
console.log(obj.cal(30))
console.log(pi)
```

然後更新 index.html：

``` html
<html>
<head>
  <script src="./main.js" type="module"></script>
</head>
<body>
</body>
</html>

```

最後一樣要用指令跑一個 server 起來：`python -m SimpleHTTPServer 8080`

發現 console 有出現 3.141592653589793，代表可以順利使用我們用 npm 安裝的模組了！

Snowpack 的使用方式就是那麼簡單，要解決的問題也很簡單，它只負責解決「引入第三方模組」這一塊，其他的不在它管理的範疇。

它能像 webpack 那樣子引入圖片跟 CSS 嗎？不行，而且官方網站直接建議你用以前的那些方法就好了：

![](/img/mods/snowpack.png)

在官網上也有誰應該要用 Snowpack 誰應該不要用的段落，例如說你想要支援 IE11 或是你需要用到不支援 ESM 的函式庫的話，就不應該使用 Snowpack。

Snowpack 還很新，而且若是想在 production 上面使用應該還有滿多問題要解決，我在這邊特別提它的目的是想讓大家看看除了 webpack 以外的另一種解決方式。

而你可能聽過的 [parcel](https://parceljs.org/) 或者是 [rollup](https://rollupjs.org/guide/en/)，都只是另外一種幫你打包的工具而已。你可以選一套工具來熟悉就好，但重點是在這之前，你必須清楚知道為什麼需要這些工具。


## 結語

先來回答開頭那幾個問題：

#### Q：為什麼很多專案（例如說 React）在部署前都要先 build？這個步驟在幹嘛你知道嗎？

因為原始碼沒辦法直接放上去瀏覽器（會沒有辦法執行），所以一定要經過 webpack 打包處理，打包完的檔案才能讓瀏覽器執行。


#### Q：你知道 `require/module.exports` 與 `import/export` 的差別嗎？

`require/module.exports` 是一套叫做 CommonJS 的規範，Node.js 有支援，瀏覽器沒有。

`import/export` 是 ES6 的規範，Node.js 部分支援，瀏覽器也是部分支援。

#### Q：你知道 import 與 export 這兩個語法在瀏覽器上面不是隨便就能使用嗎？

有使用限制，例如說要加上 `type=module`，而且也沒辦法直接引入 npm 裡的模組，要把路徑寫死才能使用。而瀏覽器支援度也是一個考量，IE11 並不支援此種寫法。

#### Q：你知道為什麼要用 webpack 嗎？

原因有很多，例如說：

1. 我想使用 npm 上的第三方模組
2. 我想把圖片當作資源 import 進來
3. 我想把 CSS 當作資源 import 進來
4. 我想在一個地方就處理好 uglify 與 minify

不過重點其實是第一個，因為瀏覽器原生的 ES6 模組支援度沒那麼高，尤其是引入第三方模組，所以才需要透過 webpack 或其他打包工具幫我們處理好這一段。

#### Q：你知道 webpack 為什麼要有 loader 嗎？

因為把圖片或是 CSS 當作資源引入這並不是正式的規範，而是 webpack 自己延伸的定義。為了支援這些資源，就必須特別寫一個 loader 去載入，否則預設的 loader 只能載入 JavaScript。

-----

我一開始接觸 webpack 時，也是超級霧煞煞。完全不知道為什麼要 webpack，也完全不知道它做了哪些魔法。

直到後來慢慢摸索才發現自己一開始就錯了，不該從 webpack 開始的。連模組化的概念都不清楚，連瀏覽器上面不能用 require 都不知道，怎麼可能理解 webpack 在幹嘛？

而前陣子接觸到的一些學生，儘管是有工作經驗或是有用過 webpack 的，對這一塊也是一知半解。而在我看來，原因就是對於模組化的理解不足，對於歷史脈絡的了解不夠，對於「在瀏覽器上面執行 JS」以及「在電腦上用 Node.js 執行 JS」這兩者的區分不夠清楚，才會把許多東西都混為一談，當作是同一種。

所以這篇雖然是叫做「webpack 新手教學」，但比較多在談的是模組化以及使用 webpack 的理由，對於真正「如何使用 webpack」並沒有加以著墨。原因之一是我認為理解原理跟理由之後，使用工具的門檻就會降低很多；之二是再寫下去就沒完沒了了，真的想講 webpack 的話可以再開一篇文章。

其實有關於模組化，我有很多東西刻意沒有提到，例如說 AMD/UMD 等等的其他規範以及 RequireJS 這個工具。我覺得對這一篇想表達的東西來說，不講這些反而是好的，因為一旦講了就會把事情搞得更複雜，所以選擇性忽略這些內容。

在寫作的時候，選擇什麼要講什麼不講也是一門技藝，或許日後可以再寫一篇文章來補齊沒有講到的這些部分。

最後，希望大家看完這篇以後真的能理解 ES6 的原生模組在瀏覽器上面會碰到的問題，就能知道為什麼要用 webpack。

若是有任何錯誤還麻煩不吝指正，感謝！

參考資料：

1. [什麼？！我們竟然有 3 個標準？ - 你有聽過 CommonJS 嗎？(Day9)](https://ithelp.ithome.com.tw/articles/10191478)