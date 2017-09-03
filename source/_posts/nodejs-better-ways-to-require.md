---
title: '[Node.js] 更好的 require 方式'
date: 2015-04-29 12:10
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---
在寫node js的project的時候，當規模變大的時候資料夾就會越來越多，然後深度也會越來越深
這個時候你的require很可能會長這樣
``` javascript
require('../../../model/article');
```
但是一堆 `../`，看了實在是十分不順眼，所以我們可以新增一個 method 去處理這件事情
``` javascript app.js
var path = require('path');
global._require = function(_path) {
    return require(path.join(__dirname, _path));
}
```

這樣在require自己的檔案時，直接用
``` js
var article = _require('/model/article')
```

如果想知道更多方法及討論，可參考 [Better local require() paths for Node.js](https://gist.github.com/branneman/8048520)