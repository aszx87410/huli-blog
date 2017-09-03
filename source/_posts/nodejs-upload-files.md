---
title: '[Node.js] 上傳檔案'
date: 2015-06-08 14:42
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---

來介紹這個好用的東西
https://github.com/expressjs/multer

1. npm install multer --save
2. 在app.js裡面加上 
``` javascript
var multer  = require('multer');
app.use(multer({ dest: './uploads/'}));
```
3. form這樣寫
``` html
<form action="(..your_action_path)" method="post" enctype="multipart/form-data">
  <input type="file"  id="input_file" name='file'>
</form>
```

4.在router裡面就可以這樣寫
``` javascript
var route = function(reqeust, response, next){
  var file_name = request.files.file.name;
}
```
就可以取得上傳的檔案的檔名（multer會自動幫你重新命名）
上傳的動作multer都自己幫你做好了
有了檔名以後再去做自己想做的事情即可（改檔名或是移動位置之類的）
