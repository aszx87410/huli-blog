---
title: '[Node.js] 串接 Amazon S3 API'
date: 2015-07-13 14:59
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [nodejs,backend]
---
最近剛好要串S3，S3是Amazon提供的一個服務，就是一個讓你存取檔案的地方
[官方新手教學](http://aws.amazon.com/tw/sdk-for-node-js/)其實寫得很清楚，而且用法超級簡單
[Document](http://docs.aws.amazon.com/AWSJavaScriptSDK/latest/AWS/S3.html)裡面有詳細的說明

下面附上一段上傳檔案的code

``` javascript
var AWS = require('aws-sdk');

function upload(data) {
	AWS.config.update({
		accessKeyId: awsConfig.key,
		secretAccessKey: awsConfig.secret
	});

	var s3 = new AWS.S3({
		params: {
			Bucket: awsConfig.s3.bucket,
			Key: 'image/test.png', //檔案名稱
			ACL: 'public-read' //檔案權限
		}
	});

	s3.upload({
		Body: data
	}).on('httpUploadProgress', function(evt) {

		//上傳進度
		console.log(evt);
	}).
	send(function(err, data) {
		
		//上傳完畢或是碰到錯誤
	});
}
```

官方教學是要你把key設定在電腦的某個位置，但如果懶得這樣做也可以自己寫個config檔之類的
再去update即可

值得一提的是`Key`這邊你可以直接傳有層次的路徑，AWS會自動幫你建立資料夾，超方便
要刪除檔案也是很簡單，就給個`Key`參數然後call `deleteObject`
``` javascript
function deleteObject(key){

	var s3 = new AWS.S3({
		params:{
			Bucket: awsConfig.s3.bucket
		}
	});

	var params = {
		Bucket: awsConfig.s3.bucket,
		Key: key
	};

	//刪除檔案囉
  s3.deleteObject(params, function(err, data) {
    if(err){
    	console.log(err);
    }

    console.log('delete '+ key +' done.');
  });
}
```

那如果想刪除一個資料夾怎麼辦呢？
可參考stackoverflow的這篇 [How can I delete folder on s3 with node.js?](http://stackoverflow.com/questions/20207063/how-can-i-delete-folder-on-s3-with-node-js)

``` javascript
var params = {
  Bucket: 'bucketName',
  Prefix: 'folder/'
};

s3.listObjects(params, function(err, data) {
  if (err) return console.log(err);

  params = {Bucket: 'bucketName'};
  params.Delete = {};
  params.Delete.Objects = [];

  data.Contents.forEach(function(content) {
    params.Delete.Objects.push({Key: content.Key});
  });

  s3.deleteObjects(params, function(err, data) {
    if (err) return console.log(err);

    return console.log(data.Deleted.length);
  });
});
```

就是先用`listObjects`找出key的prefix是某個資料夾的物件，接著再把裡面的key放進陣列
用`deleteObjects`這個api把那些objects全部移除掉
不過這邊有個小限制，`listObjects`的上限是一千個，所以如果檔案超過1000個就會刪不乾淨
但是一般的使用應該比較沒這種困擾，碰到的時候再加個判斷即可

結論：AWS真方便
