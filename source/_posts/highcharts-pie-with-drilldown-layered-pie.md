---
title: '[Highcharts] Pie with drilldown，有層次的圓餅圖'
date: 2015-05-06 17:27
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [frontend]
---
[Highcharts](http://www.highcharts.com/)是一套javascript的library
目的是快速幫你畫出好看的統計圖表
官網有很多範例，可以自己去看看，基本的像是線圖、圓餅圖、區域圖、長條圖...全部都完整的支援
甚至還有3D或是更進階一點的圖表

今天要來研究的是一種進階的圓餅圖
官方範例：http://www.highcharts.com/demo/pie-drilldown
這是瀏覽器市佔率的圓餅圖，但特殊的地方在於這個圓餅圖有兩層
你可以針對IE這個項目點下去，就會進一步出現IE各個版本的市佔率為何
但官方範例用到的功能太多，而且看source code其實很難看出來要喂的格式為何
所以我重寫了一份簡單易懂的範例
http://codepen.io/anon/pen/mJepZe

要注意的是要額外引入`drilldown`這個檔案才可以用這個功能
```
<script src="http://code.highcharts.com/modules/drilldown.js"></script>
```

要給的資料分為兩部份，第一部份是「分類」

``` json brandsData
[
   {
      "name":"Safari ",
      "y":4.64,
      "drilldown":"Safari"
   },
   {
      "name":"Opera ",
      "y":1.54,
      "drilldown":"Opera"
   },
   {
      "name":"Proprietary or Undetectable",
      "y":0.29,
      "drilldown":null
   }
];
```
y就是要顯示出來的數值，這邊要自己換算成%數
drilldown即是指定待會點下去以後會選到的id

``` json drilldownSeries
[
   {
      "name":"Safari版本",
      "id":"Safari",
      "data":[
         [
            "v5.1",
            3.53
         ],
         [
            "v5.0",
            0.85
         ],
         [
            "v4.0",
            0.14
         ],
         [
            "v4.1",
            0.12
         ]
      ]
   },
   {
      "name":"Opera版本",
      "id":"Opera",
      "data":[
         [
            "v11.x",
            1.3
         ],
         [
            "v12.x",
            0.15
         ],
         [
            "v10.x",
            0.09
         ]
      ]
   }
]
```
這裏的id對應到的是剛剛分類的drilldown，而data底下就是第二層圓餅圖的資料
以一個陣列裡面包[name,value]的形式呈現

而一個最陽春畫圖的code長這樣
``` javascript
$('#chart').highcharts({
    chart: {
        type: 'pie'
    },
    title: {
        text: '瀏覽器市佔率'
    },
    series: [{
        name: '瀏覽器',
        colorByPoint: true,
        data: brandsData
    }],
    drilldown: {
        series: drilldownSeries
    }
});
```

值得一提的是highchart提供一堆客製化的option，最上面附的範例或是我改寫的範例都多少有用到一些客製化
例如說你覺得圖表顏色太醜不喜歡，可以換成自己喜歡的顏色
``` js
Highcharts.setOptions({
	    colors: ['#058DC7', '#50B432', '#ED561B', '#DDDF00', '#24CBE5', '#64E572', '#FF9655', '#FFF263', '#6AF9C4']
});
```

滑鼠移上去的tooltip，圓餅圖的文字說明、格式也都可以自己調整，真是方便