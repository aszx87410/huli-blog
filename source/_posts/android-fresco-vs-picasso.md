---
title: '[Android] Fresco vs Picasso'
date: 2015-10-27 18:15
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
在Android，顯示圖片的Library比較著名的就那幾套
除了標題中提到的那兩套，還有glide跟universal image loader
這幾套除了fresco以外，載入圖片的方式都大同小異
之前在做的app原本是用picasso，但用久了發現一些問題很難解決，在這邊跟大家分享一下

1.圖片方向
picasso如果是讀網路上的圖片，不會去處理跟exif有關的東西
也就是說，可能你在瀏覽器看到的圖片是直的，但是在picasso load以後卻變成橫的
ref: https://github.com/square/picasso/issues/846

這問題我覺得滿難解決的，滿棘手

2.disk cache
picasso預設是沒有把圖片cache在disk裡面，那這部分的解法比較簡單
只要有引入okhttp，square的另一套library，就會自動處理好這個部分

基本上用picasso就碰到這兩個問題比較重大一點，其他都還好
`Picaaso.with(context).load(url).into(imageview)`這語法我還滿喜歡的
要注意的是如果圖片存在本地，記得改成`.load(new File(path))`

接著偶然間發現了Fresco這套facebook出的library
之前也有寫過文章稍微介紹一下，會改用這套是因為他解決了picasso上面那兩個問題
disk cache預設就有開啟，所以什麼都不用做

圖片方向的話有auto rotate，超方便的功能！
我目前載入圖片的code大概長這樣
``` java
    public static void setFrescoImage(DraweeView imageView, String path){

        if(path.startsWith("http")) {
            path = ImageUtils.getSmallImage(500, path);
        }else{
            path = "file://" + path;
        }
        Uri uri = Uri.parse(path);
        ImageRequest request = ImageRequestBuilder.newBuilderWithSource(uri)
                .setAutoRotateEnabled(true)
                .build();

        DraweeController controller = Fresco.newDraweeControllerBuilder()
                .setImageRequest(request)
                .setTapToRetryEnabled(true)
                .setOldController(imageView.getController())
                .build();
        imageView.setController(controller);
    }
```

fresco在我看來功能比較多，而且都是預設好的
但缺點就是如果要搭配imageView比較棘手，要全部換成fresco的draweeView
若是硬要搭配，這邊有範例
https://github.com/facebook/fresco/issues/364

就是用fresco去載圖，載完之後直接用imageview去set就好
如果要加上auto rotate也很簡單，把imageRequest的部分用上面那樣取代掉就好

個人主觀結論：Fresco獲勝
