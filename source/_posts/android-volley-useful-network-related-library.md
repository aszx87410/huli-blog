---
title: '[Android] volley，好用的http client library'
date: 2015-06-15 17:51
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
以前原本都用android內建的Library來進行`GET`、`POST`等等對API的連線與操作
但最近想說來找找看有沒有好用的library，應該可以事半功倍
當初有找了三套比較多人用的
1.[Android Asynchronous Http Client](http://loopj.com/android-async-http/)
2.[okhttp](http://square.github.io/okhttp/)
square開發並且開源的，因為之前用過他們家的[picasso](http://square.github.io/picasso/)，所以對這套滿有好感的，只可惜使用方式不太喜歡
3.[Volley](https://developer.android.com/training/volley/index.html)
Google在2013年Google I/O的時候發佈的，最後我選擇了這套
原因只有一個，那就是因為他是Google的親生兒子...
<!-- more -->


網路上已經有些教學寫得很詳細
[Android库Volley的使用介绍](https://bxbxbai.github.io/2014/09/14/android-working-with-volley/)
[Android Volley完全解析(一)，初识Volley的基本用法](http://blog.csdn.net/guolin_blog/article/details/17482095)
這系列一共四集，滿推薦的，從基本用法到自訂request再到源碼講解，很棒的一系列教學
如果想測Request卻懶得自己架Server可用 http://requestb.in/ 這個網站測試

如果不想把volley的專案clone下來build的話，有人把檔案放在github上
[android-volley](https://github.com/mcxiaoke/android-volley)
有提供`gradle`的引入方法，我自己就是用這個

實際用下來的心得，有些地方有被雷到
像是如果你要`POST`要去`Override`一個`getParams`的方法
在`StringRequest`底下用沒問題，但是在`JsonObjectRequest`下面卻沒有用...
所以我後來就改用`StringRequest`然後自己再parse...

通常在跟Server的API溝通時，很多地方都會用到相似的功能
像是request可能會加個time的參數
所以我就把Volley外面再包一層
現在有個API要發送簡訊，實際上call的時候會是這樣call
``` java
API.sendSMS("886","922333444", new ResponseListener(){

    public void onResponse(JSONObject response){

    }

    public void onError(VolleyError error){

    }
});
```

``` java ResponseListener.java
public abstract class ResponseListener {

    public void onResponse(String str){

    }

    public void onError(VolleyError error){

    }
}
```

``` java API.java
  public static void sendSMS(String country_code, String phone_number, final ResponseListener res){

      String url = "http://google.com";
      Map<String, String> params = new HashMap<String, String>();
      params.put("country_code", country_code);
      params.put("phone", phone_number);
      CustomJsonObjectRequest jsonObjReq = new CustomJsonObjectRequest(url,params,res);

      mQueue.add(jsonObjReq);

  }
```

``` java CustomJsonObjectRequest.java
//繼承原本的request, 新增一些function
public class CustomJsonObjectRequest extends StringRequest {

    private Map<String, String> mParams;

    public CustomJsonObjectRequest(String url, Map<String, String> params, final ResponseListener res){

        //準備參數
        super(Method.POST, url, new Response.Listener<String>() {
                    @Override
                    public void onResponse(String response) {
                        res.onResponse(response);
                    }
                },
                new Response.ErrorListener() {
                    @Override
                    public void onErrorResponse(VolleyError error) {
                        res.onError(error);
                    }
                });

        mParams = handleParams(params);
    }

    private Map<String, String> handleParams(Map<String,String> map){

        //加上時間
        Long tsLong = System.currentTimeMillis()/1000;
        String ts = tsLong.toString();
        map.put("time",ts);

        return map;
    }

    @Override
    protected Map<String, String> getParams() throws AuthFailureError {
        return mParams;
    }

}
```

解析成JSON的部分還沒做，不過就只是拿回response的時候處理一下再丟回去即可
