---
title: '[Android] java reflection - 用方法名稱呼叫'
date: 2015-07-03 11:26
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
標題好難下

先來介紹一下碰到的問題跟想要的解決方法
事情是這個樣子的，原本我們的android在跟server溝通時是走http，post資料過去然後等response回來
採用Volley這套library，自己上面再包一層，用自己喜歡的形式call api

大概是長這個樣子
``` java
//獲取好友列表
API.getFriendList(username, new ResponseListener() {

  public void onResponse(String response) {
      
  }

  public void onError(String error) {
      
  }
});
```

現在問題來了，我們想改成用thrift把原本的http server換掉，用thrift的方法call
大概會長這樣
``` java
TTransport transport;

transport = new TSocket("127.0.0.1", 9090);
transport.open();

TProtocol protocol = new TBinaryProtocol(transport);
Friend.Client client = new Friend.Client(protocol);
String response = client.getFriendList(username);
```

然後這段code要包在try...catch裡面，也要包在AsyncTask裡面
如果我想在不更動原本call api形式的情況下，改成用thrift，有沒有什麼好方法呢？

<!-- more -->

先來看看原本的實作
``` java
public static void getFriendList(String username, final ResponseListener res){

    String url = apiHost + "/friends/get";
    Map<String, String> params = new LinkedHashMap<String, String>();
    params.put("username", username);
    CustomJsonObjectRequest jsonObjReq = new CustomJsonObjectRequest(Method.POST, url,params,res);

    mQueue.add(jsonObjReq);
}
```

原本是用volley，所以其實就是包一包之後丟進queue就結束了
現在要改成thrift的話，一個最直接的想法就是在這邊改成
``` java
public static void getFriendList(String username, final ResponseListener res){

    new getFriendListTask.execute(username, res);
}
```

其他的都讓這個task去處理就好
但是這樣子有個問題，那就是只要你有一個method，你就要寫一個asyncTask
這是非常麻煩的事情，你要一直複製貼上然後寫類似的內容
有沒有更方便的做法呢？

或許有種寫法可以是這樣
``` java
public static void getFriendList(String username, final ResponseListener res){

    new ThriftTask.execute(new APICall(){

    	public void call(){
    		client.getFriendList(username);

    	}
    }, res);
}
```

這種寫法看起來滿乾淨的，只是可能還要研究一下怎麼實作
所以我採用了另外一種寫法
``` java
public static void getFriendList(String username, final ResponseListener res){

  Object arr[] = {
  	"getFriendList", 
  	username, 
  	res
  };
  new ThriftTask().execute(arr);
}
```

第一個參數是method name, 第2~length-1的參數是method要帶的參數，最後一個參數是response
要實作出這樣的功能有一個最關鍵的問題：給定一個method name，你要怎麼call?

如果是php，那就超級方便
``` php
$name = "getFriendList";
$name(username);
```
這樣子就可以了，可惜我們是在寫java

java有個機制叫做reflection，想深入瞭解的話可參考 [Java 反射機制 - 侯捷](http://jjhou.boolan.com/javatwo-2004-reflection.pdf)
google了一下之後找到一些片段，湊一湊查一查之後終於弄出來了
這邊實作的版本還沒加上response，所以call的時候是
```
public static void getFriendList(String username, final ResponseListener res){

  Object arr[] = {
  	"getFriendList", 
  	username
  };
  new ThriftTask().execute(arr);
}
```

就少了那個res而已，不過當我們可以正確執行以後，再加上這個就不是一件太困難的事了

``` java
private class ThriftTask extends AsyncTask<Object, Integer, Object> {

    @Override
    protected Object doInBackground(Object... objects) {
        Log.d("API", "task start.");
        try {
            TTransport transport;

            transport = new TSocket("127.0.0.1", 9090);
            transport.open();

            TProtocol protocol = new TBinaryProtocol(transport);
            Message.Client client = new Message.Client(protocol);

            int length = objects.length;
            String methodName = (String) objects[0];

            Class params[] = new Class[length-1];
            for(int i=1;i<length;i++){
                params[i-1] = objects[i].getClass().getSuperclass();
            }

            Log.d("API", Arrays.toString(params) );

            Object[] args = Arrays.copyOfRange(objects, 1, length);
            Log.d("API", "args:" + Arrays.toString(args) );
            Log.d("API", "args length:" + args.length);

            Class<?> c = client.getClass();
            java.lang.reflect.Method method = c.getDeclaredMethod(methodName, params);
            Object ret = method.invoke(client, args);

            transport.close();

            return ret;

        } catch (Exception e) {
            e.printStackTrace();
        }

        return "post";


    }

    protected void onProgressUpdate(Integer... progress) {

    }

    protected void onPostExecute(Object result) {

        if(result!=null) {
            Log.d("API", "result type:");
            Log.d("API", result.getClass().toString());
            Log.d("API", "thrift result:");
            Log.d("API", result.toString());
        }else{
            Log.d("API", "thrift result: null");
        }

    }
}
```

裡面最關鍵的是
`getDeclaredMethod`這個方法，要傳入兩個參數，第一個是方法名稱，這沒什麼難度
第二個是參數型態，例如說你今天有個method是`int add(int a, int b)`
就必須
``` java
getDeclaredMethod("add", new Class[]{int.class, int.class});
```

理解這個前提以後，就可以來看一下如何實際操作
基本上的想法就是先獲得每個傳入參數的class，就可以拿到相對應的method
再invoke即可

拿裡面最精華的那段出來講，附上註解說明
``` java
//先拿傳入參數的長度
int length = objects.length;

//第一個參數是方法名稱
String methodName = (String) objects[0];

//取出每個要傳入參數的class
Class params[] = new Class[length-1];
for(int i=1;i<length;i++){
    params[i-1] = objects[i].getClass().getSuperclass();
}

//印出結果確認一下
Log.d("API", Arrays.toString(params) );

//去掉第一個元素以後，其他都是要傳入的參數
Object[] args = Arrays.copyOfRange(objects, 1, length);

//印出來確認一下
Log.d("API", "args:" + Arrays.toString(args) );
Log.d("API", "args length:" + args.length);

//得到client的class
Class<?> c = client.getClass();

//傳入名稱、參數類型獲取method
java.lang.reflect.Method method = c.getDeclaredMethod(methodName, params);

//invoke 用object接收結果
Object ret = method.invoke(client, args);
```

值得注意的是`objects[i].getClass().getSuperclass();`
這裏我原本是寫`objects[i].getClass();`
但是出現一個錯誤，那就是我傳入的明明就是`byteBuffer`，但出來的結果總是`byteArrayBuffer`
導致之後會找不到method跳出錯誤，於是改成`getSuperclass`以後就正常了
這邊可以視使用情況調整

這樣就實作出一個傳入名稱、參數之後會自動呼叫相對應method的asyncTask了
解決原本要寫一堆asyncTask的問題，現在只要維護一個即可

