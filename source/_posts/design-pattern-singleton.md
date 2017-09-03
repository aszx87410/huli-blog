---
title: '[設計模式] singleton'
date: 2015-10-16 10:53
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [design pattern]
---
最近接觸到一點跟design pattern有關的東西，在這邊做一下心得筆記
現在在開發一個規模有一點大的Android App，又接觸到web開發的Flux這個架構，裡面的單向資料流概念我很喜歡
在App裡面我碰到的問題是：有很多地方、很多不同的Activity都會需要用到同一個變數
在以往我的做法是直接用一個static的class
``` java
public class Store{
  public static String id = "";
}

//其他地方在用的時候
// Store.id = "123";
```

這樣直接把變數用public開放出去超不健康，可以改成加上getter跟setter
在取用或是設定的時候就是用`Store.getId();`之類的做法了
那是這樣用仍然感覺心裡不太踏實，而且假如我要初始化的話，我就必須自己加上`static void init()`
並且在程式開始的時候`Store.init();`

之後剛好接觸到設計模式，知道裡面有一招叫做`singleton`，就是我們今天所要講解的主題
其實singleton對開發者並不陌生，寫java的可能依稀會有印象，常看到一個叫做`mInstance`的變數
或是常常看到`getInstance()`這個方法
這些就是singleton架構的慣用手法

singleton架構就如同這名字一樣，保證只會有一個instance，你不管怎麼取，取到的都會是同一個
概念不難，程式也不難，直接來寫code吧
``` java
public class Store{

  private String mId;

  //設成private，只能從內部存取
  private static Store mInstance;
  public static synchronized Store getInstance(){
    if(mInstance==null){
      mInstance = new Store();
    }
    
    return mInstance;
  }
  private Store(){
    //初始化
    mId = "5";
  }
  
  public String getId(){
    return mId;
  }
  
  public void setId(String id){
    mId = id;
  }
}

//要用的時候
//Store.getInstance().getId();
//Store.getInstance().setId("123");
```

因為`getInstance`有加上`synchronized`，所以可以保證同時只會有一個thread在存取
裡面檢查了現在`mInstance`是否存在，不存在的話就新建一個，接著把`mInstance`傳回去

依照這樣的架構，就可以保證所有用到這個store的地方，所存取到的資料都會是同一份

補充：
在getInstance的地方，其實可以再做優化
因為`synchronized`會拖慢效率，每次執行一次就要拖慢一次，會影響效能
可以改成雙重鎖定的方式
```
    private volatile static Store mInstance;
    public static Store getInstance(){
        if(mInstance==null) {
            synchronized (Store.class){
                if(mInstance==null){
                    mInstance = new Store();
                }
            }
        }
        return mInstance;
    }
```

ref:
http://www.cs.umd.edu/~pugh/java/memoryModel/DoubleCheckedLocking.html
http://blog.maxkit.com.tw/2014/01/singletonvolatile.html
http://www.infoq.com/cn/articles/ftf-java-volatile