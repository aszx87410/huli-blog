---
title: '[Android] apache thrift 入門與android上的實作'
date: 2015-07-02 12:49
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
最近想做IM相關的service，上網找了一些文件
發現一套由facebook開源，LINE有在用的RPC的framework，也就是今天要介紹的主角
[Apache Thrift](https://thrift.apache.org/)

先來談談有這套框架跟沒這套框架的差異在哪邊
假設今天我要寫一套IM，client跟server之間透過http以json格式溝通
例如說client發一個request到`api/getFriends`，server就回覆
```
{
	list: [
  	....
  ]
}
```

這樣做會碰到幾個問題
1. 透過http傳輸，你根本不需要`header`裡面的資訊，但又不可能捨棄
2. 如果哪天server要用別的語言改寫，怎麼辦？
如果有寫好document，就是直接照著之前的document重新實做一份
沒有的話就只能看著以前的code，一步步改寫成新的語言

這個時候就來介紹Thrift可以怎麼解決這些問題了
基本上這就是一套RPC的framework

你必須用thrift規範的格式寫好一份檔案，我直接把它看成api的document，例如說
```
service Calculator extends shared.SharedService {

  void ping(),
  i32 add(1:i32 num1, 2:i32 num2)
}
```

就說你有一個`Calculator`的service，有兩個function，`ping`跟`add`
`i32`其實就是32 bits的int

有了這份以後，可以用thrift把它compile成串接API所需要的檔案
`thrift --gen <language> <Thrift filename>`
thrift的強大之處就在這裡，你要用java來實作server，就編譯成java的檔案
你要用python寫client，你就編譯出.py的檔案

先以java做server為例，compile完以後就會有一份.class檔案
import進去以後就可以`implements Calculator.Iface`，實作你剛剛定義的那兩個function

client端的操作也很簡單，也是把剛剛編譯出來的檔案import進去
跟server建立連線以後就可以直接呼叫了

再來就研究一下怎麼在android上面實作出client
一開始我是在gradle上面直接直接 `compile 'org.apache.thrift:libthrift:0.9.1'`
後來發現這樣子會出現錯誤，因為裡面用到的http連接的class跟android本身的會衝突
所以不能直接這樣引入thrift
解法附在最底下的ref裡面，你要自己改code然後編譯出一個thrift的jar檔放入

但網路資源豐富，[android-thrift-tutorial](https://github.com/briananderson1222/android-thrift-tutorial)這個repo底下就有這個jar檔，所以我就直接下載下來之後`compile files('libs/libthrift-0.9.1.jar')`

除此之外我們還需要兩個thrift會用到的library
```
compile 'org.slf4j:slf4j-api:1.5.8'
compile 'org.slf4j:slf4j-log4j12:1.5.8'
```

補充說明：
android會一直說找不到`javax.annotation`
可參考 [Thrift: the import javax.annotation cannot be resolved](http://stackoverflow.com/questions/27217524/thrift-the-import-javax-annotation-cannot-be-resolved)
加入一個jar檔之後即可


加入這三行以後試著執行一下，應該就可以成功開啟了

在這邊我所定義的thrift檔是一個`getMessage`的function
```
service Message {
	string getMessage(1:string username)
}
```

android端因為是牽扯到網路連線，所以必須放在asynctask裡面
``` java
private class ThriftTask extends AsyncTask<String, Integer, String> {

    @Override
    protected String doInBackground(String... str) {
        try {
            TTransport transport;

            transport = new TSocket("127.0.0.1", 9090);
            transport.open();

            TProtocol protocol = new TBinaryProtocol(transport);
            Message.Client client = new Message.Client(protocol);

            String ret = client.getMessage("huli");
            transport.close();

            return ret;
        } catch (TException x) {
            x.printStackTrace();
        }

        return "";
    }

    protected void onProgressUpdate(Integer... progress) {

    }

    protected void onPostExecute(String result) {
        Log.d("APP", "thrift");
        Log.d("APP", result);
    }
}
```

`Message.Client`的`Message`就是thrift所產生的.java檔案
儘管我只定義了一個function，但產生的code足足有兩千多行
可見thrift背後幫你把一大堆事情都處理掉了

接著呼叫`new ThriftTask().execute();`
就可以在logcat看到api所傳來的結果

以我初步試驗的結果，覺得thrift還不錯，假設哪天要換server或是在別的client(web、desktop)也能迅速切換
不用再從頭開始打造

google有一套`protobuf`也跟這個類似，只是支援的語言好像比較少

thrift的中文討論非常少，如果之後有進一步使用或碰到什麼問題，再上來跟大家分享

Evenote也在用這套 [So API Together: Evernote and Thrift](https://blog.evernote.com/tech/2011/05/26/evernote-and-thrift/)
裡面提到facebook後來自己又open source改進的版本 [Under the Hood: Building and open-sourcing fbthrift](https://code.facebook.com/posts/1468950976659943/under-the-hood-building-and-open-sourcing-fbthrift/)

evenote有把自己thrift格式開源出來，要規劃API可以參考看看
[evernote-thrift](https://github.com/evernote/evernote-thrift/tree/master/src)
line的則是有人破解出來XDD
[purple-line](http://altrepo.eu/git/purple-line/blob/master/libpurple/line.thrift)


ref:
[关于解决 java.lang.NoClassDefFoundError: org/slf4j/impl/StaticLoggerBinder 的解决方法](http://gongstring.iteye.com/blog/481555)
[Apache Thrift » 0.9.2](http://mvnrepository.com/artifact/org.apache.thrift/libthrift/0.9.2)
[ Thrift 0.8 not compatible with Android HttpClient ](http://grokbase.com/t/thrift/commits/12cpyd071g/git-commit-thrift-1641-thrift-0-8-not-compatible-with-android-httpclient-patch-darin-tay)
[Thrift client on Android](http://stackoverflow.com/questions/19141177/thrift-client-on-android)
[android-thrift-tutorial](https://github.com/briananderson1222/android-thrift-tutorial)
[Thrift by Example](http://thrift-tutorial.readthedocs.org/en/latest/usage-example.html#java-multiplication-client)
[Apache-Thrift-Bootcamp](https://github.com/LostInBrittany/Apache-Thrift-Bootcamp)