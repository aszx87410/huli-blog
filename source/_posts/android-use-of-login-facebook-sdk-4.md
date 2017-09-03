---
title: '[Android] 利用Facebook SDK登入(4.0)'
date: 2015-04-16 10:13
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [Android]
---
在很多應用程式裡面，常常會有個功能是可以用facebook的帳號登入
今天就來實作一下，這個功能要如何完成

首先先到 https://developers.facebook.com/quickstarts/?platform=android
fb提供的quick start頁面，先照著上面的步驟做即可

1. 創立一個fb app(或選你已經有的)
2. 下載SDK
3. 安裝facebook app，看你是要裝在模擬器上還是裝在實機上
4. 把SDK加到你的project裡面
5. 告訴fb你的package name跟activity name
6. 產生key給它
7. 加入log

這邊的流程剛剛上面那個網頁都有明確清楚的教學
中間如果碰到什麼問題 丟去餵google就好

今天我卡一個地方卡超久，卡在key那個地方
我照著上面的command輸入以後，出現「輸入金鑰儲存庫密碼」
我就輸入我電腦密碼然後得到了一個key
但是這個key根本是錯的！！！所以之後在登入的時候碰到很多麻煩
這邊的密碼請輸入`android`，才會產生正確的key
剛好在看google plus API的時候看到的
https://developers.google.com/+/mobile/android/getting-started?hl=zh-tw

還有一點，這邊結束以後，請去你的app setting裡面，把你剛剛得到的`key`再貼一次
```
https://developers.facebook.com/apps/你的app_id/settings/
```
然後把Single Signed On打開

quickstart結束以後
再照著 https://developers.facebook.com/docs/android/getting-started 做一些基本設定
其實就是
1.在string.xml裡面加上facebook_app_id
``` xml strings.xml
<resources>
    <string name="app_name">Facebook_sdk_test</string>

    <string name="hello_world">Hello world!</string>
    <string name="action_settings">Settings</string>
    <string name="facebook_app_id">11111111</string>
</resources>
```
2.加user permission
``` xml
<uses-permission android:name="android.permission.INTERNET"/>
```
3.加meta data
``` xml
<application>
	<meta-data android:name="com.facebook.sdk.ApplicationId" android:value="@string/facebook_app_id"/>
</application>
```
4.加入facebook activity
``` xml
<activity android:name="com.facebook.FacebookActivity"
            android:configChanges=
                "keyboard|keyboardHidden|screenLayout|screenSize|orientation"
            android:theme="@android:style/Theme.Translucent.NoTitleBar"
            android:label="@string/app_name" />
```

上面的步驟做完，就把基本設定都搞好了
接下來就是要來看看怎麼樣結合facebook的登入
可參考
https://developers.facebook.com/docs/facebook-login/android/v2.3

裡面說到要登入facebook有兩種方法，一種用按鈕，另外一種是不用按鈕
先來看看用按鈕的怎麼登入

首先先在xml裡面加入facebook的login button
``` xml
<com.facebook.login.widget.LoginButton
        android:id="@+id/login_button"
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:layout_gravity="center_horizontal"
        android:layout_marginTop="30dp"
        android:layout_marginBottom="30dp" />
```
先在最外面宣告兩個全域變數
``` java
CallbackManager callbackManager;
private AccessToken accessToken;
```

接著直接把onCreate的程式碼貼上來，再來講解發生什麼事情

``` java MainActivity.java 
@Override
protected void onCreate(Bundle savedInstanceState) {

    //初始化FacebookSdk，記得要放第一行，不然setContentView會出錯
    FacebookSdk.sdkInitialize(getApplicationContext());
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    //宣告callback Manager
    callbackManager = CallbackManager.Factory.create();

    //找到login button
    LoginButton loginButton = (LoginButton) findViewById(R.id.login_button);

    //幫loginButton增加callback function
    //這邊為了方便 直接寫成inner class
    loginButton.registerCallback(callbackManager, new FacebookCallback<LoginResult>() {

        //登入成功
        @Override
        public void onSuccess(LoginResult loginResult) {

            //accessToken之後或許還會用到 先存起來
            accessToken = loginResult.getAccessToken();

            Log.d("FB","access token got.");

            //send request and call graph api
            GraphRequest request = GraphRequest.newMeRequest(
                    accessToken,
                    new GraphRequest.GraphJSONObjectCallback() {

                        //當RESPONSE回來的時候
                        @Override
                        public void onCompleted(JSONObject object, GraphResponse response) {

                            //讀出姓名 ID FB個人頁面連結
                            Log.d("FB","complete");
                            Log.d("FB",object.optString("name"));
                            Log.d("FB",object.optString("link"));
                            Log.d("FB",object.optString("id"));

                        }
                    });

            //包入你想要得到的資料 送出request
            Bundle parameters = new Bundle();
            parameters.putString("fields", "id,name,link");
            request.setParameters(parameters);
            request.executeAsync();
        }

        //登入取消
        @Override
        public void onCancel() {
            // App code
            Log.d("FB","CANCEL");
        }

        //登入失敗
        @Override
        public void onError(FacebookException exception) {
            // App code
            Log.d("FB",exception.toString());
        }
    });
}
```

去override Facebook提供的callback function
在onSuccess事件裡面寫下你想做的事情，而這邊會拿到`loginResult`
再用loginResult取得一組`accessToken`，之後要用到graph API的地方都用這組token
接著送一個request出去，在`onCompleted`裡面會拿到`object`，是json格式的物件，包著一些user data
而這就是我們要的資訊了
這樣一個完整的流程可以實現利用facebook登入

那如果不想要用fb提供的login button呢？ 當然也可以自己寫一個，而且code跟上面其實差不多
首先先把login button拿掉，換成我們自己的按鈕
``` xml
<Button
        android:layout_width="wrap_content"
        android:layout_height="wrap_content"
        android:text="New Button"
        android:id="@+id/fb_login"
        android:layout_below="@+id/textView"
        android:layout_alignParentLeft="true"
        android:layout_alignParentStart="true" />
```

一樣直接先附上code
``` java MainActivity.java
@Override
protected void onCreate(Bundle savedInstanceState) {

    //初始化FacebookSdk，記得要放第一行，不然setContentView會出錯
    FacebookSdk.sdkInitialize(getApplicationContext());
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);

    //宣告callback Manager
    callbackManager = CallbackManager.Factory.create();

    //找到button
    Button loginButton = (Button) findViewById(R.id.fb_login);

    loginButton.setOnClickListener(new Button.OnClickListener(){

        @Override
        public void onClick(View v) {
            LoginManager.getInstance().logInWithReadPermissions(MainActivity.this, Arrays.asList("public_profile", "user_friends"));
        }
    });

    //幫 LoginManager 增加callback function
    //這邊為了方便 直接寫成inner class
    LoginManager.getInstance().registerCallback(callbackManager, new FacebookCallback<LoginResult>() {

        //登入成功
        @Override
        public void onSuccess(LoginResult loginResult) {

            //accessToken之後或許還會用到 先存起來
            accessToken = loginResult.getAccessToken();

            Log.d("FB", "access token got.");

            //send request and call graph api
            GraphRequest request = GraphRequest.newMeRequest(
                    accessToken,
                    new GraphRequest.GraphJSONObjectCallback() {

                        //當RESPONSE回來的時候
                        @Override
                        public void onCompleted(JSONObject object, GraphResponse response) {

                            //讀出姓名 ID FB個人頁面連結
                            Log.d("FB", "complete");
                            Log.d("FB", object.optString("name"));
                            Log.d("FB", object.optString("link"));
                            Log.d("FB", object.optString("id"));

                        }
                    });

            //包入你想要得到的資料 送出request
            Bundle parameters = new Bundle();
            parameters.putString("fields", "id,name,link");
            request.setParameters(parameters);
            request.executeAsync();
        }

        //登入取消
        @Override
        public void onCancel() {
            // App code
            Log.d("FB", "CANCEL");
        }

        //登入失敗
        @Override
        public void onError(FacebookException exception) {
            // App code
            Log.d("FB", exception.toString());
        }
    });
}
```

其實可以發現，跟fb login button的寫法十分相像
差異點在於
1.用自己的按鈕，並且在`onClick`事件裡面寫下
``` java
LoginManager.getInstance().logInWithReadPermissions(MainActivity.this, Arrays.asList("public_profile", "user_friends"));
```

2.把
``` java
loginButton.registerCallback...
```
取代成
``` java
LoginManager.getInstance().registerCallback...
```

就是這麼簡單，就可以把fb sdk整合進自己的app裡面
並且提供用facebook登入的功能
github: https://github.com/aszx87410/android_facebooksdk4.0_login_simple
記得到strings.xml裡面換成自己的facebook app id