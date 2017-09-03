---
title: '[教學] React Native for Android - 1： 基礎'
date: 2015-11-18 17:44
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [android,react native]
---
React Native出來已經一陣子了，而且陸陸續續被應用在許多App上，甚至還有些已經應用在production的環境
在今年九月的時候，大家引頸期盼的 Android 版本居然提早釋出！
想當初第一天的時候我興致勃勃地把example clone下來，發現弄了一陣子居然連demo都跑不起來QQ
於是只好先放棄了

但是幾個禮拜前再試了一次，跑[ZhiHuDaily-React-Native](https://github.com/race604/ZhiHuDaily-React-Native)這個project，很順利的就跑起來了！
之後就自己開了一個project隨手玩了一下，發現用React Native來開發還真的很方便！
就想說寫一系列的基本教學，帶大家看看React Native各個components的使用

在這篇裡面，幾乎不會教你任何事情！
這系列教學文不涵蓋前面「如何跑起來」的這些細節，我已經預設讀者有個適合開發的環境了
安裝程序直接參考官方給的那些就好，只要按部就班，不會是一件困難的事
[官方教學 設置基本環境](https://facebook.github.io/react-native/docs/getting-started.html)
1. 裝homebrew
2. brew update && brew upgrade
1. 裝 nodejs 4.0以後版本（直接裝5.0.0就好）
2. brew install watchman
3. npm install -g react-native-cli

第二步很重要，請確保你的brew是最新的，載到的東西才會是最新的

[官方教學 設置android相關設定](https://facebook.github.io/react-native/docs/android-setup.html)
1. 安裝JDK
2. 安裝Android SDK
3. 設定一些環境變數

基本上只要按著上面的兩個連結，一步一步來，就不太會出錯
如果發生問題的話，可以先看這兩個很有幫助的排除問題指南
1. [Android端10个最常见问题](https://github.com/yipengmu/ReactNative_Android_QA)
2. [React Native for Android 入门老虎](http://www.race604.com/react-native-for-android-start/)

很推薦第二篇，我很多問題都是看完第二篇以後才豁然開朗的

如果你已經確定都安裝完成了
新開一個folder，打上 `react-native init myApp`
就會幫你新建一個專案出來，這之間需要一點時間，因為要下載一堆dependencies
但是辛苦的等待是會有回報的，都執行完畢以後，輸入
`cd myApp`
`react-native run-android`（記得先把模擬器開好）

一切順利的話，你就會看到你的模擬器上面開啟了一個App，並且出現Welcome to React Native! 的字樣
![螢幕快照 2015-11-18 下午6.06.01.png](http://user-image.logdown.io/user/7013/blog/6977/post/314393/FY5qZzUTRFyWwB1lpXC0_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-11-18%20%E4%B8%8B%E5%8D%886.06.01.png)

如果不順利的話，一定是看到紅紅的錯誤畫面，就參考上面那兩個連結吧！

這邊先講解一些React Native的好處
首先，他的執行方式是載入一個javascript檔案然後執行
所以你的App剛開啟的時候，會出現`Fetching JS buddle`的字樣，就是代表他在從`Server`拿這份js檔案
咦？哪來的Server？其實就是你的電腦
所以你在開發的流程是：
1. 在電腦上改code，存檔
2. 模擬器重新載入js
3. 模擬器從你電腦的server拿你改過的js回傳
4. 模擬器重新執行

因為是連到電腦上的server，所以在實機開發上會有一些問題，例如說真的device連不到之類的
5.0以上可以很簡單透過：`adb reverse tcp:8081 tcp:8081` 這個指令改善
5.0以下的就...自求多福吧，因為我自己之前試了一下也沒成功
[官方文件在這，教你怎麼在實機上跑](https://facebook.github.io/react-native/docs/running-on-device-android.html#content)

所以目前我覺得在模擬器上跑，或是找一隻5.0以上的手機是比較好的選擇
另外，按下menu鍵或是搖晃手機（模擬器的話按`f2`，mac按`fn+f2`）可以叫出設定選單
![螢幕快照 2015-11-18 下午6.13.32.png](http://user-image.logdown.io/user/7013/blog/6977/post/314393/tXPI9gOMTZGuTbkOZMLC_%E8%9E%A2%E5%B9%95%E5%BF%AB%E7%85%A7%202015-11-18%20%E4%B8%8B%E5%8D%886.13.32.png)

Dev Settings -> Auto reload on JS change 打勾
這個選項在開發的時候「一定要打開」，因為超級方便
有多方便？

你現在打開以後，模擬器開著
然後開啟`myApp/index.android.js`
有一段是
``` javascript
var myApp = React.createClass({
  render: function() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>
          Welcome to React Native!
        </Text>
        <Text style={styles.instructions}>
          To get started, edit index.android.js
        </Text>
        <Text style={styles.instructions}>
          Shake or press menu button for dev menu
        </Text>
      </View>
    );
  }
});
```

我們很簡單的把它改成：
``` javascript
var myApp = React.createClass({
  render: function() {
    return (
      <View style={styles.container}>
        <Text style={styles.welcome}>
          I am the king of the hello-world!
        </Text>
      </View>
    );
  }
});
```

然後存檔
接著切回你的模擬器，發現一切都變了
上面的文字變成你剛改的那一段

這，就是React Native！