---
title: 自己架一個 Online Judge 系統
catalog: true
header-img: /img/header_img/article-bg.png
date: 2020-03-23 22:58:31
tags: [Others]
categories:
  - Others
---

## 前言

先稍微介紹一下什麼是 Online Judge（底下簡稱 OJ）系統，簡單來說就是像 leetcode 那樣啦，可以送出程式碼解題，然後讓系統去批改，並且得到最後的結果。底下是 leetcode 的截圖：

![leetcode 介面](https://static.coderbridge.com/img/aszx87410/47ea051cb4244849908286177e42a38f.png)

在 leetcode 流行以前，最知名的 OJ 大概就是 [UVa Online Judge](https://onlinejudge.org/)，俗稱 ACM，而台灣的話應該就是 [ZeroJudge](https://zerojudge.tw/) 比較有名。

如果剛好有需求，想要自己架一個 OJ 的話，該怎麼辦呢？

<!-- more -->

## 開源 OJ 系統

在網路上搜尋一下，可以找到幾個開源的 OJ 系統，其中星星數比較多看起來也比較穩定的是底下三個：

1. [DMOJ](https://github.com/DMOJ/online-judge)
2. [NOJ](https://github.com/ZsgsDesign/NOJ)
3. [QDUOJ](https://github.com/QingdaoU/OnlineJudge)

### DMOJ

![](https://static.coderbridge.com/img/aszx87410/0664ed7eeb6b478db132935202dee433.png)

這一套功能看起來最豐富最完整，而且支援的語言最多，可以到 60 幾種！而且還支援 Google, Facebook, Github 這些第三方登入。後端是 Python 寫的，而且一直持續有在維護，[文件](https://docs.dmoj.ca/#/site/installation)也滿完整的。

唯一的缺點大概就是介面比較陽春一點，沒那麼討喜。

### NOJ

![](https://static.coderbridge.com/img/aszx87410/950d37d94365471ab8cf0b1f5f820d31.png)

中國南京郵電大學開源出來的系統，是用 Laravel 寫成的。介面使用 Material UI，看起來比較現代，但是文件比較不完整。

### QDUOJ

中國青島大學開源出來的，後端是 Python + Django，前端是 Vue，採用 docker 部署簡單快速，支援的程式語言有：C, C++, Java 跟 Python。介面的部分則是使用 Ant Design。

![](https://static.coderbridge.com/img/aszx87410/8d236caa632b42c6bde5c33c06f2ef3f.png)

想要架哪一套就是根據自己需求而定，如果 GitHub 上提供的文件完整的話，照著做就行了。若是不完整也可以透過 Issue 提問，英文不好的話也不需要太過擔心，這三個 repo 用中文應該也都可以通。

而我最後選擇的是最後一套，青島大學開源出來的 OJ。會選這一套是因為介面我滿喜歡的，然後是這三套裡面部署最容易的一套。

部署流程在這邊：https://github.com/QingdaoU/OnlineJudgeDeploy/tree/2.0 ，因為是採用 docker 部署，所以真的容易，基本上就是把 docker-compose.yml 拉下來然後跑個指令就搞定了。

我們可以來看一下 docker-compose.yml 的內容：

```
version: "3"
services:

  oj-redis:
    image: redis:4.0-alpine
    container_name: oj-redis
    restart: always
    volumes:
      - ./data/redis:/data
  
  oj-postgres:
    image: postgres:10-alpine
    container_name: oj-postgres
    restart: always
    volumes:
      - ./data/postgres:/var/lib/postgresql/data
    environment:
      - POSTGRES_DB=onlinejudge
      - POSTGRES_USER=onlinejudge
      - POSTGRES_PASSWORD=onlinejudge

  judge-server:
    image: registry.cn-hangzhou.aliyuncs.com/onlinejudge/judge_server
    container_name: judge-server
    restart: always
    read_only: true
    cap_drop:
      - SETPCAP
      - MKNOD
      - NET_BIND_SERVICE
      - SYS_CHROOT
      - SETFCAP
      - FSETID
    tmpfs:
      - /tmp
    volumes:
      - ./data/backend/test_case:/test_case:ro
      - ./data/judge_server/log:/log
      - ./data/judge_server/run:/judger
    environment:
      - SERVICE_URL=http://judge-server:8080
      - BACKEND_URL=http://oj-backend:8000/api/judge_server_heartbeat/
      - TOKEN=CHANGE_THIS
      # - judger_debug=1
  
  oj-backend:
    image: registry.cn-hangzhou.aliyuncs.com/onlinejudge/oj_backend
    container_name: oj-backend
    restart: always
    depends_on:
      - oj-redis
      - oj-postgres
      - judge-server
    volumes:
      - ./data/backend:/data
    environment:
      - POSTGRES_DB=onlinejudge
      - POSTGRES_USER=onlinejudge
      - POSTGRES_PASSWORD=onlinejudge
      - JUDGE_SERVER_TOKEN=CHANGE_THIS
      # - FORCE_HTTPS=1
      # - STATIC_CDN_HOST=cdn.oj.com
    ports:
      - "0.0.0.0:80:8000"
      - "0.0.0.0:443:1443"
```

可以看到背後分成 4 個 services：Redis、Postgres、judge-server 跟 oj-backend。

不過我當時的需求還有一個，那就是要支援 JavaScript。為了達成這個目標，只有部署是不夠的，還要來研究一下它到底是怎麼跑的。

## 進一步研究 QDUOJ

首先我們來看一下這個系統的架構，在 GitHub 的文件上有寫底下一共分成幾個模組：

1. Backend(Django): https://github.com/QingdaoU/OnlineJudge
2. Frontend(Vue): https://github.com/QingdaoU/OnlineJudgeFE
3. Judger Sandbox(Seccomp): https://github.com/QingdaoU/Judger
4. JudgeServer(A wrapper for Judger): https://github.com/QingdaoU/JudgeServer

而我們最關心的問題（如何新增語言），已經有人在 Issue 裡問過了：[How to add more language support, such as Ruby](https://github.com/QingdaoU/OnlineJudge/issues/149)

裡面提到只要修改這個檔案即可：https://github.com/QingdaoU/OnlineJudge/blob/master/judge/languages.py

這檔案就是一些設定，而這邊你也可以大概猜出 Judge Server 會做什麼事情。在這裡，每個語言的設定都會有 compile_command 跟 command，前者是來拿編譯的指令，後者是拿來跑程式的指令。由於這個 OJ 的輸出入都是透過 stdin/stdout，所以當你想要新增一種新的程式語言的時候，只要跟系統說該怎麼去執行就好。

相反地，有些 OJ 是採用 function 的方式來填空，例如說開頭提到的 leetcode，這時候若是要新增一個語言就會比較麻煩一些，因為你要額外再提供 function 的模板。

照理來說我們只要再如法泡製，加上這樣的設定就行了：

``` python
js_lang_config = {
   "run": {
       "exe_name": "solution.js",
       "command": "/usr/bin/nodejs {exe_path}",
       "seccomp_rule": "general",
   }
}
```

但若是這樣去跑，會發現有問題，搜了一下發現已經有人反映過：[problem with addding js to language configs](https://github.com/QingdaoU/JudgeServer/issues/16)，解法是把 seccomp_rule 設成 None。

什麼是 seccomp 呢？這就跟 OJ 的原理有關了！大家可以先仔細想想 OJ 中最重要的一個問題：

> 要如何安全地執行使用者提交的程式碼？

若是不知道這問題是在問什麼，可以想像以下情形：

1. 有人寫了一行重開機的程式碼怎麼辦？
2. 有人寫了一個無窮迴圈怎麼辦？
3. 有人寫了一個會把主機帳號密碼傳送到外部的程式怎麼辦？

由此可以看出，執行程式碼可沒有那麼簡單，而這塊也是 OJ 最核心的一部分。

QDUOJ 的 Judger 原始碼在這邊：https://github.com/QingdaoU/Judger/tree/newnew/src

是用 C 寫的，會 fork 一個新的 process，設定一些規則之後用 [execve](https://github.com/QingdaoU/Judger/blob/newnew/src/child.c#L163) 來執行指令。在[程式碼裡面](https://github.com/QingdaoU/Judger/blob/b6414e7a6715eb013b1ffeb7cfb04626a3ff5b4e/src/rules/general.c)也可以看出是使用 [seccomp](https://blog.betamao.me/2019/01/23/Linux%E6%B2%99%E7%AE%B1%E4%B9%8Bseccomp/) 這個東西來防止我們上面所提到的內容。

總之呢，QDUOJ 分層做得很不錯，執行流程大概是這樣的：

1. 進入 Vue 做的前端頁面
2. 送出程式碼，call 後端 API（Python）
3. 後端 API 再呼叫 Judge Server API（Go）
4. Judge Server API 呼叫 Judger 執行指令（C，execve + seccomp 執行）

所以每一個專案負責自己的事項，各司其職。

再講回來前面提到要加上 JavaScript 這一塊，儘管把 seccomp_rule 設成 None 以後，執行 JavaScript 依然會出現錯誤。我研究了一兩天，發現問題是出在題目的記憶體限制太小，我猜測是 Node.js 要執行時本來就會吃比較多記憶體，只要把記憶體改大（例如說 1024MB）就搞定了。

不過還沒結束，還有最後一個問題，那就是 ubuntu 16.04 上的 Node.js 版本滿舊的，要換成新的才能使用 ES6 那些語法，解法是去改 JudgeServer 的 [Dockerfile](https://github.com/Lidemy/JudgeServer/commit/9a98532f0f3504da20d13bd0aec4f4279a2a1fd2)，新增一個安裝 Node.js 新版的指令就好。

都改完以後，就可以來部署自己的版本了！只要先把 docker image build 好，然後更改我們最前面操作的 docker-compose 檔案就可以了。

雖然說上面講的雲淡風輕，但那時候我在找 Node.js 到底為什麼會一直 Runtime error 的時候找到快崩潰，因為錯誤訊息滿不明確的，我一直以為是指令有錯，是後來我才靈機一動想說：「咦，該不會是其他問題吧」，才發現是記憶體問題。

總而言之呢，如果你沒有想要改東西，只是單純想要部署的話，在這邊誠心推薦 QDUOJ，部署真的簡單方便，介面也好看。

## 自己寫一個 OJ

以前我也曾經嘗試過寫一個 OJ，寫是寫出來了，但是是非常陽春的版本：https://lidemy-oj.netlify.com/problems

![](https://static.coderbridge.com/img/aszx87410/016853899af54a40b11801d3e1d5f8d7.png)

那時候還沒想到用 linux 上的指令來跑，而是因為恰巧發現有 [VM2](https://github.com/patriksimek/vm2) 這個 library，覺得派得上用場，才有了寫這個簡易 OJ 的念頭。

這個簡單的 OJ 只支援 JavaScript，而且是走 leetcode 那種寫 function 的方式而不是標準輸出入，花了一點時間就把 Judger 的雛形寫了出來：

``` js
const {VM} = require('vm2');
const lodash = require('lodash')

const RESULT_CODE = {
  AC: 'AC',
  WA: 'WA',
  CE: 'CE',
  RE: 'RE',
  TLE: 'TLE'
}

class Judge {
  constructor(schema, functionCode, timeout = 3000) {
    this.schema = schema
    this.functionCode = functionCode
    this.vm = new VM({
        timeout,
        sandbox: {
          __equal: lodash.isEqual
        }
    });
  }

  t(any) {
    return JSON.stringify(any)
  }

  addWrapper(schema, code, testCase) {
    return `
      ${code}
      (() => __equal(${schema.funcName}.apply(null, ${this.t(testCase.input)}), ${this.t(testCase.output)}))()
    `
  }

  runTest(testCase) {
    try {
      this.vm.run(this.functionCode)
    } catch(e) {
      return RESULT_CODE.RE
    }

    const wrapperedCode = this.addWrapper(this.schema, this.functionCode, testCase)
    try {
      return this.vm.run(wrapperedCode) ? RESULT_CODE.AC: RESULT_CODE.WA
    } catch(e) {
      return e.message === 'Script execution timed out.' ? RESULT_CODE.TLE : RESULT_CODE.WA
      console.log('err', e)
    }
  }

  run() {
    const testCases = this.schema.testCases
    const testResult = testCases.map(testCase => this.runTest(testCase))
    const correctCount = testResult.reduce((sum, res) => sum + (res === 'AC'), 0)
    return {
      score: Math.ceil(correctCount * ( 100 / testResult.length )),
      result: testResult
    }
  }
}

const test1 = {
  input: [1, 2],
  output: 3
}

const test2 = {
  input: [2, 4],
  output: 6
}

const problemSchema = {
  funcName: 'add',
  testCases: [test1, test2]
}

const input = `function add(a, b){
    return 3
  }`

const judge = new Judge(problemSchema, input)
const result = judge.run()
console.log(result)
```

重點程式碼是 `addWrapper` 跟 `runTest`，在 `addWrapper` 裡面去執行傳進來的 function code，然後把結果跟 output 做比對，就會回傳 true 或是 false，代表匹配成功或者是失敗，就可以知道答案是不是對的。

然後 problemSchema 是題目的格式，要有一個 funcName 跟 testCases，每一個測資底下都有 input 與 output。藉由以上程式碼，就可以實作出一個 JS function-base 的超簡易 Judger。

不過這個 Judger 缺點很多，而且跟上面提到的執行指令方式根本沒得比。

我後來在研究資料的時候找到一些不錯的開源解法，以後有人想要自己寫的話可以參考考。

第一個是 IOI 開源出來的 sandbox：[isolate](https://github.com/ioi/isolate)，可以安全地執行指令。

第二個更神奇，直接給你 Judge 的 API，而且是免費的：[Judge0 API](https://github.com/judge0/api)。只要按照他的格式把輸入傳進去，就會跟你說判題結果，所以連 Judge Server 都可以不用自己做。

## 總結

之前想要來架個 OJ，所以找了滿多資料，而碰到最大的問題是：「我想要一個支援 JavaScript 的 OJ」，因為滿多都不支援的。後來無奈之下只好自己寫了一個，就是上面提到的用 JS 寫出來的小玩具。雖然說還堪用，但其實許多功能都不完整，就真的只支援最簡單的答題而已。

一直到今年一月，想要來弄個真正的 OJ，原本也一度考慮要不要自己寫，後來想說太麻煩了，不如找現成的來改，把 JS 的支援加上去。雖然一樣有碰到一些問題，但很幸運地最後還是成功了。

最後的成果在這邊：https://oj.lidemy.com/

這個 OJ 是為了搭配我最新出的免費線上課程：[[ALG101] 先別急著寫 leetcode](https://lidemy.com/p/alg101-leetcode)，是一堂給初學者的課，希望能藉由一系列簡單的題目把基礎打好，培養程式思維能力，有興趣的朋友們可以來看看。
