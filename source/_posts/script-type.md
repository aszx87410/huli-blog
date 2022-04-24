---
title: <script> type 知多少？
date: 2022-04-24 10:20:16
tags: [Security]
categories: [Security]
---

<img src="/img/script-type/cover.png" style="display:none">

前陣子剛好玩到不少跟 content type 有關的題目，寫一篇來記錄一下。

老樣子，直接講答案不有趣，開頭先來三個問題：

### 問題一

請問底下的程式碼中，`a.js` 的 content type 要是什麼才會成功載入程式碼？（先假設 MIME type sniffing 是關閉的）

例如說 `text/javascript` 就是一個答案，還有嗎？

``` html
<script src="https://example.com/a.js">
```

### 問題二

請問底下的 "???" 中可以填入哪些值？例如說 `text/javascript` 就是一個答案，`module` 也是一個答案。

``` html
<script type="???">
</script>
```

### 問題三

現在你有個網頁 `/test`，請問 response 中的 content-type 如果設定成哪些，瀏覽器載入後就能夠執行 JS 程式碼？

例如說 `text/html` 就是一個，`text/xml` 也是一個。

***  

底下就讓我們來看一下答案。

## 問題一：<script&gt; 能接受的 content type

會開始思考這個問題以及答案，是來自於 [@ankursundara](https://twitter.com/ankursundara/status/1460810934713081862) 在去年年底出的一個 XSS 挑戰：https://twitter.com/ankursundara/status/1460810934713081862

部分程式碼如下：

``` py
@app.post('/upload')
def upload():
    try:
        file_storage = request.files['file']
        mimetype = file_storage.mimetype.lower() or 'application/octet-stream'
        if 'script' in mimetype:
            mimetype = 'application/octet-stream'
        content = file_storage.read().decode('latin1')
        # dont DOS please
        if len(content) < 1024*1024:
            data = {
                'mimetype': mimetype,
                'content': content
            }
            filename = token_hex(16)
            store.set(filename, json.dumps(data), ex=300)
            return redirect(f'/uploads/{filename}', code=302)
    except:
        pass
    return 'Invalid Upload', 400

@app.get('/uploads/<filename>')
def get_upload(filename):
    data = store.get(filename)
    if data:
        data = json.loads(data)
        return data['content'].encode('latin1'), 200, {'Content-Type': data['mimetype']}
    else:
        return "Not Found", 404

@app.after_request
def headers(response):
    response.headers["Content-Security-Policy"] = "script-src 'self'; object-src 'none';"
    response.headers["X-Content-Type-Options"] = 'nosniff'
    return response
```

簡單來說，你可以上傳任意檔案，但如果檔案的 MIME type 有 `script` 的話，就會變成 `application/octet-stream`。

然後 `X-Content-Type-Options` 有設置成 `nosniff`，所以 MIME type 設置什麼就是什麼了。

目標的話則是順利執行 XSS。

從上面的程式碼不難看出，可以上傳一個 HTML 檔案，但因為 CSP 有 `script-src 'self'` 的關係，因此就算能上傳 HTML，也不能用 inline script，只能用 `<script src="/uploads/xxx">` 這種方式引入。

而如果 `/uploads/xxx` 的 content type 是 `application/octet-stream` 的話，Chrome 會直接噴錯給你看：

> Refused to execute script from 'https://uploader.c.hc.lc/uploads/xxx' because its MIME type ('application/octet-stream') is not executable, and strict MIME type checking is enabled.

所以這題的目標很明確，要找到一個沒有包含 script 但是瀏覽器又可以成功載入的 MIME type。

看到這題以後，我先去找了 Chromium 的原始碼來看，可以用 Google search 的方式搭配剛剛的錯誤訊息會比較好找：`"strict MIME type checking is enabled" site:https://chromium.googlesource.com/`

透過搜尋結果，可以直接定位到這個檔案：https://chromium.googlesource.com/chromium/blink/+/refs/heads/main/Source/core/dom/ScriptLoader.cpp

不過這檔案已經很舊了，但至少我們知道它屬於 blink 的一部份，因此可以到 Chromium 的 [blink](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink) 裡面去找類似的檔案，可以找到 [third_party/blink/renderer/core/script/script_loader.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc)

把新舊稍微對照之後，可以找到 `IsValidClassicScriptTypeAndLanguage` 這個函式：

``` cpp
// <specdef href="https://html.spec.whatwg.org/C/#prepare-a-script">
bool IsValidClassicScriptTypeAndLanguage(
    const String& type,
    const String& language,
    ScriptLoader::LegacyTypeSupport support_legacy_types) {
  // FIXME: IsLegacySupportedJavaScriptLanguage() is not valid HTML5. It is used
  // here to maintain backwards compatibility with existing web tests. The
  // specific violations are:
  // - Allowing type=javascript. type= should only support MIME types, such as
  //   text/javascript.
  // - Allowing a different set of languages for language= and type=. language=
  //   supports Javascript 1.1 and 1.4-1.6, but type= does not.
  if (type.IsNull()) {
    // <spec step="8">the script element has no type attribute but it has a
    // language attribute and that attribute's value is the empty string,
    // or</spec>
    //
    // <spec step="8">the script element has neither a type attribute
    // nor a language attribute, then</spec>
    if (language.IsEmpty())
      return true;
    // <spec step="8">Otherwise, the element has a non-empty language attribute;
    // let the script block's type string for this script element be the
    // concatenation of the string "text/" followed by the value of the language
    // attribute.</spec>
    if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType("text/" + language))
      return true;
    // Not spec'ed.
    if (MIMETypeRegistry::IsLegacySupportedJavaScriptLanguage(language))
      return true;
  } else if (type.IsEmpty()) {
    // <spec step="8">the script element has a type attribute and its value is
    // the empty string, or</spec>
    return true;
  } else {
    // <spec step="8">Otherwise, if the script element has a type attribute, let
    // the script block's type string for this script element be the value of
    // that attribute with leading and trailing ASCII whitespace
    // stripped.</spec>
    if (MIMETypeRegistry::IsSupportedJavaScriptMIMEType(
            type.StripWhiteSpace())) {
      return true;
    }
    // Not spec'ed.
    if (support_legacy_types == ScriptLoader::kAllowLegacyTypeInTypeAttribute &&
        MIMETypeRegistry::IsLegacySupportedJavaScriptLanguage(type)) {
      return true;
    }
  }
  return false;
}
```

接著拿 `IsSupportedJavaScriptMIMEType` 再去搜尋一波，就可以找到 [third_party/blink/common/mime_util/mime_util.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/common/mime_util/mime_util.cc)，裡面就能看到支援的 MIME type：

``` js
//  Support every script type mentioned in the spec, as it notes that "User
//  agents must recognize all JavaScript MIME types." See
//  https://html.spec.whatwg.org/#javascript-mime-type.
const char* const kSupportedJavascriptTypes[] = {
    "application/ecmascript",
    "application/javascript",
    "application/x-ecmascript",
    "application/x-javascript",
    "text/ecmascript",
    "text/javascript",
    "text/javascript1.0",
    "text/javascript1.1",
    "text/javascript1.2",
    "text/javascript1.3",
    "text/javascript1.4",
    "text/javascript1.5",
    "text/jscript",
    "text/livescript",
    "text/x-ecmascript",
    "text/x-javascript",
};
```

從註解中也能看到 spec 的位置，給出的列表是一樣的，而這個列表基本上就是第一題的答案，上面這些 MIME type 都可以被載入為 script。

不過我們可以發現一件事情，那就是每一個 MIME type 都有包含 script。

當時做到這邊我就卡住了，後來作者有釋出提示，叫做 `Origin trials`，循線可以找到一個正在實驗中的功能叫做 [Web Bundles](https://web.dev/web-bundles/)，這個就是這題的解答。

什麼是 Web Bundles 呢？

簡單來說呢，Web Bundle 就是把一堆資料（HTML, CSS, JS...）打包在一起，變成一個 .wbn 的檔案，上面的文章有講到一個範例，例如說你朋友在沒有網路的環境下想分享一個單機版的網頁遊戲給你，一般來說是做不到的（先不考慮你在自己電腦上架個 server 之類的）。

但透過 Web Bundle，它可以把遊戲打包成一個 .wbn 檔再傳給你，你收到以後只要丟到瀏覽器裡面就可以打開了，就像一個 app 的那種感覺。

除了載入整個 app 以外，也可以從 Web Bundle 中載入特定資源，這邊有完整的介紹：[Explainer: Subresource loading with Web Bundles](https://github.com/WICG/webpackage/blob/main/explainers/subresource-loading.md)，範例長這樣：

``` html
<script type="webbundle">
{
   "source": "https://example.com/dir/subresources.wbn",
   "resources": ["https://example.com/dir/a.js", "https://example.com/dir/b.js", "https://example.com/dir/c.png"]
}
</script>
```

透過這樣的方式，當你在網頁中載入 `https://example.com/dir/a.js` 的時候，瀏覽器就會先去 subresources.wbn 當中尋找這個資源，而不是直接去 server 下載。

所以開頭提到的那題 XSS 挑戰，答案就是這個，你把想要載入的 JS 包到 web bundle 裡面去，它的 MIME type 是 `application/webbundle`，所以不會被擋下來。

接著像上面那樣載入，從 web bundle 裡面載入的 JS 檔案 MIME type 會是正確的，所以可以成功執行。

不過，為什麼我們剛剛在看 Chromium 程式碼的時候沒看到這個功能呢？

這是因為我們太執著在 MIME type 這件事情，所以只看 `IsValidClassicScriptTypeAndLanguage`，但其實要看的應該是呼叫它的 [GetScriptTypeAtPrepare](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc)：

``` C++
ScriptLoader::ScriptTypeAtPrepare ScriptLoader::GetScriptTypeAtPrepare(
    const String& type,
    const String& language,
    LegacyTypeSupport support_legacy_types) {
  if (IsValidClassicScriptTypeAndLanguage(type, language,
                                          support_legacy_types)) {
    // <spec step="8">... If the script block's type string is a JavaScript MIME
    // type essence match, the script's type is "classic". ...</spec>
    return ScriptTypeAtPrepare::kClassic;
  }
  if (EqualIgnoringASCIICase(type, script_type_names::kModule)) {
    // <spec step="8">... If the script block's type string is an ASCII
    // case-insensitive match for the string "module", the script's type is
    // "module". ...</spec>
    return ScriptTypeAtPrepare::kModule;
  }
  if (EqualIgnoringASCIICase(type, script_type_names::kImportmap)) {
    return ScriptTypeAtPrepare::kImportMap;
  }
  if (EqualIgnoringASCIICase(type, script_type_names::kSpeculationrules)) {
    return ScriptTypeAtPrepare::kSpeculationRules;
  }
  if (EqualIgnoringASCIICase(type, script_type_names::kWebbundle)) {
    return ScriptTypeAtPrepare::kWebBundle;
  }
  // <spec step="8">... If neither of the above conditions are true, then
  // return. No script is executed.</spec>
  return ScriptTypeAtPrepare::kInvalid;
}
```

可以看到呼叫 `IsValidClassicScriptTypeAndLanguage` 只是第一步，後面還有其他步驟，可以傳入其他 type，而這剛好就是問題二的解答。

## 問題二：<script&gt; 能接受的 type

會思考這題是因為 PlaidCTF 2022 裡面有一題 YACA，就是在考這個點，官方解答在這：https://github.com/zwade/yaca/tree/master/solution

在做這題的時候我完全忘記以前做過 Web Bundle 那題，所以沒有往這方向去找。但總之呢，從剛剛貼的程式碼可以看出這題的答案就是第一題的答案（那一堆 MIME type）加上底下四個 type：

1. module
2. importmap
3. speculationrules
4. webbundle

module 這個沒什麼好講的，webbundle 剛剛也提過了，底下我們來看看 importmap 跟 speculationrules 這兩個東西。

import map 的規格在這：https://github.com/WICG/import-maps

簡單來說呢，import map 想解決的問題很簡單，就是現在雖然瀏覽器已經支援 module 跟 import 了，但你還是沒辦法在瀏覽器上這樣做：

``` js
import moment from "moment";
import { partition } from "lodash";
```

你只能寫一個路徑之類的：

``` js
import moment from "/node_modules/moment/src/moment.js";
import { partition } from "/node_modules/lodash-es/lodash.js";
```

而 import map 的解法是引入一個對照表，就可以只用名稱來引入：

``` html
<script type="importmap">
{
  "imports": {
    "moment": "/node_modules/moment/src/moment.js",
    "lodash": "/node_modules/lodash-es/lodash.js"
  }
}
</script>
```

而開頭提到的題目就是利用這點，用對照表來替代載入的檔案，像這樣：

``` html

 <script type="importmap">
{
  "imports": {
     "/js/ast-to-js.mjs": "/js/eval-code.mjs"
  }
}
</script>
```

接著我們來看 speculationrules，規格在這：https://github.com/WICG/nav-speculation

這個功能主要是想解決 pre-rendering 所造成的一些問題，我還沒有深入研究，但用起來像是這樣：

``` html
<script type="speculationrules">
{
  "prerender": [
    {"source": "list",
     "urls": ["/page/2"],
     "score": 0.5},
    {"source": "document",
     "if_href_matches": ["https://*.wikipedia.org/**"],
     "if_not_selector_matches": [".restricted-section *"],
     "score": 0.1}
  ]
}
</script>
```

就是用 JSON 的方式來制定 pre-render 的規則，跟以前用 `<link rel="prerender">` 的方式滿不一樣的。



## 問題三：

靈感一樣來自於 CTF，Securinets CTF Quals 2022 的 [PlanetSheet](https://ctf.zeyu2001.com/2022/securinets-ctf-quals-2022/planetsheet)，當 content type 是 `text/xsl` 的時候，可以用 `<x:script>` 來執行 XSS。

每篇 writeup 中都有提到這個經典的研究：[Content-Type Research
](https://github.com/BlackFan/content-type-research/blob/master/XSS.md)，細節可以點進去看，底下這五個 content type 在所有瀏覽器下都可以執行 XSS：

1. text/html	
2. application/xhtml+xml	
3. application/xml	
4. text/xml	
5. image/svg+xml	

我好奇去找了一下 Chromium 的程式碼，發現還有另外兩個 content type 總是跟其他的被放在一起：

1. application/rss+xml
2. application/atom+xml

程式碼：[xsl_style_sheet_resource.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/loader/resource/xsl_style_sheet_resource.cc#45)

``` c++
static void ApplyXSLRequestProperties(FetchParameters& params) {
  params.SetRequestContext(mojom::blink::RequestContextType::XSLT);
  params.SetRequestDestination(network::mojom::RequestDestination::kXslt);
  // TODO(japhet): Accept: headers can be set manually on XHRs from script, in
  // the browser process, and... here. The browser process can't tell the
  // difference between an XSL stylesheet and a CSS stylesheet, so it assumes
  // stylesheets are all CSS unless they already have an Accept: header set.
  // Should we teach the browser process the difference?
  DEFINE_STATIC_LOCAL(const AtomicString, accept_xslt,
                      ("text/xml, application/xml, application/xhtml+xml, "
                       "text/xsl, application/rss+xml, application/atom+xml"));
  params.MutableResourceRequest().SetHTTPAccept(accept_xslt);
}
```

不過這兩個並不會被當做 XML 載入，於是我找了一下，找到這個 bug：[Issue 104358: Consider allowing more types to parse as XML](https://bugs.chromium.org/p/chromium/issues/detail?id=104358)，裡面提到了這個 2009 就新增的 [commit](https://chromium.googlesource.com/chromium/src/+/b4599a15c90a853930187cc751c951beb819c02d%5E%21/#F0)，新增了底下的程式碼：

``` c++
if (mime_type == "application/rss+xml" ||
    mime_type == "application/atom+xml") {
  // Sad face.  The server told us that they wanted us to treat the response
  // as RSS or Atom.  Unfortunately, we don't have a built-in feed previewer
  // like other browsers.  We can't just render the content as XML because
  // web sites let third parties inject arbitrary script into their RSS
  // feeds.  That leaves us with little choice but to practically ignore the
  // response.  In the future, when we have an RSS feed previewer, we can
  // remove this logic.
  mime_type.assign("text/plain");
  response_->response_head.mime_type.assign(mime_type);
}
```

因為 RSS feed 有可能會包含第三方的東西，如果直接當 XML 來 render 的話會用 XSS 的風險，所以這兩個就被強制關掉了。

最後筆記一下一個可以幫忙搜尋原始碼的工具，超好用：https://sourcegraph.com/search

