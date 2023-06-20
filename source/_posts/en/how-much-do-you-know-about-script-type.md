---
title: How much do you know about script type?
date: 2022-04-24 10:20:16
tags: [Security]
categories: [Security]
translator: huli
photos: /img/how-much-do-you-know-about-script-type/cover-en.png
---

<img src="/img/how-much-do-you-know-about-script-type/cover-en.png" style="display:none">

A while ago, I happened to play a lot of topics related to content type, so I decided to wrote an article about it.

<!-- more -->

As usual, it’s not interesting to talk about the answer directly, so let’s start with three questions:

### Question one

In the code below, what is the content type for `a.js` to successfully load the code? (Assume MIME type sniffing is off)

For example, `text/javascript` is one answer, what else?

``` html
<script src="https://example.com/a.js">
```

### Question two

What values ​​can be filled in the "???"? For example, `text/javascriptis` and `module` are both correct answer, what else?

``` html
<script type="???">
</script>
```

### Question three

Now that you have a web page. In order to let browser run script after loaded, what should be the content type in the response?

For example, `text/html` and `text/xml` are both correct, what else?

***  

Let's take a look at the answer below.

## Question 1: Acceptable content type for <script&gt;

I start thinking about this question because of an XSS challenge made by [@ankursundara](https://twitter.com/ankursundara/status/1460810934713081862) last year: https://twitter.com/ankursundara/status/1460810934713081862

Part of the code is as follows:

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

Simply put, you can upload any file, but if the file's MIME type has `script`, it will be `application/octet-stream`.

`X-Content-Type-Optionsit` is set to `nosniff`, so we can't abuse MIME type sniffing.

The goal is to successfully execute XSS.

It is not difficult to see from the above code that an HTML file can be uploaded, but because of `script-src 'self'` CSP, even if HTML can be uploaded, inline script cannot be used.

We can only import script this way: `<script src="/uploads/xxx">`.

But, if the content type of `/uploads/xxx` is `application/octet-stream`, Chrome will throw following error:

> Refused to execute script from 'https://uploader.c.hc.lc/uploads/xxx' because its MIME type ('application/octet-stream') is not executable, and strict MIME type checking is enabled.

So the goal of this question is very clear, to find a MIME type that does not contain `script` but can be successfully loaded by the browser.

After seeing this challenge, my first idea is to check the source code of Chromium, it's easier to find the related part by googling the error message:`"strict MIME type checking is enabled" site:https://chromium.googlesource.com/`

We can find this related file through the search results: https://chromium.googlesource.com/chromium/blink/+/refs/heads/main/Source/core/dom/ScriptLoader.cpp

This file is very old and deprecated, but at least we know it's part of blink, so we can find a similiar file in the latest codebase, what I found is: [third_party/blink/renderer/core/script/script_loader.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc)

You can find this function: `IsValidClassicScriptTypeAndLanguage` 

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

Then, we can search this keyword:`IsSupportedJavaScriptMIMEType` and find this file: [third_party/blink/common/mime_util/mime_util.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/common/mime_util/mime_util.cc)

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

You can also see the URL of the spec from the comments. The list given is the same, and this list is basically the answer to the first question. The above MIME types can be loaded as script.

But we can find one thing, that is, every MIME type contains `script`.

At that time, I got stuck at this point. Later, the author released a hint: `Origin Trials`. Follow the hint I found a feature called [Web Bundles](https://web.dev/web-bundles/). This is the answer to the XSS challenge.

What is Web Bundles?

To put it simply, Web Bundles is a feature that you can package a bunch of data (HTML, CSS, JS...) together into a .wbn file. The above article mentions an example that your friend wants to share with a web game with you, but he can't do it because there is no internet connection.

But through the Web Bundles, he can package the web game into a .wbn file and send it to you. After you receive it via bluetooth or airdrop, you can just open it in the browser, just like an app.

In addition to loading the entire app, you can also load specific resources from the Web Bundle. You can find the detail here:[Explainer: Subresource loading with Web Bundles](https://github.com/WICG/webpackage/blob/main/explainers/subresource-loading.md).

Here is the example from the article:

``` html
<script type="webbundle">
{
   "source": "https://example.com/dir/subresources.wbn",
   "resources": ["https://example.com/dir/a.js", "https://example.com/dir/b.js", "https://example.com/dir/c.png"]
}
</script>
```

When you load `https://example.com/dir/a.js` , the browser will first go to subresources.wbn to find this resource, instead of reaching to the server to download it directly.

So, for the XSS challenge I mentioned in the beginning, the answer is to bundle the JavaScript into a web bundle file, and then load it. It's MIME type is `application/webbundle`, so it's allow.

After web bundle is loaded, we can load script from it.

But why didn't we see this feature when we looked at the Chromium code?

This is because we are too focus on MIME type, so we only look at`IsValidClassicScriptTypeAndLanguage`, but we should see another function who call it: [GetScriptTypeAtPrepare](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc)：

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

Calling `IsValidClassicScriptTypeAndLanguage` is just the first step, there are other `type` as well, and it's the answer to question two.

## Question 2: Acceptable types of <script&gt;

Like previous question, it's also about a CTF challenge. There is a challenge called YACA in PlaidCTF 2022, here is the offical writeup: https://github.com/zwade/yaca/tree/master/solution

We know from the code I just posted that  the answer to this question is the answer to the first question (that pile of MIME types) plus the following four types:

1. module
2. importmap
3. speculationrules
4. webbundle

We already know `module` and `webbundle`, so let's take a look at importmap and specificationrules.

The specification of import map is here: https://github.com/WICG/import-maps

What is the problem import map wants to solve?

Although the browser already supports module and import, you still can't do this on the browser:

``` js
import moment from "moment";
import { partition } from "lodash";
```

You can only write like this:

``` js
import moment from "/node_modules/moment/src/moment.js";
import { partition } from "/node_modules/lodash-es/lodash.js";
```

import map want to solve this problem by introducing a mapping table:

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

The challenge we mentioned can be solve by changing the file like this:

``` html

 <script type="importmap">
{
  "imports": {
     "/js/ast-to-js.mjs": "/js/eval-code.mjs"
  }
}
</script>
```

Let's take a look at speculationrules, here is the spec: https://github.com/WICG/nav-speculation

This feature is mainly to solve some problems caused by pre-rendering, I haven't delved into it. It works like this:

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

It uses a JSON file for the pre-render rule, quite different from `<link rel="prerender">`.

## Question 3: content type

It's from a challenge called [PlanetSheet](https://ctf.zeyu2001.com/2022/securinets-ctf-quals-2022/planetsheet) in Securinets CTF Quals 2022. When the content type is `text/xsl` , we can run script via `<x:script>`.

This classic research is mentioned in each writeup: [Content-Type Research
](https://github.com/BlackFan/content-type-research/blob/master/XSS.md), you can find the detail in it.

The following five content types can execute XSS in all browsers:

1. text/html	
2. application/xhtml+xml	
3. application/xml	
4. text/xml	
5. image/svg+xml

I was curious about this behavior, so I checked the source code of Chromium a bit, and found other two content types that are always put together with the others:

1. application/rss+xml
2. application/atom+xml

Code: [xsl_style_sheet_resource.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/loader/resource/xsl_style_sheet_resource.cc#45)

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

However, these two will not be loaded as XML, so I searched and found this bug: [Issue 104358: Consider allowing more types to parse as XML](https://bugs.chromium.org/p/chromium/issues/detail?id=104358), which mentioned a [commit](https://chromium.googlesource.com/chromium/src/+/b4599a15c90a853930187cc751c951beb819c02d%5E%21/#F0) in 2009:

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

Because the RSS feed may contain third-party cotnent, it's vulnerable to XSS if it is rendered as XML, so these two are forcibly turned off.

By the way, there is a awesome tool for searching source code: https://sourcegraph.com/search

