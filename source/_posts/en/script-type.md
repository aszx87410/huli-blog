---
title: What do you know about script type?
date: 2022-04-24 10:20:16
tags: [Security]
categories: [Security]
---

<img src="/img/script-type/cover.png" style="display:none">

Recently, I encountered many problems related to content type, so I decided to write an article to record them.

<!-- more -->

As usual, it's not interesting to directly give the answers. Let's start with three questions:

### Question 1

In the following code, what should be the content type of `a.js` to successfully load the code? (Assuming MIME type sniffing is turned off)

For example, `text/javascript` is one answer. Are there any other answers?

``` html
<script src="https://example.com/a.js">
```

### Question 2

What values can be filled in "???" below? For example, `text/javascript` is one answer, and `module` is also an answer.

``` html
<script type="???">
</script>
```

### Question 3

Now you have a webpage `/test`. What content-type should be set in the response so that the browser can execute the JS code after loading?

For example, `text/html` is one answer, and `text/xml` is also an answer.

***  

Now let's take a look at the answers.

## Question 1: Content types that <script&gt; can accept

The idea for this question and answer comes from a XSS challenge posted by [@ankursundara](https://twitter.com/ankursundara/status/1460810934713081862) at the end of last year: https://twitter.com/ankursundara/status/1460810934713081862

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

Simply put, you can upload any file, but if the file's MIME type contains `script`, it will become `application/octet-stream`.

And `X-Content-Type-Options` is set to `nosniff`, so whatever MIME type is set is what it is.

The goal is to successfully execute XSS.

From the above code, it is not difficult to see that you can upload an HTML file, but because CSP has `script-src 'self'`, even if you can upload HTML, you cannot use inline script, and can only use `<script src="/uploads/xxx">` to introduce it.

And if the content type of `/uploads/xxx` is `application/octet-stream`, Chrome will directly display an error message:

> Refused to execute script from 'https://uploader.c.hc.lc/uploads/xxx' because its MIME type ('application/octet-stream') is not executable, and strict MIME type checking is enabled.

So the goal of this question is clear: to find a MIME type that does not contain script but can still be successfully loaded by the browser.

After seeing this question, I first went to look at the Chromium source code. Using Google search with the error message just now will make it easier to find: `"strict MIME type checking is enabled" site:https://chromium.googlesource.com/`

Through the search results, we can directly locate this file: https://chromium.googlesource.com/chromium/blink/+/refs/heads/main/Source/core/dom/ScriptLoader.cpp

However, this file is already very old, but at least we know that it is part of blink, so we can go to [blink](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink) in Chromium to find similar files, and we can find [third_party/blink/renderer/core/script/script_loader.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc).

After comparing the old and new versions, we can find the `IsValidClassicScriptTypeAndLanguage` function:

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

Then, using `IsSupportedJavaScriptMIMEType` to search, we can find the supported MIME types in [third_party/blink/common/mime_util/mime_util.cc](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/common/mime_util/mime_util.cc):

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

From the comments, we can see the location of the spec, and the list provided is the same as the answer to the first question. All these MIME types can be loaded as scripts.

However, we can notice that each MIME type contains a script.

At this point, I got stuck, but the author released a hint called `Origin trials`, which led to a feature under experimentation called [Web Bundles](https://web.dev/web-bundles/), which is the answer to this question.

What is a Web Bundle?

Simply put, a Web Bundle is a package that bundles a bunch of data (HTML, CSS, JS...) into a .wbn file. The article mentioned an example: if your friend wants to share a standalone web game with you in an offline environment, it is generally impossible (without considering setting up a server on your own computer).

But with Web Bundles, it can package the game into a .wbn file and send it to you. When you receive it, you can simply throw it into the browser and open it, just like an app.

In addition to loading the entire app, specific resources can also be loaded from the Web Bundle. Here is a complete introduction: [Explainer: Subresource loading with Web Bundles](https://github.com/WICG/webpackage/blob/main/explainers/subresource-loading.md). The example looks like this:

``` html
<script type="webbundle">
{
   "source": "https://example.com/dir/subresources.wbn",
   "resources": ["https://example.com/dir/a.js", "https://example.com/dir/b.js", "https://example.com/dir/c.png"]
}
</script>
```

In this way, when you load `https://example.com/dir/a.js` in a web page, the browser will first look for this resource in subresources.wbn instead of downloading it directly from the server.

So the answer to the XSS challenge mentioned earlier is to package the JS you want to load into a web bundle. Its MIME type is `application/webbundle`, so it will not be blocked.

Then, load it as shown above, and the MIME type of the JS file loaded from the web bundle will be correct, so it can be executed successfully.

However, why didn't we see this feature when we were looking at the Chromium code earlier?

This is because we were too focused on the MIME type, so we only looked at `IsValidClassicScriptTypeAndLanguage`, but we should actually look at [GetScriptTypeAtPrepare](https://chromium.googlesource.com/chromium/src.git/+/refs/tags/103.0.5012.1/third_party/blink/renderer/core/script/script_loader.cc) that calls it:

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

We can see that calling `IsValidClassicScriptTypeAndLanguage` is only the first step, and there are other steps later, where other types can be passed in, which happens to be the answer to the second question.

## Question 2: Types that <script&gt; can accept

I thought about this question because there is a question called YACA in PlaidCTF 2022, which is testing this point. The official answer is here: https://github.com/zwade/yaca/tree/master/solution

When I was doing this question, I completely forgot that I had done the Web Bundle question before, so I didn't look in that direction. But anyway, from the code posted earlier, we can see that the answer to this question is the answer to the first question (those MIME types) plus the following four types:

1. module
2. importmap
3. speculationrules
4. webbundle

Module is nothing special, as mentioned earlier with webbundle. Let's take a look at importmap and speculationrules.

The import map specification is here: https://github.com/WICG/import-maps

Simply put, the problem that import map wants to solve is that although browsers already support module and import, you still can't do this in the browser:

``` js
import moment from "moment";
import { partition } from "lodash";
```

You can only write a path like this:

``` js
import moment from "/node_modules/moment/src/moment.js";
import { partition } from "/node_modules/lodash-es/lodash.js";
```

The solution of import map is to introduce a mapping table, so you can only use names to import:

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

The topic mentioned at the beginning is to use this point to replace the loaded files with a mapping table, like this:

``` html

 <script type="importmap">
{
  "imports": {
     "/js/ast-to-js.mjs": "/js/eval-code.mjs"
  }
}
</script>
```

Next, let's take a look at speculationrules, the specification is here: https://github.com/WICG/nav-speculation

This feature is mainly designed to solve some problems caused by pre-rendering. I haven't studied it in depth yet, but it looks like this:

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

It uses JSON to specify the pre-rendering rules, which is quite different from the previous way of using `<link rel="prerender">`.



## Question 3

The inspiration also comes from CTF, Securinets CTF Quals 2022's [PlanetSheet](https://ctf.zeyu2001.com/2022/securinets-ctf-quals-2022/planetsheet). When the content type is `text/xsl`, you can use `<x:script>` to execute XSS.

This classic research is mentioned in every write-up: [Content-Type Research](https://github.com/BlackFan/content-type-research/blob/master/XSS.md). You can click in to see the details. The following five content types can execute XSS in all browsers:

1. text/html
2. application/xhtml+xml
3. application/xml
4. text/xml
5. image/svg+xml

I was curious and looked up Chromium's code and found that there are two other content types that are always grouped with the others:

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

However, these two are not loaded as XML, so I looked it up and found this bug: [Issue 104358: Consider allowing more types to parse as XML](https://bugs.chromium.org/p/chromium/issues/detail?id=104358), which mentions this commit added in 2009: [commit](https://chromium.googlesource.com/chromium/src/+/b4599a15c90a853930187cc751c951beb819c02d%5E%21/#F0), which added the following code:

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

Because RSS feeds may contain third-party content, if they are rendered directly as XML, there is a risk of XSS, so these two are forcibly turned off.

Finally, note a tool that can help search for source code, which is super useful: https://sourcegraph.com/search
