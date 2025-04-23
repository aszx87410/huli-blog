---
title: Everyone Needs an HTTP Proxy for Debugging
date: 2025-04-23 11:50:00
catalog: true
tags: [Web]
categories: [Web]
photos: /img/everyone-need-a-http-proxy-to-debug/cover.png
---

As a front-end engineer who deals with web pages every day, it is quite reasonable to be familiar with the use of DevTools. Whenever there is an issue with an API, I just press the shortcut to open DevTools, switch to the Network tab, find the red line, right-click to copy it as cURL, and paste it into the group chat for the backend team to troubleshoot.

But I wonder if anyone has encountered situations where DevTools are not sufficient. What should we do then?

<!-- more -->

## Are DevTools Really Insufficient? Is It Just That You Don't Know How to Use Them?

Let me share a few cases I have encountered. If DevTools can solve the problem, that would be the most convenient, but sometimes I can't resolve it (it might also be that I just don't know how to use it). Additionally, the DevTools mentioned below refer specifically to Chrome DevTools; perhaps other browsers do not have these issues.

### Unable to See Request Details Before Redirection

Many websites that implement OAuth-related services will redirect to a redirect URL after logging in, carrying a code. At this point, some websites will use the code to exchange for an access_token, and then redirect to the next page with the access_token. If there is an issue with the code exchanging for the access_token, how do we debug it?

Chrome DevTools, when redirecting to another page, will by default clear the console and network data. There is an option called "Preserve log," and checking it seems to solve the problem, but it actually does not.

You can randomly find a webpage, open DevTools, check the "Preserve log" option, and then execute the following code:

``` js
fetch('https://httpbin.org/user-agent')
    .then(() => window.location = 'https://example.com')
```

After the redirection is complete, although you can see this request in the Network tab, clicking on it will only show "Failed to load response data":

![Unable to See Request](/img/everyone-need-a-http-proxy-to-debug/p1.png)

This issue has been reported since 2012, and after waiting for over a decade, it was mentioned at the end of 2023 that this would be on the roadmap for 2024, but there has been no movement so far: [DevTools: XHR (and other resources) content not available after navigation.](https://issues.chromium.org/issues/40254754).

In summary, in this scenario, not being able to see the response makes debugging nearly impossible, which is very inconvenient.

### Unable to Find the Cause of WebSocket Connection Handshake Failure

Although we usually only need one line of code to establish a connection when using WebSocket, it actually involves two steps behind the scenes.

The first step sends an HTTP Upgrade request, and only after that does it switch to the WebSocket connection. While the first step usually succeeds in most cases, what happens if it fails?

We can ask AI to write a very simple demo:

```
write a nodejs websocket server with nginx in front
when url contains ?debug, nginx should return 500 error

after websocker connected, server should a a hello message to client

use docker compose to run it
```

After the AI generates it, run it with Docker, and similarly open a webpage to establish a connection. You will find that for the connection request with debug information, you only know it failed, but have no idea why:

![Unable to Find the Cause](/img/everyone-need-a-http-proxy-to-debug/p2.png)

This error message is even similar to connecting to a random closed port, leaving you completely clueless as to why it failed, making it difficult to communicate the issue to the backend.

These are two examples that I remember, but in actual development, there are likely many more. Basically, problems that cannot be resolved by just relying on DevTools to view the Network tab are either invisible or the displayed information is incorrect.

## Simple and Easy-to-Use HTTP Proxy

Since we cannot rely on DevTools, we have to depend on lower-level tools, such as an HTTP Proxy! Some tools will set up a proxy on your local machine, allowing all traffic to pass through it, so you can see all requests without being limited by DevTools.

Moreover, another benefit is that you have a place to cross-reference. If the proxy shows something different from what DevTools displays, it is possible that there is an issue with what DevTools is showing.

Therefore, I sincerely recommend everyone to find an HTTP Proxy to use. The three that I have personally used are:

1. [Charles](https://www.charlesproxy.com/)
2. [Burp Suite](https://portswigger.net/burp/communitydownload)
3. [mitmproxy](https://mitmproxy.org/)

When I first got into proxies, I used Charles, but after getting into cybersecurity, I switched to the second one, Burp Suite. It's actually a tool that can be used for various security-related tests, but I think it's perfectly fine to just use it as a proxy; it's very convenient.

The third one, mitmproxy, is open-source and free, and it's quite well-known. I occasionally use it, but in a different way, which I'll discuss later.

### Using Burp Suite as a Proxy App

First, download the free community version from the official website: https://portswigger.net/burp/communitydownload

After opening it, click Next and then Start Burp, and you'll see the main screen. You'll notice it has many features, but for now, let's switch to the "Proxy" tab and then to the "HTTP history" page:

![Burp Screen](/img/everyone-need-a-http-proxy-to-debug/p3.png)

Then click on the very noticeable orange "Open Browser" button, which will open its built-in Chrome browser. You can use this browser to visit any webpage, for example, example.com.

Next, switch back to the tool, and you'll find that the HTTP history records all the raw content of requests and responses:

![Request Records](/img/everyone-need-a-http-proxy-to-debug/p4.png)

In this way, the redirection cases and WebSocket handshake failures mentioned earlier can be seen here with the original request content, making errors clear at a glance:

![Raw Content](/img/everyone-need-a-http-proxy-to-debug/p5.png)

If in the future you encounter some requests that you can't see, it means they have been filtered out by the default filter. Click on Filter settings, select show all, and then apply, and you should be able to see them.

(If you encounter issues with insecure connections, you need to install the certificate first. Please refer to: [Installing Burp's CA certificate](https://portswigger.net/burp/documentation/desktop/external-browser-config/certificate))

That's a basic introduction to using Burp Suite as an HTTP Proxy. If you don't want to use the Chrome it provides, you can also set up your computer or browser's proxy; it defaults to port 8080.

For example, I install another Chrome Canary on my Mac specifically for debugging. You can use this command to open it and set the proxy location:

```bash
open -a "Google Chrome Canary" --args --proxy-server="http://localhost:8080"
```

This way, you can debug using your familiar browser.

By the way, Burp Suite has many other features, such as replaying requests or brute-forcing, but I think it's already very helpful for general engineers to use it as a proxy. 

### Using mitmproxy with Scripts to Dynamically Change Content

I won't go into detail about the installation process for mitmproxy; you can refer to the [official documentation](https://docs.mitmproxy.org/stable/overview-getting-started/) or collaborate with AI to install it yourself. After installation, remember to visit `http://mitm.it` to download and install the certificate so that you can intercept HTTPS traffic.

Once everything is installed, running `mitmproxy` will start the proxy, and you'll see a CLI interface.

Since Burp Suite is already very useful, when would you use mitmproxy? It has a handy feature that allows you to customize the behavior of the proxy through simple Python scripts, which is very convenient.

For example, suppose for some reason the testing environment cannot fully simulate the production environment, but you cannot directly deploy the code to the production environment for testing. In this case, you can use the proxy to dynamically replace the production response and simulate some behaviors locally.

Although Chrome also has the [override response](https://developer.chrome.com/docs/devtools/override) feature, it has more limitations, such as fixed content, etc. Using a proxy with scripts is definitely a more flexible and higher freedom choice.

Below is a simple mitm script aimed at replacing the script.js of my blog with the local version:

```python
from mitmproxy import http
import requests

URL_MAPPINGS = {
    "https://blog.huli.tw/js/script.js": "http://localhost:5555/script.js",
}

def request(flow: http.HTTPFlow) -> None:
    for url in URL_MAPPINGS:
        if flow.request.pretty_url.startswith(url):
            replacement_url = URL_MAPPINGS[url]

            replacement_response = requests.get(replacement_url)

            flow.response = http.Response.make(
                200,
                replacement_response.content, 
                {"Content-Type": "application/javascript"} 
            )
            return
```

You can run it with this command:

```bash
mitmproxy -s proxy.py
```

Next, use the command mentioned earlier to open a browser configured with a proxy:

```bash
open -a "Google Chrome Canary" --args --proxy-server="http://localhost:8080"
```

Then visit `https://blog.huli.tw` in the browser, and you will see that the content of the script has been replaced.

## Conclusion

These are some proxies and usage methods that I commonly use.

Relying too much on the browser is not a good thing; if the browser does not display anything, you won't know what to do. However, as front-end engineers on the front line, there are definitely ways to obtain the entire request and response to clarify the issue further. In the future, if you encounter problems where requests are not visible in the browser, you can try using a proxy to capture the complete request and response.

In addition to web pages on the computer, you can also use it on mobile. You can set up a proxy on Android to connect to the same Wi-Fi as the computer, and then install the certificate on the phone to intercept the mobile traffic.

Finally, here's a little tip: when executing commands in the Mac CLI, adding `https_proxy=http://localhost:8080` will configure the proxy, such as `https_proxy=http://localhost:8080 cursor .`, which will redirect all traffic from the Cursor IDE to the proxy.
