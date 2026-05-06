---
layout: note
title: "Chrome VPN洩漏IP"
date: 2025-09-12 07:20:04
---
話說在看 YouTube 的時候，時常看到 VPN 的廣告（雖然現在很多都變 eSIM 了…），標榜的功能之一就是能隱藏自己的身份，保護隱私。

開了 VPN，本質上就是讓自己的流量透過 VPN server 再出去，所以對網站來講，只看得到封包是 VPN server 來的，拿到的 IP 也是 VPN server 的，就多少達成了所謂保護隱私的效果（還有一說是，你只是把隱私從暴露給網站，轉成暴露給了 VPN）。

也因為如此，有一類關於 VPN 的漏洞叫做：洩漏使用者 IP，意思就是利用某些漏洞，讓使用者雖然開著 VPN，但網站還是能知道使用者的真實 IP。

七月份的時候看了一篇 0x999 寫的《Leaking IPs in Brave Tor Window & Chrome VPNs + [Popunders](https://0x999.net/blog/leaking-ips-in-brave-tor-window-chrome-vpns-popunders-csp-bypass) + CSP Bypass》，紀錄了他發現的兩個這類型的漏洞，而且其實是 Chrome 的問題，回報了各家 VPN 廠商之後總賞金是 7000 美金。

先講一下，大家最常開的 VPN 可能是應用程式，但還有另一種是瀏覽器的擴充套件，如 Chrome extension，裝這個不裝 app 也可以有 VPN 的功能。各家 VPN 廠商的實作都大同小異，就只是使用 Chrome 提供出來的 API 而已（如 chrome.proxy），而 0x999 發現了兩個在 Chrome 上不會走 proxy 的功能，就繞過了幾乎所有 VPN 的防護。

第一個是 service worker 中的 backgroundFetch，第二個是 Web Authentication API 中去拿 /.well-known/webauthn 的時候，這兩個功能都可以指定一個 URL，但是發送請求時不會依照 chrome.proxy 的設定，因此伺服器就可以看到使用者的真實 IP。

不過大多數這類 VPN 的使用者應該都不太在意就是了，畢竟買來可能都只是想跨區追劇用的 😆
