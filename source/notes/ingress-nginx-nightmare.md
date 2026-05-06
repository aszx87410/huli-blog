---
layout: note
title: "Ingress NGINX惡夢"
date: 2025-03-25 19:53:59
---
今天又一個嚴重的漏洞被公開了，名為 IngressNightmare，顧名思義，就是 [Ingress NGINX](https://www.wiz.io/blog/[ingress-nginx](https://kubernetes.io/blog/2025/03/24/ingress-nginx-cve-2025-1974/)-kubernetes-vulnerabilities) 的噩夢。

找到漏洞的是最近才剛被 Google 買下來的 Wiz，我看了看 writeup，大意就是在 Ingress NGINX 中有個 admission controllers，會接收一些參數之後，把參數組裝成 NGINX config 然後用 NGINX 去做驗證。

但是呢，組裝的過程有漏洞，可以跳脫原有流程插入其他的 config，而使用 NGINX 去驗證這個惡意的 conifg 時，就能觸發 RCE，而且這個 RCE 的點是 admission controllers，在集群內的權限是較高的，可以從這個點出發去打整個 k8s 的 cluster。

所以，只要 admission controllers 是對外公開的就有風險，難怪會取叫 IngressNightmare。

由於可以注入惡意 config 的地方很多，所以背後其實有三個漏洞：
1. CVE-2025-24514 – auth-url Annotation Injection 
2. CVE-2025-1097 – auth-tls-match-cn Annotation Injection 
3. CVE-2025-1098 – mirror UID Injection

注入惡意 config 之後，這個 config 就會被 NGINX 執行，因此下一步是要找到要利用哪一個設置，才能執行程式碼。

而 Wiz 找到了一個叫做 ssl_engine 的設置可以載入檔案並執行，但這個檔案該從哪裡來呢？

這邊運用了一個在 CTF 滿常見的技巧：「請求暫存」，在 NGINX 中如果 request 超過一定大小，就會先被寫入一個暫存的檔案，雖然說這個檔案會立刻被移除掉，但是用 file descriptor 還是能存取到：/proc/31/fd/10 這樣子（PHP 的 session 功能也滿常這樣被利用的）。

因此，只要暴力去猜 PID 跟 FD，就能猜到檔案位置，利用發請求的方式以及 NGINX 的暫存功能，把檔案短暫留在 server 上。

全部湊起來的話，就能讓 NGINX 去載入你指定的 library，就達成 RCE 了。最後這個 Ingress NGINX 會用 nginx -t 去測試設定檔的漏洞為 CVE-2025-1974，跟前面提過的加起來總共四個漏洞。

看下來確實滿嚴重的，基本上只要 admission controller 有對外就 gg 了，而且從報告看起來，網路上似乎還滿多有對外的 😅
