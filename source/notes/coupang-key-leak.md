---
layout: note
title: "Coupang 外洩與金鑰"
date: 2026-03-19 20:20:19
---
今天從技術的觀點來聊前陣子沸沸揚揚的 [Coupang](https://blog.huli.tw/2026/03/19/coupang-insider-kms-and-jwt/) 個資外洩事件。

其實已經寫一篇完整的部落格文章了，懶得看全文的話，就看我這篇精簡版吧。

Coupang 是個韓國電商，在台灣也有設點，去年發生個資外洩事件，韓國那邊的調查已經告一個段落，而近期因為台灣也有受影響，所以數發部介入，目前劇情大概到這裡。

相關的技術細節韓國的報告寫得很清楚，這整起事件的攻擊者並非外部駭客，而是一個離職的前員工，而且還是開發備援 auth 系統的 Staff Back-end Engineer（但他做這件事的動機新聞跟調查都沒寫）。

Coupang 的驗證系統在登入過後會發一個類似 JWT token 的東西，直接在裡面帶上會員 id 之類的，下次就只驗這個 token 是否合法。因此，只要能拿到簽這個 token 的 key，就能偽造任何人的身份，不用登入就獲得相關權限。

而這個離職員工就是利用這種方式，還在職時拿到了這把 key，偷偷帶走，離職後拿來偽造出 token，就能進入 my information 之類的頁面看到個資。

所以呢，這整起事件就是負責開發 auth 系統的主任後端工程師，在離職後用在職時取得的 auth 系統 signing key 搞出來的。

接著可以從兩個角度聊，一是 key 該怎麼管才安全，二是這種驗證方式本身是不是有點問題。

管 key 的話，有很多公司都會用 vault 或 secret manager 之類的東西管，然後讓 SRE 或開發者自己產一把 key 放進去。雖然說放到 vault 後取用是安全的，但產 key 的時候已經有幾個人知道了。雖然說 insider 的風險跟其他比沒這麼高，比較容易被查出來，但若是發生了，外部也不會管你到底為什麼出事。

所以不只是儲存跟使用，在產生 key 的時候也要注意，最安全的是用 HSM 儲存 key 外加 KMS 管理，key 本身從不離開這個系統，但相對的成本也會高一點。

也可以先從 key rotation 做起，當這些能碰到的人離職時，把能碰到的 key 都先換過一輪，雖然在職時還是能碰到 key，但至少讓他們離職後自動喪失所有權限。

再來，key 被偷就整個 auth 系統 gg，聽起來似乎不太合理。

以傳統 session 做法來說，你保存一個 session id，每次後端查表，session id 若是不可預測，你拿到 signed cookie 的 key 也沒用。JWT 其實也是，你如果在 token 裡存的是 session id 也一樣。

但現在許多系統 JWT 是存 session data 的，裡面直接放 email 或 user id 這些可預測的東西。在這個前提下，保護 key 就變成非常重要的一件事情，而且 private key 跟 public key 都要保護。前者保證不被洩漏，後者保證不被置換。

我相信有許多公司在產 key 這段多少都有點問題，許多都是我前面說的，由人產完再放進去 secret manager。況且也沒這麼多公司有資源專門去弄個 KMS（或甚至沒想到可以這樣或需要這樣做）。

這些都是風險，都會回到風險管理的框架去討論，不少公司目前選擇的是接受風險，亦即承認風險的存在，但因發生機率小所以先不處理。若是真的有哪個能碰到這些的離職員工偷偷帶了一份資料走，那類似的事情很可能又會重演。

總結就是：
1. key 的完整生命流程要注意，尤其是產生的時候
2. 使用 stateless JWT 有個風險是 key 被偷走就 gg，要記得
3. 考慮風險時，除了外部攻擊者，也要考慮 insider threat

看完想知道更多細節的話，可以再回去快速看過部落格完整版

補充文章：<https://www.msit.go.kr/eng/bbs/view.do;jsessionid=iMyzX8C42zedbf27PtWxq844qjcyYy0VOCt74FEO.AP_msit_2?sCode=eng&mPid=2&mId=4&bbsSeqNo=42&nttSeqNo=1221&utm_source=perplexity>
