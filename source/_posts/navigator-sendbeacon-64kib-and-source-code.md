---
title: navigator.sendBeacon 的 64KiB 限制與底層實作
date: 2025-01-06 11:40:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/navigator-sendbeacon-64kib-and-source-code/cover.png
---

當你想在網頁上向 server 發送一些 tracking 相關的資訊時，比起直接用 `fetch` 送出請求，有另一個通常會被推薦的選擇：`navigator.sendBeacon`。

為什麼會推薦這個呢？

因為如果是用一般送出請求的方法，在使用者把頁面關掉或是跳轉的時候可能會有問題，例如說剛好在關掉頁面時發送請求，這個請求可能就送不出去，隨著頁面關閉一起被取消了。

雖然說可以利用一些方法嘗試強制送出請求，但這些方法通常都會傷害使用者體驗，例如說強制讓頁面晚一點關閉，或是送出一個同步的請求之類的。

而 `navigator.sendBeacon` 就是為了解決這個問題而生的。

<!-- more -->

就如同 [spec](https://w3c.github.io/beacon/) 上所寫的：

> This specification defines an interface that web developers can use to schedule asynchronous and non-blocking delivery of data that minimizes resource contention with other time-critical operations, while ensuring that such requests are still processed and delivered to destination
> 
> 此規範定義了一個 interface，供網頁開發者用於安排非同步且非阻塞的數據傳輸，以最大限度地減少與其他時間敏感操作的資源競爭，同時確保這些請求仍能被處理並傳遞到目標位置。

而使用的方式也非常簡單：

``` js
navigator.sendBeacon("/log", payload);
```

就會發送一個 POST 的請求到 `/log` 去。

雖然簡單易用，但需要注意的一點是，送出的 payload 是有大小限制的，而且這個限制不是單一請求的限制。

## navigator.sendBeacon 的 payload 限制

`sendBeacon` 的 payload 上限是 64 KiB，等同於 65536 個 bytes，如果 payload 都是由英文字組成的話，因為每一個是一個 byte，就是 65536 個字。

如果超過這個大小，你會發現請求送不出去，永遠處於 pending 狀態：

``` html
<script>
  navigator.sendBeacon("/log", 'A'.repeat(65536 + 1));
</script>
```

![永遠 pending ](/img/navigator-sendbeacon-64kib-and-source-code/p1.png)

而且這個限制其實並不是限制單一請求，而是背後有個 queue，這個 queue 只要超過 65536 bytes 就不接受新的東西了。

舉例來說，當我們連續送出 8 個 10000 字的請求時：

``` html
<script>
  for(let i=1; i<=8; i++) {
    navigator.sendBeacon("https://httpstat.us/200?log"+i, 'A'.repeat(10000));
  }
</script>
```

你會發現最後兩個一直處於 pending 狀態，送不出去：

![超過 queue 的範圍就會一直 pending](/img/navigator-sendbeacon-64kib-and-source-code/p2.png)

這是因為前六次 `sendBeacon` 已經把 queue 填到 60000 了，因此最後兩次都塞不下，所以無法接受新的請求，就會永遠處於 pending，就會 queue 空了也不會主動再塞進去。

不過嚴格來講這其實也不是 `sendBeacon` 的問題，而是 fetch 加上 keepalive 會有的限制。事實上，`navigator.sendBeacon` 的底層就是 fetch 加上 keepalive。

## navigator.sendBeacon 的規格與 Sentry 的小故事

在規格的段落 [3.2 Processing Model](https://w3c.github.io/beacon/#sec-processing-model) 的第六步中，就有提到剛剛講的 queue：

![spec 中的 queue](/img/navigator-sendbeacon-64kib-and-source-code/p3.png)

如果判斷塞不進去 queue 的話，`sendBeacon` 會回傳 false。

其實這就是 payload 碰到問題時的解法，在呼叫 `sendBeacon` 之後判斷回傳值是否為 false，是的話就進行處理，看是要 fallback 成一般的 fetch，還是自己再做個重試的機制。

而第七步則是 `sendBeacon` 主要做的事情，新建一個 keepalive 的請求然後送出：

![keepalive 的段落](/img/navigator-sendbeacon-64kib-and-source-code/p4.png)

而 fetch + keepalive 的 payload 限制就是 64 KiB，這是有寫在 [spec](https://fetch.spec.whatwg.org/#http-network-or-cache-fetch) 裡的：

![fetch 的 spec](/img/navigator-sendbeacon-64kib-and-source-code/fetch-spec.png)

專門做 error tracking 的服務 Sentry 以前其實就碰過這問題，在 2018 年時有人發現 Sentry 在 fetch 時會預設打開 keepalive，導致有些超過 65536 bytes 的請求送不出去，因此把這個 flag 給拿掉了：

![Sentry 的 issue](/img/navigator-sendbeacon-64kib-and-source-code/p5.png)

來源：[When fetch is used keepalive is the default, and Chrome only allows a POST body <= 65536 bytes in that scenario #1464](https://github.com/getsentry/sentry-javascript/issues/1464)，拿掉的 PR：[ref: Remove keepalive:true as a default and document payload size #1496](https://github.com/getsentry/sentry-javascript/pull/1496)

兩年後的 2020 年，有人發現了 keepalive 的規格以及正確用法：[Fetch KeepAlive #2547](https://github.com/getsentry/sentry-javascript/issues/2547)，提議在 payload 許可之下用 keepalive，超過才不用，而不是像當時全部都不用。

但當時並沒有任何動作，是又過了兩年，在 2022 年時，有人發現 Chrome 在 navigation 的時候會取消所有請求，因此有些請求送不出去，才想到要利用 keepalive 來解決。

因此在 2022 年 9 月時，才又把它加了回去，並且留下精闢的註解：

[feat(browser): Use fetch keepalive flag #5697](https://github.com/getsentry/sentry-javascript/issues/2547)

``` js
// Outgoing requests are usually cancelled when navigating to a different page, causing a "TypeError: Failed to
// fetch" error and sending a "network_error" client-outcome - in Chrome, the request status shows "(cancelled)".
// The `keepalive` flag keeps outgoing requests alive, even when switching pages. We want this since we're
// frequently sending events right before the user is switching pages (eg. whenfinishing navigation transactions).
// Gotchas:
// - `keepalive` isn't supported by Firefox
// - As per spec (https://fetch.spec.whatwg.org/#http-network-or-cache-fetch), a request with `keepalive: true`
//   and a content length of > 64 kibibytes returns a network error. We will therefore only activate the flag when
//   we're below that limit.
keepalive: request.body.length <= 65536,
```

中文機翻：

> 當切換到不同頁面時，未完成的請求通常會被取消，進而導致「TypeError: Failed to fetch」錯誤，並出現「network_error」。在 Chrome 中，請求狀態會顯示「(cancelled)」。
keepalive 標誌可以讓未完成的請求在頁面切換時繼續保持活動狀態。由於我們經常在使用者切換頁面前傳送事件，因此需要這個功能。
> 
> 需要注意：
>
> 1. Firefox 不支援 keepalive。
> 2. 根據規範，如果請求設定了 keepalive: true 並且內容長度超過 64 KiB，將會返回網路錯誤。因此，我們只會在請求內容長度低於該限制時啟用此標誌。

但故事還沒完，就像我剛才提到的，這個 65536 的限制並不只是單個請求，而是有個 queue，因此這樣做是不夠的。半年之後，Sentry 也注意到了這個問題，加上了計算 queue size 的邏輯，讓整個機制變得更加穩健：[fix(browser): Ensure keepalive flag is correctly set for parallel requests #7553](https://github.com/getsentry/sentry-javascript/pull/7553)

![Issue 截圖](/img/navigator-sendbeacon-64kib-and-source-code/p6.png)

如果之後有想要實作類似的東西，可以直接參考上面 Sentry 的 PR。

## sendBeacon 的實作

### Chromium 的 sendBeacon 實作

最後我們來看一下 sendBeacon 底層的實作，先從 Chromium 開始，我以寫文章時最新的穩定版 131.0.6778.205 為例，相關程式碼在：[third_party/blink/renderer/modules/beacon/navigator_beacon.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/131.0.6778.205:third_party/blink/renderer/modules/beacon/navigator_beacon.cc;l=93)

我擷取其中一小段核心程式碼：

``` c
bool NavigatorBeacon::SendBeaconImpl(
    ScriptState* script_state,
    const String& url_string,
    const V8UnionReadableStreamOrXMLHttpRequestBodyInit* data,
    ExceptionState& exception_state) {
  ExecutionContext* execution_context = ExecutionContext::From(script_state);
  KURL url = execution_context->CompleteURL(url_string);
  if (!CanSendBeacon(execution_context, url, exception_state)) {
    return false;
  }

  bool allowed;
  LocalFrame* frame = GetSupplementable()->DomWindow()->GetFrame();
  if (data) {
    switch (data->GetContentType()) {
      // [...]
      case V8UnionReadableStreamOrXMLHttpRequestBodyInit::ContentType::
          kUSVString:
        UseCounter::Count(execution_context,
                          WebFeature::kSendBeaconWithUSVString);
        allowed = PingLoader::SendBeacon(*script_state, frame, url,
                                         data->GetAsUSVString());
        break;
    }
  } else {
    allowed = PingLoader::SendBeacon(*script_state, frame, url, String());
  }

  if (!allowed) {
    UseCounter::Count(execution_context, WebFeature::kSendBeaconQuotaExceeded);
  }

  return allowed;
}
```

開頭的 `CanSendBeacon` 基本上就是檢查 URL 是否合法而已，合法的話繼續往下走，會判斷要送出的 payload 的 content type，而實際送出是在 `PingLoader::SendBeacon` 這個方法裡面。

除此之外可以在程式碼裡面看到 `UseCounter::Count`，這個是 Chromium 用來追蹤某些功能的使用頻率時會用到的。

`PingLoader::SendBeacon` 的實作在 [third_party/blink/renderer/core/loader/ping_loader.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/131.0.6778.205:third_party/blink/renderer/core/loader/ping_loader.cc)：

``` c
bool SendBeaconCommon(const ScriptState& state,
                      LocalFrame* frame,
                      const KURL& url,
                      const BeaconData& beacon) {
  if (!frame->DomWindow()
           ->GetContentSecurityPolicyForWorld(&state.World())
           ->AllowConnectToSource(url, url, RedirectStatus::kNoRedirect)) {
    // We're simulating a network failure here, so we return 'true'.
    return true;
  }

  ResourceRequest request(url);
  request.SetHttpMethod(http_names::kPOST);
  request.SetKeepalive(true);
  request.SetRequestContext(mojom::blink::RequestContextType::BEACON);
  beacon.Serialize(request);
  FetchParameters params(std::move(request),
                         ResourceLoaderOptions(&state.World()));
  // The spec says:
  //  - If mimeType is not null:
  //   - If mimeType value is a CORS-safelisted request-header value for the
  //     Content-Type header, set corsMode to "no-cors".
  // As we don't support requests with non CORS-safelisted Content-Type, the
  // mode should always be "no-cors".
  params.MutableOptions().initiator_info.name =
      fetch_initiator_type_names::kBeacon;

  frame->Client()->DidDispatchPingLoader(url);

  FetchUtils::LogFetchKeepAliveRequestMetric(
      params.GetResourceRequest().GetRequestContext(),
      FetchUtils::FetchKeepAliveRequestState::kTotal);
  Resource* resource =
      RawResource::Fetch(params, frame->DomWindow()->Fetcher(), nullptr);
  return resource->GetStatus() != ResourceStatus::kLoadError;
}
```

開頭先檢查是否違反 CSP，如果沒有違反，就送出一個 keepalive 的請求，然後回傳是否成功。

值得注意的是在同個檔案中，也有另一個功能做了類似的事情，叫做 `PingLoader::SendLinkAuditPing`。在 `<a>` 標籤上有個屬性叫做 `ping`，當使用者點了連結，瀏覽器就會發送一個請求到 ping 所指定的位置：

``` html
<a
  href="https://example.com"
  ping="https://blog.huli.tw"
  >click me
</a>
```

這背後一樣是用 keepalive 的 fetch 來實作的：

``` c
void PingLoader::SendLinkAuditPing(LocalFrame* frame,
                                   const KURL& ping_url,
                                   const KURL& destination_url) {
  if (!ping_url.ProtocolIsInHTTPFamily())
    return;

  ResourceRequest request(ping_url);
  request.SetHttpMethod(http_names::kPOST);
  request.SetHTTPContentType(AtomicString("text/ping"));
  request.SetHttpBody(EncodedFormData::Create(base::span_from_cstring("PING")));
  request.SetHttpHeaderField(http_names::kCacheControl,
                             AtomicString("max-age=0"));
  request.SetHttpHeaderField(http_names::kPingTo,
                             AtomicString(destination_url.GetString()));
  scoped_refptr<const SecurityOrigin> ping_origin =
      SecurityOrigin::Create(ping_url);
  if (ProtocolIs(frame->DomWindow()->Url().GetString(), "http") ||
      frame->DomWindow()->GetSecurityOrigin()->CanAccess(ping_origin.get())) {
    request.SetHttpHeaderField(
        http_names::kPingFrom,
        AtomicString(frame->DomWindow()->Url().GetString()));
  }

  request.SetKeepalive(true);
  request.SetReferrerString(Referrer::NoReferrer());
  request.SetReferrerPolicy(network::mojom::ReferrerPolicy::kNever);
  request.SetRequestContext(mojom::blink::RequestContextType::PING);
  FetchParameters params(
      std::move(request),
      ResourceLoaderOptions(frame->DomWindow()->GetCurrentWorld()));
  params.MutableOptions().initiator_info.name =
      fetch_initiator_type_names::kPing;

  frame->Client()->DidDispatchPingLoader(ping_url);
  FetchUtils::LogFetchKeepAliveRequestMetric(
      params.GetResourceRequest().GetRequestContext(),
      FetchUtils::FetchKeepAliveRequestState::kTotal);
  RawResource::Fetch(params, frame->DomWindow()->Fetcher(), nullptr);
}
```

### Safari 的 sendBeacon 實作

Safari 的實作在 [WebKit/Source/WebCore/Modules/beacon
/NavigatorBeacon.cpp](https://github.com/WebKit/WebKit/blob/WebKit-7620.1.16.111.5/Source/WebCore/Modules/beacon/NavigatorBeacon.cpp)：

``` cpp
ExceptionOr<bool> NavigatorBeacon::sendBeacon(Document& document, const String& url, std::optional<FetchBody::Init>&& body)
{
    URL parsedUrl = document.completeURL(url);

    // Set parsedUrl to the result of the URL parser steps with url and base. If the algorithm returns an error, or if
    // parsedUrl's scheme is not "http" or "https", throw a "TypeError" exception and terminate these steps.
    if (!parsedUrl.isValid())
        return Exception { ExceptionCode::TypeError, "This URL is invalid"_s };
    if (!parsedUrl.protocolIsInHTTPFamily())
        return Exception { ExceptionCode::TypeError, "Beacons can only be sent over HTTP(S)"_s };

    if (!document.frame())
        return false;

    if (!document.shouldBypassMainWorldContentSecurityPolicy() && !document.checkedContentSecurityPolicy()->allowConnectToSource(parsedUrl)) {
        // We simulate a network error so we return true here. This is consistent with Blink.
        return true;
    }

    ResourceRequest request(parsedUrl);
    request.setHTTPMethod("POST"_s);
    request.setRequester(ResourceRequestRequester::Beacon);
    if (RefPtr documentLoader = document.loader())
        request.setIsAppInitiated(documentLoader->lastNavigationWasAppInitiated());

    ResourceLoaderOptions options;
    options.credentials = FetchOptions::Credentials::Include;
    options.cache = FetchOptions::Cache::NoCache;
    options.keepAlive = true;
    options.sendLoadCallbacks = SendCallbackPolicy::SendCallbacks;

    if (body) {
        options.mode = FetchOptions::Mode::NoCors;
        String mimeType;
        auto result = FetchBody::extract(WTFMove(body.value()), mimeType);
        if (result.hasException())
            return result.releaseException();
        auto fetchBody = result.releaseReturnValue();
        if (fetchBody.isReadableStream())
            return Exception { ExceptionCode::TypeError, "Beacons cannot send ReadableStream body"_s };

        request.setHTTPBody(fetchBody.bodyAsFormData());
        if (!mimeType.isEmpty()) {
            request.setHTTPContentType(mimeType);
            if (!isCrossOriginSafeRequestHeader(HTTPHeaderName::ContentType, mimeType)) {
                options.mode = FetchOptions::Mode::Cors;
                options.httpHeadersToKeep.add(HTTPHeadersToKeepFromCleaning::ContentType);
            }
        }
    }

    auto cachedResource = document.protectedCachedResourceLoader()->requestBeaconResource({ WTFMove(request), options });
    if (!cachedResource) {
        logError(cachedResource.error());
        return false;
    }

    ASSERT(!m_inflightBeacons.contains(cachedResource.value().get()));
    m_inflightBeacons.append(cachedResource.value().get());
    cachedResource.value()->addClient(*this);
    return true;
}
```

可以看到整個流程與 Chromium 是差不多的，先檢查 URL 的合法性，接著檢查 CSP，然後送出一個 keepalive 的請求。

這呼應到我們之前所說的以及規格上寫的，sendBeacon 底層就是個 keepalive 的 fetch。那 keepalive queue 大小超過的原始碼會在哪裡呢？

從實作中可以看出如果 queue 的大小超過了，八成就是這一段出錯，因為只有這邊會回傳 false：

``` cpp
auto cachedResource = document.protectedCachedResourceLoader()->requestBeaconResource({ WTFMove(request), options });
if (!cachedResource) {
    logError(cachedResource.error());
    return false;
}
```

因此可以往 `requestBeaconResource` 下去追蹤。除此之外，我們也可以從另一個方向來追蹤原始碼在哪一段。

還記得剛剛那個送出 8 個長度 10000 的字串的範例嗎？在 Chrome 上只會看到請求變成 pending，但是在 Safari 上會出現貼心的提示：

> Beacon API cannot load https://httpstat.us/200?log7. Reached maximum amount of queued data of 64Kb for keepalive requests

直接用這個錯誤訊息就可以找到相關的原始碼，在 [WebKit/Source/WebCore/loader/cache/CachedResource.cpp](https://github.com/WebKit/WebKit/blob//WebKit-7620.1.16.111.5/Source/WebCore/loader/cache/CachedResource.cpp#L249)：

``` cpp
if (
    m_options.keepAlive && type() != Type::Ping &&
    !cachedResourceLoader.keepaliveRequestTracker().tryRegisterRequest(*this)
  ) {
    setResourceError({
      errorDomainWebKitInternal, 0, request.url(),
      "Reached maximum amount of queued data of 64Kb for keepalive requests"_s,
      ResourceError::Type::AccessControl
    });
    failBeforeStarting();
    return;
}
```

如果是 keepalive，而且 type 不是 ping（sendBeacon 的 type 會是 `Type::Beacon`），又沒辦法註冊新的請求，就回傳這個錯誤。

因此重點就是 `keepaliveRequestTracker().tryRegisterRequest` 這個方法了，在 [Source/WebCore/loader/cache/KeepaliveRequestTracker.cpp](https://github.com/WebKit/WebKit/blob/WebKit-7620.1.16.111.5/Source/WebCore/loader/cache/KeepaliveRequestTracker.cpp)：

``` cpp
const uint64_t maxInflightKeepaliveBytes { 65536 }; // 64 kibibytes as per Fetch specification.

bool KeepaliveRequestTracker::tryRegisterRequest(CachedResource& resource)
{
    ASSERT(resource.options().keepAlive);
    auto body = resource.resourceRequest().httpBody();
    if (!body)
        return true;

    uint64_t bodySize = body->lengthInBytes();
    if (m_inflightKeepaliveBytes + bodySize > maxInflightKeepaliveBytes)
        return false;

    registerRequest(resource);
    return true;
}
```

其實也就只是算一下還在等待的有多少，加上去會不會超過最大值 65536，做的事情跟 Sentry 最後的那個 PR 差不多。

### Firefox 的 sendBeacon 實作

在之前 Sentry 的 PR 中其實就有提到 Firefox 不支援 keepalive，對應到的 ticket 是這張：[[meta] Support Fetch keepalive flag and enforce limit on inflight keepalive bytes](https://bugzilla.mozilla.org/show_bug.cgi?id=1342484)，目前還沒被關閉，從討論中看起來似乎半年前開始有了進展，在 2024 年 11 月推出的 Firefox 133 版本中正式開始支援，雖然還有一些 bug，但應該會越來越穩定。

我用三個瀏覽器測試了一個情境，送出 10 個長度 6 萬的字串：

``` html
<script>
  for(let i=1; i<=10; i++) {
    navigator.sendBeacon("https://httpstat.us/200?log"+i, 'A'.repeat(60000));
  }
</script>
```

Chrome 跟 Safari 都只送出了一個請求，但是 Firefox 133.0.3  倒是很貼心地全部都送出去了，目前還沒有 64 KiB 的限制：

![Firefox 截圖](/img/navigator-sendbeacon-64kib-and-source-code/p7.png)

如果有人好奇底層實作，程式碼在這裡：[gecko-dev/dom/base/Navigator.cpp](https://github.com/mozilla/gecko-dev/blob/94c62970ba2f9c40efd5a4f83a538595425820d9/dom/base/Navigator.cpp#L1163)，目前看起來應該還沒把 keepalive 整進去，所以才沒有觸發到上限。未來應該會按照 spec 走，使用 keepalive 請求，並且遵守 payload 的大小限制。

## 結語

小功能大學問，一個看似簡單的 `sendBeacon`，其實深入研究之後也滿有趣的，知道了它的限制、解法，也能從 Sentry 的修補過程中學到一些經驗，還看了瀏覽器的原始碼，更理解背後的實作。

總之呢，在實務上若是要使用 `sendBeacon`，都請記得加個錯誤處理，在回傳值是 false 時，改成一般的 fetch 或是加上重試機制，才能加強資料傳輸的穩定性。