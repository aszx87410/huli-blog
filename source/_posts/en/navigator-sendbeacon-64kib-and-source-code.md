---
title: The 64KiB Limitation of navigator.sendBeacon and its implementation
date: 2025-01-06 11:40:00
catalog: true
tags: [Front-end]
categories: [Front-end]
photos: /img/navigator-sendbeacon-64kib-and-source-code/cover-en.png
---

When you want to send some tracking-related information to the server from a webpage, there is another option that is often recommended over directly using `fetch` to send requests: `navigator.sendBeacon`.

Why is this recommended?

Because if you use the usual method of sending requests, there may be issues when the user closes the page or navigates away. For example, if a request is sent just as the page is being closed, that request may not go through and could be canceled along with the page closure.

Although there are ways to try to force the request to be sent, these methods often harm the user experience, such as forcing the page to close later or sending a synchronous request.

`navigator.sendBeacon` was created to solve this problem.

<!-- more -->

As stated in the [spec](https://w3c.github.io/beacon/):

> This specification defines an interface that web developers can use to schedule asynchronous and non-blocking delivery of data that minimizes resource contention with other time-critical operations, while ensuring that such requests are still processed and delivered to destination
> 
> This specification defines an interface for web developers to schedule asynchronous and non-blocking data transmission, minimizing resource contention with other time-sensitive operations while ensuring that these requests can still be processed and delivered to the target location.

The usage is also very simple:

``` js
navigator.sendBeacon("/log", payload);
```

This will send a POST request to `/log`.

Although it is simple and easy to use, one important point to note is that the payload being sent has a size limit, and this limit is not just for a single request.

## Payload Limit of navigator.sendBeacon

The payload limit for `sendBeacon` is 64 KiB, equivalent to 65536 bytes. If the payload consists entirely of English characters, since each character is one byte, that means 65536 characters.

If you exceed this size, you will find that the request cannot be sent and remains in a pending state:

``` html
<script>
  navigator.sendBeacon("/log", 'A'.repeat(65536 + 1));
</script>
```

![Forever pending](/img/navigator-sendbeacon-64kib-and-source-code/p1.png)

Moreover, this limitation is not just for a single request; there is a queue behind it, and this queue will not accept new items if it exceeds 65536 bytes.

For example, when we continuously send 8 requests of 10000 characters each:

``` html
<script>
  for(let i=1; i<=8; i++) {
    navigator.sendBeacon("https://httpstat.us/200?log"+i, 'A'.repeat(10000));
  }
</script>
```

You will find that the last two requests remain in a pending state and cannot be sent:

![Exceeding the queue limit will keep it pending](/img/navigator-sendbeacon-64kib-and-source-code/p2.png)

This is because the first six `sendBeacon` calls have already filled the queue to 60000, so the last two cannot fit, and thus cannot accept new requests, remaining in a pending state without actively trying to push new ones in when the queue is empty.

However, strictly speaking, this is not actually a problem with `sendBeacon`, but rather a limitation that comes with fetch combined with keepalive. In fact, the underlying implementation of `navigator.sendBeacon` is fetch combined with keepalive.

## The Specification of navigator.sendBeacon and a Short Story about Sentry

In the specification section [3.2 Processing Model](https://w3c.github.io/beacon/#sec-processing-model), step six mentions the queue we just discussed:

![Queue in the spec](/img/navigator-sendbeacon-64kib-and-source-code/p3.png)

If it is determined that the request cannot fit into the queue, `sendBeacon` will return false.

This is actually the solution when the payload encounters a problem. After calling `sendBeacon`, check if the return value is false. If it is, proceed to handle it, deciding whether to fallback to a regular fetch or implement a retry mechanism.

The seventh step is what `sendBeacon` primarily does: it creates a keepalive request and sends it out:

![keepalive section](/img/navigator-sendbeacon-64kib-and-source-code/p4.png)

The payload limit for fetch + keepalive is 64 KiB, which is stated in the [spec](https://fetch.spec.whatwg.org/#http-network-or-cache-fetch):

![fetch spec](/img/navigator-sendbeacon-64kib-and-source-code/fetch-spec.png)

The error tracking service Sentry actually encountered this issue in the past. In 2018, it was discovered that Sentry had keepalive enabled by default when using fetch, causing some requests over 65536 bytes to fail to send. As a result, this flag was removed:

![Sentry issue](/img/navigator-sendbeacon-64kib-and-source-code/p5.png)

Source: [When fetch is used keepalive is the default, and Chrome only allows a POST body <= 65536 bytes in that scenario #1464](https://github.com/getsentry/sentry-javascript/issues/1464), the removed PR: [ref: Remove keepalive:true as a default and document payload size #1496](https://github.com/getsentry/sentry-javascript/pull/1496)

Two years later, in 2020, someone discovered the specifications and correct usage of keepalive: [Fetch KeepAlive #2547](https://github.com/getsentry/sentry-javascript/issues/2547), proposing to use keepalive under the payload allowance, and not to use it if exceeded, rather than not using it at all as was the case then.

However, no action was taken at that time. It was another two years later, in 2022, when someone found that Chrome cancels all requests during navigation, causing some requests to fail to send, leading to the idea of using keepalive to solve this.

Thus, in September 2022, it was added back with insightful comments:

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

Machine translation from Chinese:

> When switching to a different page, unfinished requests are often canceled, leading to a "TypeError: Failed to fetch" error and a "network_error" message. In Chrome, the request status shows "(cancelled)".
The keepalive flag allows unfinished requests to remain active during page transitions. Since we often send events before users switch pages, this functionality is necessary.
> 
> Important to note:
>
> 1. Firefox does not support keepalive.
> 2. According to the specification, if a request is set with keepalive: true and the content length exceeds 64 KiB, a network error will be returned. Therefore, we will only enable this flag when the request content length is below that limit.

But the story doesn't end here. As I mentioned earlier, this 65536 limit is not just for a single request, but there is a queue, so this approach is insufficient. Six months later, Sentry also noticed this issue and added logic to calculate the queue size, making the entire mechanism more robust: [fix(browser): Ensure keepalive flag is correctly set for parallel requests #7553](https://github.com/getsentry/sentry-javascript/pull/7553)

![Issue screenshot](/img/navigator-sendbeacon-64kib-and-source-code/p6.png)

If you want to implement something similar in the future, you can directly refer to the above Sentry PR.

## Implementation of sendBeacon

### Implementation of sendBeacon in Chromium

Finally, let's take a look at the underlying implementation of sendBeacon, starting with Chromium. I will use the latest stable version 131.0.6778.205 at the time of writing this article as an example. The relevant code can be found at: [third_party/blink/renderer/modules/beacon/navigator_beacon.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/131.0.6778.205:third_party/blink/renderer/modules/beacon/navigator_beacon.cc;l=93)

I have extracted a small segment of the core code:

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

The beginning of `CanSendBeacon` basically checks whether the URL is valid. If it is valid, it continues to check the content type of the payload to be sent, and the actual sending occurs in the `PingLoader::SendBeacon` method.

In addition, you can see `UseCounter::Count` in the code, which is used by Chromium to track the usage frequency of certain features.

The implementation of `PingLoader::SendBeacon` can be found at [third_party/blink/renderer/core/loader/ping_loader.cc](https://source.chromium.org/chromium/chromium/src/+/refs/tags/131.0.6778.205:third_party/blink/renderer/core/loader/ping_loader.cc):

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

It first checks for CSP violations. If there are none, it sends a keepalive request and returns whether it was successful.

It is worth noting that in the same file, there is another function that does something similar, called `PingLoader::SendLinkAuditPing`. There is an attribute called `ping` on the `<a>` tag, and when the user clicks the link, the browser sends a request to the location specified by the ping:

``` html
<a
  href="https://example.com"
  ping="https://blog.huli.tw"
  >click me
</a>
```

This is also implemented using a keepalive fetch:

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

### Implementation of sendBeacon in Safari

The implementation in Safari can be found at [WebKit/Source/WebCore/Modules/beacon/NavigatorBeacon.cpp](https://github.com/WebKit/WebKit/blob/WebKit-7620.1.16.111.5/Source/WebCore/Modules/beacon/NavigatorBeacon.cpp):

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

You can see that the entire process is quite similar to Chromium. It first checks the validity of the URL, then checks CSP, and then sends a keepalive request.

This echoes what we mentioned earlier and what is written in the specifications: the underlying sendBeacon is essentially a keepalive fetch. So where is the source code for when the keepalive queue size exceeds the limit?

From the implementation, it can be seen that if the queue size exceeds, it is likely that this segment is where the error occurs, because only here will it return false:

``` cpp
auto cachedResource = document.protectedCachedResourceLoader()->requestBeaconResource({ WTFMove(request), options });
if (!cachedResource) {
    logError(cachedResource.error());
    return false;
}
```

Therefore, we can trace down to `requestBeaconResource`. Additionally, we can also trace the source code from another direction.

Do you remember the example that sent a string of length 10000 eight times? In Chrome, you will only see the request become pending, but in Safari, a helpful message will appear:

> Beacon API cannot load https://httpstat.us/200?log7. Reached maximum amount of queued data of 64Kb for keepalive requests

You can directly use this error message to find the relevant source code at [WebKit/Source/WebCore/loader/cache/CachedResource.cpp](https://github.com/WebKit/WebKit/blob//WebKit-7620.1.16.111.5/Source/WebCore/loader/cache/CachedResource.cpp#L249):

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

If it is a keepalive, and the type is not ping (the type of sendBeacon will be `Type::Beacon`), and there is no way to register a new request, then this error is returned.

Therefore, the key point is the method `keepaliveRequestTracker().tryRegisterRequest`, located in [Source/WebCore/loader/cache/KeepaliveRequestTracker.cpp](https://github.com/WebKit/WebKit/blob/WebKit-7620.1.16.111.5/Source/WebCore/loader/cache/KeepaliveRequestTracker.cpp):

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

It actually just counts how many are still waiting, and checks if adding them would exceed the maximum value of 65536. The operation is quite similar to the last PR from Sentry.

### Firefox's sendBeacon Implementation

In the previous Sentry PR, it was mentioned that Firefox does not support keepalive, corresponding to this ticket: [[meta] Support Fetch keepalive flag and enforce limit on inflight keepalive bytes](https://bugzilla.mozilla.org/show_bug.cgi?id=1342484), which is still open. From the discussion, it seems there has been progress since about half a year ago, and support officially started in Firefox version 133, released in November 2024. Although there are still some bugs, it should become more stable over time.

I tested a scenario with three browsers, sending out 10 strings of length 60,000:

``` html
<script>
  for(let i=1; i<=10; i++) {
    navigator.sendBeacon("https://httpstat.us/200?log"+i, 'A'.repeat(60000));
  }
</script>
```

Both Chrome and Safari only sent one request, but Firefox 133.0.3 kindly sent them all out, currently without a 64 KiB limit:

![Firefox Screenshot](/img/navigator-sendbeacon-64kib-and-source-code/p7.png)

For those curious about the underlying implementation, the code is here: [gecko-dev/dom/base/Navigator.cpp](https://github.com/mozilla/gecko-dev/blob/94c62970ba2f9c40efd5a4f83a538595425820d9/dom/base/Navigator.cpp#L1163). It seems that keepalive has not been integrated yet, which is why the limit has not been triggered. In the future, it should follow the spec, using keepalive requests and adhering to the payload size limits.

## Conclusion

Small features can have great significance. A seemingly simple `sendBeacon` is actually quite interesting upon deeper research. Understanding its limitations and solutions, as well as learning from Sentry's patching process, and reviewing the browser's source code, provides a better understanding of the underlying implementation.

In practice, if you are going to use `sendBeacon`, please remember to add error handling. When the return value is false, switch to a regular fetch or add a retry mechanism to enhance the stability of data transmission.
