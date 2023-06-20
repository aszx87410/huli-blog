---
title: Understanding JavaScript from its history
catalog: true
date: 2022-01-15 10:29:19
tags: [JavaScript, Front-end]
categories: [JavaScript]
---

I believe that to truly understand JavaScript, we must start from its history. Why? Because by understanding its history, we can know why certain parts are designed in a certain way and why there are seemingly strange behaviors. Although some ancient knowledge may not have much practical use, it is very interesting to me.

Learning its history is not about memorizing the year it appeared or how many days it took to develop and design, but rather understanding the context in which it appeared and why it was needed and designed in a certain way.

If you want to learn about the history of JavaScript, my top recommendation is this resource: [JavaScript: The First 20 Years](http://www.wirfs-brock.com/allen/posts/866), because Brendan Eich, the father of JavaScript, is also one of the authors. If you want to read the Chinese version, it is available here: [JavaScript 20 Years](https://cn.history.js.org/).

This book records the history of JavaScript from 1995 to 2015, a total of 20 years. If you have time, I strongly recommend that you read it all. It will give you a different understanding of JavaScript (and you will also learn a lot of interesting facts).

Below, I will pick some of the more important things to write about. If there is no specific mention of the data source, it is from the book mentioned above, so it is normal if it seems familiar.

Since I was born around the same time as JavaScript, I have not personally experienced the early history. If it seems like I have participated in it, it is all just imagination.

<!-- more -->

## The Birth of JavaScript

When reading history, I think there is a key point when talking about the years, which is to make everyone feel the same way, otherwise it is just cold words.

In 1993, the well-known graphical browser Mosaic was born (it was well-known, but not the first). You may wonder why I emphasize the word "graphical". Are there browsers that are purely text-based? Yes, there are.

Browsers like [Lynx](https://en.wikipedia.org/wiki/Lynx), which appeared in 1992, or [w3m](https://en.wikipedia.org/wiki/W3m), which was launched in 2011, are text-based browsers.

If you use w3m to view my blog, it will look like this:

![w3m](/img/js-history/w3m.png)

If you are interested in trying it out, you can install w3m on a Linux system: `apt-get install w3m`, and then `w3m https://blog.huli.tw` to see it.

Then, at the end of 1994, Netscape's Netscape Navigator was launched and quickly expanded, becoming the dominant browser in just a few months.

What was 1994 like? It was 13 years before the birth of the first iPhone, and the year before the birth of Windows 95. At that time, there was no such thing as a "mobile phone", it was called a "cell phone". The legendary Nokia 3310 was launched in 2000, which was six years later.

Taiwan's internet started with academic networks in 1985, and was officially connected to the world in 1991. HiNet was established in 1994, and Ptt was established in 1995.

In 1994, none of these existed yet, indicating that it was a relatively early era and a time when the internet was just beginning to flourish.

In such a rising market, everyone naturally wants to get a piece of the pie. In late 1994, Microsoft proposed a plan to acquire Netscape, but it was rejected. The management of Netscape realized at that time that they were likely to face competition from Microsoft in the future - the famous IE, which was launched in August 1995.

At that time, Netscape originally wanted to add a scripting language to the browser. At the beginning of 1995, Sun brought the not-yet-officially-released Java to Netscape and reached a cooperation agreement to integrate Java into Netscape 2. The two companies joined forces to defeat Microsoft, and this became the Java Applet.

I believe that many young people like me do not know what a Java Applet is. In short, you can write an application in Java, compile it, and put it on a webpage for the browser to execute Java. The advantage of this is that users do not need to download Java applications actively, and the browser will take care of it for you.

You can see the Java Applet code from [Wikipedia](https://en.wikipedia.org/wiki/Java_applet):

``` java
import java.applet.Applet;
import java.awt.*;

// Applet code for the "Hello, world!" example.
// This should be saved in a file named as "HelloWorld.java".
public class HelloWorld extends Applet {
  // This method is mandatory, but can be empty (i.e., have no actual code).
  public void init() { }

  // This method is mandatory, but can be empty.(i.e.,have no actual code).
  public void stop() { }

  // Print a message on the screen (x=20, y=10).
  public void paint(Graphics g) {
    g.drawString("Hello, world!", 20,10);
  
  // Draws a circle on the screen (x=40, y=30).
    g.drawArc(40,30,20,20,0,360);
  }
}
```

This code will draw a "Hello, World" on the screen. After compiling the above Java code, you can embed it in a webpage.

``` html
<!DOCTYPE HTML PUBLIC 
  "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd"> 
<HTML>
<HEAD>
<TITLE>HelloWorld_example.html</TITLE>
</HEAD>
<BODY>
<H1>A Java applet example</H1>
<P>Here it is: <APPLET code="HelloWorld.class" WIDTH="200" HEIGHT="40">
This is where HelloWorld.class runs.</APPLET></P>
</BODY>
</HTML>
```

So why do we need a scripting language when we already have powerful web applications? Can't we just use Java?

The reason is that for some simple applications, using Java would be too cumbersome. For example, if you just want to do input field validation, you would have to learn about object-oriented class concepts and be familiar with the entire Java ecosystem before you can start writing the functionality you want, which could take more than 10 lines of boilerplate code.

Therefore, in 1995, Brendan Eich, who joined Netscape, was tasked with developing a programming language that could run in a browser, be lightweight, and look like Java. Why should it look like Java? Because initially, it was born as an auxiliary language for Java, and this language was temporarily named Mocha.

Due to time constraints, Brendan Eich spent ten days creating a prototype of Mocha. The demand from the upper level to "look like Java" also influenced the design of JavaScript. However, in addition to Java, JavaScript also referred to programming languages such as C, AWK, Scheme, and Self.

Many people have heard the phrase "Java and JavaScript are like dogs and hot dogs," but in reality, their origins may be deeper than you think, and not just following trends or having similar names.

For example, many people may have encountered a strange design:

``` js
console.log(new Date())
// Thu Aug 19 2021 22:55:22 GMT+0800 (台北標準時間)

console.log(new Date().getMonth())
7
```

It's August, why is it logging as 7? Do you think this design is unique to JavaScript? No, it was copied from `java.util.Date` in JDK 1.0. This is the [document at the time](https://web.archive.org/web/20111203213751/http://docs.oracle.com/javase/1.3/docs/api/java/util/Date.html).

![Java docs](/img/js-history/java1.png)

So why did Java do this? Some people pointed out that it may be because in the older C's [localtime](https://linux.die.net/man/3/localtime), the month starts from 0.

More related resources can be found at:

1. [Why does the month argument range from 0 to 11 in JavaScript's Date constructor?](https://stackoverflow.com/questions/2552483/why-does-the-month-argument-range-from-0-to-11-in-javascripts-date-constructor)
2. [Javascript Date method inconsistency - getDate vs getMonth](https://stackoverflow.com/questions/9687521/javascript-date-method-inconsistency-getdate-vs-getmonth/9688617#9688617)

Regarding the [reply](https://twitter.com/BrendanEich/status/771006397886533632) from the father of JavaScript on these discussions, we can also see the demand for "JavaScript to look like Java":

![twitter js](/img/js-history/twitter-js.png)

In a [press release](https://web.archive.org/web/19970614002809/http://home.netscape.com:80/newsref/pr/newsrelease67.html) released by Netscape in May 1995, JavaScript was officially launched, and the subtitle was:

> 28 INDUSTRY-LEADING COMPANIES TO ENDORSE JAVASCRIPT AS A COMPLEMENT TO JAVA FOR EASY ONLINE APPLICATION DEVELOPMENT

This explains that JavaScript exists to assist Java.

In this press release, we can also see many features of JavaScript, such as:

> JavaScript is analogous to Visual Basic in that it can be used by people with little or no programming experience to quickly construct complex applications. JavaScript's design represents the next generation of software designed specifically for the Internet and is:
> 
> 1.designed for creating network-centric applications  
> 2.complementary to and integrated with Java  
> 3.complementary to and integrated with HTML  
> 4.open and cross-platform.

They liken JavaScript to Visual Basic, which is simple and easy to learn, and JavaScript is the bridge between Java Applet and HTML. You can think of Java Applet as a standalone application that exists outside of the webpage. If you want to change the content on the webpage, you need to use JavaScript as a bridge, as stated in the following paragraph:

"With JavaScript, an HTML page might contain an intelligent form that performs loan payment or currency exchange calculations right on the client in response to user input. A multimedia weather forecast applet written in Java can be scripted by JavaScript to display appropriate images and sounds based on the current weather readings in a region."

JavaScript can exist independently as an aid to HTML, handling some basic logic, and can also be used with Java Applet. In early documents, there was a mention of how Java and JavaScript communicate with each other (referenced from Java-to-Javascript Communication).

``` js
import netscape.javascript.*;
import java.applet.*;
import java.awt.*;
class MyApplet extends Applet {
     public void init() {
         JSObject win = JSObject.getWindow(this);
         JSObject doc = (JSObject) win.getMember("document");
         JSObject loc = (JSObject) doc.getMember("location");

         String s = (String) loc.getMember("href");  // document.location.href
         win.call("f", null);                      // Call f() in HTML page
     }
}
```

It uses the `JSObject` object to obtain the DOM. Another tutorial webpage has a more complete example:

``` js
/*
Mastering JavaScript, Premium Edition
by James Jaworski 

ISBN:078212819X
Publisher Sybex CopyRight 2001
*/
<title>Accessing JavaScript from an applet</TITLE>
<form NAME="textForm">
<P>Enter some text and then click Display Text:
 <INPUT TYPE="text" NAME="textField" SIZE="20"></P>
</FORM>
<APPLET CODE="ReadForm.class" WIDTH=400 HEIGHT=100
 NAME="readApp" MAYSCRIPT>
[The ReadForm Applet]
</APPLET>

//Reading a JavaScript Form (ReadForm.java)
import java.applet.*;
import java.awt.*;
import java.awt.event.*;
import netscape.javascript.JSObject;
import netscape.javascript.JSException;
public class ReadForm extends Applet {
 String text="Enter some text for me to display!";
 Font font = new Font("TimesRoman",Font.BOLD+Font.ITALIC,24);
 JSObject win, doc, form, textField;
 public void init() {
  win = JSObject.getWindow(this);
  doc = (JSObject) win.getMember("document");
  form = (JSObject) doc.getMember("textForm");
  textField = (JSObject) form.getMember("textField");
  setLayout(new BorderLayout());
  Panel buttons = new Panel();
  Button displayTextButton = new Button("Display Text");
  displayTextButton.addActionListener(new ButtonEventHandler());
  buttons.add(displayTextButton);
  add("South",buttons);
 }
 public void paint(Graphics g) {
  g.setFont(font);
  g.drawString(text,30,30);
 }
 class ButtonEventHandler implements ActionListener {
  public void actionPerformed(ActionEvent e){
   String s = e.getActionCommand();
   if("Display Text".equals(s)) {
    text= (String) textField.getMember("value");
    win.eval("alert(\"This alert comes from Java!\")");
    repaint();
   }
  }
 }
}
```

There is another interesting paragraph in the press release:

"A server-side JavaScript script might pull data out of a relational database and format it in HTML on the fly. A page might contain JavaScript scripts that run on both the client and the server. On the server, the scripts might dynamically compose and format HTML content based on user preferences stored in a relational database, and on the client, the scripts would glue together an assortment of Java applets and HTML form elements into a live interactive user interface for specifying a net-wide search for information."

If you're too lazy to read it, the keyword is "A page might contain JavaScript scripts that run on both the client and the server." Did I read it correctly? In 1995, JavaScript could run on the server side?

Yes, that's right. My beloved JavaScript had already dominated the full stack 25 years ago. The code looks like this:

![Server side JavaScript](/img/js-history/js-server.png)

It looks a bit like PHP, where you can embed code that will be executed on the backend and output the result.

If you're interested in this, the original historical documents are still available, and the following documents will guide you step by step on how to write a backend application using JavaScript:

1. Server-Side JavaScript Reference
2. Writing Server-Side JavaScript Applications

If you want to learn more about this history, you can refer to [Server-side JavaScript a decade before Node.js with Netscape LiveWire](https://dev.to/macargnelutti/server-side-javascript-a-decade-before-node-js-with-netscape-livewire-l72).

If you want to search for information, you can use `Netscape LiveWire` as a keyword, not just `LiveWire JS`, because you will find [Laravel Livewire](https://laravel-livewire.com/), a full-stack framework based on Laravel.

## Conclusion

Java and JavaScript are indeed two different programming languages. Although the name JavaScript was chosen for marketing reasons, it cannot be denied that some of its features were influenced by Java.

In [JavaScript creator Brendan Eich | True Technologist Ep 1](https://www.youtube.com/watch?v=WqMbzVWIAjY&t=1326s&ab_channel=InfoWorld), the father of JavaScript, Brendan Eich, also briefly mentioned some of the history of that time. In addition, there are also opinions on TypeScript and WebAssembly. If you are interested, you can listen to it.

This article only mentions a small part of the history, and there are many interesting stories after that. However, I think I can't write better than "JavaScript: The First 20 Years", so I will stop here for the history part.

If you are interested in learning more about the early design and history of JavaScript, I recommend this book again.

References:

1. [Wikipedia: Java applet](https://zh.wikipedia.org/wiki/Java_applet)
2. [Wikipedia: JavaScript](https://zh.wikipedia.org/wiki/JavaScript)
3. [Taiwan Internet Development Chronology (1985~2014)](http://www.myhome.net.tw/timeline/images/internet_timeline02.pdf)
4. [Re: applet is about to become history?](https://www.ptt.cc/bbs/java/M.1366527781.A.869.html)
5. [Understand "The World of JavaScript" in 10 Minutes](https://www.slideshare.net/ccckmit/javascript-65883956)
6. [JS history](https://www.jianshu.com/p/208019383aa2)
7. [New era, new trend WebOS [17] Do you need JavaScript](https://www.ifanr.com/17760)
8. [The Hard Exploration of Technical Applications](https://www.ithome.com.tw/voice/134976)
9. [Java-to-Javascript Communication](http://www.gedlc.ulpgc.es/docencia/lp/documentacion/javadocs/guide/plugin/developer_guide/java_js.html)
10. [Using JavaScript in an Applet: Applet Jar «Development« JavaScript DHTML](http://www.java2s.com/Code/JavaScript/Development/UsingJavaScriptinanApplet.htm)
11. [NETSCAPE AND SUN ANNOUNCE JAVASCRIPT, THE OPEN, CROSS-PLATFORM OBJECT SCRIPTING LANGUAGE FOR ENTERPRISE NETWORKS AND THE INTERNET](https://web.archive.org/web/19970614002809/http://home.netscape.com:80/newsref/pr/newsrelease67.html)
12. [JavaScript: The First 20 Years](http://www.wirfs-brock.com/allen/posts/866)
