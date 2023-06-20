---
title: Preparation Experience for Japan's FE and SG Exams for Zero-Day Japanese Beginners
catalog: true
date: 2023-04-14 15:10:44
tags: [Security]
categories: [Security]
photos: /img/how-to-prepare-japan-fe-and-sg-exam/cover.png
---

Recently, as a beginner in Zero-Day Japanese, I started studying and passed Japan's Basic Information Technology and Information Security Management exams. In this post, I will share how I prepared and what exam techniques I used.

The outline of the article is as follows:

1. Why take these two exams?
2. Introduction to relevant certifications from Japan's IPA
3. What is covered in the Information Security Management exam?
4. What is covered in the Basic Information Technology exam?
5. How did I prepare for the exams? What was my strategy?
6. How are the exams conducted?
7. Exam experience and scores

<!-- more -->

## Why take these two exams?

If you want to work in Japan, you will need to apply for a work visa. Engineers will apply under a category called "Technical/Humanities Knowledge/International Services," and the detailed qualifications that can be applied for are listed on the website of the [Immigration Services Agency of Japan](https://www.moj.go.jp/isa/applications/status/gijinkoku.html). There is a PDF file called "[Regarding the criteria for activities and landing permits](https://www.moj.go.jp/isa/content/001366995.pdf)" (if the link is broken, the document may have been moved, but you can Google it with keywords) that lists the qualifications that can be applied for.

(By the way, some readers may have heard of the Highly Skilled Professional System. According to my understanding, even if you have a score of 70 for highly skilled professionals, you cannot apply for a visa if you do not meet the conditions below.)

One of the conditions is that you must prove that you have the professional ability to perform the job. How do you prove it?

1. Graduation from a university (or higher) in a related field
2. Graduation from a Japanese technical college
3. Ten or more years of work experience (strictly speaking, practical experience, which seems to include the period when you majored in related courses in school)

For the first point, I have heard of some cases where people who did not graduate in a related field were still able to obtain a visa.

But my situation is different. My highest educational qualification is high school graduation.

To supplement, it is said that depending on the size of the company, the data and qualifications that are looked at may be different. Therefore, in theory, whether you can pass or not still depends on the advice of a professional administrative scrivener, and whether you actually pass depends on how the Immigration Bureau judges it.

But anyway, our company consulted an administrative scrivener, and the conclusion was that it is unlikely that I can obtain a visa under my conditions.

If, like me, you only have a high school diploma and do not have ten years of work experience, what should you do? (Or if you cannot provide proof of ten years of experience, such as if your previous company went bankrupt and did not leave a resignation certificate, or if your labor insurance record can be used but I am not sure)

There is a special clause in the terms and conditions:

> However, if the applicant intends to engage in work that requires technical or knowledge related to information processing, and has passed an examination related to information processing technology specified by the Minister of Justice by public notice or has a qualification related to information processing technology specified by the Minister of Justice by public notice, this shall not apply.

According to Google Translate, the gist is that if you want to work in a technical field (like a software engineer), if you have the relevant certifications specified by the Minister of Justice by public notice, it can also prove that you have sufficient professional ability.

So what certifications are available?

They are listed here: "[Ministry of Justice Ordinance to establish the criteria for Article 7, Paragraph 1, Item 2 of the Immigration Control and Refugee Recognition Act regarding the special criteria for the status of residence for technical/humanities knowledge/international services](https://www.moj.go.jp/isa/laws/nyukan_hourei_h09.html)"

In addition to local certifications in Japan, certifications from countries such as Thailand, the Philippines, and South Korea, and even certifications from Taiwan are valid!

There is an organization called [ITPEC](https://www.itpec.org/about/itpec.html), which basically means that several countries are working together to take the same exam, and the questions seem to be the English translation version of the Japanese exam.

In Taiwan, it is not included in that organization, and according to the list above, these three tests implemented by the Institute for Information Industry are valid:

1. Software Design Professional
2. Network Communication Professional
3. Information Security Management Professional

More detailed regulations are available here: "[Mutual Recognition: About Taiwan's Examination System](https://www.ipa.go.jp/jinzai/asia/mutual-recognition/taiwan.html)"

And there are a few lines of small print at the bottom:

> Regarding Taiwan's examination system, it was transferred from the Taiwan Ministry of Economic Affairs to CSF/III at the end of 2012. In conjunction with this, we concluded a Mutual Cooperation Agreement (MCA) on January 21, 2013, which sets out the cooperation between the two countries regarding the examination. As a result, the relaxation measures for obtaining a work visa for Taiwan's examinations apply only to those who passed the examinations by the end of 2012 approved by the Taiwan Ministry of Economic Affairs.

According to a previous discussion on [PTT](https://www.pttweb.cc/bbs/Oversea_Job/M.1564991664.A.52F), it seems to mean that only those who took the exam before 2012 are valid. However, according to the result of my company directly asking the Immigration Bureau, those lines do not seem to mean that, so it is still valid if you take the exam now.

So, as for whether these exams are still effective in Taiwan, I can only say that I don't know. Therefore, if someone wants to pursue this path, they can ask through their Japanese friends or administrative scriveners to get a more accurate answer.

These certifications, in addition to serving as proof of qualification for applying for a work visa, are also scored in the highly skilled system's scoring table. One certification is worth 5 points, and up to two certifications can be used, so passing two certifications will give you an additional 10 points. It sounds good, doesn't it?

In summary, there are two benefits to obtaining relevant certifications:

1. You can obtain a Japanese engineer work visa without a university degree or ten years of work experience (in theory, I am still testing this in person).
2. You can earn points in the highly skilled system.

So how do you obtain these certifications? There are three ways:

1. Take the exam at a location that cooperates with ITPEC (I have heard of people going to places like the Philippines and Thailand).
2. Take the exam in Taiwan (but it is uncertain whether it is effective, so you need to ask for more information).
3. Take the exam directly in Japan, and the certifications obtained are definitely valid.

The first option can be referred to in [ITPEC Exam: Be an Engineer in Japan Without a Degree](https://ib-tec.co.jp/career-advice/itpec-exam-be-an-engineer-in-japan-without-a-degree/) and [Getting a Visa as an Engineer in Japan](https://japan-dev.com/blog/getting-a-visa-as-an-engineer-in-japan), which provide relevant information.

This article mainly discusses the third option, which is to take the exam directly in Japan.

## Introduction to Japanese IPA Certifications

The certifications we want to obtain are administered by the Information-technology Promotion Agency, Japan (IPA). The current exam system is clearly explained in the following figure, taken from: https://www.ipa.go.jp/shiken/kubun/list.html

![Exam System](/img/how-to-prepare-japan-fe-and-sg-exam/p1.png)

Starting from the bottom left, there is an exam called IT passport, which is the easiest and has the highest pass rate, but it is not useful and cannot be used to apply for a work visa or earn points in the highly skilled system.

Above that is the Information Security Management Exam, or SG for short, which is the second easiest and has the second highest pass rate. We will discuss this exam later.

Next, in the middle row, the Basic Information Technology Engineer Exam, or FE for short, is the third easiest but already has some difficulty. It covers topics such as computer science and programming.

Above that is the Applied Information Technology Engineer Exam, or AP, which is even more difficult, and there are various specialized exams that are even more challenging.

In summary, for our goal (obtaining Japanese IT certifications), the two most suitable certifications are:

1. SG Information Security Management Exam
2. FE Basic Information Technology Engineer Exam

There is little information about these exams in Chinese, so I would like to thank this Zhihu article for introducing this exam system in detail: [This may be the most detailed explanation of the Information Technology Engineer Exam (with review websites)](https://zhuanlan.zhihu.com/p/354557310), which has been very helpful to me.

## What is covered in the Information Security Management Exam?

I personally think that the exam content is similar to the work of colleagues who work on the blue team (defense side) in a company's cybersecurity department. The official website describes it as follows:

> In the department that uses information systems, the person who understands the purpose and content of the information security measures necessary for the department's business and the information security regulations (including the organization's internal regulations, including the information security policy) appropriately as an information security leader, realizes and maintains and improves the situation where information security is ensured, and utilizes information and information systems safely.

Therefore, the exam content will include some technical aspects, such as knowing the basic types of attacks, what DoS, XSS, and SQL injection are, and some basic encryption and decryption, such as understanding symmetric and asymmetric encryption and how to use these cryptographic tools for verification.

As for management, some are regulations, and some are measures for cybersecurity management.

I happened to have switched to cybersecurity before, and although I mainly focused on technical aspects, some of the things I learned were helpful for this exam, such as knowing what SOC (Security Operation Center) and IR (Incident Response) are.

The exam lasts for 120 minutes and consists of 60 multiple-choice questions. There are 48 questions in Section A, which are single-choice questions, and 12 questions in Section B, which are single-choice questions with multiple options (such as eight options to choose from).

(The reason for dividing it into Sections A and B is that the two subjects used to be tested separately, but now they are combined into one exam.)

The full score is 1000 points, and 600 points are required to pass. The scoring system is not disclosed.

After discussing so much about the exam system, you may want to see what the actual questions look like. Below, I will randomly select one or two questions from the official questions for everyone to see.

This is a question from subject A, from the autumn of the first year of Reiwa, question 18:

Q: What is WPA3?

A: Encryption standard for HTTP communication
B: Encryption standard for TCP/IP communication
C: Digital certificate standard used in web servers
D: Security standard for wireless LAN

This is also a question from subject A, from the spring of the 31st year of Heisei, question 11:

Q: What is the purpose of using SPF (Sender Policy Framework)?

A: Detecting man-in-the-middle attacks on HTTP communication routes.
B: Detecting unauthorized connections to PCs on LAN.
C: Detecting unauthorized intrusions into internal networks.
D: Detecting email sender spoofing.

As for subject B, it is more like an application question, because it is difficult to write tables and pictures here. I will briefly describe it. If you want to see the real questions, you can go here: https://www.ipa.go.jp/news/2022/shiken/gmcbt80000007cfs-att/sg_set_sample_qs.pdf

For example, the 50th question above will give you a risk assessment table and guidelines, and then blank out several places in the table, asking you how many points should be filled in according to the above data.

I think if you have worked in a large company, you may have an advantage in this subject, because large companies usually have more security management regulations, so as the managed party, you will probably know what measures the company has.

## What is the Fundamental Information Technology Engineer Examination testing?

The English name for this exam is the Fundamental Information Technology Engineer Examination (FE), which is a basic knowledge exam for IT engineers.

The SG exam combines subjects AB and the scores are calculated together, while the FE exam is different, with the two subjects tested separately.

Subject A has 60 multiple-choice questions, and the test time is 90 minutes.

Subject B has 20 multiple-choice questions (such as eight choices), and the test time is 100 minutes.

The scores for both subjects are calculated separately, with a full score of 1000 points. Both subjects require a score of 600 or more to pass.

Some of the questions in subject A may overlap with SG, such as some basic information security concepts or risk concepts, etc. Other parts are mostly about computer fundamentals, such as binary arithmetic, two's complement, OSI seven-layer, etc., which are all within the scope of the exam.

Subject B is more interesting, testing code completion questions.

Here is an example question from the official exam questions released in the past, from the autumn of the 28th year of Heisei, question 19:

Q: What is the item used as the judgment criterion for page replacement in the LRU algorithm?

A: Time of last reference
B: Time of first reference
C: Reference frequency per unit time
D: Cumulative reference count

It is difficult to put subject B questions here, so please refer to this link: https://www.ipa.go.jp/news/2022/shiken/gmcbt80000007cfs-att/fe_kamoku_b_set_sample_qs.pdf

For example, the second question inside blanks out the famous FizzBuzz code and asks what should be filled in.

If you are not familiar with anything related to information security and are unfamiliar with all the terms, then FE may be a suitable exam for engineers.

## How did I prepare for the exam? What is the strategy?

I recommend two great websites that have past SG and FE exam questions for convenient practice:

1. SG https://www.sg-siken.com/
2. FE https://www.fe-siken.com/

The first thing I did was to take the SG mock exam, then use Google Translate to translate the questions and answer them. I found that I got 38 out of 50 questions correct, with a 76% accuracy rate.

Although the score was not very high, it means that my basic knowledge is sufficient to pass the exam. If the exam is in Chinese, I would probably pass.

This is a big premise of my exam strategy, assuming that the exam is in Chinese, and you must be able to pass the exam. This means that what you lack is not technical knowledge, but language.

So how do you solve the language problem?

As I briefly introduced earlier, there are three different types of characters in the exam questions:

1. Japanese hiragana
2. Japanese katakana
3. Kanji

My exam strategy is to give up the first one, and guess the meaning of the question based on the last two, and then choose the answer.

Japanese katakana is usually used to write loanwords, and for technical exams like SG and FE, they are mostly technical terms. For example, サーバ (server) is written directly in pinyin as "sa ba". If we are familiar with Japanese katakana and technical terms, then at least we can understand the keywords in the questions.

As for kanji, although some of the meanings of kanji are different from Chinese, they are the minority. In most cases (at least for this exam), they are similar to Chinese.

For example, the exam questions I posted earlier:

Q: What is the item used as the judgment criterion for page replacement in the LRU algorithm?

A: Time of last reference
B: Time of first reference
C: Reference frequency per unit time
D: Cumulative reference count

If you know what an LRU cache is, you can probably guess that the question is about how LRU decides which elements to replace, and the answer is A, based on the last referenced time. If you can read hiragana, the understanding of the question will become "What is the criterion used for page replacement in the LRU algorithm?" and you will have a better chance of grasping the keywords for answering.

So my exam strategy is simple, which is to "try to understand the question and capture the keywords by relying on learning hiragana, based on sufficient basic knowledge and the ability to read Chinese."

I have several advantages:

1. I am confident in taking exams and consider myself good at taking exams (after all, I have passed the entrance exam for National Taiwan University in high school and have confidence in studying and taking exams).
2. My basic knowledge is sufficient, and I have some experience in information security and engineering, and I have not forgotten the principles of computer science.

My original idea was to personally verify whether this exam strategy is effective, and then write an article to share my experience after the exam (even if I fail the exam).

Next, I will briefly describe my preparation steps and process.

At first, I decided to prepare for the SG exam, but later I also registered for the FE exam, which I will explain later. Anyway, my preparation process is the same for both exams.

### Step 1: Learn Hiragana

Yes, I don't even know hiragana. Although I attended two hiragana classes at a cram school about a year ago, I have almost forgotten everything, so I can be considered a beginner.

Because we value rapid learning, remember one thing: "Any method that can help you remember is a good method." Some hiraganas are difficult to remember, so there may be some mnemonics, which may be taught by friends or found online. As long as you can remember them, it is a good method.

Just like many English homophonic memory methods when we were young, my wife and I had a quarrel and went to the balcony, saying "I don't want to see you" anymore, balcony, which is the same pronunciation as "陽台" in Chinese.

I used some mobile apps to assist me, and I used [50音起源 - 日語五十音單詞學習](https://play.google.com/store/apps/details?id=com.kevinzhow.kanaoriginlite&hl=zh_HK).

I started learning hiragana on March 15th, and I seriously studied for two or three days. Except for a few that are easy to confuse, I have memorized almost all of them. Then, because the exam strategy is mainly based on hiragana, if you really want to save time, you can skip katakana. But I learned both together, and I think it's better to learn both together, and some are easier to remember.

I spent about five or six days on this step, including hiragana, katakana, contracted sounds, and voiced sounds. I need to think about the voiced sounds that I am not familiar with, and some katakana are still easy to confuse, and I am not very familiar with hiragana later, but it doesn't matter, I focus on katakana.

### Step 2: Read Books

My initial strategy was to learn while writing exam questions, but later I found that this was not systematic and the learning efficiency was not good, so I switched to buying books.

I bought [情報処理教科書 出るとこだけ！情報セキュリティマネジメント テキスト＆問題集［科目A］［科目B］2023年版](https://www.amazon.co.jp/-/zh/gp/product/B0BFGCSDGQ/ref=ppx_yo_dt_b_d_asin_title_o00?ie=UTF8&psc=1). I saw that it was the best-selling book, so I bought it.

I bought the Kindle version, but I don't have a Kindle, so I opened it with the Kindle app on my Mac. The e-book is all images, so I used the smart lens of my phone to take a picture of the computer screen to translate it and understand the content of the book, which is genius.

Then I took notes on the computer. I read all the hiraganas that appeared in the book and re-typed them with Japanese input method on the notes, adding English or Chinese annotations. The notes look like this:

1. ハッカー(hacker)
2. ホワイトハッカー(white hacker)
3. クラッカー(cracker)
4. スクリプトキディ(scripe kiddie)
5. ソーシャルエンジニアリング(social engineering)

Typing once with the input method will make it more memorable, and I will not forget it next time I see it.

If there are some things that I don't know the meaning of even if I read them, I will write down what they are doing, like this:

1. 類推攻擊：Use personal information such as ID and name to guess the password.
2. 辭書攻擊：Dictionary attack
3. プルートフォース　(brute force)：Guess the password
4. リバースブルートフォース (reverse brute force)：Guess the account with a fixed password
5. パスワードリスト (password list)：Use other service's account and password to try, be careful not to confuse with dictionary attack
6. レインボー 攻擊 (rainbow)

I took notes on every page of the book like this, and there were a lot of hiraganas in the notes, and my accuracy and speed of reading hiragana gradually improved.

Then, for some things that I don't even know what they are, I will record them separately, such as:

1. ウイルス virus
2. アカウント account
3. キャッシュ cache
4. パターン　pattern
5. トランザクション transaction

I will record them separately, and it will be easier to review later.

Reading books took the most time, and it took me almost two weeks to finish reading the book. The main time-consuming part was procrastination and copying hiragana. About 60-70% of the knowledge in the book was what I already knew, and the other 30-40% was related to Japanese regulations or risk management, which required more time to learn.

At the end of the book, there is a simulated test, and I remember getting around 68% on it.

Step 3: Practice Exam

There was a link to practice earlier, and I followed the years to answer the questions. After answering the questions, be sure to read the explanations, and you can use Google Translate to understand them.

Below are my scores after the first round:

- Spring 2016: 80%
- Fall 2016: 80%
- Spring 2017: 78%
- Fall 2017: 82%
- Spring 2018: 86%
- Fall 2018: 72%
- Spring 2019: 82%
- Fall 2019: 68%

At this point, I felt that the learning effect of reading the book had come out. On the one hand, some of the questions appeared in the book, and on the other hand, my ability to grasp keywords and read hiragana became stronger.

At this point, you need to start learning some basic Japanese and kanji.

Don't worry, what you need to learn is very basic. You must know which common usage is "negative usage," otherwise, you will answer incorrectly.

As for how to know, it is actually quite easy to collect from the wrong questions in the practice exam. For example, if you answer incorrectly because you don't know it is negative, just copy it down. Here are some notes I wrote:

- できない: cannot
- せず: negative form
- Many verbs are followed by ず, which seems to be negative
- なし: none
- なく: without

In short, if you see なし, なく, and せず, it is negative, and the other 80% are positive.

But there are exceptions. For example, if the question contains "なければならない," after checking, I found that it means "must," and you think it is negative, but it is actually positive. For cases like this, I just let it go. If it really appears, I will just give up the score because it is too long and I can't remember it.

In addition, some kanji cannot be guessed and need to be memorized, such as:

- 手口: modus operandi
- 手間: time-consuming
- 役割: role
- 見直し: review
- 調達: procurement
- 目安: standard
- 働く人: employee
- 手当: allowance
- 取引: transaction
- 勝手: selfish
- 取組: effort
- 取扱: handling
- 口座: account

These are the kanji that will appear in the practice exam. If you don't understand them, just write them down.

At this point, we are almost complete. At this point, you:

1. Have sufficient basic knowledge and have reviewed the book again
2. Can read hiragana well, and can understand the English meaning of hiragana in the question
3. Can understand the basic negative usage of Japanese (the three tricks I mentioned earlier: なし, なく, and せず)
4. Know the meaning of the kanji that will appear in the question

After reaching this point, you can practice the practice exam again. I am too lazy to write all of them, so I picked a few years, and the scores are as follows:

- Spring 2016: 80% => 94%
- Fall 2016: 80% => 96%
- Fall 2018: 72% => 98%
- Fall 2019: 68% => 90%

This means that I have reviewed the questions I answered incorrectly before.

Exam strategy summary:

Prerequisites:

1. Sufficient knowledge of the exam content (at least 60-70% understanding)
2. Confidence in the exam

Learning and exam strategies:

1. Learn hiragana and understand the English technical terms translated from hiragana
2. Review hiragana and other knowledge in the book
3. Learn the knowledge that you did not understand before
4. Practice the practice exam to familiarize yourself with the questions
5. Find out the common negative usage of Japanese through the practice exam
6. Find out the meaning of the kanji that will appear in the question through the practice exam

The reason why this exam strategy is useful is that this is an IT exam, so hiragana appears frequently in the questions. In addition, kanji is commonly used in Japanese, so even if you don't understand Japanese, you can guess what the question is about by the kanji.

This is a bit like taking the TOEIC exam in the past. The strategy for English listening is to grasp the keywords. If you grasp the keywords, you don't need to fully understand the question to answer it.

How to take the exam?

Both the SG and FE exams originally had to be taken in a physical exam room, and they were only held twice a year.

Fortunately, these two exams will become on-demand exams starting in April 2023, and if you fail, you can take the exam again one month later. The exam method is a CBT computer exam, and the registration fee is 7,500 yen.

As a person who doesn't know Japanese at all, it is important to be familiar with the exam process and system usage in advance. You can refer to the resources I collected before:

It is also a CBT exam, and the interface is similar.
https://www.youtube.com/watch?v=dN7z4Y9MO_M
https://www.youtube.com/watch?v=xDmhY4Il8yM

Official screen, the only difference is that we don't have a report to print
https://www.youtube.com/watch?v=SFZI17TMeSU

The same system but different exam process, very similar
https://jpsk.jp/articles/cbtguide.html?p=2

Remember to bring your ID on the day of the exam. If you are already in Japan, you can bring your residence card. For me, I brought my passport.

When I went there, I just showed the screen of my phone to the receptionist (they will send a reminder letter the day before), and then they checked my ID. After confirming my identity, they showed me a sheet with my name on it and asked me to check it. After confirming, I read the exam rules and signed it.

After signing, you need to put all your belongings in the locker next to you, and then you will receive an L-shaped folder, which contains:

1. The sheet you just signed, with the account and password you will use to log in later
2. Exam operation instructions
3. The sign indicating which seat you will sit in
4. Pen
5. Calculation paper

Then go to the exam room and find the corresponding seat, click on the IPA exam with the mouse, enter the account and password on the paper to log in, and then the test will begin.

There will be a three-minute short tutorial on how to use it, which is similar to the video I posted above. I think the system is quite intuitive and easy to use.

After the exam, you will see your score directly, and there will be no score report printed out. After logging out of the system, you need to return everything you brought in, including the calculation paper, to the examination counter. The staff will thank you for your hard work and congratulate you on finishing the exam (I don't understand Japanese, so this is just a guess).

## Exam Experience and Scores

From memorizing the Hiragana and Katakana to taking the exam, it took about a month of preparation time. I didn't count how many hours I spent on it, but some weekdays I only prepared after work, and on weekends or when I took a day off, I spent more time studying.

I took the SG exam on the first day and scored 745 points.

Originally, I only registered for the SG exam, thinking that I would concentrate my efforts on this subject. However, when I was preparing, I found that the questions in the B subject were a bit long, and there were more Japanese characters, so I was afraid that my exam strategy would fail. Therefore, my strategy at that time was to get more than 80% in the A subject, so even if I failed all 12 questions in the B subject, it wouldn't matter.

But later, when I looked at the FE exam questions, I found that there were many code questions in the B subject of the FE exam. I thought it might be more advantageous for me, so I registered for the FE exam as well. If I failed, I could always retake it in a month.

So I basically didn't study for the FE exam. I wrote 20 questions from the past exams and found it too tiring and troublesome, so I gave up.

In fact, during the SG exam, I had enough time, and I finished writing with about 20 minutes left. After checking for 10 minutes, I handed in the paper.

As for the FE exam, it was on the second day. I scored 715 points in the A subject and 905 points in the B subject. I didn't expect my score to be higher than I thought.

The time for the A subject was tight, and I had almost no time to check after finishing writing, only about five minutes left. I think as long as you haven't forgotten everything you learned in the computer introduction course, you have a good chance of passing. In addition, the A subject also includes some cybersecurity topics, which overlap with the SG exam, so the cybersecurity part helped me score some points. It seems that taking both exams together is still somewhat advantageous.

On the other hand, the B subject was much easier than I thought. After finishing writing, I had time to check everything again, and I knew that my score wouldn't be too bad.

In conclusion, I think my exam strategy was effective. I was able to guess the meaning of the questions and options by using Hiragana and Kanji, even though I couldn't understand Japanese Katakana at all. Of course, this doesn't mean that 100% of the questions can be understood this way, but if 80% of the questions can be understood in this way, and you master 80% of them, you can get 64% of the score and pass the exam smoothly. Our goal is to pass the exam, not to learn Japanese or get a perfect score.

However, there is one variable that I am not sure about, which is whether the difficulty of the questions will change. Maybe I was lucky and the questions were easier. Also, I took the exam when the new system had just been launched, and the organizers might still be adjusting the difficulty, so it may become more difficult in the future.

Finally, those two exam websites have message boards for everyone to exchange exam experiences, where you can see how people with different backgrounds study and review, and what scores they get in the end:

1. SG https://www.sg-siken.com/bbs/1487.html
2. FE https://www.fe-siken.com/bbs/4784.html

In summary, if you want to work as an engineer in Japan in the future but don't have the qualifications or high scores, and you don't know Japanese like me, you can try my exam strategy and take the SG or FE exam. I think it's a good investment.

References:

1. [Basic Information Technology Engineer Examination in Japan](https://blog.gimo.me/posts/fundamental-information-technology-engineer-examination/)
2. [This may be the most detailed article explaining the Information Processing Engineer Examination (with review websites)](https://zhuanlan.zhihu.com/p/354557310)
