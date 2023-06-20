---
title: CPSA (CREST Practitioner Security Analyst) Exam Experience
date: 2021-12-15 13:00:00
tags: [Security]
categories: [Security]
photos: /img/crest-cpsa-prepare/cover-en.png
---

There is very little information available in Chinese about CREST, the organization, and CPSA, the certification. In Taiwan, it is considered a relatively obscure certification. I gained a basic understanding of this organization and certification after reading this article: [ECSA v10 Equivalent Application CREST CPSA Security Analyst Certification Tutorial / ECSA with CPSA Equivalency Recognition Step](https://medium.com/blacksecurity/crestcpsa-5a07e25e7da3).

In December, I took the CPSA certification exam with a colleague and we both passed. I am writing this post to share my experience.

<!-- more -->

## Introduction to CPSA

Let me briefly introduce CPSA, which stands for CREST Practitioner Security Analyst. It is an entry-level certification offered by CREST. The CREST series chart on the official website shows that CPSA belongs to the penetration testing category and is the most basic certification in this category:

![](/img/crest-cpsa-prepare/p1.png)

This certification is also listed in the [Professional List of Information Security Certifications](https://nicst.ey.gov.tw/Page/D94EC6EDE9B10E15/3386e586-1930-4f48-9b5e-1c9f256b7549) published by the Executive Yuan:

![](/img/crest-cpsa-prepare/p2.png)

The official website provides the following description of CPSA:

> The CREST Practitioner Security Analyst (CPSA) examination is an entry-level examination that tests a candidate’s knowledge in assessing operating systems and common network services at a basic level below that of the main CRT and CCT qualifications.  The CPSA examination also includes an intermediate level of web application security testing and methods to identify common web application security vulnerabilities.

This means that CPSA is an entry-level certification that tests basic knowledge of operating systems, network security, and intermediate-level knowledge of web security. The exam consists of 120 multiple-choice questions with five options each, and candidates have two hours to complete the exam. The exam must be taken at a specific test center (Pearson Vue test centers).

## CPSA Exam Content and Preparation

The CPSA official website provides a detailed [outline](https://www.crest-approved.org/wp-content/uploads/crest-crt-cpsa-technical-syllabus-2.4.pdf) of the exam content. However, I prefer the simplified version provided by the [CPSA course](https://icsiglobal.com/all-courses-list/29-crest-cpsa-exam-preparation-cpsa/region-UK/), which gives a basic understanding of the exam content after a quick read:

### Module 1: Soft Skills and Assessment Management

1. Engagement Lifecycle
2. Law and Compliance
3. Scoping
4. Understanding, Explaining and Managing Risk
5. Record Keeping, Interim Reporting and Final Results

### Module 2: Core Technical Skills

1. IP Protocols
1. Network Architectures
1. Network mapping and Target Identification
1. Filtering Avoidance Techniques
1. OS Fingerprinting
1. Application Fingerprinting and Evaluating Unknown Services
1. Cryptography
1. Applications of Cryptography
1. File System Permissions
1. Audit Techniques

### Module 3: Background Information Gathering and Open Source

1. Registration Records
2. Domain Name Server (DNS)
4. Google Hacking and Web Enumeration
5. Information Leakage from Mail Headers

### Module 4: Networking Equipment

1. Management Protocols
1. Network Traffic Analysis
1. Networking Protocols
1. IPsec
1. VoIP
1. Wireless
1. Configuration Analysis

### Module 5: Microsoft Windows Security Assessment

1. Domain Reconnaissance
1. User Enumeration
1. Active Directory
1. Windows Passwords
1. Windows Vulnerabilities
1. Windows Patch Management Strategies
1. Desktop Lockdown
1. Exchange
1. Common Windows Applications

### Module 6: UNIX Security Assessment

1. User Enumeration
1. UNIX/Linux Vulnerabilities
1. FTP
1. Sendmail/SMTP
1. Network File System (NFS)
1. R-Services
1. X11
1. RPC Services
1. SSH

### Module 7: Web Technologies

1. Web Server Operation & Web Servers and Their Flaws
1. Web Enterprise Architectures
1. Web Protocols
1. Web Markup Languages
1. Web Programming Languages
1. Web Application Servers
1. Web APIs
1. Web Sub-Components

### Module 8: Web-Testing Methodologies

1. Web Application Reconnaissance
1. Threat Modelling and Attack Vectors
1. Information gathering from Web Mark-up
1. Authentication Mechanisms
1. Authorisation Mechanisms
1. Input Validation
1. Information Disclosure in Error Messages
1. Use of Cross Site Scripting (XSS)
1. Use of Injection Attacks
1. Session Handling
1. Encryption
1. Source Code Review

### Module 9: Web Testing Techniques

1. Web Site Structure Discovery
1. Cross Site Scripting Attacks
1. SQL Injection
1. Parameter Manipulation

### Module 10: Databases

1. Databases
1. Microsoft SQL Server
1. Oracle RDBMS
1. MySQL

You will find that the exam content is quite extensive, covering almost everything, and a little bit of everything is tested. Therefore, at the beginning, I found it difficult to prepare and didn't know where to focus.

So the first thing I did was to search for some English exam experience online:

1. [CREST CPSA Exam](https://www.reddit.com/r/AskNetsec/comments/9qionx/crest_cpsa_exam/)
2. [Taking the CPSA (Crest Practitioner Security Analyst) Exam](https://blog.rothe.uk/taking-the-cpsa-exam/)
3. [CREST Practitioner Security Analyst (CPSA) Exam - Study Guide](https://www.linkedin.com/pulse/crest-practitioner-security-analyst-cpsa-exam-study-jean/)

The third one is the most detailed and has a lot of reference materials and resources, which I found very helpful.

Here are some directions I prepared myself:

1. The full names of various proprietary terms, such as what HTTP or SSL stands for.
2. Network-related knowledge, including the OSI model and protocols such as IP, TCP, UDP, and ICMP.
3. Basic understanding of common encryption algorithms (such as DES, AES, and RSA) and hash functions (such as MD5 and SHA1).
4. DNS-related knowledge.
5. Which ports are used by common services.

Since I consider myself more familiar with web-related topics, I didn't prepare much for that area and focused on the above topics instead.

The passing score for CPSA is 60% correct answers. My strategy was to focus on the above topics and skip the ones I found difficult or didn't want to study. So there were some topics on the exam outline that I had never even looked at before, and I had to guess on those questions during the exam.

My main resource for preparation was not the official recommended books, which I found boring and lengthy, but rather a GitHub repository that a colleague found, which had some useful summaries of key points.

Overall, I found the exam not too difficult but a bit tedious. If you are already familiar with network-related knowledge (to the point where you can answer network-related questions in a computer science course), and have basic web knowledge, studying for a week or two should be enough to pass.

## CPSA Exam

The registration fee for the exam is $400 USD, which is about NT$11,000. There seem to be only two exam centers in Taiwan, one in Taipei and one in Kaohsiung. The Taipei exam center is near the Xinyi District City Hall MRT station: https://goo.gl/maps/2hCkEpEidb8WbYQw7

You need to arrive 30 minutes early for check-in. Once you enter the exam room, you need to store all your belongings in a locker and cannot access any books or materials. So if you want to review anything, it's best to do it outside the exam room. Then you go through the check-in process, where you need to bring your passport and a signed document (I used my credit card) and take a photo.

After that, you will be taken to the testing area, where there are many individual computer desks separated by wooden boards. You take the exam on that computer, and you can mark questions for review later.

There doesn't seem to be a time limit for the exam, so you can submit your answers whenever you're finished. I think I took about an hour and a half. After submitting, the exam staff will come to your seat and escort you out. You can retrieve your belongings from the locker, and they will give you a printed result sheet with your score and pass/fail status, as well as your performance in each major category.

I barely passed, but I made it. A few days later, I received the certificate from CREST.

## Conclusion

Overall, I found the exam not too difficult but a bit tedious. My network knowledge is weak, so I lost some points there. If you are already familiar with network-related knowledge and have basic web knowledge, you should be able to pass the exam with some preparation.

Although the certification is not well-known in Taiwan, it has some recognition in some places abroad. If you have OSCP, you can use it to exchange for another CRT certification. For me, I just wanted to take the exam and be prepared for the future.

If you are interested, you can try taking the exam. If you have any related questions, you can leave a comment below, and I will try to answer within my ability.
