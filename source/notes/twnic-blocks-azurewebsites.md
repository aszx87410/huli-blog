---
layout: note
title: "TWNIC封鎖Azure網域"
date: 2025-07-10 20:07:59
---
繼 TWNIC 把 search.app、eu.org、Telegram (telegram.org)、HLS Player（hlsplayer.org） 跟 Archive.today 等等 Public Suffix / Service 相繼送進去之後
今天又送了一個大的
這次 ban 了 azurewebsites.net
不知道 azurewebsites.net 是什麼的，在這邊幫大家科普一下
這是微軟旗下雲端服務 Azure 用來讓使用者可以快速建立服務的
只要去申請，就會給你一個 <自訂ID>.azurewebsites.net
他這次直接把最上層 azurewebsites.net 擋掉
不知道會有多少服務會不能用

不過他也順帶把 icatch.azurewebsites.net
這是可取國際用來管底下設備的服務
同時他家的設備常常都是 DDoS 發起源
這樣不知道是好事還是壞事 XD
