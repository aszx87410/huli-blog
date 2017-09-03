---
title: '自架gitlab心得'
date: 2015-08-11 11:13
catalog: true
header-img: "/img/header_img/article-bg.png"
tags: [other]
---
gitlab真的是安裝方便又使用順利
一開始在一台本來上面就有一些服務，像是nginx的機器上面裝
裝好以後失敗然後又覆蓋掉原本的東西

於是只好新開一台來裝
一開始開ubuntu 14.04，發現裝的地方有錯誤
改用centos 6，順利裝好以後在某些操作時出現500錯誤
去看了一下rails的log再google一下，發現是記憶體不夠
gitlab最低要求是2g(ram+swap)

不得不說，gitlab的安裝步驟超級簡單
開一台全新的機器照著 https://about.gitlab.com/downloads/
上面的步驟執行就好，什麼都不用改

這邊是gitlab的系統需求
https://gitlab.com/gitlab-org/gitlab-ce/blob/master/doc/install/requirements.md

