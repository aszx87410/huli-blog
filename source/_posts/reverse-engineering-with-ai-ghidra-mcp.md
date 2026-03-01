---
title: 感謝 AI 讓我這外行人也能做簡單的逆向工程
date: 2026-03-01 13:20:08
catalog: true
tags: [Security]
categories: [Security]
photos: /img/reverse-engineering-with-ai-ghidra-mcp/p5.png
---

最近碰到一個場合拿到了個 Golang HTTP server 的 binary，需要把它拆開進一步研究，找到通往下一步的線索。

但關於逆向工程這件事情，我是很陌生的。我只會把 binary 丟到 Ghidra 裡面，接著就什麼都不會了，我連搜尋字串都不會。

不過現在 AI agent 已經進化得很快了，只要工具運用得當，像我這種的逆向外行人，也能簡單靠 AI 做基礎的逆向工程，這篇就來記錄一下步驟。

先寫在前面，我拿到的跟這次示範的都是比較小的程式，如果是更大或更複雜的我也不知道能不能跑。我也不會覺得 AI 可以完全取代人原本需要做的部分，但鐵定能讓部分任務變得更輕鬆。

而像我這樣的外行人，原本能逆出的東西接近沒有，靠 AI 之後能給一些線索都好，就算是亂講的也有一些些參考價值，有總比沒有好嘛，亂講的我還能想辦法再去驗證。至於原本就會逆向的，我也不確定 AI 有沒有幫助，或者是他們會怎麼用，這個不在本篇的討論範圍。

<!-- more -->

## 環境準備

為了示範整體流程，先隨意讓 AI 寫了個有註冊、登入跟上傳檔案功能的 Golang server，檔案結構是：

```
.
├── config
│   └── config.go
├── go.mod
├── go.sum
├── handlers
│   ├── auth.go
│   ├── avatar.go
│   └── user.go
├── main.go
├── Makefile
├── middleware
│   └── auth.go
├── models
│   └── user.go
├── routes
│   └── routes.go
└── uploads
```

內容的話，貼幾個最主要的檔案上來就好，一個是 route：

``` go
package routes

import (
  "database/sql"

  "github.com/gin-gonic/gin"

  "membership-api/config"
  "membership-api/handlers"
  "membership-api/middleware"
)

func Setup(db *sql.DB) *gin.Engine {
  r := gin.Default()

  authHandler := handlers.NewAuthHandler(db)
  userHandler := handlers.NewUserHandler(db)
  avatarHandler := handlers.NewAvatarHandler(db)

  authMiddleware := middleware.AuthMiddleware(config.JWTSecret)

  api := r.Group("/api")
  {
    // 公開端點
    api.POST("/register", authHandler.Register)
    api.POST("/login", authHandler.Login)

    // 需登入端點
    api.GET("/users/:id", authMiddleware, userHandler.GetUserByID)
    api.GET("/me/messages", authMiddleware, userHandler.GetMyMessages)
    api.POST("/me/avatar", authMiddleware, avatarHandler.Upload)
  }

  return r
}
```

再來是刻意埋的兩個漏洞，註冊時的 SQL injection：

``` go
package handlers

import (
  "database/sql"
  "fmt"
  "net/http"
  "time"

  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v5"

  "membership-api/config"
  "membership-api/middleware"
  "membership-api/models"
)

type RegisterRequest struct {
  Username string `json:"username" binding:"required"`
  Email    string `json:"email" binding:"required"`
  Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
  Username string `json:"username" binding:"required"`
  Password string `json:"password" binding:"required"`
}

type AuthHandler struct {
  DB *sql.DB
}

func NewAuthHandler(db *sql.DB) *AuthHandler {
  return &AuthHandler{DB: db}
}

func (h *AuthHandler) Register(c *gin.Context) {
  var req RegisterRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
    return
  }

  passwordHash, err := models.HashPassword(req.Password)
  if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
    return
  }

  // 刻意保留的 SQL injection 漏洞：使用字串拼接而非參數化查詢
  query := fmt.Sprintf("INSERT INTO users (username, email, password_hash) VALUES ('%s', '%s', '%s')",
    req.Username, req.Email, passwordHash)
  _, err = h.DB.Exec(query)
  if err != nil {
    c.JSON(http.StatusConflict, gin.H{"error": "username or email already exists"})
    return
  }

  c.JSON(http.StatusCreated, gin.H{"message": "registration successful"})
}
```

以及上傳檔案時的 path traversal：

``` go
package handlers

import (
  "database/sql"
  "net/http"
  "path/filepath"

  "github.com/gin-gonic/gin"

  "membership-api/config"
  "membership-api/middleware"
)

type AvatarHandler struct {
  DB *sql.DB
}

func NewAvatarHandler(db *sql.DB) *AvatarHandler {
  return &AvatarHandler{DB: db}
}

func (h *AvatarHandler) Upload(c *gin.Context) {
  userID, ok := middleware.GetUserID(c)
  if !ok {
    c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
    return
  }

  file, err := c.FormFile("avatar")
  if err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "missing avatar file"})
    return
  }

  // 刻意保留的 path traversal 漏洞：直接使用 file.Filename，未經 filepath.Clean 或 filepath.Base 過濾
  // 攻擊者可上傳 filename="../../../etc/passwd" 等路徑穿越到系統其他位置
  savePath := filepath.Join(config.UploadDir, file.Filename)
  if err := c.SaveUploadedFile(file, savePath); err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
    return
  }

  // 更新 user 的 avatar_path
  _, err = h.DB.Exec("UPDATE users SET avatar_path = ? WHERE id = ?", file.Filename, userID)
  if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update avatar"})
    return
  }

  c.JSON(http.StatusOK, gin.H{"message": "avatar uploaded", "path": file.Filename})
}

```

寫完之後呢，用這個指令去 build，把該拿的都拿掉，模擬更真實的情境：

``` sh
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o dist/membership-api .
```

## 前置作業

因為我們的 binary 是 stripped 的，相關符號都被拿掉了，因此找個好用的 plugin 可以更方便幫我們還原 Golang 相關的東西，我選的是這個：https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension

在分析的時候記得把相關選項勾上：

![analysis](/img/reverse-engineering-with-ai-ghidra-mcp/p1.png)

分析完以後，在 Ghidra 中其實就能看到更詳細的資訊了：

![golang analysis](/img/reverse-engineering-with-ai-ghidra-mcp/p2.png)

![c code](/img/reverse-engineering-with-ai-ghidra-mcp/p3.png)

但這樣也還是手動去看嘛，像我這種根本不會操作 Ghidra 的人，只會把 binary 丟進去而已，要我看我也不知道怎麼看。

因此我們再來裝個真正讓 AI 跟 Ghidra 搭上線的東西：[GhidraMCP](https://github.com/LaurieWired/GhidraMCP)，這個有大概兩三個版本用的人好像都滿多，我就隨意挑了一個看起來文件寫得比較好，比較方便跑起來的。

裝好並且在 Ghidra 啟用之後，在 AI 那邊配置好 MCP，例如說我用的是 Cursor，就這樣配：

``` json
{
  "mcpServers": {
    "ghidra": {
      "command": "python",
      "args": [
        "/app/GhidraMCP-release-1-4/bridge_mcp_ghidra.py",
        "--ghidra-server",
        "http://127.0.0.1:8080/"
      ]
    }
  }
}
```

到這一步為止，前置作業就準備好了。

話說我拿來示範的是 Cursor，但其實只要是 AI agent 都行，你用 codex、claude code、open code 什麼的都一樣，能接 MCP 就都可以。

## 開始使喚 AI agent 做事

接下來就是用嘴逆向的時候了，我就只是這樣先跟他講而已：

> 我現在正在逆向一個 golang 的 binary，請幫我使用 ghidra MCP 協助，幫我看一下他是什麼樣的程式，有哪些功能

他就會開始自己呼叫 MCP，搜尋他想要的東西：

![mcp call](/img/reverse-engineering-with-ai-ghidra-mcp/p4.png)

最後給出了這個 binary 用到的 library：

![reversed libraty](/img/reverse-engineering-with-ai-ghidra-mcp/p5.png)

以及 API 路由：

![reversed api route](/img/reverse-engineering-with-ai-ghidra-mcp/p6.png)

認證相關的邏輯：

![auth logic](/img/reverse-engineering-with-ai-ghidra-mcp/p7.png)

還有推測出的檔案結構：

![file structure](/img/reverse-engineering-with-ai-ghidra-mcp/p8.png)

接著我就讓他根據推測出來的結構，幫我再把反編譯得到的 C 弄回去 Golang，他就列了幾個 todo 之後開始他的工作：

![c to golang](/img/reverse-engineering-with-ai-ghidra-mcp/p9.png)

結果它逆向出來的 routes.go 長這樣：

``` go
package routes

import (
  "database/sql"

  "github.com/gin-gonic/gin"
  "membership-api/handlers"
  "membership-api/middleware"
)

func Setup(db *sql.DB) *gin.Engine {
  r := gin.Default()

  authHandler := &handlers.AuthHandler{DB: db}
  userHandler := &handlers.UserHandler{DB: db}
  avatarHandler := &handlers.AvatarHandler{DB: db, UploadPath: "uploads"}

  // 公開路由 - 不需要認證
  api := r.Group("/api")
  {
    api.POST("/register", authHandler.Register)
    api.POST("/login", authHandler.Login)
  }

  // 需要認證的路由
  apiAuth := r.Group("/api")
  apiAuth.Use(middleware.AuthMiddleware())
  {
    apiAuth.GET("/users/:id", userHandler.GetUserByID)
    apiAuth.GET("/my-messages", userHandler.GetMyMessages)
    apiAuth.POST("/avatar", avatarHandler.Upload)
  }

  return r
}
```

程式碼的結構跟原始的有些微不同，代表沒有作弊（？），話說我是讓他在不同 context 底下跑的，所以他確實是看不到原本的 Golang 原始碼沒錯。

總之，反推回來的程式碼清晰可讀，但有小部分錯誤，例如說 `/my-messages` 這個不存在，應該是 `/me/messages` 才對。`/avatar` 也應該是 `/me/avatar`，看來有部分地方應該被偷懶跳過了。

而註冊的地方則是這樣：

``` go
func (h *AuthHandler) Register(c *gin.Context) {
  var req RegisterRequest
  if err := c.ShouldBindJSON(&req); err != nil {
    c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
    return
  }

  hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
  if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
    return
  }

  query := `INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)`
  _, err = h.DB.ExecContext(c.Request.Context(), query, req.Username, req.Email, string(hashedPassword))
  if err != nil {
    c.JSON(http.StatusConflict, gin.H{"error": "username or email already exists"})
    return
  }

  c.JSON(http.StatusCreated, gin.H{"message": "registration successful"})
}
```

原本故意留做 SQL injection 的地方，現在反倒被修好了，代表他逆向出來的是錯的。

不過檔案上傳的那個 path traversal 還在，而且他有輕鬆找出來：

![vulnerability](/img/reverse-engineering-with-ai-ghidra-mcp/p10.png)

上面的結果因為我額度快用完了，所以是用 Cursor 自己出的 composer 1.5 模型，沒這麼聰明。

我換成 Opus 4.6 以後，同樣的 prompt 它還原完成之後還順便幫我做了個資安檢查，該找的漏洞有找出來，只是 route 的部分依舊有錯，`/me` 變成了 `/my`，我以為這些應該是可以完整被還原的？

![opus findings](/img/reverse-engineering-with-ai-ghidra-mcp/p11.png)

## 結語

得益於 AI agent 的進化外加 MCP 的機制，讓 agent 可以自由操作許多不同的軟體來幫助自動化。

老實說，我在逆向這件事情上有體驗到那些所謂的 vibe coder 在做產品時的喜悅，也就是：「沒想到不會寫 code 的我也可以弄出一個網站，雖然我不知道原理，但東西好像做出來了」。

但 vibe coding 會有許多不會寫 code 沒辦法發現的小問題，純靠 AI 逆向我想也是相同的。就像我一開始用 composer 1.5，出來的結果是錯的一樣。但換個方式想，整體流程跟 API endpoints 這些都是對的，也算是收穫不少了。

原本靠自己的話是 0 分，靠 AI 可以先拿到保底 60 分，怎麼想都很賺。

時代在進化，工具在進步，這篇想記錄一下自己靠著這些工具，用 AI agent 做簡單的逆向工程的流程。雖然說最後跑出來的結果還是有些許錯誤，但對於一個 web server 來說，拿到 binary 逆向之後得到的東西可以再結合動態測試去驗證，就算有點小錯誤，還是對於整體測試幫助很大。

這次跑完之後，我還是會覺得逆向工程很難，也還是覺得懂逆向的人很厲害。畢竟我這次跑的是小的 binary，大的我就不確定會怎樣了。
