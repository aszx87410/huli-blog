---
title: Using AI to Do Simple Reverse Engineering
date: 2026-03-01 13:20:08
catalog: true
tags: [Security]
categories: [Security]
photos: /img/reverse-engineering-with-ai-ghidra-mcp/p5-en.png
---

Recently, I encountered a situation where I got a Golang HTTP server binary and needed to disassemble it for further research to find clues for the next steps.

However, I am quite unfamiliar with reverse engineering. I only know how to throw the binary into Ghidra, and then I'm lost; I can't even search for strings.

But now AI agents have evolved rapidly. As long as the tools are used properly, even a reverse engineering layman like me can easily rely on AI to perform basic reverse engineering. This article will document the steps.

To start with, the program I received and the one demonstrated here are relatively small. I don't know if larger or more complex ones would work. I also don't believe AI can completely replace the tasks that humans originally needed to perform, but it can definitely make some tasks easier.

For someone like me, who originally could extract almost nothing, even getting some clues from AI is good. Even if it's nonsense, it has some reference value; having something is better than nothing. I can still find ways to verify the nonsense. As for those who already know how to reverse engineer, I'm not sure if AI would help them or how they would use it; that's beyond the scope of this discussion.

<!-- more -->

## Environment Preparation

To demonstrate the overall process, I randomly had AI write a Golang server with registration, login, and file upload features. The file structure is:

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

For the content, I'll just paste a few of the main files. One is the route:

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
    api.POST("/register", authHandler.Register)
    api.POST("/login", authHandler.Login)

    api.GET("/users/:id", authMiddleware, userHandler.GetUserByID)
    api.GET("/me/messages", authMiddleware, userHandler.GetMyMessages)
    api.POST("/me/avatar", authMiddleware, avatarHandler.Upload)
  }

  return r
}
```

Next are the two intentionally embedded vulnerabilities: SQL injection during registration:

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

And path traversal during file upload:

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

  savePath := filepath.Join(config.UploadDir, file.Filename)
  if err := c.SaveUploadedFile(file, savePath); err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save file"})
    return
  }

  _, err = h.DB.Exec("UPDATE users SET avatar_path = ? WHERE id = ?", file.Filename, userID)
  if err != nil {
    c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update avatar"})
    return
  }

  c.JSON(http.StatusOK, gin.H{"message": "avatar uploaded", "path": file.Filename})
}

```

After writing it, I used this command to build it, removing everything that shouldn't be there to simulate a more realistic scenario:

``` sh
CGO_ENABLED=0 go build -ldflags="-s -w" -trimpath -o dist/membership-api .
```

## Preliminary Work

Since our binary is stripped, all related symbols have been removed. Therefore, finding a useful plugin can help us restore Golang-related information more conveniently. I chose this one: https://github.com/mooncat-greenpy/Ghidra_GolangAnalyzerExtension

When analyzing, remember to check the relevant options:

![analysis](/img/reverse-engineering-with-ai-ghidra-mcp/p1.png)

After the analysis, you can actually see more detailed information in Ghidra:

![golang analysis](/img/reverse-engineering-with-ai-ghidra-mcp/p2.png)

![c code](/img/reverse-engineering-with-ai-ghidra-mcp/p3.png)

But this still requires manual inspection. For someone like me who doesn't know how to operate Ghidra, I just throw the binary in and don't know how to look at it.

So, we need to install something that truly connects AI with Ghidra: [GhidraMCP](https://github.com/LaurieWired/GhidraMCP). There seem to be about two or three versions that many people use, so I randomly picked one that looked like it had better documentation and was easier to run.

After installation and enabling it in Ghidra, configure MCP on the AI side. For example, I'm using Cursor, so I set it up like this:

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

Up to this point, the preliminary work is ready.

By the way, I used Cursor for demonstration, but actually, any AI agent will do. Whether you use Codex, Claude Code, Open Code, or whatever, as long as it can connect to MCP, it's fine.

## Start Commanding the AI Agent to Work

Next, it's time to reverse engineer using my words. I just told it this:

> I am currently reverse engineering a Golang binary. Please help me use Ghidra MCP to assist and let me know what kind of program it is and what functions it has.

It will start calling MCP by itself and searching for what it wants:

![mcp call](/img/reverse-engineering-with-ai-ghidra-mcp/p4-en.jpg)

Here is the translated content:

Finally, here are the libraries used by this binary:

![reversed libraty](/img/reverse-engineering-with-ai-ghidra-mcp/p5-en.jpg)

And the API routes:

![reversed api route](/img/reverse-engineering-with-ai-ghidra-mcp/p6-en.jpg)

And the inferred file structure:

![file structure](/img/reverse-engineering-with-ai-ghidra-mcp/p8-en.jpg)

Next, I let it help me convert the decompiled C back to Golang based on the inferred structure. It listed a few todos and then started its work:

![c to golang](/img/reverse-engineering-with-ai-ghidra-mcp/p9-en.jpg)

As a result, the routes.go it reverse-engineered looks like this:

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

  api := r.Group("/api")
  {
    api.POST("/register", authHandler.Register)
    api.POST("/login", authHandler.Login)
  }

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

The structure of the code is slightly different from the original, indicating that there was no cheating (?). By the way, I had it run under different contexts, so it indeed could not see the original Golang source code.

In any case, the reverse-engineered code is clear and readable, but there are a few small errors. For example, `/my-messages` does not exist; it should be `/me/messages`. `/avatar` should also be `/me/avatar`. It seems some parts were skipped lazily.

The registration part looks like this:

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

The part that was intentionally left for SQL injection has now been fixed, indicating that what it reverse-engineered is incorrect.

However, the path traversal vulnerability during file upload still exists, and it was easily identified:

![vulnerability](/img/reverse-engineering-with-ai-ghidra-mcp/p10-en.jpg)

The above results were generated using the Cursor's own composer 1.5 model because I was running out of quota, which is not as smart.

After switching to Opus 4.6, with the same prompt, it not only restored the code but also performed a security check, identifying the vulnerabilities that needed to be found. However, the route part still has errors; `/me` became `/my`. I thought these should be completely restored?

![opus findings](/img/reverse-engineering-with-ai-ghidra-mcp/p11-en.jpg)

## Conclusion

Thanks to the evolution of AI agents and the MCP mechanism, agents can freely operate many different software to assist in automation.

Honestly, I experienced the joy of those so-called vibe coders when creating products during this reverse engineering process, which is: "I didn't expect that I, who can't write code, could also create a website, even though I don't understand the principles, but it seems like something was made."

However, vibe coding can lead to many small issues that someone who can't write code might not discover, and relying solely on AI for reverse engineering is likely the same. Just like when I initially used composer 1.5, the results were incorrect. But thinking from another perspective, the overall process and API endpoints are correct, which is quite a gain.

Originally, relying on myself would score 0 points, but with AI, I can at least secure 60 points, which feels like a win.

The times are evolving, and tools are improving. This article aims to document my process of using these tools and AI agents for simple reverse engineering. Although the final results still have some minor errors, for a web server, the information obtained after reverse engineering the binary can be combined with dynamic testing for validation. Even with some small errors, it is still very helpful for overall testing.

After this run, I still feel that reverse engineering is very difficult, and I still think that those who understand reverse engineering are impressive. After all, I was working with a small binary; I’m not sure what would happen with a larger one.
