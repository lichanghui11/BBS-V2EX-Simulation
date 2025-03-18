require("dotenv").config();
//================使用node:crypto.randomBytes()生成salt和token=====
// let users = {
//   userId,
//   accountName, required
//   passwordHash,required
//   salt,required
//   createdBy,required
//   email,required
//   tel,
//   avatarUrl,
// }

// let posts = {
//   postId,
//   createdAt,
//   createdBy,
//   postTitle,
//   postContent,
//   ip,
//   isDeleted,//true表示帖子被软删除，false表示正常可见
//   deletedAt,//软删除的时间戳
// };

// let comments = {
//   commentId,
//   commentContent,
//   postId,//这里是所评论的贴文的ID
//   createdAt,
//   createdBy,
//   ip,
//   isDeleted,//true表示帖子被软删除，false表示正常可见
//   deletedAt,//软删除的时间戳
// };

// =======================================以上内容为思路设计，以下为代码逻辑
const fs = require("fs");
const express = require("express");
const path = require("node:path");
const cookieParser = require("cookie-parser");
const Ajv = require("ajv");
const { z } = require("zod");
const Database = require("better-sqlite3");
const ajvFormats = require("ajv-formats");
const crypto = require("node:crypto");
const multer = require("multer");
const sharp = require("sharp");
const svgCaptcha = require('svg-captcha');
const nodemailer = require('nodemailer');
let fileTypeFromBuffer;
(async () => {
  await import("file-type").then((module) => {
    fileTypeFromBuffer = module.fileTypeFromBuffer;
  });
})();
// console.log(fileTypeFromBuffer);
//========================================这部分内容用来引入各个模块

//配置存储引擎(memoryStorage)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 2 * 1024 * 1024, // <= 2MB
  },
});

function generateSalt(length = 16) {
  //生成随机盐
  return crypto.randomBytes(length).toString("hex");
}
function hashPassword(password, salt) {
  //salt + sha512 + 多次迭代(PBKDF2)
  //Password-Based Key Derivation Function第二代
  const iterations = 10000;
  const keyLength = 64;
  const digest = "sha512";
  return crypto
    .pbkdf2Sync(password, salt, iterations, keyLength, digest)
    .toString("hex");
}
//=======================================这部分内容用来写辅助函数

const app = express();
const port = 8899;
const db = new Database("./data/bbs.db");
const ajv = new Ajv();
ajvFormats(ajv); //启用格式验证
//========================================这部分内容用来实例化和设置初始值

app.set("views", path.join(__dirname, "./templates"));
app.use(cookieParser(process.env.COOKIE_SECRET));
app.use((req, res, next) => {
  //这里用来输出日志
  console.log("客户端发出请求的url: ", req.url);
  next();
});
app.use(express.static("./public"));
app.use(express.static("./dist"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));


const sessions = {
  //sessionId: {},
}
//下发sessionId
app.use((req, res, next) => {
  // 1. 如果客户端没有 sessionId 的cookie，就生成一个新的 sessionId 并写回cookie
  if (!req.cookies.sessionId) {
    let sessionId = Math.random().toString(36).slice(2);
    res.cookie("sessionId", sessionId, {
      maxAge: 86400000,
    });
    // 同时将该 sessionId 写到 req.cookies.sessionId，方便后续使用
    req.cookies.sessionId = sessionId;
  }
  // 2. 读取当前 sessionId 对应的session对象
  if (sessions[req.cookies.sessionId]) {
    req.session = sessions[req.cookies.sessionId];
  } else {
    // 如果之前没有为该 sessionId 建立过session，就初始化一个空对象
    req.session = sessions[req.cookies.sessionId] = {};
  }
  // 3. 为了方便在模板或后续逻辑中访问session，把它挂在 res.locals.session 上
  res.locals.session = req.session;

  next();
})

/**
 *  后端代码逻辑处理（通过 req.session） 
 *  前端页面渲染（通过 res.locals.session） 
 */

//这个中间件将验证cookie后的用户信息挂在res.locals上
app.use((req, res, next) => {
  req.user = db
    .prepare("SELECT * FROM users WHERE accountName = ?")
    .get(req.signedCookies.loginUser);
  if (req.user) {
    res.locals.loginUser = req.user; //如果验证成功，这是一个用户对象
    res.locals.isLogin = !!req.user;
  }
  console.log(" cookie验证后的用户： ", res.locals.loginUser);
  next();
});

//get 首页
app.get("/", (req, res, next) => {
  //贴文展示
  let page = req.query.page ?? 1;
  let size = 3;
  let offset = (page - 1) * size;
  let totalPosts = db
    .prepare("SELECT COUNT(*) AS totalPosts FROM posts")
    .get().totalPosts;
  let totalPages = Math.ceil(totalPosts / size);

  // let posts = db.prepare('SELECT * FROM posts LIMIT ? OFFSET ?').all(size, offset);
  let posts = db
    .prepare(
      "SELECT * FROM posts JOIN users ON posts.createdBy = users.userId LIMIT ? OFFSET ?"
    )
    .all(size, offset);
  // let ownerOfPost = db.prepare('SELECT userId, users.accountName FROM posts JOIN users ON posts.createdBy = users.userId').get()

  console.log("res.locals: ", res.locals);
  console.log("每条post所包含的信息： ", posts);
  res.render("home.pug", {
    // isLogin, //res.locals上的数据不用显示传送
    // loginUser,//res.locals上的数据不用显示传送
    posts,
    totalPages,
    page,
  });
  // console.log('info of this post ', infoOfThisPost)
});

app.get("/register", (req, res, next) => {
  res.render("register.pug");
});

//上传头像
app.post("/register", upload.single("avatar"), async (req, res, next) => {
  // console.log('请求体： ', req.body)
  // console.log('文件： ', req.file)
  //上传成功后Multer会把信息放到 req.file
  if (!req.file) {
    try {
      //这里随机生成背景色
      const backgrounds = [
        { r: 0, g: 0, b: 255, alpha: 0.5 }, // 半透明蓝色
        { r: 0, g: 255, b: 0, alpha: 0.5 }, // 半透明绿色
        { r: 255, g: 165, b: 0, alpha: 0.5 }, // 半透明橙色
        { r: 255, g: 0, b: 0, alpha: 0.5 }, // 半透明红色
        { r: 128, g: 0, b: 128, alpha: 0.5 }, // 半透明紫色
        { r: 0, g: 0, b: 0, alpha: 0.5 }, // 半透明黑色
      ];
      let index = Math.floor(Math.random() * backgrounds.length)
      const defaultAvatarBuffer = await sharp({
        create: {
          width: 48,
          height: 48,
          channels: 4,
          background: backgrounds[index],
        },
      })
        .png()
        .toBuffer();

      const fileName = "avatar-" + Date.now() + ".png";
      const filePath = path.join(__dirname, "public", "avatars", fileName);

      //将buffer写入硬盘
      fs.writeFileSync(filePath, defaultAvatarBuffer);

      //构建唯一URL
      const avatarUrl = "/avatars/" + fileName;

      //存入req.avatarUrl
      req.body.avatarUrl = avatarUrl;
      next();
    } catch (e) {
      console.log("头像上传组件的错误：", e);
      return res.status(500).send("文件处理错误");
    }
  } else {
    try {
      //使用file-type 检测 buffer
      const fileBuffer = req.file.buffer;
      const typeResult = await fileTypeFromBuffer(fileBuffer);
      if (!typeResult) {
        return res
          .status(400)
          .send("无法识别文件类型，可能文件损坏或类型不支持");
      }

      //拿到后缀和媒体类型
      const { ext, mime } = typeResult;
      // console.log('文件后缀: ', ext)
      // console.log('媒体类型: ', mime)
      const allowedType = ["jpeg", "png", "gif", "webp", "bmp", "svg", "jpg"];
      if (!allowedType.includes(ext)) {
        return res.status(400).send("文件类型不支持");
      }

      //使用Sharp对上传的图片进行处理
      const processedBuffer = await sharp(fileBuffer)
        .resize({
          width: 48,
          height: 48,
          withoutEnlargement: true, //防止图片被放大
          fit: "cover",
        })
        .png()
        .toBuffer();

      const fileName = "avatar-" + Date.now() + "." + ext;
      const filePath = path.join(__dirname, "public", "avatars", fileName);

      //将buffer写入硬盘
      fs.writeFileSync(filePath, processedBuffer);

      //构建唯一URL
      const avatarUrl = "/avatars/" + fileName;

      //存入req.avatarUrl
      req.body.avatarUrl = avatarUrl;
      next();
    } catch (e) {
      console.log("头像上传组件的错误：", e);
      return res.status(500).send("文件处理错误");
    }
  }
});

const userRegisterInfoSchema = {
  //用户所填写的注册信息需要满足该模板要求
  type: "object",
  properties: {
    accountName: {
      type: "string",
      minLength: 3,
      maxLength: 20,
    },
    password: {
      type: "string",
      minLength: 3,
    },
    confirmedPassword: {
      type: "string",
      minLength: 3,
    },
    email: {
      type: "string",
      format: "email",
      maxLength: 50,
    },
    tel: {
      type: "string",
      maxLength: 15,
    },
  },
  required: ["accountName", "password", "confirmedPassword", "email"],
  additionalProperties: true,
};
const validate = ajv.compile(userRegisterInfoSchema); //编译schema

app.post("/register", (req, res, next) => {
  //这里处理注册的页面
  let newUser = req.body;

  //先验证不是机器人
  if (req.body.captcha !== req.session.captcha) {
    res.type('html').end('验证码错误，请<a href="/back">返回</a>重新填写')
    return
  }

  const isValid = validate(newUser);
  // console.log("新用户： ", newUser);
  // console.log("文件： ", req.avatarUrl);
  // console.log("是否合法： ", isValid);
  if (isValid) {
    let result = db
      .prepare("SELECT 1 FROM users WHERE accountName = ? LIMIT 1")
      .get(newUser.accountName);
    if (result) {
      res.type("html").end('用户名重复，<a href="register">返回重新填写</a>');
      return;
    }
    if (newUser.password !== newUser.confirmedPassword) {
      res
        .type("html")
        .end('两次密码输入不一致，<a href="register">返回重新填写</a>');
      return;
    }
    //到这里验证通过
    newUser.createdAt = new Date().toISOString();
    newUser.salt = generateSalt();
    newUser.passwordHash = hashPassword(newUser.password, newUser.salt);
    newUser.avatarUrl = req.body.avatarUrl;
    console.log("新用户的注册信息： ", newUser);

    try {
      db.prepare(
        `
        INSERT INTO users (accountName, passwordHash, salt, email, tel, avatarUrl)
        VALUES ($accountName, $passwordHash, $salt, $email, $tel, $avatarUrl)
      `
      ).run(newUser);
    } catch (e) {
      if (e.code === "SQLITE_CONSTRAINT_UNIQUE") {
        res.end(e.message);
        return;
      } else {
        throw e;
      }
    }
    res.type("html").end('注册成功，去<a href="/login">登录</a>');
  } else {
    res
      .type("html")
      .end('请您按照要求填写，<a href="register">返回重新填写</a>');
  }
});

app.get("/login", (req, res, next) => {
  res.render("login.pug");
});

app.post("/login", (req, res, next) => {
  console.log("登录信息: ", req.body);
  let loginUserObj = req.body;
  //capcha后面再做

  if (req.session.failedCount >= 4 && loginUserObj.captcha !== req.session.captcha) {
    res.type('html').end('验证码不匹配，<a href="/back">返回</a>重新填写')
    return 
  }

  let targetAccount = db
    .prepare("SELECT * FROM users WHERE accountName = ?")
    .get(loginUserObj.accountName);
  if (targetAccount) {
    let saltedPassowrd = hashPassword(
      loginUserObj.password,
      targetAccount.salt
    );
    if (saltedPassowrd === targetAccount.passwordHash) {
      //验证成功，下发cookie
      req.session.failedCount = 0; //记录失败次数
      res.cookie("loginUser", targetAccount.accountName, {
        signed: true,
        maxAge: 86400 * 1000,
      });
      res.redirect("/");
    } else {
      req.session.failedCount = (req.session.failedCount | 0) + 1;
      res.type("html").end("用户名或密码错误");
    }
  } else {
    res.type("html").end('用户吗不存在，请<a href="/login">返回</a>重新输入');
  }
});

app.get("/logout", (req, res, next) => {
  res.clearCookie("loginUser");
  res.redirect("/");
});

app.post("/add-post", (req, res, next) => {
  if (!req.user) {
    res.type("html").end('<a href="/login">请登录</a>');
    return;
  }
  // console.log('一条贴文', req.body)
  let post = req.body;
  post.createdAt = new Date().toISOString();
  post.createdBy = res.locals.loginUser.userId; //这里是一个integer，用于关联用户
  post.ip = req.ip;
  // console.log(' 发帖ip: ', post.ip)
  // console.log('完整贴文: ', post)

  let result = db
    .prepare(
      `
    INSERT INTO posts (createdAt, createdBy, postTitle, postContent, ip)
    VALUES ($createdAt, $createdBy, $postTitle, $postContent, $ip)
  `
    )
    .run(post);
  // console.log('插入数据操作之后的返回对象: ', result)

  res.redirect("/post/" + result.lastInsertRowid);
});

app.get("/post/:postId", (req, res, next) => {
  // console.log('当前发文的用户: ', req.user)
  let postId = req.params.postId;
  let post = db
    .prepare(
      "SELECT * FROM posts JOIN users ON posts.createdBy = userId WHERE postId = ? "
    )
    .get(postId);
  if (post) {
    //这里还有展示贴文的逻辑
    // console.log('数据库中一条完整的贴文：', post)
    let ownerOfPost = db
      .prepare(
        "SELECT users.accountName FROM posts JOIN users ON posts.createdBy = users.userId"
      )
      .get();
    // console.log('owner of post: ',ownerOfPost)
    let comments = db
      .prepare(
        `
      SELECT avatarUrl, commentId, commentContent, postId, comments.createdAt, comments.createdBy, comments.ip, users.userId, users.accountName as commentOwner FROM 
      comments JOIN users 
      ON comments.createdBy = users.userId WHERE postId = ?
    `
      )
      .all(postId);
    console.log("结合评论与评论人、贴文所有者： ", comments);
    res.render("post.pug", {
      post,
      comments,
    });
  } else {
    res.render("404.pug");
  }
});

app.post("/add-comment/:postId", (req, res, next) => {
  if (!req.user) {
    res.type("html").end('<a href="/login">请登录</a>');
    return;
  }
  // console.log('一个评论： ', req.body)

  //使用zod验证数据
  const schema = z.object({
    commentContent: z.string().min(1),
  });
  try {
    schema.parse(req.body);
    let comment = {
      commentContent: req.body.commentContent,
      postId: req.params.postId,
      createdAt: new Date().toISOString(),
      createdBy: req.user.userId,
      ip: req.ip,
    };
    // console.log('一条评论的信息：', comment)

    db.prepare(
      `
      INSERT INTO comments (commentContent, postId, createdAt, createdBy, ip) 
      VALUES ($commentContent, $postId, $createdAt, $createdBy, $ip)
    `
    ).run(comment);
    res.redirect("/post/" + comment.postId);
  } catch (e) {
    console.log(e);
    res.type("html").end('输入不能为空，请<a href="/back">返回</a>重新填写');
  }
});

app.get("/back", (req, res, next) => {
  let previousPage = req.get("Referer");
  if (previousPage) res.redirect(previousPage);
  else res.type("html").end('无法返回上一页，<a href="/">点击</a>跳转到主页');
});

app.delete("/delete-post/:postId", (req, res, next) => {
  //前端使用ajax, 后端操作数据库
  // console.log('deleting post.............................')
  let postId = req.params.postId;
  //验证post是当前用户
  let post = db
    .prepare(
      `
    SELECT * FROM posts WHERE posts.postId = ?
  `
    )
    .get(postId);
  if (post.createdBy == res.locals.loginUser.userId) {
    //删除贴文所属的评论
    //需要先删除评论再删除贴文, 防止留下孤儿记录
    db.prepare("DELETE FROM comments WHERE postId = ?").run(postId);
    db.prepare("DELETE FROM posts WHERE postId = ?").run(postId);

    res.end();
  } else {
    res.type("html").end('没有权限，<a href="/back">点击返回</a>');
  }
});

app.delete("/delete-comment/:commentId", (req, res, next) => {
  //前端使用ajax,后端从数据库删除
  //验证评论与用户的关系
  // console.log('delete comment .....................')
  let commentId = req.params.commentId;
  let comment = db
    .prepare("SELECT * FROM comments WHERE commentId = ?")
    .get(commentId);
  console.log("要删除的这个评论： ", comment);
  if (comment.createdBy === res.locals.loginUser.userId) {
    db.prepare("DELETE FROM comments WHERE commentId = ?").run(commentId);
    res.end();
  } else {
    res.type("html").end('没有权限，<a href="/back">点击返回</a>');
  }
});

//获取验证码
app.get('/captcha', (req, res, next) => {
  const captcha = svgCaptcha.create({
    size: 4, 
    ignoreChars: '0oO1li',
    noise: 3,
    color: true,
    background: '#cc9966',
  })

  req.session.captcha = captcha.text; 
  console.log('验证码文本: ', captcha.text)

  res.type('svg').end(captcha.data);
})

app.get('/forgot-password', (req, res, next) => {
  res.render('forgot.pug')
})

const changePasswordMap = {
  //token: user
}
//忘记密码
app.post('/forgot-password', async (req, res, next) => {
  // console.log('忘记密码填写邮箱时的token映射：  ', changePasswordMap)
  let email = req.body.email.trim(); 
  let targetUser = db.prepare('SELECT * FROM users WHERE email = ? ').get(email);

  if (targetUser) {
    let token = Math.random().toString(36).slice(2);
    changePasswordMap[token] = targetUser;
    // console.log('刚建立的token映射： ', changePasswordMap)
    setTimeout(() => {
      //JavaScript中删除对象属性的方法
      delete changePasswordMap[token];
    }, 20 * 60 * 1000);

    let link = "http://192.168.3.10:8899/change-password?token=" + token;

    //发送电子邮件
    //hdjdidjd@.@![#[~
    const transporter = nodemailer.createTransport({
      host: "smtp.qq.com",
      port: 587,
      secure: false,
      auth: {
        user: "2839110607@qq.com",
        pass: "vgpqyhkervjedgci",
      },
    });
    try {
      await transporter.sendMail({
        from: "'V3EX 官方' <2839110607@qq.com>",
        to: email, 
        subject: '找回密码',
        text: '请点击以下链接修改密码: ' + link,
      })
    } catch (e) {
      console.log('邮件发送失败： ', e)
      throw e
    }

    res.type("html").end("请查收电子邮件以修改密码");
  } else {
    res.type("html").end("该邮箱未注册，请检查后重试");
  }
})

//dsf7^$&2df.,/l;'
//change password
app.get('/change-password', (req, res, next) => {
  // console.log('get change-password的token映射： ', changePasswordMap)
  let token = req.query.token; 
  let tokenInfo = changePasswordMap[token];
  if (tokenInfo) {
    res.render('change-password.pug', {
      tokenInfo,
      token,
    });
  } else {
    // console.log('get change-password 申请改密码的页面： ')
    res.type('html').end('链接已失效，请<a href="/forgot">重新申请</a>')
  }
})

app.post('/change-password', (req, res, next) => {
  // console.log('post change-password: token映射: ', changePasswordMap)
  // console.log('修改密码的信息：', req.body)
  let token = req.query.token; 
  let targetUser = changePasswordMap[token];
  let newInfo = req.body; 
  if (targetUser) {
    if (newInfo.newPassword !== newInfo.newConfirmedPassword) {
      res.type('html').end('密码输入有误，<a href="/back"><返回/a>重新填写')
    }

    let salt = targetUser.salt;
    let passwordHash = hashPassword(newInfo.newPassword, salt); 
    db.prepare('UPDATE users SET passwordHash = ? WHERE userId = ? ').run(passwordHash, targetUser.userId);
    res.type('html').end('密码修改成功，去<a href="/login">登录</a>')
  } else {
    res.type("html").end('链接已失效，请<a href="/forgot-password">重新申请</a>找回密码');
  }

})


//===============================这里开始监听端口
// console.log("环境变量：", process.env.COOKIE_SECRET);
const server = app.listen(port, "0.0.0.0", () => {
  const address = server.address();
  console.log("bbs-v2ex-like is listening on port: ", port);
  console.log("bbs-v2ex-like is listening on address : ", address.address);
});
