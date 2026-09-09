function getCookie(cookieHeader, name) {
  if (!cookieHeader) return null;

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const [key, ...rest] = cookie.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function htmlPage(title, content) {
  return `
<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport"
        content="width=device-width, initial-scale=1.0">

  <title>${title}</title>

  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont,
                   "Segoe UI", "PingFang SC",
                   "Microsoft YaHei", sans-serif;
      margin: 0;
      padding: 40px 24px;
      background: #fff;
      color: #111;
    }

    .box {
      max-width: 500px;
      margin: 80px auto 0;
    }

    .success {
      font-size: 48px;
      margin-bottom: 20px;
    }

    h1 {
      font-size: 30px;
      margin-bottom: 20px;
    }

    p {
      font-size: 17px;
      line-height: 1.8;
      color: #555;
    }

    .openid {
      margin-top: 24px;
      padding: 16px;
      background: #f6f6f6;
      border-radius: 8px;
      word-break: break-all;
      font-family: monospace;
    }

    a {
      display: block;
      margin-top: 32px;
      padding: 14px;
      background: #b5121b;
      color: #fff;
      text-decoration: none;
      text-align: center;
      border-radius: 8px;
    }
  </style>
</head>

<body>
  <div class="box">
    ${content}
  </div>
</body>
</html>`;
}

exports.handler = async function (event) {
  try {
    const code = event.queryStringParameters?.code;
    const state = event.queryStringParameters?.state;

    if (!code || !state) {
      return {
        statusCode: 400,
        headers: {
          "Content-Type": "text/html; charset=utf-8"
        },
        body: htmlPage(
          "授权失败",
          `
            <h1>微信授权失败</h1>
            <p>没有收到微信返回的授权参数。</p>
            <a href="/pay-test.html">重新测试</a>
          `
        )
      };
    }

    // 校验 state
    const cookieState = getCookie(
      event.headers.cookie || event.headers.Cookie,
      "wz_oauth_state"
    );

    if (!cookieState || cookieState !== state) {
      return {
        statusCode: 400,
        headers: {
          "Content-Type": "text/html; charset=utf-8"
        },
        body: htmlPage(
          "安全校验失败",
          `
            <h1>授权安全校验失败</h1>
            <p>state 参数不一致，请重新发起授权。</p>
            <a href="/pay-test.html">重新测试</a>
          `
        )
      };
    }

    const appId = process.env.WX_APP_ID;
    const appSecret = process.env.WX_APP_SECRET;

    if (!appId || !appSecret) {
      throw new Error("微信公众号环境变量未配置完整");
    }

    const tokenUrl =
      "https://api.weixin.qq.com/sns/oauth2/access_token" +
      "?appid=" + encodeURIComponent(appId) +
      "&secret=" + encodeURIComponent(appSecret) +
      "&code=" + encodeURIComponent(code) +
      "&grant_type=authorization_code";

    const response = await fetch(tokenUrl);

    const data = await response.json();

    if (data.errcode) {
      console.error("WeChat OAuth error:", data);

      return {
        statusCode: 400,
        headers: {
          "Content-Type": "text/html; charset=utf-8"
        },
        body: htmlPage(
          "微信授权失败",
          `
            <h1>微信授权失败</h1>
            <p>错误码：${data.errcode}</p>
            <p>${data.errmsg || "未知错误"}</p>
            <a href="/pay-test.html">重新测试</a>
          `
        )
      };
    }

    const openid = data.openid;

    // 页面只展示脱敏后的 OpenID
    const maskedOpenId =
      openid.length > 12
        ? openid.slice(0, 6) +
          "******" +
          openid.slice(-6)
        : "已成功获取";

   headers: {
  "Content-Type": "text/html; charset=utf-8",

  // 保存 OpenID 两小时，仅服务器可读取
  "Set-Cookie":
    `wz_openid=${encodeURIComponent(openid)}; Path=/; Max-Age=7200; HttpOnly; Secure; SameSite=Lax`
},

      body: htmlPage(
        "微信授权成功",
        `
          <div class="success">✓</div>

          <h1>微信授权成功</h1>

          <p>
            为准企服已经成功识别当前微信用户，
            JSAPI 支付所需的 OpenID 获取链路已经打通。
          </p>

          <div class="openid">
            OpenID：${maskedOpenId}
          </div>

          <a href="/pay-test.html">
            返回测试页
          </a>
        `
      )
    };
  } catch (error) {
    console.error("OAuth callback error:", error);

    return {
      statusCode: 500,
      headers: {
        "Content-Type": "text/html; charset=utf-8"
      },
      body: htmlPage(
        "服务器错误",
        `
          <h1>服务器处理失败</h1>
          <p>${error.message}</p>
          <a href="/pay-test.html">重新测试</a>
        `
      )
    };
  }
};
