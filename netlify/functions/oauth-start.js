const crypto = require("crypto");

exports.handler = async function () {
  try {
    const appId = process.env.WX_APP_ID;

    if (!appId) {
      return {
        statusCode: 500,
        headers: {
          "Content-Type": "text/html; charset=utf-8"
        },
        body: "WX_APP_ID 未配置"
      };
    }

    // 生成随机 state，用于防止伪造回调
    const state = crypto.randomBytes(16).toString("hex");

    // 使用正式域名，必须和公众号后台“网页授权域名”保持一致
    const redirectUri =
      "https://wzconsult.cn/.netlify/functions/oauth-callback";

    // 微信 OAuth 静默授权地址
    // snsapi_base 只获取 OpenID，不弹出授权确认页
    const authUrl =
      "https://open.weixin.qq.com/connect/oauth2/authorize" +
      "?appid=" + encodeURIComponent(appId) +
      "&redirect_uri=" + encodeURIComponent(redirectUri) +
      "&response_type=code" +
      "&scope=snsapi_base" +
      "&state=" + encodeURIComponent(state) +
      "#wechat_redirect";

    return {
      statusCode: 302,
      headers: {
        Location: authUrl,

        // 保存 state，供 oauth-callback.js 回调时校验
        // 10 分钟后自动失效
        "Set-Cookie":
          `wz_oauth_state=${state}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
      },
      body: ""
    };

  } catch (error) {
    console.error("OAuth start error:", error);

    return {
      statusCode: 500,
      headers: {
        "Content-Type": "text/html; charset=utf-8"
      },
      body: `
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
          <meta charset="UTF-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>授权启动失败</title>
        </head>
        <body style="
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',sans-serif;
          padding:40px 24px;
          color:#111;
        ">
          <h2>微信授权启动失败</h2>
          <p>${error.message}</p>
          <p>
            <a href="/pay-test.html">返回测试页</a>
          </p>
        </body>
        </html>
      `
    };
  }
};
