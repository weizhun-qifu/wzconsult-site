const crypto = require("crypto");

exports.handler = async function () {
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

  // 生成随机 state，防止伪造回调
  const state = crypto.randomBytes(16).toString("hex");

  // 目前微信后台配置的是这个域名
  const redirectUri =
    "https://weizhun.netlify.app/.netlify/functions/oauth-callback";

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

      // 保存 state，回调时验证
      "Set-Cookie":
        `wz_oauth_state=${state}; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax`
    },
    body: ""
  };
};
