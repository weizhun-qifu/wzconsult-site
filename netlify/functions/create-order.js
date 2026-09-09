const crypto = require("crypto");

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

function createNonce() {
  return crypto.randomBytes(16).toString("hex");
}

function signWithPrivateKey(message, privateKey) {
  const signer = crypto.createSign("RSA-SHA256");
  signer.update(message);
  signer.end();

  return signer.sign(privateKey, "base64");
}

exports.handler = async function (event) {
  try {
    if (event.httpMethod !== "POST") {
      return {
        statusCode: 405,
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          success: false,
          message: "Method Not Allowed"
        })
      };
    }

    const appId = process.env.WX_APP_ID;
    const mchId = process.env.WX_MCH_ID;
    const serialNo = process.env.WX_SERIAL_NO;

    // 兼容 Netlify 中真正换行和 \\n 两种保存方式
    const privateKey = process.env.WX_PRIVATE_KEY
      ?.replace(/\\n/g, "\n")
      .trim();

    if (!appId || !mchId || !serialNo || !privateKey) {
      throw new Error("微信支付环境变量配置不完整");
    }

    // 从 HttpOnly Cookie 获取授权后的 OpenID
    const openid = getCookie(
      event.headers.cookie || event.headers.Cookie,
      "wz_openid"
    );

    if (!openid) {
      return {
        statusCode: 401,
        headers: {
          "Content-Type": "application/json; charset=utf-8"
        },
        body: JSON.stringify({
          success: false,
          needAuth: true,
          message: "未获取到微信 OpenID，请先完成微信授权"
        })
      };
    }

    let requestBody = {};

    try {
      requestBody = JSON.parse(event.body || "{}");
    } catch {
      requestBody = {};
    }

    /*
      第一阶段只允许 1 分钱测试。
      正式上线以后绝对不能直接相信前端传来的金额，
      应根据 serviceId 在服务器端查价格。
    */
    const amount = 1;

    const description =
      requestBody.description || "为准企服支付测试";

    // 微信要求商户订单号 6-32 位且同一商户号下唯一
    const outTradeNo =
      "WZ" +
      Date.now().toString() +
      crypto.randomBytes(3).toString("hex").toUpperCase();

    const apiPath = "/v3/pay/transactions/jsapi";

    const payBody = {
      appid: appId,
      mchid: mchId,
      description,
      out_trade_no: outTradeNo,

      // 下一步我们会建立这个支付结果回调函数
      notify_url:
        "https://wzconsult.cn/.netlify/functions/pay-notify",

      amount: {
        total: amount,
        currency: "CNY"
      },

      payer: {
        openid
      }
    };

    const bodyString = JSON.stringify(payBody);

    const timestamp = Math.floor(Date.now() / 1000).toString();
    const nonceStr = createNonce();

    /*
      微信 API v3 请求签名串：

      HTTP方法
      URL
      时间戳
      随机串
      请求体

      每一行都以 \n 结束
    */
    const message =
      "POST\n" +
      apiPath +
      "\n" +
      timestamp +
      "\n" +
      nonceStr +
      "\n" +
      bodyString +
      "\n";

    const signature = signWithPrivateKey(
      message,
      privateKey
    );

    const authorization =
      'WECHATPAY2-SHA256-RSA2048 ' +
      `mchid="${mchId}",` +
      `nonce_str="${nonceStr}",` +
      `signature="${signature}",` +
      `timestamp="${timestamp}",` +
      `serial_no="${serialNo}"`;

    const response = await fetch(
      "https://api.mch.weixin.qq.com" + apiPath,
      {
        method: "POST",

       headers: {
  Authorization: authorization,
  Accept: "application/json",
  "Content-Type": "application/json",

  "Wechatpay-Serial":
    process.env.WX_PAY_PUBLIC_KEY_ID
},

        body: bodyString
      }
    );

    const responseText = await response.text();

    let wxData;

    try {
      wxData = JSON.parse(responseText);
    } catch {
      wxData = {
        raw: responseText
      };
    }

    if (!response.ok) {
      console.error(
        "WeChat Pay create order error:",
        response.status,
        wxData
      );

      return {
        statusCode: response.status,
        headers: {
          "Content-Type":
            "application/json; charset=utf-8"
        },
        body: JSON.stringify({
          success: false,
          message: "微信支付下单失败",
          wxError: wxData
        })
      };
    }

    const prepayId = wxData.prepay_id;

    if (!prepayId) {
      throw new Error(
        "微信支付没有返回 prepay_id"
      );
    }

    /*
      生成前端调起微信支付所需参数
    */
    const payTimestamp =
      Math.floor(Date.now() / 1000).toString();

    const payNonceStr = createNonce();

    const packageValue =
      `prepay_id=${prepayId}`;

    /*
      JSAPI 调起支付签名串：

      appId
      timeStamp
      nonceStr
      package
    */
    const payMessage =
      appId +
      "\n" +
      payTimestamp +
      "\n" +
      payNonceStr +
      "\n" +
      packageValue +
      "\n";

    const paySign = signWithPrivateKey(
      payMessage,
      privateKey
    );

    return {
      statusCode: 200,

      headers: {
        "Content-Type":
          "application/json; charset=utf-8",
        "Cache-Control": "no-store"
      },

      body: JSON.stringify({
        success: true,

        order: {
          outTradeNo,
          amount,
          description
        },

        payParams: {
          appId,
          timeStamp: payTimestamp,
          nonceStr: payNonceStr,
          package: packageValue,
          signType: "RSA",
          paySign
        }
      })
    };

  } catch (error) {
    console.error(
      "Create order error:",
      error
    );

    return {
      statusCode: 500,

      headers: {
        "Content-Type":
          "application/json; charset=utf-8"
      },

      body: JSON.stringify({
        success: false,
        message: error.message
      })
    };
  }
};
