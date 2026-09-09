const crypto = require("crypto");

function jsonResponse(statusCode, body) {
  return {
    statusCode,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    },
    body: JSON.stringify(body)
  };
}

/**
 * 验证微信支付回调签名
 */
function verifyWechatSignature({
  timestamp,
  nonce,
  body,
  signature,
  publicKey
}) {
  const message =
    timestamp + "\n" +
    nonce + "\n" +
    body + "\n";

  return crypto.verify(
    "RSA-SHA256",
    Buffer.from(message),
    publicKey,
    Buffer.from(signature, "base64")
  );
}

/**
 * AES-256-GCM 解密微信支付 resource
 */
function decryptResource(resource, apiV3Key) {
  if (
    !resource ||
    resource.algorithm !== "AEAD_AES_256_GCM"
  ) {
    throw new Error("不支持的微信支付加密算法");
  }

  const key = Buffer.from(apiV3Key, "utf8");

  if (key.length !== 32) {
    throw new Error("WX_API_V3_KEY 必须是32字节");
  }

  const ciphertext = Buffer.from(
    resource.ciphertext,
    "base64"
  );

  // 微信将 16 字节 GCM Auth Tag 放在密文末尾
  const authTag = ciphertext.subarray(
    ciphertext.length - 16
  );

  const encryptedData = ciphertext.subarray(
    0,
    ciphertext.length - 16
  );

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(resource.nonce, "utf8")
  );

  decipher.setAuthTag(authTag);

  if (resource.associated_data) {
    decipher.setAAD(
      Buffer.from(
        resource.associated_data,
        "utf8"
      )
    );
  }

  const decrypted = Buffer.concat([
    decipher.update(encryptedData),
    decipher.final()
  ]);

  return JSON.parse(
    decrypted.toString("utf8")
  );
}

exports.handler = async function (event) {
  try {
    if (event.httpMethod !== "POST") {
      return jsonResponse(405, {
        code: "METHOD_NOT_ALLOWED",
        message: "Method Not Allowed"
      });
    }

    /*
      注意：
      微信支付签名校验必须使用“原始请求体”。
      event.body 不要在验签之前重新 JSON.stringify。
    */
    const rawBody = event.body || "";

    const headers = event.headers || {};

    const timestamp =
      headers["wechatpay-timestamp"] ||
      headers["Wechatpay-Timestamp"];

    const nonce =
      headers["wechatpay-nonce"] ||
      headers["Wechatpay-Nonce"];

    const signature =
      headers["wechatpay-signature"] ||
      headers["Wechatpay-Signature"];

    const serial =
      headers["wechatpay-serial"] ||
      headers["Wechatpay-Serial"];

    if (
      !timestamp ||
      !nonce ||
      !signature ||
      !serial
    ) {
      console.error(
        "Missing WeChat Pay headers"
      );

      return jsonResponse(401, {
        code: "SIGN_ERROR",
        message: "缺少微信支付签名头"
      });
    }

    /*
      防止重放攻击：
      回调时间戳距离当前时间超过5分钟则拒绝。
    */
    const now = Math.floor(
      Date.now() / 1000
    );

    const callbackTime =
      Number(timestamp);

    if (
      !Number.isFinite(callbackTime) ||
      Math.abs(now - callbackTime) > 300
    ) {
      return jsonResponse(401, {
        code: "SIGN_ERROR",
        message: "微信支付回调时间戳无效"
      });
    }

    /*
      微信偶尔会发送 SIGNTEST 探测流量，
      正常商户必须拒绝这种错误签名。
    */
    if (
      signature.startsWith(
        "WECHATPAY/SIGNTEST/"
      )
    ) {
      return jsonResponse(401, {
        code: "SIGN_ERROR",
        message: "签名验证失败"
      });
    }

    const expectedPublicKeyId =
      process.env.WX_PAY_PUBLIC_KEY_ID;

    const publicKey =
      process.env.WX_PAY_PUBLIC_KEY
        ?.replace(/\\n/g, "\n")
        .trim();

    const apiV3Key =
      process.env.WX_API_V3_KEY;

    const mchId =
      process.env.WX_MCH_ID;

    const appId =
      process.env.WX_APP_ID;

    if (
      !expectedPublicKeyId ||
      !publicKey ||
      !apiV3Key ||
      !mchId
    ) {
      throw new Error(
        "微信支付回调环境变量配置不完整"
      );
    }

    /*
      当前项目明确采用微信支付公钥模式。
    */
    if (
      serial !== expectedPublicKeyId
    ) {
      console.error(
        "Unexpected Wechatpay-Serial:",
        serial
      );

      return jsonResponse(401, {
        code: "SIGN_ERROR",
        message: "微信支付公钥ID不匹配"
      });
    }

    /*
      1. 验证通知确实来自微信支付
    */
    const verified =
      verifyWechatSignature({
        timestamp,
        nonce,
        body: rawBody,
        signature,
        publicKey
      });

    if (!verified) {
      console.error(
        "WeChat Pay signature verify failed"
      );

      return jsonResponse(401, {
        code: "SIGN_ERROR",
        message: "微信支付通知验签失败"
      });
    }

    /*
      2. 验签通过以后，
         才能解析并解密业务数据
    */
    const notifyBody =
      JSON.parse(rawBody);

    if (!notifyBody.resource) {
      throw new Error(
        "微信支付回调缺少 resource"
      );
    }

    const payment =
      decryptResource(
        notifyBody.resource,
        apiV3Key
      );

    console.log(
      "Decrypted WeChat Pay notification:",
      JSON.stringify(payment)
    );

    /*
      3. 基础业务校验
    */

    if (
      payment.mchid !== mchId
    ) {
      throw new Error(
        "支付通知商户号不匹配"
      );
    }

    if (
      appId &&
      payment.appid &&
      payment.appid !== appId
    ) {
      throw new Error(
        "支付通知 AppID 不匹配"
      );
    }

    if (
      payment.trade_state !==
      "SUCCESS"
    ) {
      /*
        不是支付成功通知，
        不把订单标记为已付款。
      */
      console.log(
        "Trade state:",
        payment.trade_state
      );

      return jsonResponse(200, {
        code: "SUCCESS",
        message: "成功"
      });
    }

    /*
      当前阶段是 ¥0.01 测试。

      正式上线后，这里必须：
      1. 根据 out_trade_no 查询服务器订单
      2. 核对服务项目
      3. 核对订单金额
      4. 防止同一通知重复处理
    */

    if (
      !payment.amount ||
      payment.amount.total !== 1
    ) {
      throw new Error(
        "测试订单金额异常"
      );
    }

    if (
      !payment.out_trade_no ||
      !payment.out_trade_no.startsWith(
        "WZ"
      )
    ) {
      throw new Error(
        "商户订单号异常"
      );
    }

    /*
      这里以后正式接数据库。

      例如：
      await markOrderPaid({
        outTradeNo:
          payment.out_trade_no,

        transactionId:
          payment.transaction_id,

        amount:
          payment.amount.total,

        paidAt:
          payment.success_time
      });
    */

    console.log(
      "PAYMENT SUCCESS:",
      {
        outTradeNo:
          payment.out_trade_no,

        transactionId:
          payment.transaction_id,

        amount:
          payment.amount.total,

        successTime:
          payment.success_time
      }
    );

    /*
      4. 必须向微信支付返回成功
    */
    return jsonResponse(200, {
      code: "SUCCESS",
      message: "成功"
    });

  } catch (error) {
    console.error(
      "Pay notify error:",
      error
    );

    /*
      返回非2xx后，
      微信支付会按照通知机制继续重试。
    */
    return jsonResponse(500, {
      code: "FAIL",
      message:
        error.message ||
        "支付通知处理失败"
    });
  }
};
