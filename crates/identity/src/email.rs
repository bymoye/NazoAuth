use std::{error::Error, fmt};

use lettre::Address;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmailAddressError;

impl fmt::Display for EmailAddressError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("email address is invalid")
    }
}

impl Error for EmailAddressError {}

pub fn normalize_email_address(raw: &str) -> Result<String, EmailAddressError> {
    let normalized = raw.trim().to_ascii_lowercase();
    normalized
        .parse::<Address>()
        .map(|address| address.to_string())
        .map_err(|_| EmailAddressError)
}

pub struct VerificationEmail<'a> {
    code: &'a str,
    ttl_seconds: u64,
}

impl<'a> VerificationEmail<'a> {
    #[must_use]
    pub const fn new(code: &'a str, ttl_seconds: u64) -> Self {
        Self { code, ttl_seconds }
    }

    #[must_use]
    pub fn render_html(&self) -> String {
        let code = self.code;
        let expiry = expiry_text(self.ttl_seconds);
        format!(
            r#"<!doctype html>
<html lang="zh-CN">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Nazo OAuth 注册验证码</title>
  </head>
  <body style="margin:0;padding:0;background:#f4f6f8;color:#111827;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif;">
    <div style="display:none;max-height:0;overflow:hidden;opacity:0;color:transparent;">你的 Nazo OAuth 注册验证码是 {code}</div>
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="background:#f4f6f8;margin:0;padding:32px 16px;">
      <tr>
        <td align="center">
          <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:560px;background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
            <tr>
              <td style="padding:28px 32px 18px 32px;border-bottom:1px solid #edf0f3;">
                <div style="font-size:13px;line-height:18px;color:#6b7280;font-weight:600;letter-spacing:0;text-transform:uppercase;">Nazo OAuth</div>
                <h1 style="margin:8px 0 0 0;font-size:22px;line-height:30px;color:#111827;font-weight:700;">注册验证码</h1>
              </td>
            </tr>
            <tr>
              <td style="padding:30px 32px 8px 32px;">
                <p style="margin:0 0 18px 0;font-size:15px;line-height:24px;color:#374151;">请在注册页面输入下面的验证码：</p>
                <div style="margin:0 0 20px 0;padding:18px 20px;background:#f8fafc;border:1px solid #dbe3ea;border-radius:8px;text-align:center;">
                  <div style="font-size:34px;line-height:42px;color:#111827;font-weight:700;letter-spacing:8px;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,'Liberation Mono','Courier New',monospace;">{code}</div>
                </div>
                <p style="margin:0;font-size:14px;line-height:22px;color:#4b5563;">验证码将在 <strong style="color:#111827;">{expiry}</strong> 后失效。</p>
              </td>
            </tr>
            <tr>
              <td style="padding:18px 32px 30px 32px;">
                <div style="padding:14px 16px;background:#fff7ed;border:1px solid #fed7aa;border-radius:8px;color:#9a3412;font-size:13px;line-height:20px;">如非本人操作，请忽略这封邮件。不要将验证码转发给任何人。</div>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>"#
        )
    }
}

fn expiry_text(ttl_seconds: u64) -> String {
    if ttl_seconds >= 60 && ttl_seconds.is_multiple_of(60) {
        format!("{} 分钟", ttl_seconds / 60)
    } else {
        format!("{ttl_seconds} 秒")
    }
}
