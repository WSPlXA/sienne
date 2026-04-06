# IDP 原型说明

## 1. 用户体验分析
- 核心目标：让用户在最少步骤内完成 `认证 -> MFA -> 授权`，同时保证安全校验（CSRF、TOTP、防重放）。
- 关键痛点：登录回调链路长，用户容易在 MFA 绑定与授权页迷失。
- 设计策略：所有页面顶部统一展示当前阶段，按钮文案统一使用“继续/允许/拒绝”，减少说明性段落。

## 2. 产品界面规划
- `login.html`：账号密码/联邦入口。
- `login_totp.html`：登录时二次验证码。
- `totp_bind.html`：首次绑定 MFA（扫码 + 验证码确认）。
- `consent.html`：客户端权限授权决策。
- `device.html`：设备码授权。
- `logout.html`：会话退出。
- `register.html`：账号注册（扩展页）。
- `index.html`：iframe 总览页，用于评审与联调。

## 3. 跳转流程（建议）
- `GET /login` -> 密码成功
- 若未绑定 MFA 且策略强制：`/mfa/totp/setup?return_to=...`
- 若已绑定 MFA：`/login/totp`
- 成功后：`/oauth2/authorize...` -> `/consent`
- 用户同意后回调客户端 `redirect_uri`
- 退出链路：`/connect/logout` -> `post_logout_redirect_uri`
