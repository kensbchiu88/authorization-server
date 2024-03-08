# 數據中台MFG Authorization Server

數據中台MFG Authorization Server

## Description
開發OAuth2.0協議下的Autorization Server。提供數據中台各component的登入認證。
- 可使用LDAP與儲存在DataBase中的帳密認證(儲存在DataBase中密碼使用BCrypt加密)。
- 可與其他thrid party software透過OIDC認證，如Grafana, Datahub。
- 提供輸入帳密的頁面。

