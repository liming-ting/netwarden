# 使用 Pi-hole

[English](pihole.md)

netwarden 可以讀取 **Pi-hole v6** 的查詢紀錄(query log),取代或搭配 AdGuard Home。
它走 Pi-hole v6 內建的 REST API(`/api/auth`、`/api/queries`),**只讀取查詢紀錄**:
不會更動 Pi-hole 的任何設定、清單或封鎖規則,也不會碰你的路由器。

## 版本

| Pi-hole | 狀態 |
|---|---|
| **v6**(FTL v6.x,REST API「6.0」) | 支援。已對照目前的 API 文件與 FTL 原始碼(2026 年 10 月),並在測試套件中用模擬伺服器驗證;**還沒有在真正的 Pi-hole 上測試過**,歡迎回報。 |
| v5 以前(`admin/api.php`) | 不支援:netwarden 只讀 v6 的 REST API(從來沒有支援過 v5)。遇到 v5 時會明確告訴你,而不是給一個模糊的錯誤。 |

## 設定(`.env` 或 compose 的 env 檔)

```ini
PIHOLE_URL=http://pi.hole          # 或 http://192.168.1.2、https://pi.hole(帶 ".../admin" 也可以)
PIHOLE_PASSWORD=...                # 建議用「應用程式密碼」(見下方)
# PIHOLE_VERIFY_TLS=0              # 只有 HTTPS 用 Pi-hole 內建的自簽憑證時才需要
# NETWARDEN_DNS_SOURCE=pihole      # 同時設定了 AdGuard 與 Pi-hole 時才需要;預設用 AdGuard
```

- **應用程式密碼(建議):** 在 Pi-hole 網頁介面打開 **Settings → Web interface / API**
  (看不到的話先切到 *Expert* 模式),按 **Configure app password**,複製密碼後按
  **Enable new app password**。它可以單獨撤銷,而且**開了兩步驟驗證(2FA)時只能用它**:
  netwarden 不會要你輸入 2FA 驗證碼。注意:設定新的應用程式密碼會登出 Pi-hole 目前所有的
  會話(netwarden 會自動重新登入)。
- 沒開 2FA 時,網頁登入密碼也可以用。
- Pi-hole v5 的「API token」(64 個十六進位字元)在 v6 **不能用**;netwarden 看到時會提醒你。
- Pi-hole 沒設密碼時,`PIHOLE_PASSWORD` 留空即可。
- **HTTPS:** 預設會**驗證憑證**。Pi-hole v6 的 HTTPS 用的是自己產生的自簽憑證;在家用網路
  最簡單的做法是用 `http://`。如果要用 `https://` 搭配那張憑證,請設定 `PIHOLE_VERIFY_TLS=0`
  (明確選擇關閉檢查;只在你信任的網路使用)。
- **隱私等級**(Settings → Privacy)必須是 0(「全部顯示」):等級 1 到 3 會隱藏網域或用戶端,
  netwarden 就無法告訴你每台裝置在做什麼。這時狀態頁會直接說明,不會顯示成一個「很安靜」的家。
- **用戶端名稱:** Pi-hole 會從 DHCP 租約、`/etc/hosts` / 本機 DNS 紀錄和反查 DNS 取得
  用戶端名稱。netwarden 把它們當作提示;你在 netwarden 裡自己取的名稱永遠優先。
- 只能用一個 DNS 來源:兩個都設定時用 `NETWARDEN_DNS_SOURCE=adguard|pihole` 選擇。

## 執行

```bash
python3 -m netwarden ingest        # 擷取一次 + 每台裝置的報告
python3 -m netwarden run           # 儀表板 + 每 60 秒自動擷取
python3 -m netwarden status        # 看「DNS(Pi-hole)」是否正常,以及修正提示
```

儀表板的 **設定 → 測試連線** 會問 Pi-hole 一個很輕量的問題(登入、`GET /api/info/version`、
登出),有問題時用白話說明。

## 會話(session)

Pi-hole 同時能開的 API 會話有限(「seats」,`webserver.api.max_sessions`)。netwarden
每次執行(或整個 `run` 背景迴圈)只登入**一次**並重複使用;會話過期(HTTP 401)會自動
重新登入一次;結束時一定會登出(`DELETE /api/auth`)釋放名額。當機或被強制結束(來不及登出)
留下的會話,會在下次啟動時清掉:netwarden 會列出會話,只結束**自己的**(User-Agent 同為
`netwarden/<版本>`)而且閒置 10 分鐘以上的會話。其他用戶端(包括你的瀏覽器)的會話絕不會動。

## 查詢紀錄的細節

- 分頁照 FTL 的做法:第一頁固定一個 `cursor`,之後的頁面帶上它與 `start`;`from`(含)
  從已存的最後一筆查詢開始。
- FTL 只在記憶體保留最近 24 小時。netwarden 停機超過這段時間時,下次會改從 Pi-hole 的
  磁碟資料庫(`disk=true`)補回中間的空檔。
- 每次執行最多存 100,000 筆查詢(從最新的開始):在很忙的 Pi-hole 上第一次執行時,會從最近的
  紀錄開始,而不是一次載入好幾個月。
- 還在等回應的查詢(`IN_PROGRESS`)會在下一次執行時重新抓取。

## 封鎖狀態

每筆查詢都會記下 Pi-hole 的原始狀態(`reason` 欄,例如 `GRAVITY`、`FORWARDED`),
以及統一的 `blocked`(0/1)與簡短原因 `block_reason`:

| Pi-hole 狀態 | block_reason |
|---|---|
| GRAVITY、GRAVITY_CNAME | blocklist(封鎖清單) |
| REGEX、REGEX_CNAME | regex(正規表示式) |
| DENYLIST、DENYLIST_CNAME | denylist(自訂黑名單) |
| EXTERNAL_BLOCKED_* | upstream(上游 DNS 封鎖) |
| SPECIAL_DOMAIN | special |
| DBBUSY | busy |
| FORWARDED、CACHE、CACHE_STALE、RETRIED… | 未封鎖(NULL) |

AdGuard Home 的 `reason` 也對應到同一組代碼(FilteredBlackList → blocklist、
FilteredSafeBrowsing → safebrowsing、FilteredParental → parental、
FilteredBlockedService → service、FilteredInvalid → invalid)。

## 疑難排解

| netwarden 顯示 | 怎麼處理 |
|---|---|
| 登入被拒——請檢查帳號、密碼或金鑰 | `PIHOLE_PASSWORD` 不對。建立一組應用程式密碼,重新貼上。 |
| 已開啟兩步驟驗證 | 改用應用程式密碼(netwarden 不會要 2FA 驗證碼)。 |
| 這看起來是 Pi-hole v5 的 API 權杖 | v6 要用網頁登入密碼或應用程式密碼,不是 v5 的 token。 |
| 這不是 Pi-hole v6 的 API | `PIHOLE_URL` 指到 Pi-hole v5 或其他東西。把 Pi-hole 升級到 v6,或修正位址(`http://<pi-hole>`,不用加路徑)。 |
| Pi-hole 已沒有空的 API 會話 | 登入的用戶端太多。關掉其他 API 工具或等幾分鐘;用很多工具的話,在 Pi-hole 調高 `webserver.api.max_sessions`。 |
| 登入嘗試太多次 | 密碼錯太多次,Pi-hole 暫時限制登入。改好密碼,等一分鐘。 |
| HTTPS 憑證不受信任 | 在區網改用 `http://`,或設定 `PIHOLE_VERIFY_TLS=0`。 |
| 連得上,但查詢紀錄已關閉或被隱藏 | 把 Settings → Privacy 設成「全部顯示」(等級 0)。 |
| 每台裝置都顯示成路由器 | 路由器把所有 DNS 轉給 Pi-hole。改用 DHCP(路由器或 Pi-hole 自己的 DHCP)把 Pi-hole 的位址直接發給各裝置。 |

## 限制

- 每台裝置的辨識跟 AdGuard 相同:查詢的用戶端 IP 透過已知裝置與 ARP 表對應到 MAC。
  Pi-hole 必須直接看到各裝置的 IP(若所有查詢都經過路由器轉送,就只會看到路由器一台)。
- 相容性細節與資料來源:[dev/integrations.md](dev/integrations.md)(英文)。
