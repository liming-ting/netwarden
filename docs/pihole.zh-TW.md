# 使用 Pi-hole

[English](pihole.md)

netwarden 可以讀取 **Pi-hole v6** 的查詢紀錄(query log),取代或搭配 AdGuard Home。
它走 Pi-hole v6 內建的 REST API(`/api/auth`、`/api/queries`),**只讀取查詢紀錄**:
不會更動 Pi-hole 的任何設定、清單或封鎖規則,也不會碰你的路由器。

## 設定(`.env`)

```ini
PIHOLE_URL=http://pi.hole          # 或 http://192.168.1.2、https://pi.hole
PIHOLE_PASSWORD=...                # 建議用「應用程式密碼」(Settings → Web interface / API → App password)
# PIHOLE_VERIFY_TLS=0              # 只有 HTTPS 用 Pi-hole 內建的自簽憑證時才需要
# NETWARDEN_DNS_SOURCE=pihole      # 同時設定了 AdGuard 與 Pi-hole 時才需要;預設用 AdGuard
```

- **應用程式密碼**比主密碼更好:可單獨撤銷,開了兩步驗證(2FA)也能用。
- Pi-hole 沒設密碼時,`PIHOLE_PASSWORD` 留空即可。
- HTTPS 預設會**驗證憑證**;`PIHOLE_VERIFY_TLS=0` 只在你信任的區網內使用。
- 只能用一個 DNS 來源:兩個都設定時用 `NETWARDEN_DNS_SOURCE=adguard|pihole` 選擇。

## 執行

```bash
python3 -m netwarden ingest        # 擷取一次 + 每台裝置的報告
python3 -m netwarden run           # 儀表板 + 每 60 秒自動擷取
python3 -m netwarden status        # 看「DNS(Pi-hole)」是否正常,以及修正提示
```

## 會話(session)

Pi-hole 同時能開的 API 會話有限。netwarden 每次執行(或整個 `run` 背景迴圈)只登入
**一次**並重複使用;會話過期(HTTP 401)會自動重新登入一次;結束時一定會登出
(`DELETE /api/auth`)釋放名額。若出現「no free API session (HTTP 429)」,
請關閉其他 API 用戶端,或等幾分鐘讓舊會話逾時。

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

## 限制

- 只支援 Pi-hole **v6**(FTL REST API)。v5 以前沒有這套 API。
- 每台裝置的辨識跟 AdGuard 相同:查詢的用戶端 IP 透過已知裝置與 ARP 表對應到 MAC。
  Pi-hole 必須直接看到各裝置的 IP(若所有查詢都經過路由器轉送,就只會看到路由器一台)。
