# 推播通知

[English](notifications.md)

netwarden 可以透過你選擇的服務,把挑選過的警示與摘要傳到手機。**在你新增頻道之前完全關閉**,
而且新頻道一開始是**暫停**的:先傳送測試,再啟用。通知頻道是少數會讓 netwarden 連到你網路以外
伺服器的功能之一(完整清單見 README 的[隱私表格](../README.zh-TW.md#隱私哪些資料可能離開你的網路在什麼時候));
而且你能看到確切送出的內容:編輯頻道時,畫面會即時顯示範例訊息的實際 HTTP 請求(機密資料會遮蔽)。

開啟「**設定 > 通知**」(或按 Ctrl+K 輸入「通知」)。只有管理員能看到、新增、編輯、測試或刪除頻道:
也就是這台電腦,或管理員工作階段(`pair --admin`,見 [lan.md](lan.md))。以檢視者身分配對的手機
看不到任何頻道資訊。

## 選哪個服務

| 服務 | 文字會送到哪裡 | 需要準備 |
|---|---|---|
| [ntfy](https://docs.ntfy.sh/publish/) | 你的 ntfy 伺服器(留在家裡)或 ntfy.sh | 伺服器網址、主題;可選存取權杖或帳號 + 密碼 |
| [Gotify](https://gotify.net/docs/pushmsg) | 你的 Gotify 伺服器 | 伺服器網址、應用程式權杖 |
| [Home Assistant](https://www.home-assistant.io/integrations/notify/) | 你的 Home Assistant,再到它的手機 App | HA 網址、長期存取權杖、notify 服務 |
| Webhook(JSON) | 任何你掌控的網址(n8n、Node-RED、自己的程式) | 網址;可選 HMAC 密鑰 |
| [Discord](https://support.discord.com/hc/en-us/articles/228383668) | Discord(一家公司) | 頻道的 Webhook 網址 |
| [Slack](https://api.slack.com/messaging/webhooks) | Slack(一家公司) | 傳入 Webhook 網址 |
| [Telegram](https://core.telegram.org/bots/tutorial) | Telegram(一家公司) | @BotFather 給的機器人權杖、聊天 ID |
| [LINE](https://developers.line.biz/en/docs/messaging-api/sending-messages/) | LINE(一家公司) | Messaging API 的頻道存取權杖、使用者 / 群組 ID |
| [Matrix](https://spec.matrix.org/latest/client-server-api/#sending-events-to-a-room) | 你的 homeserver(或公開的) | homeserver 網址、存取權杖、聊天室 ID |

自架的服務只要伺服器在家裡,所有資料都留在你的網路內。雲端服務的頁面會顯示提醒:文字會經過
該公司的伺服器。

設定提示:

- **ntfy**:知道公開主題名稱的人都能讀取。在 ntfy.sh 上請取一個又長又隨機的主題,或用自架伺服器
  搭配存取權杖。
- **Telegram**:用 @BotFather 建立機器人,先傳任意訊息給它,再在編輯畫面按「**找出我的聊天 ID**」。
  netwarden 只有在你按下時才會向 Telegram 呼叫一次 `getUpdates`。
- **LINE**:LINE Notify 已於 2025 年 3 月結束服務;netwarden 改用 **Messaging API** 的推送訊息。
  為 LINE 官方帳號建立 Messaging API 頻道,發行頻道存取權杖,再填入你的使用者 ID(`U` 開頭,
  可在 LINE Developers 主控台看到)或群組 ID。**額度**:推送訊息會算進官方帳號每月的免費訊息
  則數,數量依國家與方案而不同(例如部分地區的免費方案每月只有幾百則);用完後訊息會被拒絕或
  開始收費。請到「LINE 官方帳號管理後台 > 方案」查看你的實際數字。一則文字訊息最多 5,000 字,
  netwarden 會截斷更長的內容。頻率上限請設低一點。
- **Matrix**:請用專用的機器人帳號;訊息以 `m.notice` 傳送(純文字,netwarden 不做端對端加密)。
- **Home Assistant**:為什麼要填網址和權杖,見[下方說明](#home-assistant為什麼要填網址和權杖)。
  按「**列出通知服務**」即可選擇 `mobile_app_<你的手機>`。

## 傳什麼、什麼時候傳

每個頻道各自選擇:

- **類別**:安全(威脅、開放連接埠、UPnP、DNS 盲點)、新出現 / 有變化的裝置、家庭(深夜活動、
  就寢規則)、網路健康(斷線、流量暴增)、家庭網路分數下降(與前一天相比降 10 分以上),以及
  每週摘要。預設:安全、裝置、健康。
- 警示的**最低嚴重程度**(嚴重 / 高 / 中 / 低)。
- **每小時訊息數上限**(1-60,預設 10)。超過的部分會合併成**一則**摘要訊息(「另外 12 則警示」),
  不會一次送出一大堆。
- **每日摘要**:每天在摘要時間傳一則簡短訊息(家庭網路分數、收件匣待辦項目)。
- **訊息語言**:跟儀表板相同,或另外指定(12 種語言)。

警示會遵守你在儀表板上的所有設定:你**靜音、稍後提醒、已確認或調低敏感度**的警示都不會傳送
(已排入佇列的也會在你操作時被取消)。每個事件在每個頻道只會傳**一次**,重新啟動後也一樣。
頻道剛建立或剛啟用時,當下已經存在的事件不算新消息:只會傳之後新發生的事件。

**勿擾時段**(設定 > 勿擾時段)會先把通知留著;時段結束時合併成**一則**「你休息時發生的事」。
每個頻道的「勿擾時段仍傳送緊急安全警示」(預設開啟)會讓嚴重 / 高嚴重度的安全警示照常送出。

所有頻道共用的設定:**摘要傳送時間**(預設當地時間 08:00,`NETWARDEN_NOTIFY_DIGEST_TIME`)與
**每週摘要日**。

訊息文字**絕不由 AI 撰寫**:就是儀表板與勿擾摘要用的同一句話,每次都用同樣方式組成。

## 隱私等級

| 等級 | 範例 | 絕不包含 |
|---|---|---|
| **最少** | 「1 則新警示:安全。詳情請開啟儀表板。」 | 名稱、位址、網域 |
| **標準**(預設) | 「客廳電視 連線到威脅清單上的網域:🟠 高風險」 | MAC 或 IP 位址、原始網域(威脅只會寫「高風險」/「已知惡意」) |
| **詳細** | 加上裝置的 IP 與 MAC 位址、網域、裝置連結 | - |

即使是最少與標準等級,任何看起來像 IPv4 / IPv6 或 MAC 位址的字串都會被遮蔽,包括你自己取的
裝置名稱裡的。頻道若位於你的私人網路之外(所有雲端服務,或公開的伺服器),選擇**詳細**時需要
明確確認。

只有在你設定了對外網址(`lan.advertised_url`,設定 > 手機存取)時,訊息才會附上儀表板連結;
否則不附任何連結。

## 機密資料

權杖、密碼、Webhook 網址(本身就含有憑證)和 HMAC 密鑰都是**僅能寫入**:頁面只顯示「已設定」/
「未設定」,可以替換或移除,但永遠無法讀回。它們絕不會出現在 API 回應、紀錄(只記錄協定 + 主機,
例如 `https://ntfy.sh`)、錯誤訊息、匯出檔、報告、備份或靜態示範裡。**備份不包含通知頻道**:
還原後請重新新增。已儲存的機密資料只會送到當初輸入時的那台伺服器:如果你把頻道的網址改到別的主機
(或別的連接埠、http / https),請重新輸入權杖 / 密碼。

## 用環境變數定義頻道

Docker / 無螢幕安裝可以從環境變數定義最多 9 個頻道。頁面會標示為「由環境變數管理」(唯讀),
它們的機密資料也絕不會寫進資料庫。`<n>` 為 1-9:

| 變數 | 意義 |
|---|---|
| `NETWARDEN_NOTIFY_<n>_TYPE` | `ntfy`、`gotify`、`homeassistant`、`webhook`、`discord`、`slack`、`telegram`、`line`、`matrix`(必填) |
| `NETWARDEN_NOTIFY_<n>_NAME` | 顯示名稱(預設 `env-<n>`) |
| `NETWARDEN_NOTIFY_<n>_URL` / `_TOPIC` / `_TOKEN` / `_USER` / `_PASSWORD` / `_SECRET` / `_SERVICE` / `_CHAT_ID` / `_TO` / `_ROOM` / `_PIN` | 該類型的欄位(見上表) |
| `NETWARDEN_NOTIFY_<n>_LEVEL` | `minimal`、`standard`(預設)、`detailed` |
| `NETWARDEN_NOTIFY_<n>_CATEGORIES` | 以逗號分隔:`security,devices,family,health,score,digest` |
| `NETWARDEN_NOTIFY_<n>_MIN_SEVERITY` | `critical`、`high`、`medium`、`low`(預設) |
| `NETWARDEN_NOTIFY_<n>_RATE` | 每小時訊息數(預設 10) |
| `NETWARDEN_NOTIFY_<n>_DAILY` | `1` = 每日摘要 |
| `NETWARDEN_NOTIFY_<n>_QUIET_BYPASS` | `0` = 勿擾時段連緊急安全警示也先留著 |
| `NETWARDEN_NOTIFY_<n>_LANG` | 訊息語言,例如 `en`、`zh-Hant` |

環境變數定義的頻道只要設定有效就會啟用;無效的會被略過,並記錄一次(不含任何值)。範例:

```bash
NETWARDEN_NOTIFY_1_TYPE=ntfy
NETWARDEN_NOTIFY_1_URL=https://ntfy.example.org
NETWARDEN_NOTIFY_1_TOPIC=home-3f9c2a71
NETWARDEN_NOTIFY_1_TOKEN=tk_...
```

## Webhook 格式

以 `POST` 傳送,`Content-Type: application/json`,格式版本 `netwarden.notification/1`(版本 1 內
只會新增欄位):

```json
{
  "schema": "netwarden.notification/1",
  "id": "nw-3b1f0c9a27d44e8a6b51",
  "kind": "alert",
  "category": "devices",
  "severity": "low",
  "title": "netwarden · 新的或不明裝置",
  "body": "新裝置:客廳電視",
  "url": null,
  "lang": "zh-Hant",
  "level": "standard",
  "sent_at": "2026-10-21T12:00:00.000000Z",
  "count": 1
}
```

`kind` 為 `alert`、`score`、`weekly`、`daily`、`summary`(勿擾時段)、`bundle`(頻率上限)或
`test`;`severity` 為 `critical`、`high`、`medium` 或 `low`;`count` 是摘要 / 合併訊息裡的警示數。
同一事件的 id 固定不變(低於詳細等級時是雜湊值,不會帶有裝置位址)。

設定 HMAC 密鑰時會多兩個標頭:

```
X-Netwarden-Timestamp: 1792584000
X-Netwarden-Signature: sha256=<hex HMAC-SHA256(密鑰, 時間戳記 + "." + 原始內容)>
```

請在接收端驗證(並拒絕太舊的時間戳記),例如 Python:

```python
import hashlib, hmac
expected = "sha256=" + hmac.new(secret.encode(), ts.encode() + b"." + body, hashlib.sha256).hexdigest()
ok = hmac.compare_digest(expected, request_signature)
```

密鑰絕不會出現在網址裡。

## 傳送與安全

- 訊息會先排在 netwarden 資料庫裡的佇列:絕不會卡住儀表板或警示迴圈,重新啟動後也還在。
  背景迴圈每 15 秒傳送一次。
- 只接受 `http://` 和 `https://`,網址裡不可有 `帳號:密碼@`,有大小限制,逾時 8 秒。**絕不**跟隨
  重新導向(伺服器必須在你填的網址直接回應)。
- 暫時性問題(逾時、連線錯誤、HTTP 429 / 5xx)最多重試 3 次,間隔 30 秒、2 分鐘、10 分鐘並加上
  隨機抖動;會遵守 `Retry-After` 標頭(最多一小時)。權杖或網址錯誤(401 / 403 / 404)不會重試。
- 一律驗證 TLS 憑證。若自架伺服器使用**自簽憑證**,請把它的 SHA-256 指紋填入固定憑證;之後憑證
  必須完全相同,而且會在送出任何內容之前檢查。沒有任何關閉驗證的開關。取得指紋的方法:
  `openssl s_client -connect host:443 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256`
- 每個頻道都有**傳送紀錄**(時間、內容、已送達或錯誤類別);最近一次錯誤會用白話顯示在設定頁,
  並告訴你下一步該怎麼做。
- 示範家庭永遠不會傳送任何東西(它的範例頻道指向 `.invalid` 主機)。

## Home Assistant:為什麼要填網址和權杖

以 Home Assistant 附加元件執行時,netwarden 其實可以透過 Supervisor 代理呼叫通知服務,但前提是
開啟 `homeassistant_api: true`,這會讓附加元件取得整個 Home Assistant Core API 的存取權,並降低
附加元件的安全評等。netwarden 讓這個權限保持**關閉**。改由你填入 HA 網址(例如
`http://homeassistant.local:8123`)和一組**長期存取權杖**(HA 個人資料 > 安全性)。若想限制權杖
能做的事,可以另外建立一個專用的 HA 使用者;netwarden 只會呼叫 `GET /api/services`(在你按下時)
和 `POST /api/services/notify/<service>`。

## 命令列

```bash
python3 -m netwarden notify list                  # 頻道、狀態、上次送達
python3 -m netwarden notify test "Phone"          # 傳一則測試訊息
python3 -m netwarden notify send-digest [--daily] # 立刻排入並傳送摘要
```

每週執行的 `python3 -m netwarden alerts`(cron)照舊印出摘要,永遠不會傳送通知。

## 疑難排解

| 你看到 | 該怎麼做 |
|---|---|
| 「不接受這個權杖」(401) | 重新產生權杖,貼上後儲存 |
| 「拒絕存取」(403) | 權杖沒有發送到那裡的權限(ntfy ACL、Gotify 應用程式、Slack 頻道) |
| 「找不到這個網址」(404) | Webhook 已被刪除,或網址打錯了 |
| 「要求放慢速度」(429) | 調低每小時訊息數;netwarden 會自己重試 |
| 「回應了重新導向」 | 填入最終的網址(常見的是 `https://` 而非 `http://`) |
| 「無法驗證伺服器的憑證」 | 自簽憑證:填入固定憑證的指紋 |
| 「與固定的指紋不符」 | 你更新過憑證:填入新的指紋 |
| 沒收到、也沒有錯誤 | 頻道啟用了嗎?類別和最低嚴重程度選對了嗎?是不是在勿擾時段? |

*本文件由英文版翻譯,部分內容借助機器輔助。*
