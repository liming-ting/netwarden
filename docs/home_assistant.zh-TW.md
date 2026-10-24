# 把 netwarden 當作 Home Assistant 附加元件使用

[English](home_assistant.md)

netwarden 可以作為 Home Assistant 附加元件(add-on)執行(Home Assistant OS 或 Supervised
安裝),並出現在 Home Assistant 的側邊欄。它會找出你網路上的裝置,從 AdGuard Home 或
Pi-hole 讀取每台裝置的 DNS 查詢,再用白話解釋它看到的事情。它是唯讀的:絕不會修改你的
路由器、防火牆、AdGuard Home 或 Pi-hole。

> Home Assistant **Container** 與 **Core** 安裝方式沒有附加元件功能,請改用 Docker 映像檔
> 或 Linux 安裝(docs/install.zh-TW.md)。

## 安裝

1. 在 Home Assistant 開啟 **設定 > 附加元件 > 附加元件商店**,再點右上角選單(⋮)>
   **儲存庫**,加入:

   ```
   https://github.com/liming-ting/netwarden
   ```

2. 在商店找到 **netwarden**(沒出現的話重新整理頁面),點 **安裝**,再點 **啟動**。
   建議保持 **開機時啟動**;**在側邊欄顯示** 預設已開啟。
3. 點 **開啟網頁介面**,或側邊欄的 **netwarden**。只有 Home Assistant 管理員看得到這個面板。

附加元件映像檔是 `ghcr.io/liming-ting/netwarden-addon`,支援 amd64、aarch64(64 位元 Raspberry Pi)
和 armv7。有新版本時,Home Assistant 會像其他附加元件一樣顯示更新。(Home Assistant 從
2025.12 版起不再支援 32 位元系統;armv7 映像檔仍會建置給既有的安裝使用,但沒有實測過。)

## 選項

在附加元件的 **設定(Configuration)** 分頁設定,改完後重新啟動附加元件。沒用到的選填欄位
要點 **顯示未使用的選填設定選項** 才會出現。

| 選項 | 對應的環境變數 | 說明 |
|---|---|---|
| `language` | `NETWARDEN_LANG` | zh-Hant(預設)、en、zh-Hans、es、pt-BR、ja、de、fr、ko、ru、id、hi |
| `timezone` | `NETWARDEN_TZ` | IANA 時區名稱;留空 = 使用 Home Assistant 的時區 |
| `dns_source` | `NETWARDEN_DNS_SOURCE` | `adguard` 或 `pihole` |
| `adguard_url` / `adguard_user` / `adguard_password` | `ADGUARD_URL` / `ADGUARD_USER` / `ADGUARD_PASS` | 只讀取查詢紀錄 |
| `pihole_url` / `pihole_password` | `PIHOLE_URL` / `PIHOLE_PASSWORD` | Pi-hole v6;建議用應用程式密碼 |
| `ntopng_url` / `ntopng_user` / `ntopng_password` | `NTOPNG_URL` / `NTOPNG_USER` / `NTOPNG_PASS` | 選用:每台裝置的流量 |
| `ntopng_token` | `NTOPNG_TOKEN` | 選用;取代 ntopng 的帳號 + 密碼 |
| `adguard_verify_tls` / `pihole_verify_tls` / `ntopng_verify_tls` | `ADGUARD_VERIFY_TLS` / `PIHOLE_VERIFY_TLS` / `NTOPNG_VERIFY_TLS` | 不設定 = 驗證憑證;只有 `https://` 位址搭配來源自己的自簽憑證時才關閉 |
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | 選用;只有你在 AI 頁面提問時才會呼叫 |
| `ai_api_key` | `NETWARDEN_AI_KEY` | 選用;本機 / 私有 OpenAI 相容伺服器的金鑰 |
| `offline_ai` | `NETWARDEN_OFFLINE_AI` | 永遠不呼叫任何 AI 模型 |
| `lan_access` | `NETWARDEN_LAN` | 讓區域網路上的手機也能開啟(需要配對) |
| `retention_days` | `NETWARDEN_RETENTION_DAYS` | 歷史資料保留天數,8-3650(預設 90) |

優先順序:**附加元件選項 > 儀表板設定 > 內建預設值**,和其他地方的環境變數規則一樣。
由選項決定的設定,在儀表板會顯示「已在 Home Assistant 的附加元件選項中設定」,無法在那裡
修改;想在儀表板管理(例如 AI 伺服器位址與模型、勿擾時段、警示調整),就把選項留空。
密碼和金鑰只存在 Home Assistant 的附加元件選項中,不會傳到瀏覽器,也不會寫進紀錄檔。

### AdGuard Home 或 Pi-hole 也是附加元件時

- **AdGuard Home 附加元件:** 在它的 **網路** 設定中替網頁介面指定一個埠(例如 3000),
  重新啟動它,再把 `adguard_url` 設為 `http://<你的 Home Assistant IP>:3000`,並填入
  AdGuard Home 的帳號密碼。
- 網路上另一台的 **Pi-hole:** `dns_source: pihole`、`pihole_url: http://192.168.1.3` 加上密碼。

接著到儀表板的 **設定 > 連線測試** 確認。

## Ingress(側邊欄面板)

Home Assistant 透過 *ingress* 顯示儀表板:你的瀏覽器只和 Home Assistant 溝通,再由
Home Assistant 的 Supervisor 把請求轉給附加元件。

- 你已經由 Home Assistant 登入,netwarden 不會再要求其他登入。只有管理員看得到面板
  (`panel_admin`),在面板裡你擁有 netwarden 的管理權限(設定、備份、連接埠檢查、配對)。
- netwarden 只信任一個來源:Supervisor 的 ingress 代理位址(172.30.32.2)。其他任何來源
  送來的轉送標頭(`X-Ingress-Path`、`X-Forwarded-*`)一律忽略,所以區域網路上的裝置
  無法假裝成 Home Assistant。
- 透過 Nabu Casa 遠端存取也能使用,因為它同樣經過 Home Assistant。
- 即時更新(綠色的「即時」圓點)和家庭週報在面板中都能正常運作。

## 手機與其他電腦(區域網路存取)

預設情況下,netwarden **只能透過 Home Assistant 開啟**。想直接用手機瀏覽器開啟:

1. 把 `lan_access` 設為 `true`,重新啟動附加元件。
2. 在面板開啟 **設定** 的「在手機上開啟」卡片,點 **顯示配對碼**,用同一個 Wi-Fi 的手機
   掃描 QR code。

手機之後會開啟 `http://<Home Assistant IP>:8787`。配對的手機可以看儀表板,但不能執行
管理動作;也可以在同一張卡片撤銷。這是一般 HTTP(沒有加密):只在你信任的家用網路使用。
用 Home Assistant App 或 Nabu Casa 的話,直接開側邊欄面板也可以。

## 通知送到 Home Assistant App

netwarden 可以透過 Home Assistant 的 notify 服務(`notify.mobile_app_<你的手機>`)把挑選過的警示
傳到手機:到「**設定 > 通知**」新增一個 **Home Assistant** 頻道。它需要你的 HA 網址(例如
`http://homeassistant.local:8123`)和一個**長期存取權杖**(HA 個人資料 > 安全性),因為附加元件
刻意把 `homeassistant_api` 保持**關閉**:這個權限會讓它能使用整個 Home Assistant Core API,也會
降低附加元件的安全評分。原因與權杖的用途見
[notifications.zh-TW.md](notifications.zh-TW.md#home-assistant為什麼要填網址和權杖)。

## 附加元件能做什麼、不能做什麼

- **網路存取:** 使用主機網路(`host_network`),探索功能(ARP 表、ping 掃描、mDNS /
  SSDP)才看得到你的區域網路。不是特權模式,不需要額外權限,也無法存取 Home Assistant
  或 Supervisor 的 API。映像檔只在啟動時以 root 身分取得 `/data` 資料夾的擁有權,之後
  立刻切換成一般使用者。
- **連接埠 8787:** 附加元件會在主機上使用(本機迴路與 Supervisor 內部網路;開啟
  `lan_access` 才會開放到區域網路)。如果主機上有其他程式占用,附加元件無法啟動。
- **備份:** `/data`(資料庫、設定、配對)包含在 Home Assistant 備份中。備份時附加元件會
  短暫停止,確保 SQLite 檔案一致。
- **探索範圍** 是 Home Assistant 主機所在的網路;另一台路由器後面、訪客 Wi-Fi 或 VLAN
  裡的裝置可能看不到。
- **DNS** 只看得到使用 AdGuard Home / Pi-hole 的裝置。開啟私人 DNS 的手機或使用
  DNS-over-HTTPS 的瀏覽器會繞過它;netwarden 會指出這種情況。
- 目前 **沒有提供 AppArmor 設定檔**(使用 Home Assistant 預設的容器設定檔),所以商店中的
  安全評分會稍微低一點。
- 英文和繁體中文以外的 **翻譯** 是機器輔助翻譯。
- 本專案在大量 AI 協助下開發,並有大型自動化測試涵蓋;附加元件是用模擬的 Supervisor 和
  ingress 代理測試,還沒有在真正的 Home Assistant 安裝上實測過。

## 疑難排解

| 狀況 | 怎麼做 |
|---|---|
| 商店裡找不到附加元件 | 確認儲存庫網址;重新整理商店頁面(⋮ > 檢查更新)。 |
| 面板空白 / 502 Bad Gateway | 看附加元件的 **紀錄** 分頁。出現「連接埠 8787 已被使用」表示主機上有其他程式占用。 |
| 沒有 DNS 資料 / 未設定 DNS 來源 | 設定 `adguard_url` 或 `pihole_url`,重新啟動,再到 **設定 > 連線測試**。 |
| 儀表板裡某個設定無法修改 | 它由附加元件選項決定;到設定分頁修改或清空。 |
| 手機連不上 | `lan_access` 開了嗎?附加元件重新啟動了嗎?同一個 Wi-Fi 嗎?重新配對(配對碼 10 分鐘內有效)。 |
| AI 回答顯示「離線模式」 | 沒有設定金鑰,或開啟了 `offline_ai`。這是預設的隱私做法。 |

紀錄只會列出哪些選項有設定(只有名稱),絕不會顯示選項的值。
