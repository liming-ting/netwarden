# netwarden

[![ci](https://github.com/liming-ting/netwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/liming-ting/netwarden/actions/workflows/ci.yml)
[![docker](https://github.com/liming-ting/netwarden/actions/workflows/docker.yml/badge.svg)](https://github.com/liming-ting/netwarden/actions/workflows/docker.yml)
授權:[AGPL-3.0-or-later](LICENSE)

[English](README.md)

**看見家裡網路上的每一台裝置、它們在跟誰連線,並用白話說明——跑在你自己的機器上,
除非你自己選擇,否則沒有任何資料會離開你家**
([哪些資料可能離開、在什麼時候](#隱私哪些資料可能離開你的網路在什麼時候))。

netwarden 會找出區域網路上的裝置,從你已經在用的 AdGuard Home 或 Pi-hole 讀取它們在跟誰連線,
再用一家人看得懂、做得到的話,告訴你哪些是新的、奇怪的或有風險的。它是唯讀的:
絕不更改你的路由器或 DNS 過濾器。

**[線上示範](https://liming-ting.github.io/netwarden/)** - 在瀏覽器裡直接看真正的儀表板,
資料是虛構的一個家:唯讀、不用安裝,也不會傳送任何資料。

![裝置清單:類型、使用者、房間、隱私等級與流量](docs/images/devices-desktop.png)

> 狀態:**早期預覽版(0.1.0)。** 作者自己家裡在用;仍有不少粗糙之處。

## 安裝

三選一。完整說明(含 Docker Desktop、升級、備份與移除):[docs/install.zh-TW.md](docs/install.zh-TW.md)。

**Docker**(放在區網上的 Linux 主機、樹莓派或 NAS;使用 host 網路,掃描才看得到區網):

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
cp deploy/netwarden.env.example deploy/netwarden.env     # 填入你的 AdGuard Home / Pi-hole 位址
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs netwarden     # 會顯示一次性管理員代碼
```

開啟 `http://<那台機器>:8787` 並輸入代碼;首次設定頁會檢查與 DNS 過濾器的連線。
`deploy/compose.adguard.yaml` 會一併啟動 AdGuard Home。

**Home Assistant 附加元件**(HA OS / Supervised):設定 > 附加元件 > 附加元件商店 > 儲存庫,
加入 `https://github.com/liming-ting/netwarden`,安裝 *netwarden*,在「設定」分頁選擇 DNS 來源,
再從側邊欄開啟。見 [docs/home_assistant.zh-TW.md](docs/home_assistant.zh-TW.md)。

**不用 Docker 的 Linux / 樹莓派**(systemd 服務,從原始碼安裝):

```bash
sh scripts/install_linux.sh --dry-run      # 列出每個動作,不做任何變更
sudo sh scripts/install_linux.sh           # 接著編輯 /etc/netwarden/netwarden.env
```

**先看看就好:**[線上示範](https://liming-ting.github.io/netwarden/),或從原始碼在本機執行
(Python 3.11 以上,只用標準函式庫,不需要 pip 套件):
`python3 -m netwarden run --demo --offline-ai`,再開 http://127.0.0.1:8787。Windows 上可用
`scripts\start_demo_windows.cmd` 在 WSL 裡啟動示範(連接埠 8788)。

## 需要什麼

- **AdGuard Home 或 Pi-hole v6**:用來知道「每台裝置在跟誰連線」。netwarden 沒有自己的 DNS
  解析器,而是透過它們的 HTTP API 唯讀讀取查詢紀錄([docs/pihole.zh-TW.md](docs/pihole.zh-TW.md))。
  裝置必須**直接**使用過濾器(否則所有查詢看起來都來自路由器)。
- **沒有它們**也還是有:裝置掃描與辨識、路由器 / 網路連線健康與斷線紀錄、需自行啟用的開放連接埠
  檢查、UPnP 連接埠對應、家庭成員與房間、待辦、報告與通知——只是沒有每台裝置的 DNS。
- 選用:**ntopng** 提供每台裝置的流量([docs/bandwidth.zh-TW.md](docs/bandwidth.zh-TW.md));
  **AI 模型**(Anthropic,或本機的 Ollama / LM Studio)用來自由發問——沒有的話,助理會用規則和
  你自己的資料回答([docs/private_ai.md](docs/private_ai.md))。

## 它會做什麼

**看見**
- 找出裝置(ping / ARP、mDNS、SSDP/UPnP、NetBIOS、DHCP 名稱、反向 DNS),推測每台裝置的類型
  並說明理由;任何東西都能自己改名、更正。
- 為裝置標上家庭成員與房間;網路地圖。

**看懂**
- 每台裝置的 DNS:用了哪些服務與追蹤器、隱私等級(A-F)、高風險雲端、DNS 盲點(DNS-over-HTTPS)。
- 新裝置、不尋常時段、開放連接埠、流量暴增等警示——每則都附「為什麼會有這則提醒?」。
- 網路健康:是路由器、網路業者還是 DNS 的問題?附斷線紀錄。
- 0-100 分的家庭網路分數與建議:由你自己動手的步驟與可複製的規則。
- 家庭:螢幕使用時間*估計*、只提醒不封鎖的就寢規則、可列印的週報。
- 可以發問的助理(「攝影機為什麼一直連那個網域?」)。

**隨時掌握**
- 警示與建議集中在一個待辦清單:靜音、稍後提醒、信任、復原;勿擾時段。
- **選用的推播通知**:ntfy、Gotify、Home Assistant、附簽章的 JSON Webhook,或 Discord、Slack、
  Telegram、LINE、Matrix——每個頻道各有隱私等級、勿擾時段、頻率上限,以及請求內容的確切預覽
  ([docs/notifications.zh-TW.md](docs/notifications.zh-TW.md))。
- **可分享的家庭網路報告**(7 或 30 天),單一 HTML 檔或 Markdown;預設等級會隱藏 MAC、IP、
  網域和家人名字([docs/report.zh-TW.md](docs/report.zh-TW.md))。

**照你的習慣用**
- 12 種語言(預設繁體中文)、淺色與深色、手機與電腦。
- 鍵盤優先:**Ctrl+K**(Mac 為 **Cmd+K**)開啟指令面板,找裝置、成員、頁面、設定並執行動作;
  按 `?` 看所有快捷鍵。
- 配對後可在區網內用手機開啟([docs/lan.md](docs/lan.md))。

| | |
|---|---|
| ![裝置詳情](docs/images/device-drawer-desktop.png) | ![網路健康(深色主題)](docs/images/health-dark.png) |
| ![離線助理的回答](docs/images/assistant-offline.png) | ![手機上的家庭頁面(繁體中文)](docs/images/family-phone-zh-TW.png) |
| ![指令面板:搜尋「galaxy」的裝置與動作](docs/images/palette.png) | |

所有截圖都來自內建的模擬示範家庭(`python3 -m netwarden demo`)。

## 隱私:哪些資料可能離開你的網路、在什麼時候

**除非你設定了 AI 服務或通知頻道,或開啟下表中需要自己啟用的下載 / 探測,否則沒有任何資料會離開
你的網路;而且你能看到確切送出的內容。** 沒有遙測、沒有帳號,也沒有自己的雲端服務。(AdGuard Home、
Pi-hole 與 ntopng 只會在你指定的位址查詢,通常在你的區網內。)

| 內容 | 時機 | 送到哪裡 |
|---|---|---|
| 網路的摘要快照 + 你的問題 | **只有在你按下**「提問」/「產生洞察」時 | 你設定的 AI:Anthropic(雲端)、你的 OpenAI 相容伺服器(本機 / 區網 / 雲端),離線模式則哪裡都不送 |
| 一段簡短的通知文字(每個頻道各有隱私等級) | 只限你新增並啟用的頻道:發生你勾選的警示 / 摘要時,或你按下「傳送測試」時 | 你選的服務:自架的 ntfy / Gotify / Home Assistant / Webhook(通常在區網內),或 Discord、Slack、Telegram、LINE、Matrix(文字會經過該公司) |
| 向 AdGuard Home / Pi-hole / ntopng 查詢 | `run` 執行時每 30-60 秒 | 你設定的位址(通常在區網內) |
| 廠商資料庫(OUI)與威脅清單下載 | 只有在你執行 `python3 -m netwarden scan --update-vendors` / `python3 -m netwarden.threatintel --update "URL"` 時 | wireshark.org / 你選的清單,例如 abuse.ch URLhaus(需要免費的 abuse.ch Auth-Key;只下載,不送出任何關於你的資料;見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)) |
| 選用的網際網路探測(只做 TCP 連線,不傳資料) | 只有在你設定 `health.internet_probe` 時(預設空白 = 關閉) | 你填的 host:port,例如 `1.1.1.1:443` |

- 背景迴圈和開啟頁面都不會呼叫 AI。
- **送往雲端 AI 時預設會去識別化**:裝置名稱、主機名稱、使用者、房間、MAC 與私有 IP 會換成代號
  (`[D3]`、`[P1]`、`[M2]`、`[IP4]`),回覆在本機換回原名。網域、廠商、次數與時間不會隱藏——
  那正是 AI 推理的依據。「預覽將送出的內容」會先顯示確切的文字。
- 通知文字由固定範本產生,絕不由 AI 撰寫。新頻道一開始是暫停的;預設等級絕不傳送 MAC/IP 位址
  或原始網域;啟用前,編輯畫面就會顯示確切的請求內容。
- **對你的網路唯讀:**不更改路由器、防火牆、AdGuard Home 或 Pi-hole;不做 ARP 欺騙、不做中間人、
  不擷取封包。你的操作(改名、信任、靜音)只會寫進 netwarden 自己的 SQLite 資料庫。它本身不會
  封鎖任何東西,也不能取代防火牆或防毒軟體。
- 在桌機上,`run` 只聽 127.0.0.1。Docker 映像、compose 檔和 Linux 服務會開啟區網模式;
  區網存取一定要配對。

## 限制(老實說)

- **在 WSL2 或 Docker Desktop 下,掃描只看得到少數裝置**(虛擬機的網路擋住了大部分區網)。
  放在同一個區網的 Linux 主機、樹莓派或 HA 附加元件效果最好。
- 每台裝置的 DNS 需要裝置直接使用 AdGuard Home / Pi-hole;使用 DNS-over-HTTPS 的裝置會繞過它
  (netwarden 會標出這些盲點)。
- 螢幕使用時間、在家狀態與「不尋常」都是依 DNS 時間推得的**估計**,不是測量。裝置類型是
  有根據的猜測,你可以更正。
- Pi-hole v6 與 ntopng 的支援是依官方 API 文件開發,並用假的伺服器測試;AdGuard Home 在真實的
  安裝上測試過。流量需要把 ntopng 放在流量會經過的位置。
- 容器映像與 Home Assistant 附加元件在 CI 中建置並做基本測試;在 NAS 與 Home Assistant 實機上的
  測試還很少。
- 英文與繁體中文以外的翻譯是機器輔助的,非常歡迎母語使用者協助修正。
- 每套安裝對應一個家,沒有使用者帳號;本身不提供 HTTPS(請用需配對的區網模式,或放在你自己的
  反向代理後面)。

## 怎麼做出來的

netwarden 是在人的主導下,大量借助 AI(Claude Code)開發的:作者決定要做什麼與硬性規則
(唯讀、只用標準函式庫、沒有遙測)並審查結果,大部分的程式碼、測試與翻譯由 AI 撰寫。
專案有大量自動化測試(unittest,只用假的伺服器、不連網路),每次推送都在 CI 中執行。
閱讀程式碼時請把這點放在心上,發現問題也請告訴我們。

## 未來方向

- 收集第一批使用者的回饋,修正預覽版的錯誤。
- 區網模式的 HTTPS;封鎖原因的細分;更多裝置類型規則與服務對照。

## 參與貢獻

歡迎回報錯誤、協助翻譯,以及小而聚焦的 pull request——見 [CONTRIBUTING.md](CONTRIBUTING.md)。
資安問題請私下回報,見 [SECURITY.md](SECURITY.md)。所有人都應遵守[行為準則](CODE_OF_CONDUCT.md)。
變更紀錄:[CHANGELOG.md](CHANGELOG.md)。第三方程式碼與資料:[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 授權

Copyright (C) 2026 liming-ting and contributors.

netwarden 是自由軟體,採用 **GNU AGPL v3 或更新版本**(SPDX `AGPL-3.0-or-later`,全文見
[LICENSE](LICENSE))。簡單來說:

- 你可以使用、研究、修改並自行架設它,在家裡或任何地方都可以。
- 如果你把副本提供給別人(不論有沒有修改),也必須以同一個授權提供該版本的原始碼。
- 如果你修改了它,並讓其他人透過網路使用你修改後的版本(例如別人也能開啟的儀表板),
  就必須以同一個授權向這些使用者提供你那個版本的原始碼。設定頁上的「原始碼」連結就是為此而設。
- 本軟體不提供任何擔保。

以上摘要不是法律意見,以 LICENSE 全文為準。第三方元件及其授權列在
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。
