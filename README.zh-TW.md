# netwarden

[![ci](https://github.com/liming-ting/netwarden/actions/workflows/ci.yml/badge.svg)](https://github.com/liming-ting/netwarden/actions/workflows/ci.yml)
[![docker](https://github.com/liming-ting/netwarden/actions/workflows/docker.yml/badge.svg)](https://github.com/liming-ting/netwarden/actions/workflows/docker.yml)
授權:[AGPL-3.0-or-later](LICENSE)

[English](README.md)

**用白話告訴你家裡的網路發生了什麼——而且以隱私為優先。** netwarden 會找出區域網路上的裝置,
從你自己的 AdGuard Home 或 Pi-hole 讀取它們在跟誰連線,再用一家人看得懂、做得到的話,
告訴你哪些是新的、奇怪的或有風險的。AI 是選用的:可以用雲端模型、本機的 OpenAI 相容伺服器
(例如 Ollama),或完全不用模型(離線、規則式的固定說明)。

> 狀態:**0.1.0,第一個公開預覽版。** 作者自己在用;仍有不少粗糙之處。

![裝置清單:類型、使用者、房間、隱私等級與流量](docs/images/devices-desktop.png)

## 適合誰

- 已經在用(或願意架)AdGuard Home / Pi-hole 的 homelab 玩家,想要的不只是查詢紀錄,
  而是「這是哪台裝置?這樣正常嗎?需要在意嗎?」
- 想要一個平靜總覽的家庭:有新裝置、攝影機連到高風險雲端、平板過了就寢時間還在上網——
  不用訂閱,也不用雲端帳號。

## 它會做什麼

- **看見**:找出裝置(ping/ARP 掃描、mDNS、SSDP/UPnP、NetBIOS、DHCP 名稱、反向 DNS),
  推測每台裝置的類型並說明理由。
- **觀察**:從 AdGuard Home 或 Pi-hole v6 取得每台裝置的 DNS 活動;可選用 ntopng 取得每台裝置的流量;
  路由器 / 網路業者 / DNS 的健康狀態與斷線紀錄。
- **解釋**:附「為什麼會有這則提醒?」的警示、隱私等級(追蹤器比例)、高風險雲端、開放連接埠
  (需自行啟用的檢查)、DNS 盲點(DoH)、螢幕使用時間估計與只提醒不封鎖的就寢規則、
  0-100 分的家庭網路分數與建議,以及可以發問的助理。
- 儀表板支援 12 種語言(預設繁體中文)、淺色與深色、手機與電腦、可完整用鍵盤操作;
  也可選擇在區域網路內配對手機使用。

| | |
|---|---|
| ![裝置詳情](docs/images/device-drawer-desktop.png) | ![網路健康(深色主題)](docs/images/health-dark.png) |
| ![離線助理的回答](docs/images/assistant-offline.png) | ![手機上的家庭頁面(繁體中文)](docs/images/family-phone-zh-TW.png) |

所有截圖都來自內建的模擬示範家庭(`python3 -m netwarden demo`)。

## 它不會做什麼

- **唯讀。** 絕不更改你的路由器、防火牆、AdGuard Home 或 Pi-hole。修正方式都是建議:
  由你自己動手的步驟與可複製的規則。你在 netwarden 裡的操作(改名、信任、靜音、稍後提醒)
  只會寫進 netwarden 自己的 SQLite 資料庫。
- **沒有遙測**,沒有帳號,也沒有自己的雲端服務。
- **不做 ARP 欺騙、不做中間人、不擷取封包。** 不重做 DNS 紀錄或流量嗅探,而是讀取
  AdGuard Home / Pi-hole / ntopng。
- 它本身不會封鎖任何東西,也不能取代防火牆或防毒軟體。

## 快速開始

完整說明:[docs/install.zh-TW.md](docs/install.zh-TW.md)。需要 Python 3.11 以上,只用標準函式庫
(不需要 pip 套件)。無螢幕的安裝第一次啟動後,紀錄裡會出現一組一次性的管理員代碼,
用來從瀏覽器認領儀表板。

**Docker compose**(Linux 主機,使用 host 網路,掃描才看得到區域網路):

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs netwarden     # 一次性管理員代碼
```

`deploy/compose.adguard.yaml` 會一併啟動 AdGuard Home;`deploy/compose.bridge.yaml` 給
Docker Desktop 使用(看得到的裝置較少)。

**Home Assistant 附加元件**(HA OS / Supervised):把 `https://github.com/liming-ting/netwarden` 加為附加元件
儲存庫,安裝 *netwarden*,從側邊欄開啟。見 [docs/home_assistant.zh-TW.md](docs/home_assistant.zh-TW.md)。

**Linux / 樹莓派**(systemd 服務):

```bash
sh scripts/install_linux.sh --dry-run      # 列出每個動作,不做任何變更
sudo sh scripts/install_linux.sh
```

**Windows(WSL2)** 或任何桌機,從原始碼執行:

```bash
python3 -m netwarden run --demo --offline-ai   # 先試試:示範家庭、不用 AI,http://127.0.0.1:8787
python3 -m netwarden run                       # 你的網路
```

Windows 上可用 `scripts\start_windows.cmd` / `scripts\start_demo_windows.cmd` 在 WSL 裡啟動。
在 WSL 下掃描只看得到少數裝置(見「限制」)。

## AdGuard Home 與 Pi-hole

netwarden 沒有自己的 DNS 解析器。照常讓裝置(或路由器 DHCP 發的 DNS)使用 AdGuard Home 或
Pi-hole;netwarden 透過它們的 HTTP API 讀取每個用戶端的查詢紀錄(`ADGUARD_URL` /
`ADGUARD_USER` / `ADGUARD_PASS`,或 `PIHOLE_URL` / `PIHOLE_PASSWORD`),再把用戶端 IP 對應到裝置。
沒有 DNS 來源時,仍然有裝置掃描與辨識。詳見 [docs/pihole.zh-TW.md](docs/pihole.zh-TW.md)、
[docs/install.zh-TW.md](docs/install.zh-TW.md)。選用的每台裝置流量:
[docs/bandwidth.zh-TW.md](docs/bandwidth.zh-TW.md)。

## AI 與隱私

哪些資料可能離開這台電腦、在什麼時候:

| 內容 | 時機 | 送到哪裡 |
|---|---|---|
| 網路的摘要快照 + 你的問題 | **只有在你按下**「提問」/「產生洞察」時 | 你設定的 AI:Anthropic(雲端)、你的 OpenAI 相容伺服器(本機 / 區網 / 雲端),離線模式則哪裡都不送 |
| 向 AdGuard Home / Pi-hole / ntopng 查詢 | `run` 執行時每 30-60 秒 | 你設定的位址(通常在區網內) |
| 廠商資料庫(OUI)與威脅清單下載 | 只有在你執行 `python3 -m netwarden scan --update-vendors` / `python3 -m netwarden.threatintel --update "URL"` 時 | wireshark.org / 你選的清單,例如 abuse.ch URLhaus(需要免費的 abuse.ch Auth-Key;只下載,不送出任何關於你的資料;見 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)) |
| 選用的網際網路探測(只做 TCP 連線,不傳資料) | 只有在你設定 `health.internet_probe` 時(預設空白 = 關閉) | 你填的 host:port,例如 `1.1.1.1:443` |

- 背景迴圈從不呼叫 AI;開啟頁面也不會呼叫 AI。
- **送往雲端時預設會去識別化**:裝置名稱、主機名稱、使用者、房間、MAC 與私有 IP 會換成代號
  (`[D3]`、`[P1]`、`[M2]`、`[IP4]`),回覆在本機換回原名。網域、廠商、次數與時間不會隱藏——
  那正是 AI 推理的依據。「預覽將送出的內容」會先顯示確切的文字。
- 離線模式(`--offline-ai`,或沒設定 AI)用規則與你自己的資料回答,什麼都不送出。
- 在桌機上,`run` 只聽 127.0.0.1,區網 / 手機存取預設關閉。Docker 映像、compose 檔和 Linux 服務會開啟區網模式。區網存取一定要配對([docs/lan.md](docs/lan.md))。

更多:[docs/private_ai.md](docs/private_ai.md)。

## 限制(老實說)

- **在 WSL2 或 Docker Desktop 下,掃描只看得到少數裝置**(虛擬機的網路擋住了大部分區網)。
  放在同一個區網的 Linux 主機、樹莓派或 HA 附加元件效果最好。
- 每台裝置的 DNS 需要裝置**直接**使用 AdGuard Home / Pi-hole;如果全都由路由器轉送,
  所有查詢看起來都來自路由器。使用 DNS-over-HTTPS 的裝置會繞過它(netwarden 會標出這些盲點)。
- 螢幕使用時間、在家狀態與「不尋常」都是依 DNS 時間推得的**估計**,不是測量。
- 裝置類型是有根據的猜測,你可以更正。
- 流量需要把 ntopng 放在流量會經過的位置。
- 英文與繁體中文以外的翻譯是機器輔助的,非常歡迎母語使用者協助修正。
- Docker 映像與 Home Assistant 附加元件會在第一次推送時由 CI 建置與基本測試,還沒有在真正的
  Home Assistant 硬體上跑過。
- 單一家庭、單一使用者模型;本身不提供 HTTPS(請用需配對的區網模式,或放在你自己的反向代理後面)。

## 未來方向

- 收集第一批使用者的回饋,修正預覽版的錯誤。
- 區網模式的 HTTPS;封鎖原因的細分;更多裝置類型規則與服務對照。
- 改善 WSL / Docker Desktop 看不到的主機。

## 怎麼做出來的

netwarden 是在人的主導下,大量借助 AI(Claude Code)開發的:作者決定要做什麼並審查結果,
大部分的程式碼、測試與翻譯由 AI 撰寫。專案有大量自動化測試(1000 多個 unittest,只用假的伺服器、
不連網路),並在 CI 中執行。閱讀程式碼時請把這點放在心上,發現問題也請告訴我們。

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
