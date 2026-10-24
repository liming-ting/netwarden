# 頻寬 / 網速監控可行性調查(設計筆記)

使用者指南:[../bandwidth.md](../bandwidth.md)([繁體中文](../bandwidth.zh-TW.md))。
這份是當初的設計筆記:為什麼 DNS 給不了頻寬、有哪些選項、為什麼選 ntopng,以及計數器怎麼算。

> 結論先講:**用 netwarden 現有的資料來源(DNS)拿不到「位元組 / 網速」**,只能拿到「誰在跟誰通訊 + 查詢次數」。
> 想要「每台裝置的用量」需要一個**新的資料來源**。一般廉價家用路由器沒有乾淨的機器介面可用;
> 最划算的是**旁路/閘道 + ntopng**,netwarden 以**唯讀**方式去讀它的 REST API。
> 頻寬做成**可選、可插拔的 traffic adapter**(跟 DNS adapter 一樣的結構),優雅降級,而不是核心必需。

---

## 1. 為什麼 DNS 給不了頻寬

netwarden 吃的是 AdGuard Home / Pi-hole 的 **per-client DNS 日誌**。DNS 記錄的是
「某裝置問了某網域」這個**事件**,它有:時間、用戶端、網域、是否被擋、查詢類型。
它**沒有**的:這次連線傳了多少位元組、持續多久、速率多少。

- AdGuard Home 的統計系統只彙總 **查詢次數 / 攔截率 / Top 網域 / Top 用戶端 / 上游耗時**,
  **完全不含位元組或頻寬**(來源:AdGuard Home `internal/stats`)。
- 所以裝置詳情裡「近 7 天查詢量」長條圖標的是**查詢次數**,不是流量——UI 已如實標註。

一句話:**查詢次數 ≠ 流量**。一台裝置可以查 1 次 DNS 然後下載 10GB;也可以狂查 DNS 但幾乎不傳資料。

---

## 2. 一般家用路由器能提供什麼

低階家用路由器(原廠韌體)通常只開 DNS (53) 與網頁管理介面 (80);SNMP、流量匯出
(NetFlow/sFlow/IPFIX)、TR-069 多半沒有或依型號 / 韌體而定。開發時實測的一台,網頁上的
「流量統計」只有**每個介面的封包數**,沒有位元組,也沒有每台裝置的資料。

**含義:** 想從這類路由器拿資料,只能登入後**抓網頁**——脆弱(要存密碼、換韌體就壞、每個型號 DOM 不同),
而且常常連每台裝置的資料都沒有。**決策:不做路由器網頁抓取 adapter。**

---

## 3. 測量「每台裝置用量」的根本選項

| 選項 | 原理 | 能到「每台裝置」嗎 | 全本地 | 契合 netwarden「唯讀不改」 |
|---|---|---|---|---|
| **A. 路由器 SNMP (ifTable)** | 輪詢介面位元組計數器 | ❌ 只到**介面級** | ✅ | ✅ 純讀 |
| **B. 路由器網頁抓取** | 登入管理介面抓「流量統計」頁 | ⚠️ 看型號 | ✅ | ✅ 純讀,但脆弱 |
| **C. 流量匯出 (NetFlow/sFlow/IPFIX)** | 路由器把每條流送給收集器 | ✅ per-device | ✅ | ✅ 純讀 |
| **D. 旁路/閘道 + ntopng** | 讓感測器**看得到封包**:當閘道、橋接、或交換器鏡像埠(SPAN) | ✅ per-device | ✅ | ✅ 只看不改(拓撲由使用者決定) |
| **E. 本機 vnStat / nftables 計數** | 統計**本機網卡**流量 | ❌ 只有本機 | ✅ | ✅ |
| **F. ARP 欺騙 / 中間人** | 騙區域網路讓流量經過自己 | ✅ | ✅ | ❌ **紅線:攻擊手法,直接排除** |
| **G. 每台裝置裝 agent** | 裝置自己回報 | ✅ | ✅ | — 智慧燈泡/攝影機裝不了 |

- 真正的 per-device bytes 只有兩條正路:**流量匯出(C)** 或 **讓感測器看得到封包(D)**。
- **選項 F 明確排除**——和「唯讀、不動網路、對家人透明」的原則衝突。即使在自己的網路裡也不做。

---

## 4. 分層

- **Tier 0(預設):** DNS 衍生的「活動量」,誠實標註為**查詢次數 / 連線對象**,不是位元組。
- **Tier 1(未做):** 路由器支援 SNMP 或流量匯出時的收集 adapter(OpenWrt / MikroTik / pfSense ...)。
  乾淨的 SNMP 需要函式庫(違反零依賴),NetFlow 收集器 stdlib 能寫但較重。
- **Tier 2(已實作):** `netwarden/traffic_ingest.py` 的 `NtopngSource`,stdlib urllib + HTTP basic auth,只讀。

---

## 5. 實作(Tier 2)

- 讀 `GET /lua/rest/v2/get/host/active.lua?ifid=<N>&mode=local&currentPage=<p>&perPage=<n>`(分頁),
  回應 `rsp.data[]` 每台主機用 `ip`、`is_localhost`、`bytes.recvd`(= 裝置**下載** rx)、`bytes.sent`(= **上傳** tx)。
  欄位依官方文件:<https://www.ntop.org/guides/ntopng/api/rest/api_v2.html>、
  <https://www.ntop.org/guides/ntopng/api/rest/examples_v2.html>(Get active hosts)。
  active-hosts 清單**不含 MAC**,所以用既有的 IP→MAC 對照(`store.ip_to_mac`)歸到裝置。
- `store.py` — `traffic_samples(mac, ip, ts, rx_bytes, tx_bytes)` 存**累計**計數器;
  `bandwidth_summary()` / `bandwidth_trend()` 讀取時差分。
- `brain.snapshot()` 有資料時每台裝置附 `bandwidth`、頂層 `has_bandwidth: true`。
- 儀表板:有資料才出現「流量」欄與裝置詳情的 7 天流量圖;沒資料只顯示一行提示。

### 計數器怎麼變成「用量」與「速率」(`store.bandwidth_summary` / `bandwidth_trend`)

1. **以 (裝置, IP) 為一條序列,各自差分。** 一台裝置常同時有好幾個 IP(IPv4 + IPv6、DHCP 換租),
   ntopng 對每個 IP 各有**獨立**計數器;混在一起相減會把每次切換當成「重置」,用量被灌大。
   分組鍵是 `(mac, ip)`(還沒對上裝置的樣本用 `ip:<位址>`),同序列內依 `ts`(再依 rowid)排序後相鄰相減。
   時間相同的重複樣本只加位元組、不算速率(Δt = 0)。
2. **計數器重置。** 後一筆比前一筆**小** = 重開機,這一段用量取「新的值本身」,**絕不為負**。
3. **時窗前的基準點。** 每條序列再取**時窗開始前一天內的最後一筆**當基準;`bandwidth_trend` 同理,
   每段差值算進「後一筆樣本」所在的那一天。
4. **總量 / 目前速率 / 峰值。** 總量 = 所有序列時窗內差值總和;目前速率 = 每條「還活著」序列
   (最新一筆不比裝置最新一筆舊超過 `STALE_SERIES_SECONDS` = 10 分鐘)最後一對樣本的速率相加;
   峰值 = 同一取樣時間點所有序列速率相加的最大值。
5. 一台裝置(含基準點)至少要有兩筆樣本才會出現在結果裡。

保留期限:`traffic_samples` 由每日清理刪除超過 `NETWARDEN_RETENTION_DAYS`(預設 90,最少 8)的資料。
