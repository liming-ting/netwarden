# 每台裝置的頻寬(選用,透過 ntopng)

[English](bandwidth.md)

netwarden 主要的資料來源是 AdGuard Home 或 Pi-hole 的 DNS 紀錄。DNS 能告訴你「裝置在跟誰連線」
和「查詢了幾次」,但**不知道傳了多少位元組**:一台裝置可以只查一次網域,然後下載 10 GB。
所以「每日查詢量」圖表是查詢次數,不是流量,儀表板也是這樣標示的。

如果你想看每台裝置真正的流量,netwarden 可以**唯讀**讀取你已經在跑的
[ntopng](https://www.ntop.org/products/traffic-analysis/ntop/)。沒有 ntopng 時一切照舊,
儀表板上和頻寬有關的部分就不會出現。

## ntopng 要放在哪裡

ntopng 只算得到它看得見的流量,所以要放在流量會經過的位置:

- 直接跑在**閘道**上(刷了 OpenWrt、pfSense、OPNsense 等的路由器),或
- **橋接**在路由器和區域網路之間,或
- 接在網管交換器的**鏡像埠**(SPAN / port mirror)。

netwarden 不會為了取得流量去改你的網路:不做 ARP 欺騙、不做中間人、不改路由器設定。
ntopng 放哪裡由你決定。大部分家用路由器根本沒有每台裝置的位元組計數,
這也是 netwarden 不去抓路由器網頁的原因。

ntopng 的 local networks(`-m`)請設成你的區域網路,例如 `192.168.1.0/24`。

## 連接

在 netwarden 的環境設定(`.env`、compose 的 env 檔,或附加元件選項)加上:

```
NTOPNG_URL=http://<ntopng 主機>:3000
NTOPNG_USER=...
NTOPNG_PASS=...
NTOPNG_IFID=0        # 選填:ntopng 的介面編號
# NTOPNG_TOKEN=...   # 取代帳號 + 密碼:API 權杖(ntopng 的使用者設定)
# NTOPNG_VERIFY_TLS=0  # 只有 https:// 搭配自簽憑證時才需要
```

ntopng 帳號只要能讀取該介面即可:netwarden 只呼叫一個端點
`GET /lua/rest/v2/get/host/active.lua`(REST API v2、本地主機、分頁)。帳密錯誤時 ntopng 會
回它的登入頁,netwarden 會顯示「登入被拒」。`NTOPNG_IFID` 是 ntopng 介面選單中的介面編號
(第一個是 0);填錯會顯示 `INVALID_INTERFACE`。

`python3 -m netwarden run` 會每 30 秒取樣一次;也可以單獨跑
`python3 -m netwarden traffic --watch 30`。總量和速率至少要兩次取樣才算得出來。
沒設定 `NTOPNG_URL` 時,`netwarden traffic` 只印一段提示並以 0 結束。

## 會多出什麼

- 裝置清單多一欄「流量」,裝置詳情多一張 7 天下載 / 上傳圖;
- 某台裝置 24 小時內傳輸至少 2 GB、而且是平常的 4 倍以上時,會有「大量傳輸」提醒;
- AI(或離線說明)可以把上傳量和裝置連線的對象一起看。

ntopng 給的是累計計數器;netwarden 原樣存下來,讀取時才算用量(計數器變小代表重新開機,
用量絕不會是負數)。樣本和 DNS 紀錄一起依 `NETWARDEN_RETENTION_DAYS`(預設 90 天)清理。

設計筆記:[dev/bandwidth_investigation.md](dev/bandwidth_investigation.md)。
