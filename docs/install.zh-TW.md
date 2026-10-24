# 安裝 netwarden

[English](install.md)

netwarden 是一支 Python 程式(只用標準函式庫,沒有任何執行期相依套件),附一個網頁儀表板。它讀取你的 DNS 過濾器(AdGuard Home 或 Pi-hole v6)本來就有的紀錄,看看你的區網,再用白話解釋給你聽。它對你的網路**只讀不寫**:絕不會更改你的路由器、防火牆、AdGuard Home 或 Pi-hole 的設定。

選一種:

| 你有 | 用 | 看得到區網嗎? |
|---|---|---|
| 裝了 Docker 的 Linux 主機 / 樹莓派 / NAS | [Docker compose](#docker)(host 網路) | 可以 |
| Windows / macOS 上的 Docker Desktop | [bridge compose](#docker-desktopwindows--macos) | 不行(DNS、AI、儀表板可用) |
| 沒有 Docker 的 Linux 主機 / 樹莓派 | [systemd 安裝腳本](#linux--樹莓派不用-docker) | 可以 |
| 開發或試用用的桌機 | [從原始碼執行](#從原始碼執行pippipx開發) | Linux 可以;WSL 下看到的很少 |

v0.1.0 的實際限制:在 WSL2 或 Docker Desktop 下(它們跑在虛擬機裡),裝置探索只看得到很少或完全看不到裝置;裝置名稱取決於裝置自己廣播了什麼;AI 部分需要 API 金鑰或本機模型(沒有的話會用離線的規則式摘要);英文與繁體中文以外的翻譯是機器輔助的。這個專案大量借助 AI 開發,並有一套大型自動化測試。

## Docker

Linux 主機,使用 host 網路(裝置探索需要:ARP 表、ping、mDNS/SSDP、UPnP)。

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
cp deploy/netwarden.env.example deploy/netwarden.env     # 填入 AdGuard / Pi-hole
chmod 600 deploy/netwarden.env
docker compose -f deploy/compose.yaml up -d
docker compose -f deploy/compose.yaml logs netwarden     # 一次性的管理員代碼
```

不用 compose 的話:

```bash
docker run -d --name netwarden --network host --restart unless-stopped --init \
  -e NETWARDEN_HOST=127.0.0.1 -e NETWARDEN_LAN=1 \
  --env-file deploy/netwarden.env -v netwarden-data:/data ghcr.io/liming-ting/netwarden:latest
```

使用 host 網路時,一定要像上面這樣設定 `NETWARDEN_HOST=127.0.0.1` 加 `NETWARDEN_LAN=1`:映像檔預設的 `0.0.0.0` 在 host 網路下會監聽主機的**每一個**介面(包括 VPN 或對外的介面),配對頁面就會暴露在區網之外。

`deploy/compose.adguard.yaml` 會在 netwarden 旁邊一起跑 AdGuard Home(官方 `adguard/adguardhome` 映像檔)。要不要把裝置(或路由器 DHCP 發的 DNS)指到它,由你自己決定、自己動手。

### 映像檔

- `python:3.12-slim-bookworm` + `iproute2`、`iputils-ping`、`tzdata`;不含編譯器。
- 以沒有特權的使用者 `netwarden`(uid 10001)執行;所有資料都在 `/data` volume(資料庫、快取)。連接埠 8787。
- `HEALTHCHECK` 呼叫 `GET /healthz`(公開、內容固定、不碰任何資料)。
- `docker stop`(SIGTERM)約一秒內乾淨地結束,就算是 PID 1 也一樣。
- 紀錄輸出到 stdout/stderr(`docker logs`),不寫檔案。
- 多架構:linux/amd64、linux/arm64、linux/arm/v7。

### 設定(環境變數)

`.env` 裡的所有設定都可以改用環境變數(見 `deploy/netwarden.env.example`)。容器專用的:

| 變數 | 映像檔預設值 | 意思 |
|---|---|---|
| `NETWARDEN_DB` | `/data/netwarden.db` | 資料庫檔案(同一個資料夾也放快取) |
| `NETWARDEN_HOST` | `0.0.0.0` | `127.0.0.1` = 只有本機;私有區網位址或 `0.0.0.0` = 區網模式(其他裝置要先配對)。公開位址和主機名稱一律拒絕。 |
| `NETWARDEN_LAN` | – | `1` = 也在偵測到的區網位址上監聽(host 網路時搭配 `NETWARDEN_HOST=127.0.0.1`) |
| `NETWARDEN_PORT` | `8787` | 連接埠 |
| `NETWARDEN_ADVERTISED_URL` | – | 自動偵測的位址不對時(bridge 網路、反向代理),手機要開的位址,例如 `http://192.168.1.20:8787` |
| `NETWARDEN_HEADLESS` | `1` | 紀錄輸出到 stderr;在被認領之前印出一組管理員代碼 |

沒有 root 的 ping:Docker 允許容器使用非特權的 ICMP socket;主機不允許時,netwarden 會改用 TCP 探測。`cap_add: [NET_RAW]` 可加可不加,絕不是必要的。

### Docker Desktop(Windows / macOS)

容器跑在虛擬機裡,netwarden 看不到你的區網(沒有裝置探索、沒有 mDNS/SSDP 裝置名稱、沒有路由器 UPnP)。仍然可用的:從 AdGuard Home 或 Pi-hole 讀取 DNS、AI 解說、警示和儀表板。請用 `deploy/compose.bridge.yaml`,並設定 `NETWARDEN_ADVERTISED_URL`(在這台電腦上用 `http://localhost:8787` 即可)。

### 53 連接埠與 systemd-resolved

在 Ubuntu / Debian 上,`systemd-resolved` 佔用 127.0.0.53:53,在 host 網路上跑的 AdGuard Home(或 Pi-hole)會出現「address already in use」。請自己動手:

```bash
sudo mkdir -p /etc/systemd/resolved.conf.d
printf '[Resolve]\nDNSStubListener=no\n' | sudo tee /etc/systemd/resolved.conf.d/no-stub.conf
sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf
sudo systemctl restart systemd-resolved
```

netwarden 本身不需要 53 連接埠(它只讀 DNS 過濾器的紀錄)。

## 認領沒有螢幕的安裝(用瀏覽器當管理員)

在那台機器本身,開 http://127.0.0.1:8787 的瀏覽器一定是管理員。樹莓派、NAS 或容器沒有這樣的瀏覽器,所以在區網模式下**第一次啟動**時,netwarden 會在紀錄裡印出一組管理員代碼:

```
========================================================================
認領這台 netwarden:用家裡網路上的瀏覽器以管理員身分登入

  開啟 http://192.168.1.20:8787/pair(或你連到這台機器用的位址加上 /pair),輸入代碼 ABCDE-FGHJK
  ...
  只能用一次,15 分鐘內有效(到 2026-01-01 12:15 UTC 為止)。
========================================================================
```

用 `docker logs netwarden` 或 `journalctl -u netwarden` 看紀錄,從區網上的瀏覽器開啟 `/pair` 輸入代碼。那個瀏覽器會得到**管理員工作階段**(在「系統 -> 在手機上開啟」的清單裡有「管理員」標記)。只要用過一次管理員代碼,之後的啟動就不會再印。隨時可以在那台機器的終端機產生新的代碼:

```bash
docker exec netwarden netwarden pair --admin           # Docker
sudo -u netwarden netwarden pair --admin               # systemd 安裝
python3 -m netwarden pair --admin                      # 從原始碼
```

一般手機(用一般代碼配對,`netwarden pair`)可以查看、命名、靜音和聊天,但不能變更設定、配對裝置或執行連接埠檢查。

**取捨:**儀表板在你的區網上用的是一般 HTTP,管理員工作階段的 cookie 會未加密地經過網路。只在你信任的家用網路上透過區網使用管理員功能,用完後撤銷管理員工作階段(`netwarden pair --list`、`--revoke ID`,或在清單裡按「撤銷」),優先使用 SSH 通道(`ssh -L 8787:127.0.0.1:8787 user@box`,然後在你的電腦上開 http://127.0.0.1:8787),而且**絕對不要把 netwarden 開放到網際網路上**(不要在路由器上做連接埠轉送)。

反向代理:把 `NETWARDEN_ADVERTISED_URL` 設成代理的位址。代理是從 127.0.0.1 連進來的,而且可能把訪客送來的任何 Host 標頭原樣轉過來,所以一旦設定了公告網址,**就沒有任何瀏覽器算是「這台電腦」**:每個瀏覽器(包括主機本身上的)都要登入(管理員用 `netwarden pair --admin`)。帶有 `X-Forwarded-For`、`X-Forwarded-Host`、`X-Real-IP` 或 `Forwarded` 標頭的本機請求,一律當作其他裝置。

## Linux / 樹莓派(不用 Docker)

需要 `python3` >= 3.11(Raspberry Pi OS bookworm 和 Ubuntu 24.04 都有)、`ip` 和 `ping`(`apt install iproute2 iputils-ping`)。在原始碼目錄裡:

```bash
sh scripts/install_linux.sh --dry-run      # 列出每個動作,什麼都不改
sudo sh scripts/install_linux.sh           # 安裝並啟動服務
sudo nano /etc/netwarden/netwarden.env     # AdGuard / Pi-hole / AI 金鑰,然後:
sudo systemctl restart netwarden
journalctl -u netwarden -b | grep -A8 '====='   # 一次性的管理員代碼
```

程式裝到 `/opt/netwarden/app`,資料放在 `/var/lib/netwarden`(專用的系統使用者 `netwarden`),設定在 `/etc/netwarden/netwarden.env`(只建立一次,不會被覆蓋),`netwarden` 指令放在 `/usr/local/bin`,另有強化過的 `netwarden.service`(`NoNewPrivileges`、`ProtectSystem=strict`、`ProtectHome`、`PrivateTmp`、沒有任何 capability、只有 `/var/lib/netwarden` 可寫、`Restart=on-failure`)。服務監聽 127.0.0.1 和區網位址(`NETWARDEN_LAN=1`);想要「只有本機」再搭配 SSH 通道,就在設定檔裡寫 `NETWARDEN_LAN=0`。

## 從原始碼執行(pip、pipx、開發)

```bash
git clone https://github.com/liming-ting/netwarden netwarden && cd netwarden
python3 -m netwarden run --demo --offline-ai    # 試用:虛構的家,不呼叫 AI
python3 -m netwarden run                        # 你的網路:http://127.0.0.1:8787
pipx install .                                  # 或:pip install .  -> `netwarden run`
```

從原始碼執行時資料放在 `./data`;安裝成套件時用 `~/.local/share/netwarden`(或 `$XDG_DATA_HOME/netwarden`、`NETWARDEN_DATA_DIR`、`NETWARDEN_DB`)。`python3 -m netwarden --version` 會印出版本。

指令預設以繁體中文(zh-Hant)輸出。想改成英文,在 `.env` 設定 `NETWARDEN_LANG=en`(其他語言代碼見 docs/home_assistant.zh-TW.md 的語言列表),或只對單一指令加上 `--lang en`,例如 `python3 -m netwarden scan --lang en`。儀表板有自己的語言選單。

**Windows(開發用):**在 WSL2 裡執行(`scripts\start_windows.cmd`)。使用 mirrored 網路時 WSL 只看得到部分區網;手機需要一條 Windows 防火牆規則,儀表板會把它顯示給你(docs/lan.md)。

## 升級

- Docker:`docker compose -f deploy/compose.yaml pull && docker compose -f deploy/compose.yaml up -d`(資料庫會在啟動時自動遷移)。
- systemd:更新原始碼後再執行一次 `sudo sh scripts/install_linux.sh`(資料和設定都會保留)。
- pip / pipx:`pipx upgrade netwarden` / `pip install --upgrade .`。

## 備份與還原

你自己的筆記(名稱、擁有者、信任、規則、設定 - 不含密碼,也不含手機的工作階段):

```bash
docker exec netwarden netwarden backup -o - > netwarden-backup.json
docker exec -i netwarden sh -c 'cat > /data/restore.json' < netwarden-backup.json
docker exec netwarden netwarden restore /data/restore.json --dry-run
```

全部(包含歷史紀錄):先停止容器,再複製 `/data` volume,例如
`docker run --rm -v netwarden-data:/data -v "$PWD":/out busybox tar czf /out/netwarden-data.tgz -C /data .`
systemd 安裝:`sudo systemctl stop netwarden` 後複製 `/var/lib/netwarden`。

## 移除

- Docker:`docker compose -f deploy/compose.yaml down`(加上 `-v` 會刪掉資料 volume)。
- systemd:`sudo sh scripts/install_linux.sh --uninstall`(保留 `/var/lib/netwarden` 和 `/etc/netwarden`;加 `--purge` 會連同使用者一起刪除)。
- pip / pipx:`pipx uninstall netwarden`;資料會留在 `~/.local/share/netwarden`。
