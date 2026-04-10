# Pull Guard

`Pull Guard` 是一個本機掃描工具，目標是讓你在 `git pull` 或 `docker pull` 之後，立即做一次惡意檔案與可疑行為檢查。

## 指令速查表

### 掃本地 Git repo

已經 `git clone` 完，只想掃本地 repo，不碰遠端：

```bash
cd /path/to/repo
gpullsafe --scan-only
```

指定路徑掃描：

```bash
gpullsafe /path/to/repo --scan-only
python3 /Users/apple/checking-git/pull_guard.py scan-repo /path/to/repo
```

想先試 `git pull`，失敗也照樣掃本地：

```bash
gpullsafe
gpullsafe /path/to/repo
```

### 掃本地 Docker image

image 已經 pull 到本機，只想離線掃描：

```bash
dpullsafe nginx:1.17.3-alpine --scan-only
python3 /Users/apple/checking-git/pull_guard.py scan-image nginx:1.17.3-alpine
```

想先試 `docker pull`，失敗就 fallback 掃本地 image：

```bash
dpullsafe nginx:1.17.3-alpine
```

### 常用參數

只掃本地，不碰遠端：

```bash
--scan-only
```

跳過漏洞掃描，只做惡意檔案 / 可疑行為掃描：

```bash
--skip-vuln-scan
```

不要顯示進度列：

```bash
--no-progress
```

不要顯示顏色：

```bash
--no-color
```

改成純文字輸出：

```bash
--plain
```

輸出 JSON：

```bash
--json
```

控制 dashboard 詳細列出幾筆 findings：

```bash
--max-findings 10
```

### 資料庫更新

更新 ClamAV 病毒碼：

```bash
/Users/apple/checking-git/scripts/update_clamav_db.sh
```

更新 Trivy 漏洞資料庫：

```bash
/Users/apple/checking-git/scripts/update_trivy_db.sh
```

### 最常用組合

repo 本地安全掃描：

```bash
gpullsafe --scan-only
```

image 本地安全掃描：

```bash
dpullsafe your-image:tag --scan-only
```

repo 掃描但不做漏洞掃描：

```bash
gpullsafe --scan-only --skip-vuln-scan
```

image 掃描輸出 JSON：

```bash
dpullsafe your-image:tag --scan-only --json
```

它目前提供兩種能力：

1. 內建啟發式掃描
2. 若系統有安裝 `clamscan`，自動串接 ClamAV 再掃一次
3. 若系統有安裝 `trivy`，自動做本地漏洞掃描

這不是完整 EDR，也不是雲端沙箱，但很適合拿來做「拉下來先過一遍」的第一道防線。

## 功能

- 掃描 git working tree 中的可疑腳本與二進位
- 掃描 Docker image history 與匯出的檔案系統
- 偵測常見風險訊號
- `curl | sh` / `wget | bash`
- reverse shell / `nc -e`
- PowerShell download cradle / base64 execute
- crypto miner 關鍵字
- 可疑副檔名
- repo 外部 symlink
- image 中的 setuid / cron / `authorized_keys` / `ld.so.preload`
- repo 依賴套件與 lockfile 的已知漏洞
- docker image 內 OS / 套件的已知 CVE

## 檔案

- [`.pullguardignore`](/Users/apple/checking-git/.pullguardignore)
- [`pull_guard.py`](/Users/apple/checking-git/pull_guard.py)
- [`tests/test_pull_guard.py`](/Users/apple/checking-git/tests/test_pull_guard.py)

## 基本用法

預設會輸出終端 dashboard 版面，包含狀態卡、live progress、風險統計、依 severity 分區的 findings、折疊摘要、top risks 和建議區塊；如果你想要舊版純文字，可加 `--plain`。

掃描目前 repo:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo .
```

掃描指定 repo:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo /path/to/repo
```

`git pull` 完立刻掃:

```bash
python3 /Users/apple/checking-git/pull_guard.py git-pull-scan /path/to/repo
python3 /Users/apple/checking-git/pull_guard.py git-pull-scan /path/to/repo --remote origin --branch main
```

如果你已經 `git clone` 完，只想掃本地 repo，不想碰遠端：

```bash
python3 /Users/apple/checking-git/pull_guard.py git-pull-scan /path/to/repo --scan-only
python3 /Users/apple/checking-git/pull_guard.py scan-repo /path/to/repo
```

在 repo 目錄內也可以直接掃目前資料夾：

```bash
gpullsafe
python3 /Users/apple/checking-git/pull_guard.py scan-repo
```

掃描本機 Docker image:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-image nginx:1.17.3-alpine
```

`docker pull` 完立刻掃:

```bash
python3 /Users/apple/checking-git/pull_guard.py docker-pull-scan nginx:1.17.3-alpine
```

如果 image 早就已經 pull 到本機，只想離線掃本地 image：

```bash
python3 /Users/apple/checking-git/pull_guard.py docker-pull-scan nginx:1.17.3-alpine --scan-only
python3 /Users/apple/checking-git/pull_guard.py scan-image nginx:1.17.3-alpine
```

輸出 JSON:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --json
```

輸出純文字:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --plain
```

關閉進度或調整詳細 findings 顯示數量:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --no-progress
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --max-findings 12
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --skip-vuln-scan
```

## 回傳碼

- `0`: 沒發現可疑項目
- `1`: 有可疑項目，請人工複查
- `2`: 執行錯誤

## 建議整合方式

### 1. 當成安全版 git pull

在你的 shell 設 alias:

```bash
alias gpullsafe='python3 /Users/apple/checking-git/pull_guard.py git-pull-scan'
```

之後可直接跑:

```bash
gpullsafe /path/to/repo --remote origin --branch main
gpullsafe
```

`gpullsafe` 現在的行為是：

- 預設先試 `git pull`
- 如果遠端連不上，仍然會繼續掃描你目前本地已 clone 的 repo
- 如果你完全不想碰遠端，可加 `--scan-only`

### 2. 當成安全版 docker pull

```bash
alias dpullsafe='python3 /Users/apple/checking-git/pull_guard.py docker-pull-scan'
```

之後可直接跑:

```bash
dpullsafe nginx:1.17.3-alpine
dpullsafe nginx:1.17.3-alpine --scan-only
```

`dpullsafe` 現在的行為是：

- 預設先試 `docker pull`
- 如果 registry 需要登入、白名單擋住、或當下沒網路，只要本機已有這個 image，仍然會繼續掃描本地 image
- 如果你完全不想連網，可加 `--scan-only`

### 3. 接到 git hook

如果你想在單一 repo 裡面自動掃描，可在該 repo 建立 `.git/hooks/post-merge`：

```bash
#!/bin/sh
python3 /Users/apple/checking-git/pull_guard.py scan-repo "$(pwd)"
```

再加執行權限:

```bash
chmod +x .git/hooks/post-merge
```

## 忽略規則

若你有已知的測試樣本、誤報目錄或不想掃的檔案，可在 repo 根目錄放 `.pullguardignore`，每行一個 pattern：

```bash
tests/*
docs/*
samples/eicar.txt
dist/
```

## 安裝 ClamAV

若你有裝 ClamAV，`Pull Guard` 會自動呼叫 `clamscan`。

macOS 可用 Homebrew:

```bash
brew install clamav
```

安裝後建議先初始化設定，再更新病毒碼：

```bash
/Users/apple/checking-git/scripts/setup_clamav_homebrew.sh
/Users/apple/checking-git/scripts/update_clamav_db.sh
```

確認可用：

```bash
clamscan --version
freshclam --config-file=/opt/homebrew/etc/clamav/freshclam.conf --version
```

如果你想開背景服務：

```bash
sudo brew services start clamav
```

這個專案目前不依賴 `clamd` 常駐服務，因為 `Pull Guard` 直接呼叫 `clamscan`；真正必要的是：

- `clamscan` 指令可用
- 病毒碼已透過 `freshclam` 更新

## 安裝 Trivy

若你要啟用本地漏洞掃描，可先安裝 Trivy：

```bash
/Users/apple/checking-git/scripts/install_trivy_homebrew.sh
/Users/apple/checking-git/scripts/update_trivy_db.sh
```

或手動：

```bash
brew install trivy
trivy image --download-db-only
trivy image --download-java-db-only
```

安裝後 `Pull Guard` 會自動把 Trivy 接進 repo / docker image 掃描流程，而且預設使用本地 DB，不會每次掃描都去聯網更新。

如果你想純本地離線掃描：

```bash
gpullsafe --scan-only
dpullsafe nginx:1.17.3-alpine --scan-only
```

前提是：

- 該 repo / image 已經在本機
- Trivy DB 已經事先更新過

## 測試

```bash
python3 -m unittest discover -s /Users/apple/checking-git/tests -v
```

## 注意事項

- 這個工具偏向「快速篩出高風險跡象」，不是保證無毒
- 某些 devops repo、安裝腳本、系統映像本來就可能包含 `curl`、cron、setuid 檔案，所以可能有誤報
- Docker image 掃描需要本機 Docker daemon 可讀取
- 若 image 很大，匯出掃描會花比較久
