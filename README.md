# Pull Guard

`Pull Guard` 是一個本機掃描工具，目標是讓你在 `git pull` 或 `docker pull` 之後，立即做一次惡意檔案與可疑行為檢查。

它目前提供兩種能力：

1. 內建啟發式掃描
2. 若系統有安裝 `clamscan`，自動串接 ClamAV 再掃一次

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

## 檔案

- [`.pullguardignore`](/Users/apple/checking-git/.pullguardignore)
- [`pull_guard.py`](/Users/apple/checking-git/pull_guard.py)
- [`tests/test_pull_guard.py`](/Users/apple/checking-git/tests/test_pull_guard.py)

## 基本用法

預設會輸出終端 dashboard 版面，包含狀態卡、風險統計、依 severity 分區的 findings 和建議區塊；如果你想要舊版純文字，可加 `--plain`。

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

掃描本機 Docker image:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-image nginx:1.17.3-alpine
```

`docker pull` 完立刻掃:

```bash
python3 /Users/apple/checking-git/pull_guard.py docker-pull-scan nginx:1.17.3-alpine
```

輸出 JSON:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --json
```

輸出純文字:

```bash
python3 /Users/apple/checking-git/pull_guard.py scan-repo . --plain
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
```

### 2. 當成安全版 docker pull

```bash
alias dpullsafe='python3 /Users/apple/checking-git/pull_guard.py docker-pull-scan'
```

之後可直接跑:

```bash
dpullsafe nginx:1.17.3-alpine
```

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

## 測試

```bash
python3 -m unittest discover -s /Users/apple/checking-git/tests -v
```

## 注意事項

- 這個工具偏向「快速篩出高風險跡象」，不是保證無毒
- 某些 devops repo、安裝腳本、系統映像本來就可能包含 `curl`、cron、setuid 檔案，所以可能有誤報
- Docker image 掃描需要本機 Docker daemon 可讀取
- 若 image 很大，匯出掃描會花比較久
