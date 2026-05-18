# LINE wxSQLite3 Recovery Tool

Windows版LINEのローカルDBを、学習目的で解析・復元するためのツールです。

このツールは、wxSQLite3で暗号化されたLINE for Windowsの `.edb` を対象に、LINEプロセスのメモリから復号候補を探索し、DBを復号してSQLiteとして開けるか検証します。復元できたDBは、全テーブル・全カラムをCSVとして出力します。

## 重要な注意

- 本ツールは学習・研究目的のみに使用してください。
- 自分自身が管理しているPC、自分のアカウント、または明示的な許可を得たデータだけを対象にしてください。
- 本ツールの使用は自己責任です。作者は、データ破損、情報漏えい、アカウント停止、規約違反、法的問題などについて責任を負いません。
- 復元結果には個人情報やトーク内容が含まれます。`line_recovery_output` をGitHubなどに公開しないでください。
- LINE本体、LINEのサービス、第三者のアカウント、第三者のデータに対する不正アクセスや無断解析を目的とした使用は禁止します。

## 必要環境

- Windows 10 / 11
- Python 3.10以降
- LINE for Windowsがインストール済み
- 対象ユーザーでLINEにログイン済み、かつLINEプロセスが起動中

## インストール

```powershell
py -m pip install -r requirements.txt
```

`py` が使えない場合は、環境に合わせて `python` に置き換えてください。

```powershell
python -m pip install -r requirements.txt
```

## 使い方

通常は、リポジトリのルートで次を実行します。

```powershell
py .\tools\line_wxsqlite3_recover.py
```

デフォルトでは、実行ユーザーのDownloads配下に出力されます。

```text
C:\Users\<実行ユーザー>\Downloads\line_recovery_output\YYYYMMDD_HHMMSS\
```

例:

```text
C:\Users\yourname\Downloads\line_recovery_output\20260518_233719\
```

## 出力内容

出力フォルダには主に以下が作成されます。

```text
snapshot\
  復元前の暗号化DBコピー

decrypted\
  復号済みSQLite DB

exports\
  復元DBから出力したCSVとスキーマ情報

recovery_report.json
  復元結果、検証結果、出力先のレポート
```

CSVは全テーブル・全カラムを対象に出力します。BLOB値はCSVで壊れないよう `0x...` 形式の16進文字列として保存されます。

トークを読みやすく見るため、可能な場合は `_message` と `_contact` を結合した `messages_joined.csv` も出力します。

## 出力先を指定する

```powershell
py .\tools\line_wxsqlite3_recover.py --out "D:\line_restore"
```

この場合は、次のように日時フォルダが作成されます。

```text
D:\line_restore\YYYYMMDD_HHMMSS\
```

## LINEデータの場所を指定する

通常は自動で以下を参照します。

```text
%LOCALAPPDATA%\LINE\Data
```

別の場所を指定したい場合:

```powershell
py .\tools\line_wxsqlite3_recover.py --line-data "C:\Users\<user>\AppData\Local\LINE\Data"
```

## メモリ探索せずキーを指定する

メモリから取得済みの32桁hexキーがある場合:

```powershell
py .\tools\line_wxsqlite3_recover.py --key "0123456789abcdef0123456789abcdef" --skip-memory
```

## 実行時のポイント

- LINEを起動したまま実行してください。
- 復号キーはLINE.exeのメモリから探索します。
- LINEが未ログイン、ログアウト済み、または対象DBのキーがメモリにない状態では復元できない場合があります。
- 実行中のLINEからDB/WALをコピーするため、WALが途中で不整合になることがあります。その場合、スクリプトはSQLiteの `PRAGMA quick_check` が通る最新のWAL適用位置を自動で採用します。

## GitHub公開時の注意

以下は公開しないでください。

- `line_recovery_output/`
- 復号済み `.sqlite`
- CSV出力
- LINEの `.edb`, `.edb-wal`, `.edb-shm`
- 個人のPDF、ログ、画像、添付ファイル
- `.codex_deps/`, `.codex_research/`

`.gitignore` に基本的な除外設定を入れていますが、公開前に必ず `git status` を確認してください。

## ライセンス

本リポジトリは独自の教育目的ライセンスで提供されます。詳細は [LICENSE.md](LICENSE.md) を確認してください。
