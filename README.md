# ReconFeed

セキュリティ研究者向けの脆弱性・攻撃手法モニタリングサービス。研究テーマを「プリセットタグ＋自由拡張」の
ハイブリッド方式で登録すると、以下の情報源を定期的に横断監視し、該当する更新を日次メールで通知します。

- CVE（NVD API 2.0）
- CISA KEV（Known Exploited Vulnerabilities カタログ）
- EPSS（Exploit Prediction Scoring System）
- GitHub Security Advisories（GHSA）
- GitHub上のPoC/Exploitコード新規公開
- MITRE ATT&CK / CAPEC の更新差分

## 設計の肝: 柔軟なタグ／キーワード辞書システム

研究テーマは今後変化する可能性があるため、固定タグに縛らない設計にしています。

- **プリセットタグ**: 初期侵入・経路探索に関連する代表的なタグ（Active Directory, Kerberos,
  Windows/Linux Privilege Escalation, Initial Access, RCE, Authentication Bypass,
  Credential Access, Lateral Movement, VPN/Edge Device Exploitation, ADCS）をあらかじめ用意。
  定義は [`seed/preset_tags.yaml`](seed/preset_tags.yaml) にあり、コードとは分離されています。
- **カスタムタグ**: ユーザーが自由に作成可能（例: "Prompt Injection"）。デフォルトでは作成者のみに表示されます。
- **キーワード辞書・ATT&CK Technique紐付けの編集**: プリセット・カスタム問わず、任意のタグに対して
  キーワードやATT&CK Technique IDを追加・削除できます（UI: `/tags`）。プリセットの初期エントリ自体は
  削除できませんが、自分が追加した分はいつでも削除できます。
- **キーワード所有権スコープ**: 誰かが共有プリセットタグに追加した独自キーワードは、その人にしか
  通知への影響を与えません（他ユーザーの通知には混入しません）。マッチング自体はタグ単位で一度だけ行い、
  配布（通知）段階でユーザーごとに所有権スコープを適用します。

## 技術スタック

| 項目 | 選定 | 理由 |
|---|---|---|
| バックエンド | Python 3.12 + FastAPI | |
| フロントエンド | Jinja2 SSR | 過剰なSPAを避け、保守しやすい構成 |
| DB | [Neon](https://neon.tech)（無料 Postgres, 永続） | Render無料Postgresは作成30日で削除されるため回避 |
| ORM/マイグレーション | SQLAlchemy 2.0 + Alembic | |
| 認証 | セッションCookie + passlib(bcrypt) | OAuth・パスワードリセットはMVP対象外 |
| メール送信 | [Resend](https://resend.com)（無料枠） | |
| スケジューラ | GitHub Actions scheduled workflow | 下記「なぜGitHub Actionsか」参照 |
| ホスティング | Render 無料 Web Service | |

### なぜスケジューラに GitHub Actions を使うか

Render の Cron Jobs は無料プランの対象外です。GitHub Actions の scheduled workflow は
public リポジトリであれば実質無制限・無料で使え、Render無料Webサービスのスリープ挙動の影響も受けない
（Renderにデプロイされたアプリを経由せず、Actions環境から直接 `python -m app.jobs.daily` を実行する）ため、
コストゼロで最も堅牢な構成として採用しています。

## ディレクトリ構成

```
app/
  main.py            FastAPI アプリ本体
  config.py          環境変数設定
  db.py              SQLAlchemy engine/session
  models/            SQLAlchemyモデル
  auth/              認証（ハッシュ化・セッション）
  web/               Jinja2ルーター（auth/tag/watchlist/dashboard/settings）
  templates/          Jinja2テンプレート
  sources/           情報源フェッチャ（nvd/kev/epss/ghsa/github_poc/attack/capec）
  matching/          マッチングエンジン・配布ロジック
  notify/            Resend送信・日次ダイジェスト生成
  jobs/daily.py      取得→マッチング→配布→通知 のバッチ本体
seed/preset_tags.yaml プリセットタグのシードデータ
scripts/seed.py       シードデータをDBへ投入するスクリプト
alembic/               DBマイグレーション
tests/                 pytestユニットテスト
.github/workflows/     daily.yml（バッチ実行）, ci.yml（lint/test）
render.yaml             Renderへのデプロイ定義
```

## ローカル開発セットアップ

### 1. Python環境

Python 3.12 の仮想環境（venv・conda等）を用意してください。

```bash
# 例: venv
python -m venv .venv && source .venv/Scripts/activate   # Windows Git Bash
pip install -r requirements-dev.txt
```

### 2. 環境変数

`.env.example` を `.env` にコピーし、値を埋めます。

```bash
cp .env.example .env
```

| 変数 | 用途 | 取得元 |
|---|---|---|
| `DATABASE_URL` | Neon Postgres 接続文字列 | [Neonコンソール](https://console.neon.tech) > Connection Details。**末尾に `&sslnegotiation=direct` が必要**（下記「既知の制限」参照） |
| `SESSION_SECRET` | セッションCookie署名鍵 | ランダム文字列を自分で生成: `python -c "import secrets; print(secrets.token_hex(32))"` |
| `NVD_API_KEY` | NVD APIのレート制限緩和 | [NVD API Key申請ページ](https://nvd.nist.gov/developers/request-an-api-key) |
| `GITHUB_TOKEN` | GHSA・GitHub PoC検索用 | GitHubの Settings > Developer settings > Fine-grained tokens（`Public repositories (read-only)` で作成） |
| `RESEND_API_KEY` | メール送信 | [Resendダッシュボード](https://resend.com) > API Keys（`Sending access`権限） |
| `RESEND_FROM_EMAIL` | 送信元アドレス | 検証段階は `onboarding@resend.dev` でOK（自分宛のみ送信可）。他ユーザーへ送るには自分のドメインをResendに追加・検証する |
| `APP_BASE_URL` | メール本文のリンク生成用 | ローカルは `http://localhost:8000` |
| `DEMO_MODE` | サインアップ・ダッシュボードに「これはデモ環境です」の注意書きを表示するか（既定 `true`） | `RESEND_FROM_EMAIL` を検証済み独自ドメインに切り替え、本番運用へ移行したら `false` にする |

### 3. DBスキーマ適用 + シードデータ投入

```bash
alembic upgrade head
python scripts/seed.py
```

`scripts/seed.py` は `seed/preset_tags.yaml` の内容を **冪等に** DBへ反映します
（既存のプリセット行のみ更新・削除し、ユーザーが追加した辞書エントリには一切触れません）。

### 4. ローカルサーバー起動

```bash
uvicorn app.main:app --reload
```

`http://localhost:8000` でサインアップ・タグ編集・ウォッチリスト作成が行えます。

### 5. バッチジョブの手動実行

```bash
python -m app.jobs.daily
```

取得（7情報源）→マッチング→通知（Resend経由）を通しで実行します。初回は各フェッチャの初期ルックバック
期間（既定7日）分のデータを取得するため、数分〜十数分かかります。

### 6. テスト

```bash
pytest -v
ruff check .
```

## プリセットタグ・キーワード辞書の追加方法

1. [`seed/preset_tags.yaml`](seed/preset_tags.yaml) を編集（タグ追加・キーワード追加・ATT&CK Technique ID追加）
2. `python scripts/seed.py` を実行してDBへ反映
3. 変更をコミット・pushすれば、他の開発者/デプロイ環境にも同じ定義が伝わります

ユーザー自身の手元での調整（UIからのキーワード追加等）はこのシードファイルとは独立して機能するため、
プリセットの更新はユーザーの個人設定を上書きしません。

## Renderへのデプロイ

1. [Neon](https://neon.tech) でプロジェクトを作成し、接続文字列を控える
   （`?sslmode=require&sslnegotiation=direct` を末尾に付与すること）
2. [Resend](https://resend.com) でAPIキーを発行
3. [NVD API Key](https://nvd.nist.gov/developers/request-an-api-key) を申請
4. GitHubでPAT（Fine-grained, Public repositories read-only）を発行
5. Renderで「New Blueprint」からこのリポジトリを指定し、`render.yaml` を読み込ませる
6. Render側で以下の環境変数を設定（`sync: false` のためダッシュボードから手動入力が必要）:
   - `DATABASE_URL`, `NVD_API_KEY`, `GITHUB_TOKEN`, `RESEND_API_KEY`, `APP_BASE_URL`
   - `SESSION_SECRET` は `generateValue: true` によりRenderが自動生成
   - `DEMO_MODE` は `render.yaml` に定義がないため既定値の `true` のまま動作する（デモ注意書きが表示される）。
     独自ドメインをResendに検証し本番運用へ移行したら、Renderダッシュボードで `DEMO_MODE=false` を追加する
7. 初回デプロイ後、シードデータを投入（ローカルから本番の `DATABASE_URL` を指して実行するのが簡単）:
   ```bash
   DATABASE_URL=<Neonの接続文字列> python scripts/seed.py
   ```
8. GitHub Actions側のSecretsを設定（Settings > Secrets and variables > Actions）:
   - `DATABASE_URL`, `SESSION_SECRET`, `NVD_API_KEY`, `RESEND_API_KEY`, `RESEND_FROM_EMAIL`, `APP_BASE_URL`
   - `GH_PAT`: GitHub PAT（**`GITHUB_TOKEN` という名前ではSecretを作成できない**ため別名にし、
     `.github/workflows/daily.yml` 内で `GITHUB_TOKEN` 環境変数にマッピングしている）
9. `.github/workflows/daily.yml` は1日2回（07:00 / 19:00 JST）自動実行される。
   `Actions` タブから `workflow_dispatch` で手動実行も可能

## 既知の制限事項

- **無料枠のAPIレート制限**: NVD（APIキーありで50req/30s）、GitHub Search API（認証済み30req/min）に
  それぞれ準拠したレート制御を実装していますが、上限に近い使い方をすると日次バッチの実行時間が伸びます。
- **Render無料Webサービスのスリープ**: 15分間アクセスがないとスリープし、次回アクセス時にコールドスタート
  （数十秒）が発生します。日次バッチはRender経由ではなくGitHub Actionsから直接DBを操作するため、
  この影響を受けません。
- **Neonのautosuspend**: 無料枠のNeon Postgresは非アクティブ時に自動サスペンドされ、次回接続時に
  数百ms〜数秒の遅延が発生します（データは失われません）。
- **フェッチャの初期ルックバック**: NVD/GHSA/GitHub PoC検索は、初回実行時に無制限へ遡ることを避けるため
  既定7日分のみを取得します（過去の全履歴は取り込みません）。継続運用で徐々にカバレッジが広がります。
- **KEV→CVEのis_kevフラグ逆引き**: 対応する `source=cve` のFinding行が既にDBに存在する場合のみ
  反映されます。NVDの取得ウィンドウ外の古いCVEがKEVに追加されても、そのCVE自体の行にはフラグが
  付かないことがあります（KEV自体のFinding行では正しく `is_kev=true` として扱われます）。
- **CVSS補助フィルタ**: CVSSベクトルを持たない検出結果（ATT&CK/CAPEC/一部のGHSA/GitHub PoC）には
  適用されません（フィルタが有効でも素通しされます）。
- **通知は日次のみ**: MVPでは通知頻度は日次固定です（`users.notify_frequency` カラムは将来拡張用に
  存在しますが、UIからは変更できません）。
- **カスタムタグの共有機能なし**: `tags.is_public` 列は将来拡張用に用意していますが、MVPでは
  カスタムタグは作成者のみに表示されます。

## 未実装（将来拡張として設計のみ考慮）

OAuthログイン・パスワードリセット・メール認証、Discord/Slack/RSS通知、arXiv等の論文取り込み、
研究室・チーム単位の共有ウォッチリスト（`organizations`テーブル追加は容易な設計）、
ウォッチリストのAND条件・除外キーワード、意味的類似度スコアリング、ダッシュボードのグラフ表示。
