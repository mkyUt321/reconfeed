# ReconFeed

セキュリティ研究者向けの脆弱性・攻撃手法モニタリングWebサービス（MVP）。
研究テーマ（例: Initial Access / 攻撃経路探索）に紐づく最新の CVE・KEV・EPSS・GHSA・GitHub PoC・
MITRE ATT&CK/CAPEC 更新を横断監視し、該当ユーザーへ日次メール通知する。

将来的に他の研究者も登録するマルチユーザー無料公開サービスを前提に、最初から正規化されたマルチテナント
スキーマで構築する。実装計画の全文は `docs/plan.md`（コピー先、任意）または元の plan ファイルを参照。

## 設計上の最重要ポイント（肝）

固定タグに縛らない「プリセットタグ + 自由拡張」のハイブリッド方式。

- プリセットタグ・キーワード辞書・ATT&CK Technique 対応表は `seed/preset_tags.yaml` に定義し、
  `scripts/seed.py` で DB に冪等 upsert する（`is_preset=true`, `created_by_user_id=NULL`）。
  **コードとシードデータを分離**しているのは、ユーザーがUI経由で編集した内容とプリセットの初期定義を
  同じテーブル・同じロジックで扱うため。
- ユーザーは任意のタグ（プリセット／自分のカスタムタグ）に対してキーワード・ATT&CK IDを追加できる。
  追加時は `is_preset=false, created_by_user_id=<自分>` で記録する。
- **キーワード所有権スコープ**: マッチングはタグ単位で一度だけ実行し `finding_tag_matches` に
  「どの `tag_keywords`/`tag_attack_techniques` 行でマッチしたか」を記録する。ユーザーへの配布時
  （`app/matching/distribute.py`）に `is_preset=true OR created_by_user_id=<配布先ユーザー>` の行だけを
  有効とみなす。これにより、共有プリセットタグに他ユーザーが追加した独自キーワードが、自分の通知に
  混入することはない。この境界を壊す変更（例: マッチング時点でユーザー別にフィルタする等）は避けること。
- 同一 CVE / finding の再スキャンを避けるため `findings` は `UNIQUE(source, external_id)`、
  通知の二重送信を避けるため `notifications_sent` は `UNIQUE(user_id, finding_id)`。

## 技術スタック

- バックエンド: Python 3.12 + FastAPI
- フロントエンド: Jinja2 サーバーサイドレンダリング（SPA不使用）
- DB: **Neon**（無料 Postgres・永続。Render無料Postgresは作成30日で削除されるため不採用）
- ORM/マイグレーション: SQLAlchemy 2.0 + Alembic
- 認証: セッションCookie（Starlette SessionMiddleware）+ passlib[bcrypt]（OAuth・パスワードリセットはMVP対象外）
- HTTPクライアント: httpx（async、レート制御・リトライ付き）
- メール送信: Resend（無料枠）
- スケジューラ: **GitHub Actions scheduled workflow が `python -m app.jobs.daily` を直接実行**
  （Render の cron は有料枠のため。GH Actions は公開リポジトリで実質無制限・無料枠のWeb dyno スリープの
  影響を受けない）
- Webホスティング: Render 無料 Web Service（`render.yaml` で定義）

## ディレクトリ構成（予定）

```
app/
  main.py            FastAPI app, SessionMiddleware, ルーター登録
  config.py          Pydantic Settings（環境変数）
  db.py              SQLAlchemy engine/session
  models/            SQLAlchemy モデル（テーブルごと）
  schemas/           Pydantic スキーマ
  auth/              ハッシュ化・セッション・get_current_user
  web/               Jinja2 を返すルーター（auth/tag/watchlist/dashboard/settings）
  templates/         Jinja2 テンプレート
  static/            最小限の CSS/JS
  sources/           情報源フェッチャ（nvd/kev/epss/ghsa/github_poc/attack/capec、1ファイル1ソース）
  matching/          engine.py（タグ単位マッチング）, distribute.py（ユーザー配布・所有権スコープ適用）
  notify/            resend_client.py, digest.py
  jobs/
    daily.py         取得→保存→マッチング→配布→通知のパイプライン本体
seed/
  preset_tags.yaml   プリセットタグ×キーワード×ATT&CK対応表
scripts/
  seed.py            seed/*.yaml を DB に冪等 upsert
alembic/             マイグレーション
tests/
.github/workflows/
  daily.yml          scheduled: app.jobs.daily を直接実行
  ci.yml             lint/test
render.yaml
```

## コマンド（実装後に有効）

```bash
# セットアップ（conda環境。初回のみ conda create -n reconfeed python=3.12 -y）
conda activate reconfeed
pip install -r requirements-dev.txt
cp .env.example .env   # 値を埋める（Neon利用時は DATABASE_URL に ?sslmode=require&sslnegotiation=direct を付与）

# DBスキーマ適用
alembic upgrade head

# プリセットタグのシード投入（seed/preset_tags.yaml 編集後は毎回再実行）
python scripts/seed.py

# ローカルサーバー
uvicorn app.main:app --reload

# 日次バッチを手動実行（取得→マッチング→配布→通知）
python -m app.jobs.daily

# テスト
pytest
```

## 環境変数

| 変数 | 用途 | 取得元 |
|---|---|---|
| `DATABASE_URL` | Neon Postgres 接続文字列 | Neon コンソール |
| `SESSION_SECRET` | セッションCookie署名鍵（ランダム文字列） | 自分で生成 |
| `NVD_API_KEY` | NVD API 2.0 レート緩和 | NVD API Key申請ページ |
| `GITHUB_TOKEN` | GHSA GraphQL・GitHub Search API | GitHub PAT (fine-grained, read-only) |
| `RESEND_API_KEY` | メール送信 | Resend ダッシュボード |
| `RESEND_FROM_EMAIL` | 送信元アドレス | Resend でドメイン/テスト送信元を設定 |
| `APP_BASE_URL` | メール内リンク生成用 | Renderのサービスドメイン等 |

## 既知の落とし穴

- **Neon (Postgres 18) は Direct SSL Negotiation を要求する**。`psycopg[binary]` は 3.3.4 以上が必要で、
  `DATABASE_URL` の末尾に `sslnegotiation=direct` を付ける必要がある（例:
  `...neon.tech/neondb?sslmode=require&sslnegotiation=direct`）。片方だけだと
  `OperationalError: connection to server ... failed: server closed the connection unexpectedly`
  という分かりにくいエラーになる（TCP/TLS自体は張れるが、Postgresプロトコルの旧来のSSLRequestネゴシエーション
  に応答が返らないため）。`.env.example` に記載済み。
- 本プロジェクトの Python 実行環境は **conda 環境 `reconfeed`**（`conda activate reconfeed`）。素の `python` は
  Anaconda の base 環境を指すため、コマンド実行前に必ず `conda activate reconfeed` すること。

## 実装時の注意

- プリセットの `tag_keywords`/`tag_attack_techniques` 行はユーザーに削除させない（他ユーザー共有のため）。
  ユーザーは自分が追加した行（`created_by_user_id = 自分`）のみ削除可能。
- `findings.raw` (JSONB) にソース固有データ（CPE, CWE, GHSA重大度等）を格納し、共通カラムを増やしすぎない。
- MITRE ATT&CK/CAPEC は STIX オブジェクトの `modified`/バージョンを前回取得分と比較して差分検出する
  （全量再取得はしない）。
- レート制御が必須の外部API: NVD（50req/30s, APIキー利用時）, GitHub Search（30req/min）。
  `app/sources/base.py` の共通レート制御ヘルパーを必ず経由すること。
- 未実装機能（設計のみ考慮、コードは書かない）: OAuth・パスワードリセット・メール認証、
  Discord/Slack/RSS通知、arXiv取込、organizations（チーム共有）、カスタムタグの他ユーザー公開、
  ウォッチリストのAND条件・除外キーワード、意味的類似度スコアリング、ダッシュボードのグラフ。
  スキーマ上は拡張しやすくしておくが、UI/ロジックは追加しない。
