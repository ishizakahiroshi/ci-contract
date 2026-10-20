<!-- このファイルはプロジェクト固有ルールのみを書く。個人/グローバル AI ルール
（言語・確認スタイル・出力フォーマット等）は各 AI ツールのグローバル設定へ。
fresh public clone でも有効な内容に保つこと。 -->

# ci-contract 開発ガイド

> **このファイルは索引であって本文ではない。** 全 AI セッションで全文がロードされるので、
> ルールの本文はここへ書かず、破る人が必ず開く場所（コード・検査スクリプト・テスト・README）へ置き、
> ここには索引の 1 行だけを残す。

## プロジェクト概要

CI の契約（どの変更でどの検査を走らせ、結果をどう受け入れるか）を、宣言だけから決める共通エンジン。今あるのは、canonical JSON と domain hash のバイト層、宣言だけによる check の選択（`explain`）、読み取り専用の Git の読み取りと plan 文書の組み立て（`plan`）。入出力と終了コードは `README.md` が正本。

## やらないこと（スコープ外）

- 検査の実行（execute）、結果の検証（verify）、GitHub への接続、request（repo 全体の実行を含む）、必須の検査の集約（aggregator）は、まだ実装していない。未実装のものを実装済みとして書かない
- manifest から任意の shell・argv・URL を実行させない
- 実装（`src/`）から Git へ書き込まない・ネットワークへ出ない

## 技術スタック

| 項目 | 内容 |
|---|---|
| 言語 | Python 3.12 以上（実行時は標準ライブラリのみ） |
| 構造の検証 | 任意で `jsonschema==4.26.0`（`schema` extra） |
| テスト | 標準の `unittest` |

## ディレクトリ構成

```text
src/ci_contract/        エンジン本体（CLI は cli.py、選択は selection.py、plan は plan.py、Git の読み取りは gitsource.py）
src/ci_contract/data/   固定の schema・正規化の台帳・出典（SOURCES.json）
tests/                  unittest。受入例の照合と陰性対照を含む
tests/fixtures/         合成の入力（golden vectors・受入例の抜き出し・合成の manifest と policy）
scripts/                秘密の検査（doxguard の実行アダプタ）と hook の installer
```

## 主要コマンド

- テスト: `PYTHONPATH=src python -m unittest discover -s tests -v`（Windows の PowerShell では `$env:PYTHONPATH='src'` を先に設定）
- 使い方の例: `README.md` の冒頭

## 設計原則の索引（本文は正本にある）

| ルール | 正本（本文はここ） | 機械検査 |
|---|---|---|
| バイト列（canonical JSON・hash）を変えない | `tests/fixtures/golden-vectors.json` | `tests/test_contract_bytes.py` |
| 受入例の期待値を実装に合わせて書き換えない | `tests/acceptance-coverage.json`・`src/ci_contract/data/SOURCES.json` | `tests/test_selection.py`・`tests/test_plan.py` |
| fixture は合成値だけ | `tests/fixtures/` | doxguard（`scripts/secrets-scan.dual.mjs`）・gitleaks |
| path の大文字小文字や改行で結果が変わる比べ方をしない | `README.md` | Linux と Windows の両方でテストを通す |

## AI 作業共通ルール

ビルド・コミット禁止、secrets-scan 責務、plan/bugfix/pending md の作成ルール等の AI 作業共通ルールは、各利用者のグローバル AI 設定に従う（作者環境の例: `~/.claude/CLAUDE.md` および `~/.claude/guides/`）。

## Obsidian artifacts

If `docs/obsidian/README.md` exists, use it as an index for related knowledge artifacts.
Use the repository-relative `docs/obsidian` entry. Do not write to a central absolute
path and do not silently fall back to `docs/local` when the entry is missing.

## secrets-scan（このリポジトリの配線）

書く瞬間の責務（固有名詞の一般化・fixture は合成データ等）は上記「AI 作業共通ルール」の参照先に従う。このリポジトリ固有の配線は以下:

- layer 2: `.githooks/pre-commit`（doxguard の opt-in。有効化は `scripts/install-hooks.ps1` か `scripts/install-hooks.sh`）
- layer 3: `.github/workflows/secrets-scan.yml`（doxguard 0.2.0 の strict を `node scripts/secrets-scan.dual.mjs --native-only --all-tracked` で実行。設定は `doxguard.ci.json`）と `.github/workflows/gitleaks.yml`
- CI には私有の監視語の一覧が無いので、CI で走るのは構造の検査（絶対パス・私有の IP・メール）だけ。監視語は各自の手元で確かめる

## 関連ドキュメント

| 項目 | パス |
|---|---|
| ユーザー向け README | `README.md` |
| Codex/他 AI 用入口 | `AGENTS.md` |
| ローカル作業ノート（非公開） | `docs/local/`（存在する場合） |
| Obsidian knowledge artifacts | `docs/obsidian/`（存在する場合。作業キューではない） |
