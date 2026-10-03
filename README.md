# 打鍵道場

プログラミングとAIプロンプト(日本語)の入力を鍛えるタイピング練習ゲーム。
`index.html` をブラウザで開くだけで遊べます(インストール不要)。

## モード
- **コード**: C#(Unity) / Python / JavaScript / 記号ラッシュ / 自作コード
- **ローマ字**: AIプロンプト・日常文。shi/si, tsu/tu, nn/n など打ち方は自由
- **IME変換**: IMEで実際に変換して入力。自作のお題(1行1問)も可
- **苦手特訓**: ミス率と反応速度から苦手キーを含む問題を自動生成
- **記録**: 速度の推移グラフ(回ごと/日ごと)、苦手キー、キーボードのヒートマップ(ミス率/反応速度)、記録の書き出し・読み込み

## 設定
- 長さ(短め/標準/長め)、ミスしても先に進む、ミスした行をもう一度出す、打鍵音・効果音

## ログインと端末間の同期(任意)
ログインしなくても今まで通り遊べます。ログインすると、記録・設定・自作テキストを別の端末と共有できます。
Web版(Vercel)でだけ動き、`index.html` をローカルで開いたときはログイン欄が出ません。

### セットアップ(Vercel)
1. Vercel のプロジェクトで **Storage → Neon (Postgres)** を作成し、このプロジェクトに接続する(`DATABASE_URL` が自動で入ります)。
2. **Settings → Environment Variables**(画面によっては Environments の Production などを開いた先)に、次を追加する。

| 名前 | 必須 | 内容 |
|---|---|---|
| `AUTH_SECRET` | 必須 | ログインの署名用。32文字以上のランダムな文字列(Secret) |
| `TURNSTILE_SECRET` | 必須 | Cloudflare Turnstile のシークレットキー(Secret)。**未設定だと新規登録は閉じたまま**です |
| `CRON_SECRET` | 必須 | 掃除の定期実行の認証用。32文字以上のランダムな文字列(Secret) |
| `MAX_USERS` | 任意 | 登録できる総ユーザー数。既定 300 |
| `MAX_REGISTRATIONS_PER_DAY` | 任意 | 1日の新規登録数。既定 30 |
| `REGISTER_PER_IP_PER_HOUR` | 任意 | 同じIPからの登録回数/時間。既定 3(学校など、同じIPを大勢が使う場所では増やす) |
| `SYNC_PER_USER_PER_10MIN` | 任意 | 1人あたりの同期回数/10分。既定 60 |
| `REGISTRATION_OPEN` | 任意 | `0` にすると新規登録を即停止(緊急用) |

3. `index.html` の `TURNSTILE_SITE_KEY`(公開してよい値)に、Turnstile のサイトキーを入れる。
4. 再デプロイする。テーブルは最初のアクセスで自動作成されます。

`DATABASE_URL` か `AUTH_SECRET` が未設定のときは、ログイン欄が自動で隠れ、ゲーム自体は今まで通り動きます。

### Cloudflare Turnstile の設定
1. Cloudflare の無料アカウントを作り、**Turnstile → Add widget**。
2. Hostname に本番のドメイン(例: `typing-practice-three-beta.vercel.app`)を入れ、Widget Mode は Managed。
3. 表示される **Site Key** を `index.html` に、**Secret Key** を Vercel の `TURNSTILE_SECRET` に設定する。

### いたずら対策の仕組み
- 新規登録: Turnstile(人間確認)→ IPごとの回数制限 → 1日の登録数と総ユーザー数の上限 → パスワードのハッシュ化、の順。安い確認を先に行い、重い処理は最後です。
- 同期: 1人あたり60回/10分、1回の履歴は5000件・本文1MBまで。履歴は1人2万件まで(古い順に削除)、キー統計は200キーまで。
- 範囲外の値(未来の日時、人間の限界を超える速度、辻褄の合わないキー統計など)は保存せずに捨てます。設定は決まった項目だけを保存します。
- 毎日1回、古い回数カウンタとログイン失敗の記録、**記録が0件で30日以上使われていないアカウント**を自動で削除します(Vercel Cron)。

### 運用メモ
- **登録を止めたい**: Vercel の環境変数に `REGISTRATION_OPEN=0` を入れて再デプロイ。戻すときは削除して再デプロイ。
- **攻撃を受けたとき**: 上の方法で登録を止める。Vercel の Firewall や Attack Challenge Mode も使えます(使える範囲はダッシュボードで確認)。
- **Neon の SQL エディタで使えるクエリ**
  ```sql
  select count(*) from users;                                   -- ユーザー数
  select pg_size_pretty(pg_database_size(current_database()));  -- データベースの容量
  select username, to_timestamp(created_at/1000) from users order by id desc limit 20;  -- 最近の登録
  delete from users where username = 'ここにユーザー名';          -- ユーザーの削除(記録も一緒に消えます)
  ```

### 仕組み
- パスワードは scrypt + ユーザーごとのsaltでハッシュ化して保存(元のパスワードは復元できません)。ログイン時に同じ計算をして照合します。
- ユーザー名は半角英数字と `_ - .`(3〜20文字)、パスワードは8文字以上で英字・数字・記号のうち2種類以上。メールアドレスは使いません(忘れたら復旧不可)。
- 5回続けて失敗すると15分ロック。セッションは30日、HttpOnly+Secure のcookieです。
- 履歴は `t+モード` で重複を除き、キー統計は差分だけを足すので二重に数えません。設定は新しい方が勝ちます。
- 全期間の推移グラフは、記録画面で「全期間」を選ぶと日/週/月ごとに自動で集計します。

## メモ
- 記録はブラウザの localStorage に保存されます。
- コード/ローマ字モードはIMEをオフ(半角英数)にして入力します。
