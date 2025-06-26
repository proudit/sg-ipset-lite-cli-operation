# AWS SecurityGroup & WAF IP-Set IP Manager

## 概要

このツールは、AWSのセキュリティグループ（SG）とWAF IPSetの許可IPを一括で更新する簡易CLIツールです。IP変更依頼に対して、指定した変更前IPを削除し、変更後IPを追加する操作を自動化します。

## 機能

- **一括IP更新**: セキュリティグループとWAF IPSetの許可IPを同時に更新
- **単一IP対応**: 変更前・変更後それぞれに単一のIPアドレスを指定
- **削除機能**: 既存のIPを削除（追加なし）
- **現在状態表示**: 更新後の許可IP一覧をテキスト形式で出力
- **エラーハンドリング**: 個別IPの更新失敗時も処理を継続
- **自動バックアップ**: 実行前に現在の許可IP一覧をCSVファイルに自動バックアップ

## 前提条件

### AWS設定
- AWS CLIがインストール済み
- 適切なIAM権限が設定済み
  - EC2: `ec2:DescribeSecurityGroups`, `ec2:AuthorizeSecurityGroupIngress`, `ec2:RevokeSecurityGroupIngress`
  - WAF: `wafv2:GetIPSet`, `wafv2:UpdateIPSet`, `wafv2:ListIPSets`

### AWS認証情報の設定

#### 方法1: AWS CLI設定（推奨）
```bash
# AWS CLIで認証情報を設定
aws configure

# 以下の情報を入力
AWS Access Key ID: [your_access_key_id]
AWS Secret Access Key: [your_secret_access_key]
Default region name: ap-northeast-1
Default output format: json
```

#### 方法2: 環境変数
```bash
# macOS/Linux
export AWS_ACCESS_KEY_ID=your_access_key_id
export AWS_SECRET_ACCESS_KEY=your_secret_access_key
export AWS_DEFAULT_REGION=ap-northeast-1

# Windows (コマンドプロンプト)
set AWS_ACCESS_KEY_ID=your_access_key_id
set AWS_SECRET_ACCESS_KEY=your_secret_access_key
set AWS_DEFAULT_REGION=ap-northeast-1

# Windows (PowerShell)
$env:AWS_ACCESS_KEY_ID="your_access_key_id"
$env:AWS_SECRET_ACCESS_KEY="your_secret_access_key"
$env:AWS_DEFAULT_REGION="ap-northeast-1"
```

#### 方法3: 認証情報ファイル
```bash
# ~/.aws/credentials ファイルを作成
mkdir ~/.aws
nano ~/.aws/credentials

# 以下の内容を記述
[default]
aws_access_key_id = your_access_key_id
aws_secret_access_key = your_secret_access_key

# ~/.aws/config ファイルを作成
nano ~/.aws/config

# 以下の内容を記述
[default]
region = ap-northeast-1
output = json
```

### 認証情報の確認
```bash
# 認証情報が正しく設定されているか確認
aws sts get-caller-identity

# 正常な場合の出力例
{
    "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    "Account": "123456789012",
    "Arn": "arn:aws:iam::123456789012:user/username"
}
```

## Python環境の準備

### macOSの場合

1. **HomebrewでPythonをインストール（推奨）**
    ```bash
    brew install python
    ```

2. **バージョン確認**
    ```bash
    python3 --version
    ```

3. **仮想環境の作成（推奨）**
    ```bash
    python3 -m venv venv
    source venv/bin/activate
    ```

### Windowsの場合

1. **公式サイトからPythonをインストール**  
   [Python公式ダウンロードページ](https://www.python.org/downloads/)

2. **インストール時に「Add Python to PATH」にチェックを入れる**

3. **コマンドプロンプトでバージョン確認**
    ```cmd
    python --version
    ```

4. **仮想環境の作成（推奨）**
    ```cmd
    python -m venv venv
    venv\Scripts\activate
    ```

## インストール

1. リポジトリをクローン
```bash
git clone <repository-url>
cd taiko-towns-operation
```

2. 依存関係をインストール
```bash
pip install -r requirements.txt
```

3. 設定ファイルを作成
```bash
cp config.json.example config.json
# config.jsonを編集して実際の値を設定
```

## 設定

### config.json
```json
{
  "aws_region": "ap-northeast-1",
  "security_group_name": "your-security-group-name",
  "waf_ipset_name": "your-ipset-name"
}
```

| 項目 | 説明 |
|------|------|
| `aws_region` | AWSリージョン（例: ap-northeast-1） |
| `security_group_name` | 更新対象のセキュリティグループ名 |
| `waf_ipset_name` | 更新対象のWAF IPSet名 |

**注意**: セキュリティグループ名とWAF IPSet名は、AWSコンソールで確認できる名前を指定してください。

### 設定値の確認方法

#### セキュリティグループ名の確認
1. AWSコンソール → EC2 → セキュリティグループ
2. 対象のセキュリティグループの「名前」列を確認

#### WAF IPSet名の確認
1. AWSコンソール → WAF & Shield → IP sets
2. 対象のIPSetの「名前」列を確認

## 使用方法

### パラメータ

| パラメータ | 短縮形 | 必須 | 説明 |
|-----------|--------|------|------|
| `--before` | `-b` | △ | 削除するIPアドレス（IP変更時のみ） |
| `--after` | `-a` | △ | 追加するIPアドレス（IP変更時のみ） |
| `--delete` | - | △ | 削除するIPアドレス（削除時のみ） |
| `--no-backup` | - | - | バックアップをスキップする |

### 使用方法

#### 1. IP変更（既存IPを削除して新しいIPを追加）
```bash
python main.py --before <削除IP> --after <追加IP>
```

#### 2. 削除（既存IPを削除、追加なし）
```bash
python main.py --delete <削除IP>
```

#### 3. バックアップをスキップしてIP変更
```bash
python main.py --before 1.2.3.4/32 --after 5.6.7.8/32 --no-backup
```

**注意**: `--before`と`--after`、`--delete`は同時に使用できません。

### バックアップ機能

実行前に自動的に以下のバックアップが作成されます：

- **セキュリティグループ**: `backups/backup_YYYYMMDD_HHMMSS_sg_[SG名].csv`
- **WAF IPSet**: `backups/backup_YYYYMMDD_HHMMSS_waf_[IPSet名].csv`
- **サマリー**: `backups/backup_summary_YYYYMMDD_HHMMSS.txt`

#### バックアップファイルの内容

**セキュリティグループCSV:**
- プロトコル、ポート範囲、IP/CIDR、説明、SG名、SG ID、バックアップ日時

**WAF IPSet CSV:**
- IP/CIDR、WAF IPSet名、WAF IPSet ID、バックアップ日時

#### バックアップをスキップする場合
```bash
python main.py --before 1.2.3.4 --after 5.6.7.8 --no-backup
```

### 使用例

#### 例1: 単一IPの変更
```bash
python main.py --before 1.2.3.4/32 --after 5.6.7.8/32
```

#### 例2: 既存IPの削除
```bash
python main.py --delete 1.2.3.4/32
```

#### 例3: バックアップをスキップしてIP変更
```bash
python main.py --before 1.2.3.4/32 --after 5.6.7.8/32 --no-backup
```

## 出力例

### IP変更モード
```bash
$ python main.py --before 1.2.3.4/32 --after 5.6.7.8/32

セキュリティグループID: sg-xxxxxxxxxxxxxxxxx
WAF IPSet ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

=== IP変更の確認 ===
セキュリティグループ: your-security-group-name
WAF IPSet: your-ipset-name

【削除するIP】
  - 1.2.3.4/32 (SG ✓, WAF ✓)

【追加するIP】
  + 5.6.7.8/32 (SG ✓, WAF ✓)

==================================================
上記の変更を実行しますか？ (yes/no): yes

=== バックアップ実行 ===
[SG] your-security-group-name のバックアップを作成中...
  [バックアップ] backups/backup_20241201_143022_sg_your-security-group-name.csv
[WAF] your-ipset-name のバックアップを作成中...
  [バックアップ] backups/backup_20241201_143022_waf_your-ipset-name.csv
  [サマリー] backups/backup_summary_20241201_143022.txt
バックアップ完了

変更を実行します...

[SG] your-security-group-name (sg-xxxxxxxxxxxxxxxxx) の許可IPを更新します
  削除: 1.2.3.4/32 (プロトコル: 2個)
  追加: 5.6.7.8/32 (プロトコル: 2個)

[WAF] your-ipset-name (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) のIPSetを更新します
  削除: 1.2.3.4/32
  追加: 5.6.7.8/32
  許可IPセット: ['5.6.7.8/32', '9.10.11.12/32']

=== 現在の許可IP一覧 ===
[SG] your-security-group-name
  tcp 80-80: 5.6.7.8/32
  tcp 443-443: 5.6.7.8/32
[WAF] your-ipset-name
  5.6.7.8/32
  9.10.11.12/32

処理が完了しました。
```

### 削除モード
```bash
$ python main.py --delete 1.2.3.4/32

セキュリティグループID: sg-xxxxxxxxxxxxxxxxx
WAF IPSet ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

=== 削除の確認 ===
セキュリティグループ: your-security-group-name
WAF IPSet: your-ipset-name

【削除するIP】
  - 1.2.3.4/32 (SG ✓, WAF ✓)

【追加するIP】
==================================================
上記の変更を実行しますか？ (yes/no): yes

=== バックアップ実行 ===
[SG] your-security-group-name のバックアップを作成中...
  [バックアップ] backups/backup_20241201_143022_sg_your-security-group-name.csv
[WAF] your-ipset-name のバックアップを作成中...
  [バックアップ] backups/backup_20241201_143022_waf_your-ipset-name.csv
  [サマリー] backups/backup_summary_20241201_143022.txt
バックアップ完了

変更を実行します...

[SG] your-security-group-name (sg-xxxxxxxxxxxxxxxxx) の許可IPを更新します
  削除: 1.2.3.4/32 (プロトコル: 2個)

[WAF] your-ipset-name (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx) のIPSetを更新します
  削除: 1.2.3.4/32
  許可IPセット: ['9.10.11.12/32']

=== 現在の許可IP一覧 ===
[SG] your-security-group-name
  tcp 80-80: 9.10.11.12/32
  tcp 443-443: 9.10.11.12/32
[WAF] your-ipset-name
  9.10.11.12/32

処理が完了しました。
```

## 処理内容

1. **セキュリティグループ更新**
   - 変更前IPのすべての権限（プロトコル・ポート）を削除
   - 変更後IPに同じ権限を追加

2. **WAF IPSet更新**
   - 変更前IPをIPSetから削除
   - 変更後IPをIPSetに追加

3. **現在状態表示**
   - セキュリティグループの現在の許可IP
   - WAF IPSetの現在の許可IP

## エラーハンドリング

- 個別IPの更新失敗時も処理を継続
- エラーが発生したIPはログに出力
- 設定ファイルやAWS認証情報の不備は適切なエラーメッセージを表示

## トラブルシューティング

### よくあるエラー

#### 1. AWS認証エラー
```
botocore.exceptions.NoCredentialsError: Unable to locate credentials
```
**解決方法**: AWS認証情報を正しく設定してください

#### 2. 権限エラー
```
botocore.exceptions.ClientError: An error occurred (AccessDenied) when calling the ListIPSets operation: User: arn:aws:iam::123456789012:user/username is not authorized to perform: wafv2:ListIPSets on resource: arn:aws:wafv2:ap-northeast-1:123456789012:ipset/your-ipset-name
```
**解決方法**: 適切なIAM権限が設定されているか確認してください
