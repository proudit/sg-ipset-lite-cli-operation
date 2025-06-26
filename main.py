import boto3
import click
import json
import os
import ipaddress

def load_config():
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)

def parse_ip_list(ip_str):
    """IPアドレスまたはCIDRレンジを解析"""
    if not ip_str:
        return []
    
    ip_list = []
    for ip in ip_str.replace(',', ' ').split():
        ip = ip.strip()
        if ip:
            # CIDR表記がない場合は/32を追加
            if '/' not in ip:
                ip = f"{ip}/32"
            ip_list.append(ip)
    
    return ip_list

def normalize_cidr(cidr_str):
    """CIDR表記を正規化（/32がない場合は追加）"""
    if '/' not in cidr_str:
        return f"{cidr_str}/32"
    return cidr_str

def validate_cidr(cidr_str):
    """CIDR表記の妥当性をチェック"""
    try:
        ipaddress.ip_network(cidr_str, strict=False)
        return True
    except ValueError:
        return False

def get_security_group_id_by_name(ec2_client, sg_name):
    """セキュリティグループ名からIDを取得"""
    try:
        response = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': [sg_name]}
            ]
        )
        if response['SecurityGroups']:
            return response['SecurityGroups'][0]['GroupId']
        else:
            return None
    except Exception as e:
        print(f"警告: セキュリティグループ取得エラー: {e}")
        return None

def get_waf_ipset_id_by_name(wafv2_client, ipset_name):
    """WAF IPSet名からIDを取得"""
    try:
        response = wafv2_client.list_ip_sets(Scope='REGIONAL')
        for ipset in response['IPSets']:
            if ipset['Name'] == ipset_name:
                return ipset['Id']
        return None
    except Exception as e:
        print(f"警告: WAF IPSet取得エラー: {e}")
        return None

def get_ip_permissions_for_cidr(sg_permissions, target_cidr):
    """指定CIDRに関連するすべての権限を取得"""
    permissions = []
    
    for perm in sg_permissions:
        for ip_range in perm.get('IpRanges', []):
            if ip_range['CidrIp'] == target_cidr:
                permissions.append(perm)
                break
    
    return permissions

def confirm_execution(before_cidrs, after_cidrs, sg_name, waf_ipset_name, sg_available, waf_available):
    """実行前の確認プロンプト"""
    print("\n=== 変更内容の確認 ===")
    
    if sg_available:
        print(f"セキュリティグループ: {sg_name} ✓")
    else:
        print(f"セキュリティグループ: {sg_name} ✗ (見つかりません)")
    
    if waf_available:
        print(f"WAF IPSet: {waf_ipset_name} ✓")
    else:
        print(f"WAF IPSet: {waf_ipset_name} ✗ (見つかりません)")
    
    print()
    
    if before_cidrs:
        print("【削除するIP/CIDR】")
        for cidr in before_cidrs:
            print(f"  - {cidr}")
    else:
        print("【削除するIP/CIDR】なし")
    
    print()
    
    if after_cidrs:
        print("【追加するIP/CIDR】")
        for cidr in after_cidrs:
            print(f"  + {cidr}")
    else:
        print("【追加するIP/CIDR】なし")
    
    print("\n" + "="*50)
    
    while True:
        response = input("上記の変更を実行しますか？ (yes/no): ").strip().lower()
        if response in ['yes', 'y']:
            return True
        elif response in ['no', 'n']:
            return False
        else:
            print("'yes' または 'no' で回答してください。")

@click.command()
@click.option('--before', '-b', help='変更前IP/CIDR（カンマまたはスペース区切り、複数可）', required=True)
@click.option('--after', '-a', help='変更後IP/CIDR（カンマまたはスペース区切り、複数可）', required=True)
def main(before, after):
    """
    指定したSGとWAF IPSetの許可IPを一括で更新します。
    IPアドレスまたはCIDR表記（例: 192.168.1.0/24）に対応しています。
    """
    config = load_config()
    region = config["aws_region"]
    sg_name = config["security_group_name"]
    waf_ipset_name = config["waf_ipset_name"]

    before_cidrs = parse_ip_list(before)
    after_cidrs = parse_ip_list(after)

    # CIDR表記の妥当性チェック
    invalid_before = [cidr for cidr in before_cidrs if not validate_cidr(cidr)]
    invalid_after = [cidr for cidr in after_cidrs if not validate_cidr(cidr)]
    
    if invalid_before:
        print(f"エラー: 無効なCIDR表記（削除対象）: {invalid_before}")
        return
    
    if invalid_after:
        print(f"エラー: 無効なCIDR表記（追加対象）: {invalid_after}")
        return

    # AWSクライアント
    ec2 = boto3.client("ec2", region_name=region)
    wafv2 = boto3.client("wafv2", region_name=region)

    # セキュリティグループIDとWAF IPSet IDを取得
    sg_id = get_security_group_id_by_name(ec2, sg_name)
    waf_ipset_id = get_waf_ipset_id_by_name(wafv2, waf_ipset_name)
    
    sg_available = sg_id is not None
    waf_available = waf_ipset_id is not None
    
    if sg_available:
        print(f"セキュリティグループID: {sg_id}")
    else:
        print(f"警告: セキュリティグループ '{sg_name}' が見つかりません")
    
    if waf_available:
        print(f"WAF IPSet ID: {waf_ipset_id}")
    else:
        print(f"警告: WAF IPSet '{waf_ipset_name}' が見つかりません")
    
    # 両方とも見つからない場合はエラー
    if not sg_available and not waf_available:
        print("エラー: セキュリティグループとWAF IPSetの両方が見つかりません。設定を確認してください。")
        return

    # 実行前の確認
    if not confirm_execution(before_cidrs, after_cidrs, sg_name, waf_ipset_name, sg_available, waf_available):
        print("実行をキャンセルしました。")
        return

    print("\n変更を実行します...")

    # --- セキュリティグループ更新 ---
    if sg_available:
        print(f"\n[SG] {sg_name} ({sg_id}) の許可IPを更新します")
        
        # 現在のSG情報を取得
        sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
        sg = sg_response["SecurityGroups"][0]
        
        # 1. 変更前CIDRのすべての権限を削除
        for cidr in before_cidrs:
            try:
                # 指定CIDRに関連するすべての権限を取得
                permissions_to_remove = get_ip_permissions_for_cidr(sg["IpPermissions"], cidr)
                
                if permissions_to_remove:
                    # 権限を削除
                    ec2.revoke_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=permissions_to_remove
                    )
                    print(f"  削除: {cidr} (プロトコル: {len(permissions_to_remove)}個)")
                else:
                    print(f"  削除対象なし: {cidr}")
                    
            except Exception as e:
                print(f"  削除失敗: {cidr} ({e})")
        
        # 2. 変更後CIDRを追加（削除した権限と同じ権限を新しいCIDRで追加）
        for cidr in after_cidrs:
            try:
                # 削除された権限と同じ権限を新しいCIDRで作成
                permissions_to_add = []
                
                # 削除された権限をベースに新しいCIDR用の権限を作成
                for removed_cidr in before_cidrs:
                    removed_permissions = get_ip_permissions_for_cidr(sg["IpPermissions"], removed_cidr)
                    for perm in removed_permissions:
                        new_perm = perm.copy()
                        new_perm['IpRanges'] = []
                        
                        # 新しいCIDR用のIPRangeを作成
                        for ip_range in perm.get('IpRanges', []):
                            if ip_range['CidrIp'] == removed_cidr:
                                new_perm['IpRanges'].append({
                                    'CidrIp': cidr,
                                    'Description': ip_range.get('Description', f'Updated from {removed_cidr}')
                                })
                            else:
                                new_perm['IpRanges'].append(ip_range)
                        
                        permissions_to_add.append(new_perm)
                
                # 権限を追加
                if permissions_to_add:
                    ec2.authorize_security_group_ingress(
                        GroupId=sg_id,
                        IpPermissions=permissions_to_add
                    )
                    print(f"  追加: {cidr} (プロトコル: {len(permissions_to_add)}個)")
                else:
                    print(f"  追加対象なし: {cidr}")
                    
            except Exception as e:
                print(f"  追加失敗: {cidr} ({e})")
    else:
        print(f"\n[SG] {sg_name} の更新をスキップします（見つかりません）")

    # --- WAF IPSet更新 ---
    if waf_available:
        print(f"\n[WAF] {waf_ipset_name} ({waf_ipset_id}) のIPSetを更新します")
        try:
            ipset = wafv2.get_ip_set(Name=waf_ipset_name, Id=waf_ipset_id, Scope="REGIONAL")
            addresses = set(ipset["IPSet"]["Addresses"])
            # 1. 変更前CIDRを削除
            for cidr in before_cidrs:
                addresses.discard(cidr)
            # 2. 変更後CIDRを追加
            for cidr in after_cidrs:
                addresses.add(cidr)
            # 3. 反映
            wafv2.update_ip_set(
                Name=waf_ipset_name,
                Id=waf_ipset_id,
                Scope="REGIONAL",
                Addresses=list(addresses),
                LockToken=ipset["LockToken"]
            )
            print(f"  許可IPセット: {sorted(addresses)}")
        except Exception as e:
            print(f"  WAF更新失敗: {e}")
    else:
        print(f"\n[WAF] {waf_ipset_name} の更新をスキップします（見つかりません）")

    # --- 現在の許可IP一覧を出力 ---
    print("\n=== 現在の許可IP一覧 ===")
    
    # SG
    if sg_available:
        try:
            sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
            print(f"[SG] {sg_name}")
            for perm in sg["IpPermissions"]:
                if perm.get('IpRanges'):
                    for ip_range in perm.get('IpRanges', []):
                        protocol = perm.get('IpProtocol', 'all')
                        from_port = perm.get('FromPort', 'all')
                        to_port = perm.get('ToPort', 'all')
                        print(f"  {protocol} {from_port}-{to_port}: {ip_range['CidrIp']}")
        except Exception as e:
            print(f"[SG] {sg_name} の状態取得に失敗: {e}")
    else:
        print(f"[SG] {sg_name} - 利用不可")
    
    # WAF
    if waf_available:
        try:
            ipset = wafv2.get_ip_set(Name=waf_ipset_name, Id=waf_ipset_id, Scope="REGIONAL")
            print(f"[WAF] {waf_ipset_name}")
            for ip in sorted(ipset["IPSet"]["Addresses"]):
                print(f"  {ip}")
        except Exception as e:
            print(f"[WAF] {waf_ipset_name} の状態取得に失敗: {e}")
    else:
        print(f"[WAF] {waf_ipset_name} - 利用不可")

    print("\n処理が完了しました。")

if __name__ == "__main__":
    main() 