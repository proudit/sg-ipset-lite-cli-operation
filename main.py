import boto3
import click
import json
import os

def load_config():
    with open("config.json", "r", encoding="utf-8") as f:
        return json.load(f)

def parse_ip_list(ip_str):
    # カンマ区切り or スペース区切り対応
    if not ip_str:
        return []
    return [ip.strip() for ip in ip_str.replace(',', ' ').split() if ip.strip()]

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
            raise ValueError(f"セキュリティグループ '{sg_name}' が見つかりません")
    except Exception as e:
        raise ValueError(f"セキュリティグループ取得エラー: {e}")

def get_waf_ipset_id_by_name(wafv2_client, ipset_name):
    """WAF IPSet名からIDを取得"""
    try:
        response = wafv2_client.list_ip_sets(Scope='REGIONAL')
        for ipset in response['IPSets']:
            if ipset['Name'] == ipset_name:
                return ipset['Id']
        raise ValueError(f"WAF IPSet '{ipset_name}' が見つかりません")
    except Exception as e:
        raise ValueError(f"WAF IPSet取得エラー: {e}")

def get_ip_permissions_for_ip(sg_permissions, target_ip):
    """指定IPに関連するすべての権限を取得"""
    target_cidr = f"{target_ip}/32"
    permissions = []
    
    for perm in sg_permissions:
        for ip_range in perm.get('IpRanges', []):
            if ip_range['CidrIp'] == target_cidr:
                permissions.append(perm)
                break
    
    return permissions

def confirm_execution(before_ips, after_ips, sg_name, waf_ipset_name):
    """実行前の確認プロンプト"""
    print("\n=== 変更内容の確認 ===")
    print(f"セキュリティグループ: {sg_name}")
    print(f"WAF IPSet: {waf_ipset_name}")
    print()
    
    if before_ips:
        print("【削除するIP】")
        for ip in before_ips:
            print(f"  - {ip}")
    else:
        print("【削除するIP】なし")
    
    print()
    
    if after_ips:
        print("【追加するIP】")
        for ip in after_ips:
            print(f"  + {ip}")
    else:
        print("【追加するIP】なし")
    
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
@click.option('--before', '-b', help='変更前GIP（カンマまたはスペース区切り、複数可）', required=True)
@click.option('--after', '-a', help='変更後GIP（カンマまたはスペース区切り、複数可）', required=True)
def main(before, after):
    """
    指定したSGとWAF IPSetの許可IPを一括で更新します。
    """
    config = load_config()
    region = config["aws_region"]
    sg_name = config["security_group_name"]
    waf_ipset_name = config["waf_ipset_name"]

    before_ips = parse_ip_list(before)
    after_ips = parse_ip_list(after)

    # AWSクライアント
    ec2 = boto3.client("ec2", region_name=region)
    wafv2 = boto3.client("wafv2", region_name=region)

    # セキュリティグループIDとWAF IPSet IDを取得
    try:
        sg_id = get_security_group_id_by_name(ec2, sg_name)
        waf_ipset_id = get_waf_ipset_id_by_name(wafv2, waf_ipset_name)
        print(f"セキュリティグループID: {sg_id}")
        print(f"WAF IPSet ID: {waf_ipset_id}")
    except ValueError as e:
        print(f"エラー: {e}")
        return

    # 実行前の確認
    if not confirm_execution(before_ips, after_ips, sg_name, waf_ipset_name):
        print("実行をキャンセルしました。")
        return

    print("\n変更を実行します...")

    # --- セキュリティグループ更新 ---
    print(f"\n[SG] {sg_name} ({sg_id}) の許可IPを更新します")
    
    # 現在のSG情報を取得
    sg_response = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = sg_response["SecurityGroups"][0]
    
    # 1. 変更前IPのすべての権限を削除
    for ip in before_ips:
        try:
            # 指定IPに関連するすべての権限を取得
            permissions_to_remove = get_ip_permissions_for_ip(sg["IpPermissions"], ip)
            
            if permissions_to_remove:
                # 権限を削除
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=permissions_to_remove
                )
                print(f"  削除: {ip} (プロトコル: {len(permissions_to_remove)}個)")
            else:
                print(f"  削除対象なし: {ip}")
                
        except Exception as e:
            print(f"  削除失敗: {ip} ({e})")
    
    # 2. 変更後IPを追加（削除した権限と同じ権限を新しいIPで追加）
    for ip in after_ips:
        try:
            # 削除された権限と同じ権限を新しいIPで作成
            permissions_to_add = []
            
            # 削除された権限をベースに新しいIP用の権限を作成
            for removed_ip in before_ips:
                removed_permissions = get_ip_permissions_for_ip(sg["IpPermissions"], removed_ip)
                for perm in removed_permissions:
                    new_perm = perm.copy()
                    new_perm['IpRanges'] = []
                    
                    # 新しいIP用のIPRangeを作成
                    for ip_range in perm.get('IpRanges', []):
                        if ip_range['CidrIp'] == f"{removed_ip}/32":
                            new_perm['IpRanges'].append({
                                'CidrIp': f"{ip}/32",
                                'Description': ip_range.get('Description', f'Updated from {removed_ip}')
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
                print(f"  追加: {ip} (プロトコル: {len(permissions_to_add)}個)")
            else:
                print(f"  追加対象なし: {ip}")
                
        except Exception as e:
            print(f"  追加失敗: {ip} ({e})")

    # --- WAF IPSet更新 ---
    print(f"\n[WAF] {waf_ipset_name} ({waf_ipset_id}) のIPSetを更新します")
    ipset = wafv2.get_ip_set(Name=waf_ipset_name, Id=waf_ipset_id, Scope="REGIONAL")
    addresses = set(ipset["IPSet"]["Addresses"])
    # 1. 変更前IPを削除
    for ip in before_ips:
        addresses.discard(f"{ip}/32")
    # 2. 変更後IPを追加
    for ip in after_ips:
        addresses.add(f"{ip}/32")
    # 3. 反映
    wafv2.update_ip_set(
        Name=waf_ipset_name,
        Id=waf_ipset_id,
        Scope="REGIONAL",
        Addresses=list(addresses),
        LockToken=ipset["LockToken"]
    )
    print(f"  許可IPセット: {sorted(addresses)}")

    # --- 現在の許可IP一覧を出力 ---
    print("\n=== 現在の許可IP一覧 ===")
    # SG
    sg = ec2.describe_security_groups(GroupIds=[sg_id])["SecurityGroups"][0]
    print(f"[SG] {sg_name}")
    for perm in sg["IpPermissions"]:
        if perm.get('IpRanges'):
            for ip_range in perm.get('IpRanges', []):
                protocol = perm.get('IpProtocol', 'all')
                from_port = perm.get('FromPort', 'all')
                to_port = perm.get('ToPort', 'all')
                print(f"  {protocol} {from_port}-{to_port}: {ip_range['CidrIp']}")
    # WAF
    ipset = wafv2.get_ip_set(Name=waf_ipset_name, Id=waf_ipset_id, Scope="REGIONAL")
    print(f"[WAF] {waf_ipset_name}")
    for ip in sorted(ipset["IPSet"]["Addresses"]):
        print(f"  {ip}")

    print("\n処理が完了しました。")

if __name__ == "__main__":
    main() 