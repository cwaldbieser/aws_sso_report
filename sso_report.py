#! /usr/bin/env python

import csv
import functools

import boto3


def main():
    """
    Create report of SSO users and permissions.
    """
    user_map = {}
    for user in generate_users():
        user_id = user["UserId"]
        username = user["UserName"]
        user_displayname = user["DisplayName"]
        user_map[user_id] = (username, user_displayname)
    group_map = {}
    for group in generate_groups():
        group_id = group["GroupId"]
        group_name = group["DisplayName"]
        group_desc = group.get("Description", "")
        members = [
            user_map[user_id] for user_id in generate_group_memberships(group_id)
        ]
        members.sort()
        group_map[group_id] = (group_name, group_desc, members)
    field_names = [
        "ACCOUNT_ID",
        "ACCOUNT_NAME",
        "PERM_ARN",
        "PERMISSION",
        "PERM_DESC",
        "PRINCIPAL_TYPE",
        "GROUP",
        "GROUP_DESC",
        "USER_ID",
        "USER_NAME",
    ]
    with open("./sso_report.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=field_names)
        writer.writeheader()
        for account_id, account_name in generate_accounts():
            print(f"Processing account {account_id}: {account_name} ...")
            for permission_set in generate_permission_sets_for_account(account_id):
                perm_info = describe_permission_set(permission_set)
                perm_name = perm_info["Name"]
                perm_desc = perm_info.get("Description", "")
                for assignment in generate_account_assignments(
                    account_id, permission_set
                ):
                    # print(assignment)
                    principal_type = assignment["PrincipalType"]
                    principal_id = assignment["PrincipalId"]
                    if principal_type == "USER":
                        username, user_displayname = user_map[principal_id]
                        row = {
                            "ACCOUNT_ID": account_id,
                            "ACCOUNT_NAME": account_name,
                            "PERM_ARN": permission_set,
                            "PERMISSION": perm_name,
                            "PERM_DESC": perm_desc,
                            "PRINCIPAL_TYPE": principal_type,
                            "USER_ID": username,
                            "USER_NAME": user_displayname,
                        }
                        writer.writerow(row)
                    if principal_type == "GROUP":
                        group_name, group_desc, members = group_map[principal_id]
                        for username, user_displayname in members:
                            row = {
                                "ACCOUNT_ID": account_id,
                                "ACCOUNT_NAME": account_name,
                                "PERM_ARN": permission_set,
                                "PERMISSION": perm_name,
                                "PERM_DESC": perm_desc,
                                "PRINCIPAL_TYPE": principal_type,
                                "GROUP": group_name,
                                "GROUP_DESC": group_desc,
                                "USER_ID": username,
                                "USER_NAME": user_displayname,
                            }
                            writer.writerow(row)


@functools.lru_cache
def get_identity_center():
    """
    Get the identity center.
    """
    client = boto3.client("sso-admin")
    response = client.list_instances()
    instances = response["Instances"]
    instance = instances[0]
    identity_store_id = instance["IdentityStoreId"]
    iam_id_center_arn = instance["InstanceArn"]
    return iam_id_center_arn, identity_store_id


@functools.lru_cache
def describe_permission_set(permission_set):
    """
    Describe a permission set.
    """
    client = boto3.client("sso-admin")
    iam_id_center_arn, identity_store_id = get_identity_center()
    response = client.describe_permission_set(
        InstanceArn=iam_id_center_arn,
        PermissionSetArn=permission_set,
    )
    return response["PermissionSet"]


def generate_group_memberships(group_id):
    """
    Generate group memberships.
    """
    iam_id_center_arn, identity_store_id = get_identity_center()
    client = boto3.client("identitystore")
    paginator = client.get_paginator("list_group_memberships")
    page_iterator = paginator.paginate(
        IdentityStoreId=identity_store_id, GroupId=group_id
    )
    for page in page_iterator:
        for member in page["GroupMemberships"]:
            member_id = member["MemberId"]
            user_id = member_id["UserId"]
            yield user_id


def generate_users():
    """
    Generate SSO users.
    """
    iam_id_center_arn, identity_store_id = get_identity_center()
    client = boto3.client("identitystore")
    paginator = client.get_paginator("list_users")
    page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
    for page in page_iterator:
        for user in page["Users"]:
            yield user


def generate_groups():
    """
    Generate SSO groups.
    """
    iam_id_center_arn, identity_store_id = get_identity_center()
    client = boto3.client("identitystore")
    paginator = client.get_paginator("list_groups")
    page_iterator = paginator.paginate(IdentityStoreId=identity_store_id)
    for page in page_iterator:
        for group in page["Groups"]:
            yield group


def generate_account_assignments(account_id, account_assignment):
    """
    Generate account assignments.
    """
    client = boto3.client("sso-admin")
    iam_id_center_arn, identity_store_id = get_identity_center()
    paginator = client.get_paginator("list_account_assignments")
    page_iterator = paginator.paginate(
        AccountId=account_id,
        InstanceArn=iam_id_center_arn,
        PermissionSetArn=account_assignment,
    )
    for page in page_iterator:
        for account_assignment in page["AccountAssignments"]:
            yield account_assignment


def generate_permission_sets_for_account(account_id):
    """
    Generate permission sets for an account ID.
    """
    client = boto3.client("sso-admin")
    iam_id_center_arn, identity_store_id = get_identity_center()
    paginator = client.get_paginator("list_permission_sets_provisioned_to_account")
    page_iterator = paginator.paginate(
        AccountId=account_id,
        InstanceArn=iam_id_center_arn,
    )
    for page in page_iterator:
        for permission_set in page["PermissionSets"]:
            yield permission_set


def generate_accounts():
    """
    Generates accounts.
    """
    client = boto3.client("organizations")
    paginator = client.get_paginator("list_accounts")
    page_iterator = paginator.paginate()
    for page in page_iterator:
        for account in page["Accounts"]:
            yield account["Id"], account["Name"]


if __name__ == "__main__":
    main()
