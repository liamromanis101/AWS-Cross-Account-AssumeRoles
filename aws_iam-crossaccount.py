import boto3
from botocore.exceptions import ClientError

def get_account_id():
     """Returns the current AWS account ID."""
     sts = boto3.client("sts")
     return sts.get_caller_identity()["Account"]

def is_cross_account(principal_arn, local_account_id):
     """Returns True if the principal ARN belongs to a different AWS account."""
     if ":iam::" in principal_arn:
         principal_account = principal_arn.split(":")[4]
         return principal_account != local_account_id
     return False

def check_conditions(statement):
     """Checks for the presence of ExternalId and MFA in the trust policy condition."""
     conditions = statement.get("Condition", {})
     external_id_present = (
         "StringEquals" in conditions and "sts:ExternalId" in conditions["StringEquals"]
     )
     mfa_present = (
         ("Bool" in conditions and "aws:MultiFactorAuthPresent" in conditions["Bool"]) or
         ("BoolIfExists" in conditions and "aws:MultiFactorAuthPresent" in conditions["BoolIfExists"])
     )
     return external_id_present, mfa_present

def get_lambda_roles():
     """Returns a set of IAM role ARNs used by Lambda functions across all regions."""
     ec2 = boto3.client("ec2", region_name="us-east-1")  # Required for describe_regions
     lambda_roles = set()
     denied_regions = []

     try:
         regions = [r["RegionName"] for r in ec2.describe_regions()["Regions"]]
     except Exception as e:
         print(f"Failed to retrieve regions: {e}")
         return lambda_roles, denied_regions

     for region in regions:
         try:
             lambda_client = boto3.client("lambda", region_name=region)
             paginator = lambda_client.get_paginator("list_functions")
             for page in paginator.paginate():
                 for fn in page["Functions"]:
                     if "Role" in fn:
                         lambda_roles.add(fn["Role"])
         except ClientError as e:
             if e.response["Error"]["Code"] == "AccessDeniedException":
                 denied_regions.append(region)
             else:
                 print(f"Error in region {region}: {e}")
         except Exception as e:
             print(f"Skipping region {region} due to unexpected error: {e}")

     return lambda_roles, denied_regions

def main():
     iam = boto3.client('iam')
     account_id = get_account_id()
     lambda_roles, lambda_denied_regions = get_lambda_roles()
     findings = []
     permission_issues = []

     try:
         roles = iam.list_roles()["Roles"]
     except ClientError as e:
         print(f"❌ Could not list IAM roles: {e}")
         return

     for role in roles:
         role_name = role["RoleName"]
         role_arn = role["Arn"]
         trust_policy = role.get("AssumeRolePolicyDocument", {})

         for statement in trust_policy.get("Statement", []):
             effect = statement.get("Effect")
             principal = statement.get("Principal", {})
             action = statement.get("Action")

             if effect != "Allow" or "AWS" not in principal:
                 continue

             principals = principal["AWS"]
             if isinstance(principals, str):
                 principals = [principals]

             for principal_arn in principals:
                 if is_cross_account(principal_arn, account_id):
                     external_id_present, mfa_present = check_conditions(statement)

                     if not external_id_present and not mfa_present:
                         # Defaults
                         used_by_ec2 = "Unknown (Insufficient Permissions)"
                         used_by_lambda = "Unknown"
                         has_inline_policies = "Unknown (Insufficient Permissions)"
                         has_managed_policies = "Unknown (Insufficient Permissions)"

                         # Check EC2 usage
                         try:
                             instance_profiles = iam.list_instance_profiles_for_role(RoleName=role_name)
                             used_by_ec2 = len(instance_profiles.get("InstanceProfiles", [])) > 0
                         except ClientError as e:
                             if e.response["Error"]["Code"] == "AccessDenied":
                                 permission_issues.append(f"IAM: list_instance_profiles_for_role on {role_name}")
                         except Exception:
                             pass

                         # Check Lambda usage
                         try:
                             used_by_lambda = role_arn in lambda_roles
                         except Exception:
                             used_by_lambda = "Unknown"

                         # Check inline policies
                         try:
                             inline_policies = iam.list_role_policies(RoleName=role_name)
                             has_inline_policies = len(inline_policies.get("PolicyNames", [])) > 0
                         except ClientError as e:
                             if e.response["Error"]["Code"] == "AccessDenied":
                                 permission_issues.append(f"IAM: list_role_policies on {role_name}")

                         # Check managed policies
                         try:
                             managed_policies = iam.list_attached_role_policies(RoleName=role_name)
                             has_managed_policies = len(managed_policies.get("AttachedPolicies", [])) > 0
                         except ClientError as e:
                             if e.response["Error"]["Code"] == "AccessDenied":
                                 permission_issues.append(f"IAM: list_attached_role_policies on {role_name}")

                         findings.append({
                             "RoleName": role_name,
                             "Principal": principal_arn,
                             "ExternalId": external_id_present,
                             "MFA": mfa_present,
                             "FindingValid": True,
                             "UsedByEC2": used_by_ec2,
                             "UsedByLambda": used_by_lambda,
                             "HasInlinePolicies": has_inline_policies,
                             "HasManagedPolicies": has_managed_policies,
                             "Reason": "Valid: Role allows cross-account AssumeRole without ExternalId or MFA"
                         })

     # Print findings
     if findings:
         print("\n❗ Valid Cross-Account AssumeRole Findings:\n")
         for f in findings:
             print(f"- Role: {f['RoleName']}")
             print(f"  Trusted Principal: {f['Principal']}")
             print(f"  ExternalId Present: {f['ExternalId']}")
             print(f"  MFA Condition Present: {f['MFA']}")
             print(f"  ✅ Finding Valid: {f['FindingValid']} — {f['Reason']}")
             print(f"  Used by EC2: {f['UsedByEC2']}")
             print(f"  Used by Lambda: {f['UsedByLambda']}")
             print(f"  Inline Policies Present: {f['HasInlinePolicies']}")
             print(f"  Managed Policies Present: {f['HasManagedPolicies']}")
             print("")
     else:
         print("✅ No valid cross-account AssumeRole vulnerabilities found.")

     # Report permission issues
     if permission_issues:
         print("\n⚠️  Permission issues encountered with specific IAM role queries:")
         for issue in set(permission_issues):
             print(f"- {issue}")

     if lambda_denied_regions:
         print("\n⚠️  Could not access Lambda in the following regions:")
         for region in lambda_denied_regions:
             print(f"- {region}")

if __name__ == "__main__":
     main()
