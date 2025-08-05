# AWS Cross-Account IAM Role Trust Policy Audit

This Python script identifies potentially insecure IAM role trust policies in your AWS environment. Specifically, it detects roles that allow **cross-account `AssumeRole` access** without enforcing
**ExternalId** or **MFA**, which can pose a security risk.

---

## 🔍 What It Does

- Scans all IAM roles in the AWS account.
- Checks each role's trust policy for:
   - External principals (other AWS accounts).
   - Absence of `ExternalId` and `MFA` conditions.
- Flags roles as valid findings if:
   - Trusts a different AWS account.
   - Does **not** enforce `ExternalId` **or** `MFA`.
- Additionally checks:
   - If the role is used by EC2 instance profiles.
   - If the role is used by Lambda functions (across **all AWS regions**).
   - Whether inline or managed policies are attached.
- Gracefully handles permission errors and reports them at the end.

---

## ✅ Example Output

```
❗ Valid Cross-Account AssumeRole Findings:

- Role: CrossAccountAuditRole
   Trusted Principal: arn:aws:iam::111122223333:root
   ExternalId Present: False
   MFA Condition Present: False
   ✅ Finding Valid: True — Valid: Role allows cross-account AssumeRole without ExternalId or MFA
   Used by EC2: True
   Used by Lambda: False
   Inline Policies Present: False
   Managed Policies Present: True

⚠️  Permission issues encountered with specific IAM role queries:
- IAM: list_instance_profiles_for_role on SomeRestrictedRole

⚠️  Could not access Lambda in the following regions:
- ap-south-1
- af-south-1
```

---

## 🧰 Requirements

- Python 3.7+
- AWS credentials with the following permissions:
   - `iam:ListRoles`
   - `iam:GetRole`
   - `iam:ListRolePolicies`
   - `iam:ListAttachedRolePolicies`
   - `iam:ListInstanceProfilesForRole`
   - `lambda:ListFunctions` (for each region)
   - `ec2:DescribeRegions`
- The `boto3` Python package

---

## 📦 Installation

```bash
git clone https://github.com/liamromanis101/AWS-Cross-Account-AssumeRoles
cd AWS-Cross-Account-AssumeRoles
pip install boto3
```

Ensure your AWS credentials are configured via:

- `~/.aws/credentials`
- Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,etc.)
- IAM role (if running in an AWS environment)

---

## 🚀 Usage

```bash
python3 aws-iam_crossaccount.py
```

Output is printed to the terminal. You can redirect it to a file if
needed:

```bash
python3 aws-iam_crossaccount.py > audit_results.txt ```

---

## 💡 Notes

- Script dynamically queries **all available AWS regions** for Lambda roles.
- Permission errors (e.g., `AccessDenied`) are caught and listed at the end of the output.
- You may enhance the script to **whitelist trusted AWS account IDs** (e.g., in the same AWS Organization) if those roles are not considered risky in your environment.

---

## 🛡️ Security Considerations

This script is useful for identifying trust relationships in IAM roles
that:

- Allow access from unknown or untrusted AWS accounts.
- Lack ExternalId or MFA enforcement, which can allow abuse if credentials are compromised.
- Helps meet security compliance requirements such as CIS AWS Foundations Benchmark or internal audit standards.

---
