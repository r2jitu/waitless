#!/usr/bin/env bash
# deploy-aws.sh — Deploy a unikernel to AWS EC2
#
# Prerequisites:
#   brew install awscli
#   aws configure  (set up access key, secret key, region)
#
# Usage:
#   ./scripts/deploy-aws.sh [name] [path-to-elf]
#
# This script:
#   1. Builds the unikernel (if no ELF path given)
#   2. Creates a bootable raw disk image
#   3. Uploads to S3
#   4. Imports as an AMI via EC2 VM Import
#   5. Launches an EC2 instance
#
# The VM uses a t3.micro instance with ENA (virtio-based) networking.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

NAME="${1:-waitless-webserver}"
ELF="${2:-}"
REGION="${AWS_DEFAULT_REGION:-us-east-1}"
INSTANCE_TYPE="${WAITLESS_EC2_TYPE:-t3.micro}"
BUCKET="${WAITLESS_S3_BUCKET:-${NAME}-images-$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo 'unknown')}"
TIMESTAMP="$(date +%Y%m%d-%H%M%S)"
IMAGE_NAME="${NAME}-${TIMESTAMP}"
DISK_FILE="/tmp/${IMAGE_NAME}.raw"

echo "==> AWS Region: $REGION"
echo "    Instance type: $INSTANCE_TYPE"

# --- Build if needed ---
if [ -z "$ELF" ]; then
    echo "==> Building webserver..."
    cd "$PROJECT_ROOT"
    bazel build //apps/webserver:webserver.elf 2>&1
    ELF="$PROJECT_ROOT/bazel-bin/apps/webserver/webserver.elf"
fi

if [ ! -f "$ELF" ]; then
    echo "Error: ELF not found: $ELF"
    exit 1
fi

# --- Create a bootable raw disk image ---
echo "==> Creating bootable disk image..."

DISK_SIZE_MB=1024 # AWS prefers at least 1GB

# Create the raw disk
dd if=/dev/zero of="$DISK_FILE" bs=1M count=0 seek=$DISK_SIZE_MB 2>/dev/null

if command -v grub-mkrescue &>/dev/null; then
    ISODIR="$(mktemp -d)"
    mkdir -p "$ISODIR/boot/grub"
    cp "$ELF" "$ISODIR/boot/kernel.elf"
    cat >"$ISODIR/boot/grub/grub.cfg" <<'GRUB_EOF'
set timeout=0
set default=0
menuentry "unikernel" {
    multiboot2 /boot/kernel.elf
    boot
}
GRUB_EOF
    grub-mkrescue -o "$DISK_FILE" "$ISODIR" 2>/dev/null
    rm -rf "$ISODIR"
    echo "    Created bootable image with GRUB"
else
    echo "    Warning: grub-mkrescue not found. Creating raw image with embedded ELF."
    dd if="$ELF" of="$DISK_FILE" bs=1M seek=1 conv=notrunc 2>/dev/null
fi

# --- Ensure S3 bucket exists ---
echo "==> Ensuring S3 bucket: s3://$BUCKET"
aws s3 mb "s3://$BUCKET" --region "$REGION" 2>/dev/null || true

# --- Upload to S3 ---
echo "==> Uploading image to S3..."
aws s3 cp "$DISK_FILE" "s3://$BUCKET/${IMAGE_NAME}.raw"

# --- Create VMImport service role (if it doesn't exist) ---
echo "==> Ensuring vmimport service role..."
ROLE_POLICY='{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": { "Service": "vmie.amazonaws.com" },
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": { "sts:Externalid": "vmimport" }
            }
        }
    ]
}'

aws iam create-role \
    --role-name vmimport \
    --assume-role-policy-document "$ROLE_POLICY" 2>/dev/null || true

BUCKET_POLICY=$(
    cat <<EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket"],
            "Resource": ["arn:aws:s3:::${BUCKET}", "arn:aws:s3:::${BUCKET}/*"]
        },
        {
            "Effect": "Allow",
            "Action": ["ec2:ModifySnapshotAttribute", "ec2:CopySnapshot", "ec2:RegisterImage", "ec2:Describe*"],
            "Resource": "*"
        }
    ]
}
EOF
)

aws iam put-role-policy \
    --role-name vmimport \
    --policy-name vmimport-policy \
    --policy-document "$BUCKET_POLICY" 2>/dev/null || true

# --- Import as AMI ---
echo "==> Importing disk image as AMI (this may take several minutes)..."
IMPORT_TASK=$(aws ec2 import-image \
    --description "Waitless ${IMAGE_NAME}" \
    --disk-containers "[{
        \"Description\": \"Waitless root disk\",
        \"Format\": \"raw\",
        \"UserBucket\": {
            \"S3Bucket\": \"${BUCKET}\",
            \"S3Key\": \"${IMAGE_NAME}.raw\"
        }
    }]" \
    --region "$REGION" \
    --query 'ImportTaskId' \
    --output text)

echo "    Import task: $IMPORT_TASK"
echo "    Waiting for import to complete..."

# Poll for completion
while true; do
    STATUS=$(aws ec2 describe-import-image-tasks \
        --import-task-ids "$IMPORT_TASK" \
        --region "$REGION" \
        --query 'ImportImageTasks[0].Status' \
        --output text)

    PROGRESS=$(aws ec2 describe-import-image-tasks \
        --import-task-ids "$IMPORT_TASK" \
        --region "$REGION" \
        --query 'ImportImageTasks[0].Progress' \
        --output text 2>/dev/null || echo "0")

    echo "    Status: $STATUS ($PROGRESS%)"

    if [ "$STATUS" = "completed" ]; then
        break
    elif [ "$STATUS" = "deleted" ] || [ "$STATUS" = "error" ]; then
        MSG=$(aws ec2 describe-import-image-tasks \
            --import-task-ids "$IMPORT_TASK" \
            --region "$REGION" \
            --query 'ImportImageTasks[0].StatusMessage' \
            --output text)
        echo "Error: Import failed: $MSG"
        exit 1
    fi

    sleep 15
done

# Get the AMI ID
AMI_ID=$(aws ec2 describe-import-image-tasks \
    --import-task-ids "$IMPORT_TASK" \
    --region "$REGION" \
    --query 'ImportImageTasks[0].ImageId' \
    --output text)

echo "    AMI: $AMI_ID"

# --- Create security group for HTTP ---
echo "==> Ensuring security group..."
SG_ID=$(aws ec2 describe-security-groups \
    --group-names "waitless-http" \
    --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' \
    --output text 2>/dev/null || echo "")

if [ -z "$SG_ID" ] || [ "$SG_ID" = "None" ]; then
    SG_ID=$(aws ec2 create-security-group \
        --group-name "waitless-http" \
        --description "Allow HTTP for unikernel instances" \
        --region "$REGION" \
        --query 'GroupId' \
        --output text)

    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 80 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"

    aws ec2 authorize-security-group-ingress \
        --group-id "$SG_ID" \
        --protocol tcp \
        --port 22 \
        --cidr 0.0.0.0/0 \
        --region "$REGION"
fi

# --- Launch instance ---
echo "==> Launching EC2 instance..."
INSTANCE_ID=$(aws ec2 run-instances \
    --image-id "$AMI_ID" \
    --instance-type "$INSTANCE_TYPE" \
    --security-group-ids "$SG_ID" \
    --region "$REGION" \
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${NAME}}]" \
    --query 'Instances[0].InstanceId' \
    --output text)

echo "    Instance: $INSTANCE_ID"
echo "    Waiting for instance to be running..."

aws ec2 wait instance-running \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION"

# Get public IP
PUBLIC_IP=$(aws ec2 describe-instances \
    --instance-ids "$INSTANCE_ID" \
    --region "$REGION" \
    --query 'Reservations[0].Instances[0].PublicIpAddress' \
    --output text)

echo ""
echo "========================================="
echo "  Deployment complete!"
echo "========================================="
echo "  Instance: $INSTANCE_ID"
echo "  AMI:      $AMI_ID"
echo "  Region:   $REGION"
echo "  IP:       $PUBLIC_IP"
echo "  URL:      http://$PUBLIC_IP/"
echo ""
echo "  View serial console:"
echo "    aws ec2 get-console-output --instance-id $INSTANCE_ID --region $REGION"
echo ""
echo "  Cleanup:"
echo "    aws ec2 terminate-instances --instance-ids $INSTANCE_ID --region $REGION"
echo "    aws ec2 deregister-image --image-id $AMI_ID --region $REGION"
echo "    aws s3 rm s3://$BUCKET/${IMAGE_NAME}.raw"
echo "========================================="

# Cleanup local temp files
rm -f "$DISK_FILE"
