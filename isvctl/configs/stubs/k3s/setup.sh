#!/bin/bash
# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

# k3s Inventory Stub - Queries local k3s cluster
#
# Requirements:
#   - k3s installed and running
#   - kubectl or k3s kubectl available
#   - KUBECONFIG set or /etc/rancher/k3s/k3s.yaml readable

set -eo pipefail

# Detect kubectl command
if command -v kubectl &> /dev/null; then
    KUBECTL="kubectl"
elif command -v k3s &> /dev/null; then
    KUBECTL="k3s kubectl"
else
    echo "Error: Neither kubectl nor k3s found" >&2
    exit 1
fi

# Set KUBECONFIG for k3s if not already set and default config exists
if [ -z "$KUBECONFIG" ] && [ -f /etc/rancher/k3s/k3s.yaml ]; then
    export KUBECONFIG=/etc/rancher/k3s/k3s.yaml
fi

CLUSTER_NAME="k3s-$(hostname)"
USE_NVIDIA_SMI_FALLBACK="true"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/../common/k8s_common.sh"
