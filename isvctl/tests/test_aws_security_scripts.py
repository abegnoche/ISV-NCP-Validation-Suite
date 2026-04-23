# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Tests for AWS security reference scripts."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ISVCTL_ROOT = Path(__file__).resolve().parents[1]
AWS_SECURITY_SCRIPTS = ISVCTL_ROOT / "configs" / "providers" / "aws" / "scripts" / "security"


def _load_security_script(script_name: str) -> ModuleType:
    """Load an AWS security script as a module for direct helper testing."""
    script_path = AWS_SECURITY_SCRIPTS / script_name
    spec = importlib.util.spec_from_file_location(f"test_{script_path.stem}", script_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeEksClient:
    """Small fake for the EKS client calls used by api_endpoint_test."""

    def __init__(self, cluster_configs: dict[str, dict[str, Any]]) -> None:
        """Store fake cluster configs keyed by cluster name."""
        self.cluster_configs = cluster_configs

    def list_clusters(self) -> dict[str, list[str]]:
        """Return fake cluster names."""
        return {"clusters": list(self.cluster_configs)}

    def describe_cluster(self, name: str) -> dict[str, dict[str, dict[str, Any]]]:
        """Return fake cluster config for a cluster name."""
        return {"cluster": {"resourcesVpcConfig": self.cluster_configs[name]}}


def _patch_eks_client(monkeypatch: pytest.MonkeyPatch, module: ModuleType, eks: FakeEksClient) -> None:
    """Patch boto3.client to return a fake EKS client."""

    def fake_client(service_name: str, region_name: str | None = None) -> FakeEksClient:
        """Return the fake EKS client for EKS requests."""
        assert service_name == "eks"
        assert region_name == "us-west-2"
        return eks

    monkeypatch.setattr(module.boto3, "client", fake_client)


def test_eks_private_check_fails_public_private_cluster_with_world_open_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dual endpoint EKS clusters still fail when public access is world-open."""
    module = _load_security_script("api_endpoint_test.py")
    eks = FakeEksClient(
        {
            "wide-open": {
                "endpointPublicAccess": True,
                "endpointPrivateAccess": True,
                "publicAccessCidrs": ["0.0.0.0/0"],
            }
        }
    )
    _patch_eks_client(monkeypatch, module, eks)

    result = module._check_eks_private("us-west-2")

    assert result["passed"] is False
    assert "open to the internet" in result["error"]


def test_eks_private_check_accepts_dual_endpoint_with_restricted_public_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Dual endpoint EKS clusters pass when public CIDRs are restricted."""
    module = _load_security_script("api_endpoint_test.py")
    eks = FakeEksClient(
        {
            "restricted": {
                "endpointPublicAccess": True,
                "endpointPrivateAccess": True,
                "publicAccessCidrs": ["203.0.113.0/24"],
            }
        }
    )
    _patch_eks_client(monkeypatch, module, eks)

    result = module._check_eks_private("us-west-2")

    assert result["passed"] is True


def test_eks_private_check_fails_public_only_cluster_even_with_restricted_cidr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public-only EKS clusters fail even if public CIDRs are restricted."""
    module = _load_security_script("api_endpoint_test.py")
    eks = FakeEksClient(
        {
            "public-only": {
                "endpointPublicAccess": True,
                "endpointPrivateAccess": False,
                "publicAccessCidrs": ["203.0.113.0/24"],
            }
        }
    )
    _patch_eks_client(monkeypatch, module, eks)

    result = module._check_eks_private("us-west-2")

    assert result["passed"] is False
    assert "public-only" in result["error"]


class FakeIamTags:
    """Small fake for IAM list_user_tags responses."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        """Store responses returned by list_user_tags."""
        self.responses = responses

    def list_user_tags(self, **kwargs: Any) -> dict[str, Any]:
        """Return the next fake list_user_tags response."""
        assert kwargs["UserName"] == "isv-sa-test-1234"
        return self.responses.pop(0)


def test_teardown_only_treats_created_by_isvtest_users_as_owned() -> None:
    """Teardown ownership requires the CreatedBy=isvtest tag."""
    module = _load_security_script("teardown.py")
    iam = FakeIamTags([{"Tags": [{"Key": "CreatedBy", "Value": "isvtest"}], "IsTruncated": False}])

    assert module._user_has_isvtest_tag(iam, "isv-sa-test-1234") is True


def test_teardown_does_not_treat_prefix_only_users_as_owned() -> None:
    """A matching username prefix is not enough to delete a user."""
    module = _load_security_script("teardown.py")
    iam = FakeIamTags([{"Tags": [{"Key": "CreatedBy", "Value": "someone-else"}], "IsTruncated": False}])

    assert module._user_has_isvtest_tag(iam, "isv-sa-test-1234") is False


def test_teardown_checks_paginated_user_tags() -> None:
    """Ownership checks scan paginated IAM user tags."""
    module = _load_security_script("teardown.py")
    iam = FakeIamTags(
        [
            {"Tags": [{"Key": "Name", "Value": "validation"}], "IsTruncated": True, "Marker": "next"},
            {"Tags": [{"Key": "CreatedBy", "Value": "isvtest"}], "IsTruncated": False},
        ]
    )

    assert module._user_has_isvtest_tag(iam, "isv-sa-test-1234") is True
