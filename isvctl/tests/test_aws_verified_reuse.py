# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: LicenseRef-NvidiaProprietary

# NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
# property and proprietary rights in and to this material, related
# documentation and any modifications thereto. Any use, reproduction,
# disclosure or distribution of this material and related documentation
# without an express license agreement from NVIDIA CORPORATION or
# its affiliates is strictly prohibited.

"""Tests for AWS common/ec2.py verified-reuse guards (oracle gap U2).

``create_key_pair`` and ``create_security_group`` previously accepted any
existing-by-name resource as a success without verifying the shape matched
what the caller asked for. These tests verify that reuse is now gated on
the suite's ownership tag and the documented invariants (description /
SSH ingress rule).
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

_COMMON_DIR = Path(__file__).resolve().parents[1] / "configs" / "providers" / "aws" / "scripts"
if str(_COMMON_DIR) not in sys.path:
    sys.path.insert(0, str(_COMMON_DIR))

from common.ec2 import create_key_pair, create_security_group  # noqa: E402


def _client_error(code: str, message: str = "error") -> ClientError:
    """Build a ClientError with a specific AWS Error.Code."""
    return ClientError({"Error": {"Code": code, "Message": message}}, "op")


_ISV_TAGS = [{"Key": "Name", "Value": "k1"}, {"Key": "CreatedBy", "Value": "isvtest"}]
_OTHER_TAGS = [{"Key": "Name", "Value": "k1"}, {"Key": "CreatedBy", "Value": "someone-else"}]
_NO_TAGS: list[dict[str, str]] = []


class TestCreateKeyPairVerifiedReuse:
    """create_key_pair must refuse to adopt keys it didn't create."""

    def test_reuses_existing_key_when_tagged_and_file_present(self, tmp_path: Path) -> None:
        """Verified reuse: AWS key has suite tag + local PEM exists."""
        key_file = tmp_path / "k1.pem"
        key_file.write_text("-----BEGIN RSA PRIVATE KEY-----\nstub\n-----END RSA PRIVATE KEY-----")
        ec2 = MagicMock()
        ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "k1", "Tags": _ISV_TAGS}]}

        result = create_key_pair(ec2, "k1", key_dir=tmp_path)

        assert result == str(key_file)
        ec2.create_key_pair.assert_not_called()
        ec2.delete_key_pair.assert_not_called()

    def test_raises_when_existing_key_missing_isv_tag(self, tmp_path: Path) -> None:
        """Refuse to adopt a key some other caller created."""
        (tmp_path / "k1.pem").write_text("stub")
        ec2 = MagicMock()
        ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "k1", "Tags": _OTHER_TAGS}]}

        with pytest.raises(RuntimeError, match="not tagged CreatedBy=isvtest"):
            create_key_pair(ec2, "k1", key_dir=tmp_path)
        ec2.create_key_pair.assert_not_called()
        ec2.delete_key_pair.assert_not_called()

    def test_raises_when_existing_key_has_no_tags(self, tmp_path: Path) -> None:
        """Missing tag block is treated the same as wrong tag."""
        (tmp_path / "k1.pem").write_text("stub")
        ec2 = MagicMock()
        ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "k1", "Tags": _NO_TAGS}]}

        with pytest.raises(RuntimeError, match="not tagged"):
            create_key_pair(ec2, "k1", key_dir=tmp_path)

    def test_recreates_when_tagged_but_local_file_missing(self, tmp_path: Path) -> None:
        """Tag matches but PEM missing — delete and recreate (ours, unrecoverable)."""
        ec2 = MagicMock()
        ec2.describe_key_pairs.return_value = {"KeyPairs": [{"KeyName": "k1", "Tags": _ISV_TAGS}]}
        ec2.create_key_pair.return_value = {
            "KeyMaterial": "-----BEGIN RSA PRIVATE KEY-----\nnew\n-----END RSA PRIVATE KEY-----"
        }

        result = create_key_pair(ec2, "k1", key_dir=tmp_path)

        ec2.delete_key_pair.assert_called_once_with(KeyName="k1")
        ec2.create_key_pair.assert_called_once()
        assert Path(result).exists()

    def test_creates_fresh_when_no_existing_key(self, tmp_path: Path) -> None:
        """No prior key on AWS → normal create path."""
        ec2 = MagicMock()
        ec2.describe_key_pairs.side_effect = _client_error("InvalidKeyPair.NotFound")
        ec2.create_key_pair.return_value = {
            "KeyMaterial": "-----BEGIN RSA PRIVATE KEY-----\nfresh\n-----END RSA PRIVATE KEY-----"
        }

        result = create_key_pair(ec2, "k1", key_dir=tmp_path)

        ec2.create_key_pair.assert_called_once()
        assert Path(result).exists()


_EXPECTED_DESC = "ISV validation security group"
_EXPECTED_INGRESS = [
    {
        "IpProtocol": "tcp",
        "FromPort": 22,
        "ToPort": 22,
        "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}],
    }
]


class TestCreateSecurityGroupVerifiedReuse:
    """create_security_group must refuse to adopt SGs with the wrong shape."""

    def test_creates_fresh_when_no_duplicate(self) -> None:
        """No existing SG → normal create path."""
        ec2 = MagicMock()
        ec2.create_security_group.return_value = {"GroupId": "sg-new"}

        assert create_security_group(ec2, "vpc-1", "sg1") == "sg-new"
        ec2.authorize_security_group_ingress.assert_called_once()

    def test_reuses_verified_existing_sg(self) -> None:
        """Verified reuse: tag + description + SSH rule all match."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("InvalidGroup.Duplicate")
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-existing",
                    "Description": _EXPECTED_DESC,
                    "Tags": _ISV_TAGS,
                    "IpPermissions": _EXPECTED_INGRESS,
                }
            ]
        }

        assert create_security_group(ec2, "vpc-1", "sg1") == "sg-existing"
        # Did NOT authorize ingress on reuse — the rule already exists.
        ec2.authorize_security_group_ingress.assert_not_called()

    def test_raises_on_duplicate_missing_isv_tag(self) -> None:
        """Reject reuse when the SG lacks the suite's ownership tag."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("InvalidGroup.Duplicate")
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-foreign",
                    "Description": _EXPECTED_DESC,
                    "Tags": _OTHER_TAGS,
                    "IpPermissions": _EXPECTED_INGRESS,
                }
            ]
        }
        with pytest.raises(RuntimeError, match="not tagged CreatedBy=isvtest"):
            create_security_group(ec2, "vpc-1", "sg1")

    def test_raises_on_duplicate_with_wrong_description(self) -> None:
        """Reject reuse when the description doesn't match the caller's."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("InvalidGroup.Duplicate")
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-desc-mismatch",
                    "Description": "something else",
                    "Tags": _ISV_TAGS,
                    "IpPermissions": _EXPECTED_INGRESS,
                }
            ]
        }
        with pytest.raises(RuntimeError, match="description differs"):
            create_security_group(ec2, "vpc-1", "sg1", description=_EXPECTED_DESC)

    def test_raises_on_duplicate_missing_ssh_rule(self) -> None:
        """Reject reuse when the required SSH ingress rule is absent."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("InvalidGroup.Duplicate")
        ec2.describe_security_groups.return_value = {
            "SecurityGroups": [
                {
                    "GroupId": "sg-no-ssh",
                    "Description": _EXPECTED_DESC,
                    "Tags": _ISV_TAGS,
                    "IpPermissions": [
                        {
                            "IpProtocol": "tcp",
                            "FromPort": 443,
                            "ToPort": 443,
                            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        }
                    ],
                }
            ]
        }
        with pytest.raises(RuntimeError, match="missing the required SSH ingress"):
            create_security_group(ec2, "vpc-1", "sg1")

    def test_raises_on_duplicate_but_describe_empty(self) -> None:
        """API race: duplicate error but describe returns nothing — raise the
        original ClientError rather than swallow silently."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("InvalidGroup.Duplicate")
        ec2.describe_security_groups.return_value = {"SecurityGroups": []}
        with pytest.raises(ClientError):
            create_security_group(ec2, "vpc-1", "sg1")

    def test_propagates_non_duplicate_client_error(self) -> None:
        """Non-duplicate errors propagate unchanged."""
        ec2 = MagicMock()
        ec2.create_security_group.side_effect = _client_error("AccessDenied")
        with pytest.raises(ClientError):
            create_security_group(ec2, "vpc-1", "sg1")


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
