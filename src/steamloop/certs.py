"""Embedded client certificates for thermostat mTLS authentication."""

from __future__ import annotations

import base64
import ssl
import tempfile
import zlib
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass

# Primary client cert + key (zlib compressed, base64 encoded)
_PRIMARY_CHAIN = (
    "eNptVcnSszgSvPMUfSc6DGb1oQ8SO5h9MXBjX81izGKefvx/PTPdEz26SCpVKFJZWanff/8OKEiK"
    "8RsnOJ4iKhzwhF/B3xFdUfi+5Tgw0BXYFQgqBWo8MGDVzXXXSLcdg8BeRMDDXLeXnbMjPrBtSdjV"
    "wD+FENGhLwHcF7hqN90HNcSheqbXY7kHap0+7UM8QQArI4Bg0fmuX+Nr8MmutyXlcDd6UB2iO/su"
    "VT+38jw03PR6wxTBWJIHXueSX9kBVL97qEMy5D2B0j1hN9qf+dT7MUR4T8d+BfW/gnvoCXcddD/I"
    "YK1zQaD/Dcn4P0iQ/0DRnWwX/3zfnQeUmj7zPhuMLZX2t/8U15gXMh2OP5eCfff8523LOcgjqdS/"
    "o9DpFUG0XRfytvcl1FV23o5UbYyVessMYAsQ2oCvKsEC/PfcHrnvGgI9+yDJHDU0z8Y7uUJW0xr7"
    "MqLH5d1bruzjbMUtHRUx9YdlcTm/1G2+SGAMaC30m1myXFNECBt8aqEDMmOsVjb77fYsqCR8dq1l"
    "uc2HN+E8jHkVZaHEqfYiC025q3ElAVpJ9ab0kJ6hRd7UomJ4UlxE3ZNgFNscfWnnS58lMG/+hPqw"
    "yQRUFlc3dnSHehWbFKAq5TIBZSLuaVQc+brMtHxdUREE2RI/n1tSoN7n0DE3qhleJpO5lYWPuAdi"
    "RG4M7q5XrgslEl1qxJhrJ3cxAR2mTTkyYrM168K/dagscXD68i7XwmsML1b3jB1ZRcu20DjMNrks"
    "EQMUzsh5XnjCLLXx2EJUuLGlz3JgFwBIjFoX2Z0H39I6mAds+QKBsgMemL/0INssBCUrIN9acICu"
    "duXPxP4nEUa7CCJF26Nv+Xz52yMSx335t30R7vpXldgvPeR8ZT8QCB3G62AlubdeYWfvxt5LXuNw"
    "GSufWPt/mgqYXx0IYDiizDJyDcE9QomuW/G4E+lNPKV+3O7tBaB+tUiSSH3o03+m11xrtVSktyq6"
    "eI/oVEmVYFpC9x0PUVK1GjqHnkxljy26mmi2/pD3FWTZi1nIx0TG6MfkO/KDhZL1dM2GxL40lbPs"
    "saTTyEgsDFpXSgAeuZsRHeGyqcG9dNSgknHOlIr0HbEJrIo6/ZPLs9S7WTefAdf8CX3+5ZzIpB74"
    "YaAqq3akGtNNe1i5uSzYYW+sO6E3I6/N23L2cJa6jfbTAx8Jv4N3IFLXtTJWxMj1ks+V/eNW10u6"
    "lUfex5RCg1MvCuAnN/bGnpJKQoqmvUB8FLwhJes8uC/1hLIGUUR+rpRzPfJWVD0W/PEH8uN0gsH/"
    "0/1+/8sZLUcJvvHfNCH6rzMK2y9H/IcbCt/CuRzUur2q3B5UX4mN3zybl/Xn/FTW6iJl5h2pSq4Z"
    "O4u2lpKJPazGjVIBL9V8mGS2WYZDlGREpLDSxKLpcWWuW6ytcwzoo6MCiJ5I2hJarzDUsD56alLO"
    "ExuX6qySiZYjSRaPqvHv8FAGlntEsDIb6VQGjCrQ2j6bpzxRyGo/TffaJzAiyvmz0KdWV9oL18oe"
    "RAO06iPtnr4nFAnxOvqyKfwVL7xuOSOwahd6rZHba6ttMbxL8fS6DlvHLp4hPJViP1BpHo9DrzPR"
    "eZh39Oa/3tUkHqv1Urxk9EP/Da2JRtKPHhoMxrWXnfGAe5eCDIcsJB2NFi8npT5951MOJNFUb4Gv"
    "BqkOyipZ2Mt+O4fPrKcIfqmtUsYtUOkQAOGXZQL5ZGqXIQsAyqaVCyMlAr+WnG5u1M2ScrNLumTY"
    "UEFqiAkJzSgvw05Zo0+SDXR8MaV6ClsHTYkP1nDJVVLncnWK2epem6Zcrft4sYUdQ+99sycvDyE1"
    "5Si/QhsYrJ1lTIXGxzIjYDmPtxo1coQLbCKpl9cwve00w/llxonnjYyig7kpAeMi2OZZ9rPvW1qn"
    "h2tgrCcRUDnn7NtKVVCkht22I4B1SYXZ6guKdtcJRXke5GUPlA0/Ee2mf9nUqlcYLWSWv0JSq6dI"
    "SOnx3TmBeH/Y1tdL866YcIYy+aQWaNC9uanBI0tnmwwJeINBF4m5s+TKEE4bxp47qSoa5/N6tSeq"
    "T4RQmq8RsDVY2TxLkY9BeOEtb76ZzVpwBLSBm5KP1JXfG+j8rWSOB2wOvVkSnV5sbGq4mpuHW9p+"
    "FJ/so4/saywBDm2oCec2HsiF6Pd94dvh7TyUWZpJ88iVU3WwGKZXY9oFNlf7ZCkqOmLvVtSMYslH"
    "sfA+S/+mJwBHctm+XrHPIb20dJtMbMO+L3swxrn/QFbHabS9qI31TQ+tLZdcN9Hess64+giuFu8j"
    "HSFFN/DCt6tdNzxaWDlZLudb/IRzBmxU8FCMJfkDMACQGeDJDoPkStaBcrqNdxUS5BHb/u15JayB"
    "naP1sE+37R4Zzjy3uayHmA43YxjAdI7rcc+skSMZ8WJQhfPCziE5LhBp7kSyNwlZ/cly/G27fUma"
    "jyRGoZzmoVbdyUCOXkfpoKfDUwUx+cyhABb4OBA/FVJEr3dmKh3Gz3gmwDCU+ikP/H1pW8NM65Zp"
    "Yfp5419he/tmsvbUKSn0sEV94tVZBBOi4O1A12A3Pay/lhaazKvRsd4IxgJryD2jibcPjAZVjiW9"
    "TnJdo1nfES2J/iDmPKR4Kx5QdW2fYXwPiANjex+qtM2d6lvpwOLeSgLfAOXYDCWwxJJ5kfqkL3dS"
    "wYUOjQSkK/COkVSRqOvyjvuPgg7jxOg9SszI+z3QUpqXFcmc8iM0NfR+dzfbptNJVYLMJx6hiKip"
    "LZBhNPQiKNiyZuYRk/jVeWAUvMVMNBTBlmn6NvybZEcL2Lch7ZWnpHgpOioyisOm3VqFGIRpyoq7"
    "dxE/5WNA3cdZXH0NrjNaL7elyl0FrvlzyEbcK0T9IZ8ypxiYgCxkqRj6GlfZib8YF3c6K2iKtzPq"
    "XlXyRLvc2s4w9OJxCC0jOmTH3OMXyWxZYBuRqNTIM4NaOgYWYLyIMOD1ET8Wy1Nxo/r7X/WP/+hf"
    "XPHJPg=="
)

# Secondary client cert + key (zlib compressed, base64 encoded)
_SECONDARY_CHAIN = (
    "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"
    "BNI9+NefT9H/fG7+DWdR0uU="
)

# Secondary root CA (zlib compressed, base64 encoded)
_SECONDARY_ROOT_CA = (
    "eNrNlMvOs0YMhvdcRffRLw6BJCy6mIEBBkLIhDM7jkNCDiRAJnD1zfdXqlT1Burla8uW/dj+9etr"
    "EJn48IeGTgE2sAYC9CP+4lyMdWnRNDB4FDAMAcXQCcAB0u7ZdmdTZQIEZDCADieXDEwjqR4RYiJm"
    "R+GCEs6FoQnEEGmUeX6s3LPEXgrpM+wjuy1u5GMsIIL0EEEwuHp3nTIpmktJHQpN9NNY6TjXF5jD"
    "fmfVde0UljdjynwY5mY0F7G6VKYhYMN+F2tCifTpi9gQvn4Yoo4SATHOasuDG3TM04H8LSF4AZbj"
    "H20hP5rwj3b537ZAKTq7QDA1/2n6uFjrBH2nHgIgY6gzwL5+Bzy+dIgO2NDdxfyYlPReN9ZzvQtw"
    "zDGwKsrj0TfTcnTZzUwrs/BdNeW3YiQr95zkt4rm6SHWAbG2ebwUwLkZm9p6CO1Fxhmn70PVX/BB"
    "f79PTmgFr9Yva3dbduqudlb0Plb26J3f/G6vZiPKN+3rljF+LI4vCXrbZs2FsrXSdnFKHHxqL5d6"
    "yg/F1gbVXXPn9TSm1XvcSCdwGZbZDrocN5in0d7F5LzKcK9AjuycdVm8n8/FYDgfz/w5LFev90V1"
    "SNzW3XZ1jRam61NMn14yekm9LxL4SHpVgcLlc9C5x+lF0nLlH92yYH1Zq4eMP2iSR061gbtq90jX"
    "mjYakyOW+yKeGnNvqUOvrj61gm9lI3KAuhAA80JTl9EUMB18kZ6E4DsyHgLMgA68nz2wyA6CZvdF"
    "5Gogl5lFfsd5HIQpMpxlhpmQkhZ4n/6x+M+NQHD8nroq+Yb/LFplf/HyjMQuJKamDeYXtQGZq3GQ"
    "0hekyICk1EEAmt/VfBeZOogp9IcdjSsTYaIPee4Kz2lEmvHa9la0/H2x3L9OFngaIAiMSoysNZV2"
    "9S29b9DTleYALnFW1HqTjK3brjZdbqK01rcFJ3T+mXyUtG5mkvc7JD/obKeJHHinsLO7l5qAVMqV"
    "8oaDl8zSc08bOGvLjMSLRjcPi8uW/npltB688Vwppf+SHtK43F+z1Lp8pYrdUJiW5b6WeWmGZq+/"
    "k5C/e7UMlWg/OFjkNITkVxvuvY+6zvJxZ68Emk/2rdtG/eqaNbaFa3QN9X133IpJcjF9oVGGq8/W"
    "PK8G3YMbrWiwPuDdoJMzzIelraJH7g3l4AzYFNPR3B2qzewBQ6vvtb20eXv2qks18ad9r03ym7sc"
    "r/HIW+sgPA4xUGKtu7KtNAR22d43lShO5y3/fJe9Rf/8k/v9RtFB/+9r/QuNPsOH"
)


def _decode(data: str) -> bytes:
    """Decode a zlib-compressed, base64-encoded PEM blob."""
    return zlib.decompress(base64.b64decode(data))


@contextmanager
def _pem_path(data: bytes) -> Generator[str, None, None]:
    """
    Yield a file path containing PEM data, cleaned up on exit.

    ssl.SSLContext.load_cert_chain() only accepts file paths — there is no
    in-memory (cadata) variant for client certs in Python's ssl module.
    """
    with tempfile.NamedTemporaryFile(suffix=".pem") as f:
        f.write(data)
        f.flush()
        yield f.name


@dataclass(frozen=True)
class CertSet:
    """A set of client certificates for mTLS authentication."""

    name: str
    chain_data: str
    root_ca_data: str | None = None


def create_ssl_context(cert_set: CertSet) -> ssl.SSLContext:
    """
    Create an SSL context configured for thermostat mTLS.

    Decodes the embedded cert data and loads it via load_cert_chain().
    A brief temp file is used because ssl.SSLContext.load_cert_chain()
    only accepts file paths.
    """
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Thermostat only supports TLSv1.2 — TLS 1.3 ClientHello causes it to
    # drop the connection with EOF during handshake.
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    # Lower security level to allow older ciphers the thermostat requires
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    # Enable legacy server connect for older TLS implementations
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)

    chain_pem = _decode(cert_set.chain_data)
    with _pem_path(chain_pem) as chain_path:
        ctx.load_cert_chain(certfile=chain_path)

    if cert_set.root_ca_data is not None:
        root_pem = _decode(cert_set.root_ca_data)
        ctx.load_verify_locations(cadata=root_pem.decode("ascii"))

    return ctx


CERT_SETS = [
    CertSet(
        name="primary",
        chain_data=_PRIMARY_CHAIN,
    ),
    CertSet(
        name="secondary",
        chain_data=_SECONDARY_CHAIN,
        root_ca_data=_SECONDARY_ROOT_CA,
    ),
]
