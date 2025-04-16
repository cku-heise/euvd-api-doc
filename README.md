# Reverse engineered EUVD API Documentation

This is just by looking at the web site, and it's a WIP. More for my personal use, but if I help you not do the same work, all the better.

## Authentication
- none for read requests? At least no authentication headers in XHR
## Return codes
- Seems to return 403 even if request is authorized, but syntactically incorrect (i.e. using float for fromScore)
- 
## Base URL
* https://euvdservices.enisa.europa.eu/api/
## Endpoints
### List Vulnerabilities
* /vulnerabilities
* assigner= (CNA name, like "Linux" or "ENISA") 
* product=
* vendor=
* text=
* fromDate=
* toDate=
* fromScore= (int) [0..10]
* toScore= (int) [0..10]
* fromEpss= (int) [0..100]
* toEpss=100 (int) [0..100]
* exploited= bool
* page=0 (int)
* size=10 (int)

Returns JSON
{
    "items": [
        {
            "id": "EUVD-2025-11154",
            "description": "A vulnerability was found in TOTOLINK A3700R 9.1.2u.5822_B20200513. It has been rated as critical. Affected by this issue is the function setL2tpServerCfg of the file /cgi-bin/cstecgi.cgi. The manipulation leads to improper access controls. The attack may be launched remotely. The exploit has been disclosed to the public and may be used.",
            "datePublished": "Apr 16, 2025, 7:00:16 AM",
            "dateUpdated": "Apr 16, 2025, 7:00:16 AM",
            "baseScore": 6.9,
            "baseScoreVersion": "4.0",
            "baseScoreVector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
            "references": "https://vuldb.com/?id.304964\nhttps://vuldb.com/?ctiid.304964\nhttps://vuldb.com/?submit.551304\nhttps://lavender-bicycle-a5a.notion.site/TOTOLINK-A3700R-setL2tpServerCfg-1cb53a41781f80319d38dc5a8e9174ae?pvs\u003d4\nhttps://www.totolink.net/\n",
            "aliases": "CVE-2025-3675\n",
            "assigner": "VulDB",
            "exploitedSince": "Apr 9, 2025, 12:00:00 AM",
            "epss": 0,
            "enisaIdProduct": [
                {
                    "id": "0d6b229c-1944-3f6f-8359-e1ea8ef9ff80",
                    "product": {
                        "name": "A3700R"
                    },
                    "product_version": "9.1.2u.5822_B20200513"
                }
            ],
            "enisaIdVendor": [
                {
                    "id": "3218b1b4-d0d4-30c3-a604-f8f6cb3f780c",
                    "vendor": {
                        "name": "Totolink"
                    }
                }
            ]
        }
    ],
    "total": 168061
}
### list critical / exploited / last vulns
- /criticalvulnerabilities - convenience API call, alias for ?fromScore=9&toScore=10
- /exploitedvulnerabilities - convenience API call, alias for ?exploited=1
- /lastvulnerabilities - probably convenience API call, alias for some kind of fromDate magic?

### Lookup by EUVD-ID
/enisaid
  ?id=EUVD-2025-11105

Returns JSON
{
    "id": "EUVD-2024-51869",
    "description": "In the Linux kernel, the following vulnerability has been resolved:\n\nALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices\n\nA bogus device can provide a bNumConfigurations value that exceeds the\ninitial value used in usb_get_configuration for allocating dev-\u003econfig.\n\nThis can lead to out-of-bounds accesses later, e.g. in\nusb_destroy_configuration.",
    "datePublished": "Dec 27, 2024, 1:49:39 PM",
    "dateUpdated": "Jan 20, 2025, 6:21:03 AM",
    "baseScore": 0,
    "references": "https://git.kernel.org/stable/c/0b4ea4bfe16566b84645ded1403756a2dc4e0f19\nhttps://git.kernel.org/stable/c/9b8460a2a7ce478e0b625af7c56d444dc24190f7\nhttps://git.kernel.org/stable/c/62dc01c83fa71e10446ee4c31e0e3d5d1291e865\nhttps://git.kernel.org/stable/c/9887d859cd60727432a01564e8f91302d361b72b\nhttps://git.kernel.org/stable/c/920a369a9f014f10ec282fd298d0666129379f1b\nhttps://git.kernel.org/stable/c/b8f8b81dabe52b413fe9e062e8a852c48dd0680d\nhttps://git.kernel.org/stable/c/379d3b9799d9da953391e973b934764f01e03960\nhttps://git.kernel.org/stable/c/b521b53ac6eb04e41c03f46f7fe452e4d8e9bcca\nhttps://git.kernel.org/stable/c/b909df18ce2a998afef81d58bbd1a05dc0788c40\n",
    "aliases": "CVE-2024-53197\n",
    "assigner": "Linux",
    "epss": 0.24,
    "exploitedSince": "Apr 9, 2025, 12:00:00 AM",
    "enisaIdProduct": [
        {
            "id": "09bcc46b-d09e-3cbe-94e3-82742c1082b7",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c9887d859cd60727432a01564e8f91302d361b72b"
        },
        {
            "id": "126851af-d4c6-3475-b02c-d0121a05cfdd",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c9b8460a2a7ce478e0b625af7c56d444dc24190f7"
        },
        {
            "id": "26e27032-27e9-3e8f-bc8e-b27495b03f13",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb8f8b81dabe52b413fe9e062e8a852c48dd0680d"
        },
        {
            "id": "3662685d-9939-3fe5-acb5-591f43687cea",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 0"
        },
        {
            "id": "3dc90042-7629-3c57-8508-895ea1614297",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c379d3b9799d9da953391e973b934764f01e03960"
        },
        {
            "id": "72aacb74-b091-3f5f-87da-79cd61229461",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 6.6.64"
        },
        {
            "id": "825f4d40-4627-3c4b-9abe-01b98a3d021e",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 5.4.287"
        },
        {
            "id": "89dd2f1b-24d9-343e-b41e-a4655f08d329",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 6.12.2"
        },
        {
            "id": "9bd9ec7f-c075-3c31-bd85-d911fb2c3123",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb909df18ce2a998afef81d58bbd1a05dc0788c40"
        },
        {
            "id": "a105d531-acd9-37e3-8b11-60e7cec337a3",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 6.13"
        },
        {
            "id": "a46580c9-240e-3cc1-af9f-f7601c0ad4b5",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 4.19.325"
        },
        {
            "id": "a7f2d5af-b2f1-3f4e-b03a-6f027d02e964",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 6.11.11"
        },
        {
            "id": "ab99fce5-aa08-3cc0-9d4d-249a91323e1e",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c920a369a9f014f10ec282fd298d0666129379f1b"
        },
        {
            "id": "bf727c9a-bf68-3e3b-9866-7f064047e78b",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 6.1.120"
        },
        {
            "id": "c91f283c-2f74-3b6a-9a09-71ade3248d6d",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c62dc01c83fa71e10446ee4c31e0e3d5d1291e865"
        },
        {
            "id": "cd840441-5e33-3654-a7e7-4ed5b886a6c3",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb521b53ac6eb04e41c03f46f7fe452e4d8e9bcca"
        },
        {
            "id": "e08c1321-912a-3ff7-9f6a-10b9b055cfe4",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 5.10.231"
        },
        {
            "id": "e1cb8d69-0063-33d0-85cb-29b84dd69a23",
            "product": {
                "name": "Linux"
            },
            "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c0b4ea4bfe16566b84645ded1403756a2dc4e0f19"
        },
        {
            "id": "e267464a-9c91-3779-8990-4d799abf5ab7",
            "product": {
                "name": "Linux"
            },
            "product_version": "2.6.12"
        },
        {
            "id": "fcb5a8db-5c02-3e05-a270-670de3a2193d",
            "product": {
                "name": "Linux"
            },
            "product_version": "patch: 5.15.174"
        }
    ],
    "enisaIdVendor": [
        {
            "id": "a83d8e62-e256-36d2-89c6-1dccc8aed7b2",
            "vendor": {
                "name": "Linux"
            }
        }
    ],
    "enisaIdVulnerability": [
        {
            "id": "8fa03f98-ee51-3f6b-823a-de10ab9cb1fc",
            "vulnerability": {
                "id": "CVE-2024-53197",
                "description": "In the Linux kernel, the following vulnerability has been resolved:\n\nALSA: usb-audio: Fix potential out-of-bound accesses for Extigy and Mbox devices\n\nA bogus device can provide a bNumConfigurations value that exceeds the\ninitial value used in usb_get_configuration for allocating dev-\u003econfig.\n\nThis can lead to out-of-bounds accesses later, e.g. in\nusb_destroy_configuration.",
                "datePublished": "Dec 27, 2024, 1:49:39 PM",
                "dateUpdated": "Jan 20, 2025, 6:21:03 AM",
                "status": "PUBLISHED",
                "baseScore": 0,
                "references": "https://git.kernel.org/stable/c/0b4ea4bfe16566b84645ded1403756a2dc4e0f19\nhttps://git.kernel.org/stable/c/9b8460a2a7ce478e0b625af7c56d444dc24190f7\nhttps://git.kernel.org/stable/c/62dc01c83fa71e10446ee4c31e0e3d5d1291e865\nhttps://git.kernel.org/stable/c/9887d859cd60727432a01564e8f91302d361b72b\nhttps://git.kernel.org/stable/c/920a369a9f014f10ec282fd298d0666129379f1b\nhttps://git.kernel.org/stable/c/b8f8b81dabe52b413fe9e062e8a852c48dd0680d\nhttps://git.kernel.org/stable/c/379d3b9799d9da953391e973b934764f01e03960\nhttps://git.kernel.org/stable/c/b521b53ac6eb04e41c03f46f7fe452e4d8e9bcca\nhttps://git.kernel.org/stable/c/b909df18ce2a998afef81d58bbd1a05dc0788c40\n",
                "enisa_id": "EUVD-2024-51869\n",
                "assigner": "Linux",
                "epss": 0.24,
                "exploitedSince": "Apr 9, 2025, 12:00:00 AM",
                "vulnerabilityProduct": [
                    {
                        "id": "14d923c1-aaf3-3620-996d-eec992a76b29",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 6.13"
                    },
                    {
                        "id": "1a3a6fa6-b8b0-30c2-9856-3893358e7984",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 4.19.325"
                    },
                    {
                        "id": "1e50b70f-be26-3695-a072-036095b40310",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 6.12.2"
                    },
                    {
                        "id": "209ec5ea-bf80-39e3-8612-9efaf8529941",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 0"
                    },
                    {
                        "id": "249ee3a3-7712-35fc-945c-aa01f63fbfc0",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "2.6.12"
                    },
                    {
                        "id": "5cb7a071-a05f-3ea1-9e48-44297ceace12",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c0b4ea4bfe16566b84645ded1403756a2dc4e0f19"
                    },
                    {
                        "id": "631b28ee-f185-36c8-bd80-71fca25c0bdb",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 6.6.64"
                    },
                    {
                        "id": "65b3d32b-f447-3ad8-bb78-8de1ab5f5c6d",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c9b8460a2a7ce478e0b625af7c56d444dc24190f7"
                    },
                    {
                        "id": "7154dc6b-6999-3894-94c2-6c565f862f24",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c9887d859cd60727432a01564e8f91302d361b72b"
                    },
                    {
                        "id": "7901bd51-cc5d-3909-9fde-817353c2d222",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 6.1.120"
                    },
                    {
                        "id": "7b86520c-60af-3083-9365-d25a6757e796",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 5.15.174"
                    },
                    {
                        "id": "884263bf-2fed-3182-84c9-e4939954492c",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 5.4.287"
                    },
                    {
                        "id": "8a7cbfb6-0dc8-3d4e-87d8-08d217316432",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c62dc01c83fa71e10446ee4c31e0e3d5d1291e865"
                    },
                    {
                        "id": "9a48d07a-caf7-3dcb-b976-634ab152a323",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 6.11.11"
                    },
                    {
                        "id": "a8b4eb76-3f6c-366c-8a9b-812d41b6f496",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb521b53ac6eb04e41c03f46f7fe452e4d8e9bcca"
                    },
                    {
                        "id": "b0566937-5bb9-34e9-9328-1ed11ceb7512",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb909df18ce2a998afef81d58bbd1a05dc0788c40"
                    },
                    {
                        "id": "d8743ae4-423e-3c8c-b648-3443340af93c",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c920a369a9f014f10ec282fd298d0666129379f1b"
                    },
                    {
                        "id": "dfeb22ed-70c9-3d9c-8436-c6f4621dc2b2",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003c379d3b9799d9da953391e973b934764f01e03960"
                    },
                    {
                        "id": "f25a1e76-7d64-311c-bb12-91275cffad69",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2 \u003cb8f8b81dabe52b413fe9e062e8a852c48dd0680d"
                    },
                    {
                        "id": "f6f902a5-dd1c-3997-934a-6226590a9b60",
                        "product": {
                            "name": "Linux"
                        },
                        "product_version": "patch: 5.10.231"
                    }
                ],
                "vulnerabilityVendor": [
                    {
                        "id": "7ff545fd-dba4-33e2-9d61-ea3e3d7fb447",
                        "vendor": {
                            "name": "Linux"
                        }
                    }
                ]
            }
        }
    ],
    "enisaIdAdvisory": [
        {
            "id": "8b8a19a8-0fa2-3456-843f-4832d6754b91",
            "advisory": {
                "id": "WID-SEC-W-2024-3762",
                "description": "Linux Kernel: Mehrere Schwachstellen ermöglichen Denial of Service",
                "summary": "Ein lokaler Angreifer kann mehrere Schwachstellen in Linux Kernel ausnutzen, um einen Denial of Service Angriff durchzuführen und um nicht näher beschriebene Effekte zu erzielen.",
                "datePublished": "Dec 29, 2024, 11:00:00 PM",
                "dateUpdated": "Mar 5, 2025, 11:00:00 PM",
                "baseScore": 0,
                "references": "https://wid.cert-bund.de/.well-known/csaf/white/2024/wid-sec-w-2024-3762.json\nhttps://wid.cert-bund.de/portal/wid/securityadvisory?name\u003dWID-SEC-2024-3762\n",
                "aliases": "CVE-2024-53172\nCVE-2024-53176\nCVE-2024-53178\nCVE-2024-53179\nCVE-2024-53180\nCVE-2024-53181\nCVE-2024-53182\nCVE-2024-53183\nCVE-2024-53184\nCVE-2024-53185\nCVE-2024-53186\nCVE-2024-53187\nCVE-2024-53188\nCVE-2024-53189\nCVE-2024-53191\nCVE-2024-53194\nCVE-2024-53195\nCVE-2024-53196\nCVE-2024-53197\nCVE-2024-53198\nCVE-2024-53199\nCVE-2024-53200\nCVE-2024-53201\nCVE-2024-53202\nCVE-2024-53203\nCVE-2024-53204\nCVE-2024-53205\nCVE-2024-53206\nCVE-2024-53207\nCVE-2024-53208\nCVE-2024-53209\nCVE-2024-53210\nCVE-2024-53211\nCVE-2024-53212\nCVE-2024-53213\nCVE-2024-53214\nCVE-2024-53215\nCVE-2024-53216\nCVE-2024-53217\nCVE-2024-53218\nCVE-2024-53219\nCVE-2024-53220\nCVE-2024-53221\nCVE-2024-53222\nCVE-2024-53223\nCVE-2024-53224\nCVE-2024-53225\nCVE-2024-53226\nCVE-2024-53227\nCVE-2024-53228\nCVE-2024-53229\nCVE-2024-53230\nCVE-2024-53231\nCVE-2024-53232\nCVE-2024-53233\nCVE-2024-53234\nCVE-2024-53235\nCVE-2024-53236\nCVE-2024-53237\nCVE-2024-53238\nCVE-2024-53239\nCVE-2024-56531\nCVE-2024-56532\nCVE-2024-56533\nCVE-2024-56534\nCVE-2024-56535\nCVE-2024-56536\nCVE-2024-56537\nCVE-2024-56538\nCVE-2024-56539\nCVE-2024-56540\nCVE-2024-56541\nCVE-2024-56542\nCVE-2024-56543\nCVE-2024-56544\nCVE-2024-56545\nCVE-2024-56546\nCVE-2024-56547\nCVE-2024-56548\nCVE-2024-56549\nCVE-2024-56550\nCVE-2024-56551\nCVE-2024-56552\nCVE-2024-56553\nCVE-2024-56554\nCVE-2024-56555\nCVE-2024-56556\nCVE-2024-56557\nCVE-2024-56558\nCVE-2024-56559\nCVE-2024-56560\nCVE-2024-56561\nCVE-2024-56562\nCVE-2024-56563\nCVE-2024-56564\nCVE-2024-56565\nCVE-2024-56566\nCVE-2024-56567\nCVE-2024-56568\nCVE-2024-56569\nCVE-2024-56570\nCVE-2024-56571\nCVE-2024-56572\nCVE-2024-56573\nCVE-2024-56574\nCVE-2024-56575\nCVE-2024-56576\nCVE-2024-56577\nCVE-2024-56578\nCVE-2024-56579\nCVE-2024-56580\nCVE-2024-56581\nCVE-2024-56582\nCVE-2024-56583\nCVE-2024-56584\nCVE-2024-56585\nCVE-2024-56586\nCVE-2024-56587\nCVE-2024-56588\nCVE-2024-56589\nCVE-2024-56590\nCVE-2024-56591\nCVE-2024-56592\nCVE-2024-56593\nCVE-2024-56594\nCVE-2024-56595\nCVE-2024-56596\nCVE-2024-56597\nCVE-2024-56598\nCVE-2024-56599\nCVE-2024-56600\nCVE-2024-56601\nCVE-2024-56602\nCVE-2024-56603\nCVE-2024-56604\nCVE-2024-56605\nCVE-2024-56606\nCVE-2024-56607\nCVE-2024-56608\nCVE-2024-56609\nCVE-2024-56610\nCVE-2024-56611\nCVE-2024-56612\nCVE-2024-56613\nCVE-2024-56614\nCVE-2024-56615\nCVE-2024-56616\nCVE-2024-56617\nCVE-2024-56618\nCVE-2024-56619\nCVE-2024-56620\nCVE-2024-56621\nCVE-2024-56622\nCVE-2024-56623\nCVE-2024-56624\nCVE-2024-56625\nCVE-2024-56626\nCVE-2024-56627\nCVE-2024-56628\nCVE-2024-56629\nCVE-2024-56630\nCVE-2024-56631\nCVE-2024-56632\nCVE-2024-56633\nCVE-2024-56634\nCVE-2024-56635\nCVE-2024-56636\nCVE-2024-56637\nCVE-2024-56638\nCVE-2024-56639\nCVE-2024-56640\nCVE-2024-56641\nCVE-2024-56642\nCVE-2024-56643\nCVE-2024-56644\nCVE-2024-56645\nCVE-2024-56646\nCVE-2024-56647\nCVE-2024-56648\nCVE-2024-56649\nCVE-2024-56650\nCVE-2024-56651\nCVE-2024-56652\nCVE-2024-56653\nCVE-2024-56654\nCVE-2024-56655\nCVE-2024-56656\nCVE-2024-56657\nCVE-2024-56658\nCVE-2024-56659\nCVE-2024-56660\nCVE-2024-56661\nCVE-2024-56662\nCVE-2024-56663\nCVE-2024-56664\nCVE-2024-56665\nCVE-2024-56666\nCVE-2024-56667\nCVE-2024-56668\nCVE-2024-56669\nCVE-2024-56670\nCVE-2024-56671\nCVE-2024-56672\nCVE-2024-56673\nCVE-2024-56674\nCVE-2024-56675\nCVE-2024-56676\nCVE-2024-56677\nCVE-2024-56678\nCVE-2024-56679\nCVE-2024-56680\nCVE-2024-56681\nCVE-2024-56682\nCVE-2024-56683\nCVE-2024-56684\nCVE-2024-56685\nCVE-2024-56686\nCVE-2024-56687\nCVE-2024-56688\nCVE-2024-56689\nCVE-2024-56690\nCVE-2024-56691\nCVE-2024-56692\nCVE-2024-56693\nCVE-2024-56694\nCVE-2024-56695\nCVE-2024-56696\nCVE-2024-56697\nCVE-2024-56698\nCVE-2024-56699\nCVE-2024-56700\nCVE-2024-56701\nCVE-2024-56702\nCVE-2024-56703\nCVE-2024-56704\nCVE-2024-56705\nCVE-2024-56706\nCVE-2024-56707\nCVE-2024-56708\nCVE-2024-56709\nCVE-2024-56710\nCVE-2024-56711\nCVE-2024-56712\nCVE-2024-56713\nCVE-2024-56714\nCVE-2024-56715\nCVE-2024-56716\nCVE-2024-56717\nCVE-2024-56718\nCVE-2024-56719\nCVE-2024-56720\nCVE-2024-56721\nCVE-2024-56722\nCVE-2024-56723\nCVE-2024-56724\nCVE-2024-56725\nCVE-2024-56726\nCVE-2024-56727\nCVE-2024-56728\nCVE-2024-56729\nCVE-2024-56730\nCVE-2024-56739\nCVE-2024-56740\nCVE-2024-56741\nCVE-2024-56742\nCVE-2024-56743\nCVE-2024-56744\nCVE-2024-56745\nCVE-2024-56746\nCVE-2024-56747\nCVE-2024-56748\nCVE-2024-56749\nCVE-2024-56750\nCVE-2024-56751\nCVE-2024-56752\nCVE-2024-56753\nCVE-2024-56754\nCVE-2024-56755\nCVE-2024-56756\n",
                "source": {
                    "id": 8,
                    "name": "csaf_certbund"
                },
                "advisoryProduct": [
                    {
                        "id": "d5a82f11-832a-3b87-8aa6-b6803d79410b",
                        "product": {
                            "name": "Ubuntu Linux"
                        }
                    }
                ]
            }
        }
    ]
}
