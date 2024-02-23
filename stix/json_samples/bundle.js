{
    "type": "bundle",
    "id": "bundle--97b40f76-c1b8-4407-b050-ff177f3d67ed",
    "objects": [
        {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "Fake BPP (Branistan Peoples Party)",
            "threat_actor_types": [
                "nation-state"
            ],
            "roles": [
                "director"
            ],
            "goals": [
                "Influence the election in Branistan"
            ],
            "sophistication": "strategic",
            "resource_level": "government",
            "primary_motivation": "ideology",
            "secondary_motivations": [
                "dominance"
            ]
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--8c6af861-7b20-41ef-9b59-6344fd872a8f",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "Franistan Intelligence",
            "identity_class": "organization"
        },
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "Branistan Peoples Party",
            "identity_class": "organization",
            "external_references": [
                {
                    "source_name": "website",
                    "url": "http://www.bpp.bn"
                }
            ]
        },
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2017-01-30T21:15:04.127Z",
            "name": "Content Spoofing",
            "external_references": [
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/148.html",
                    "external_id": "CAPEC-148"
                }
            ]
        },
        {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": "attack-pattern--f6050ea6-a9a3-4524-93ed-c27858d6cb3c",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2017-01-30T21:15:04.127Z",
            "name": "HTTP Flood",
            "external_references": [
                {
                    "source_name": "capec",
                    "url": "https://capec.mitre.org/data/definitions/488.html",
                    "external_id": "CAPEC-488"
                }
            ]
        },
        {
            "type": "campaign",
            "spec_version": "2.1",
            "id": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "Operation Bran Flakes",
            "description": "A concerted effort to insert false information into the BPP's web pages.",
            "aliases": [
                "OBF"
            ],
            "first_seen": "2016-01-08T12:50:40.123Z",
            "objective": "Hack www.bpp.bn"
        },
        {
            "type": "campaign",
            "spec_version": "2.1",
            "id": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "Operation Raisin Bran",
            "description": "A DDOS campaign to flood BPP web servers.",
            "aliases": [
                "ORB"
            ],
            "first_seen": "2016-02-07T19:45:32.126Z",
            "objective": "Flood www.bpp.bn"
        },
        {
            "type": "intrusion-set",
            "spec_version": "2.1",
            "id": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713",
            "created": "2016-08-08T15:50:10.983Z",
            "modified": "2016-08-08T15:50:10.983Z",
            "name": "APT BPP",
            "description": "An advanced persistent threat that seeks to disrupt Branistan's election with multiple attacks.",
            "aliases": [
                "Bran-teaser"
            ],
            "first_seen": "2016-01-08T12:50:40.123Z",
            "goals": [
                "Influence the Branistan election",
                "Disrupt the BPP"
            ],
            "resource_level": "government",
            "primary_motivation": "ideology",
            "secondary_motivations": [
                "dominance"
            ]
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--98765000-efdf-4a86-8681-36481ceae57f",
            "created": "2020-02-29T17:41:44.938Z",
            "modified": "2020-02-29T17:41:44.938Z",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "target_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--53a55c73-f2c8-47b9-8e50-ae34d8c5da4d",
            "created": "2020-02-29T17:41:44.938Z",
            "modified": "2020-02-29T17:41:44.938Z",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "target_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--5047c2c0-524b-4afd-9cd6-e197efe59495",
            "created": "2020-02-29T17:41:44.939Z",
            "modified": "2020-02-29T17:41:44.939Z",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "target_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--9cc131ca-b64d-4ab1-a300-5e4a0073280a",
            "created": "2020-02-29T17:41:44.939Z",
            "modified": "2020-02-29T17:41:44.939Z",
            "relationship_type": "attributed-to",
            "source_ref": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "target_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--c171fd27-2a8a-42b7-8293-34016b70c1c8",
            "created": "2020-02-29T17:41:44.939Z",
            "modified": "2020-02-29T17:41:44.939Z",
            "relationship_type": "attributed-to",
            "source_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713",
            "target_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--554e3341-d7b1-4b3c-a522-28ef52fbb49b",
            "created": "2020-02-29T17:41:44.939Z",
            "modified": "2020-02-29T17:41:44.939Z",
            "relationship_type": "targets",
            "source_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--06964095-5750-41fe-a9af-6c6a9d995489",
            "created": "2020-02-29T17:41:44.940Z",
            "modified": "2020-02-29T17:41:44.940Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713",
            "target_ref": "attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--4fe5dab1-fd6d-41aa-b8b1-d3118a708284",
            "created": "2020-02-29T17:41:44.940Z",
            "modified": "2020-02-29T17:41:44.940Z",
            "relationship_type": "uses",
            "source_ref": "intrusion-set--ed69450a-f067-4b51-9ba2-c4616b9a6713",
            "target_ref": "attack-pattern--f6050ea6-a9a3-4524-93ed-c27858d6cb3c"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--d8b7932d-0ecb-4891-b021-c78ff2b63747",
            "created": "2020-02-29T17:41:44.940Z",
            "modified": "2020-02-29T17:41:44.940Z",
            "relationship_type": "targets",
            "source_ref": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--96cfbc6f-5c08-4372-b811-b90fbb2ec180",
            "created": "2020-02-29T17:41:44.940Z",
            "modified": "2020-02-29T17:41:44.940Z",
            "relationship_type": "targets",
            "source_ref": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--33c22977-d104-45d8-be19-273f7ab03de1",
            "created": "2020-02-29T17:41:44.940Z",
            "modified": "2020-02-29T17:41:44.940Z",
            "relationship_type": "uses",
            "source_ref": "campaign--e5268b6e-4931-42f1-b379-87f48eb41b1e",
            "target_ref": "attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--8848cba9-4c7b-4695-bc09-5033a6f20ff4",
            "created": "2020-02-29T17:41:44.941Z",
            "modified": "2020-02-29T17:41:44.941Z",
            "relationship_type": "uses",
            "source_ref": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "target_ref": "attack-pattern--f6050ea6-a9a3-4524-93ed-c27858d6cb3c"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--a97b3ea5-4ca1-46a0-a7ad-f10143ce22b2",
            "created": "2020-02-29T17:41:44.941Z",
            "modified": "2020-02-29T17:41:44.941Z",
            "relationship_type": "impersonates",
            "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--4292a6df-fb16-43d1-805d-dc1b33946fdf",
            "created": "2020-02-29T17:41:44.941Z",
            "modified": "2020-02-29T17:41:44.941Z",
            "relationship_type": "targets",
            "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--4bd67b9e-d112-4ea6-98bb-080a051667c7",
            "created": "2020-02-29T17:41:44.941Z",
            "modified": "2020-02-29T17:41:44.941Z",
            "relationship_type": "attributed-to",
            "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "target_ref": "identity--8c6af861-7b20-41ef-9b59-6344fd872a8f"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--1f4ee02a-7f6e-45a6-aedd-c1492af5e179",
            "created": "2020-02-29T17:41:44.942Z",
            "modified": "2020-02-29T17:41:44.942Z",
            "relationship_type": "targets",
            "source_ref": "campaign--1d8897a7-fdc2-4e59-afc9-becbe04df727",
            "target_ref": "identity--ddfe7140-2ba4-48e4-b19a-df069432103b"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--ba30893a-400a-43f3-b193-69d65d2a8f40",
            "created": "2020-02-29T17:41:44.942Z",
            "modified": "2020-02-29T17:41:44.942Z",
            "relationship_type": "uses",
            "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "target_ref": "attack-pattern--19da6e1c-71ab-4c2f-886d-d620d09d3b5a"
        },
        {
            "type": "relationship",
            "spec_version": "2.1",
            "id": "relationship--70880ead-0b19-4785-be52-a69064d4cb6c",
            "created": "2020-02-29T17:41:44.942Z",
            "modified": "2020-02-29T17:41:44.942Z",
            "relationship_type": "uses",
            "source_ref": "threat-actor--56f3f0db-b5d5-431c-ae56-c18f02caf500",
            "target_ref": "attack-pattern--f6050ea6-a9a3-4524-93ed-c27858d6cb3c"
        }
    ]
}
