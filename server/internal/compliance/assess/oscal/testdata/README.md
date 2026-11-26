# Vendored NIST OSCAL JSON schemas

`oscal_ssp_schema.json` and `oscal_poam_schema.json` are NIST's OSCAL 1.1.2 JSON schemas, unchanged,
from https://github.com/usnistgov/OSCAL/releases/download/v1.1.2/ (a U.S. government work, public
domain). The test pins their SHA-256 and fails if either changes. To move to another OSCAL version,
amend ADR-0078, change `Version` in `oscal.go`, vendor the new schemas and update the checksums in
`oscal_test.go`.
