# Third-party runtime and public reference sources

## Runtime

Waitress 3.0.2 is distributed as the original official PyPI wheel under vendor/.
It is covered by Zope Public License 2.1; copyright and license text are included
inside the wheel and installed dist-info. requirements.txt pins its SHA256 digest.
The installer verifies the digest and pip independently enforces the same lock.

## Reference sources (downloaded at runtime; not bundled as evidence)

CISA Known Exploited Vulnerabilities catalog, official cisagov/kev-data repository:
https://github.com/cisagov/kev-data
Canonical catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

CVE Program records, official CVEProject/cvelistV5 repository:
https://github.com/CVEProject/cvelistV5
CVE Program Terms of Use: https://www.cve.org/Legal/TermsOfUse
The current delta window is not a full historical mirror.

MITRE ATT&CK enterprise STIX data, official mitre-attack/attack-stix-data repository:
https://github.com/mitre-attack/attack-stix-data
Terms and attribution: https://attack.mitre.org/resources/terms-of-use/
ATT&CK and MITRE ATT&CK are registered trademarks of The MITRE Corporation.
This application uses the technique reference catalog, not an assertion of attacks
against the user's systems. Consult the publisher's license/terms when redistributing
or using the downloaded data.

OSV API for explicit project dependency checks: https://osv.dev/
It receives declared dependency names/versions, not source files or credentials.

Catalog data can change after release. Source identity, publisher timestamps,
fetch timestamps, content revision hashes and coverage are preserved locally.
No endorsement by the publishers is implied.
