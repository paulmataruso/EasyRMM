# Project Requirements: Compliance Engine, CIS Benchmark Licensing, and Independent Security Controls

Given by the owner on 2026-11-24 as directions for the plan. Verbatim.

I want you to understand and account for the intellectual property and licensing implications of implementing security compliance frameworks in our project.

## 1. Background: Wazuh and CIS Benchmarks

Wazuh provides a Security Configuration Assessment (SCA) engine that includes machine-readable security policies based on CIS Benchmarks.

CIS Benchmark publications are generally distributed under Creative Commons Attribution-NonCommercial-ShareAlike 4.0 (CC BY-NC-SA 4.0), subject to the applicable benchmark-specific licensing terms.

There is an important distinction between:

- The actual CIS Benchmark publication and its copyrighted expressive content.
- The underlying security configuration requirements and technical concepts.
- Independently written code that evaluates whether a system satisfies a particular security requirement.
- Original remediation scripts and implementation instructions.

We want to leverage publicly documented security standards without improperly copying copyrighted benchmark publications or introducing licensing restrictions that could prevent commercial distribution of our software.

Do not assume that Wazuh's implementation automatically establishes that all CIS-derived policies can be commercially redistributed.

## 2. Our Objective

Design our compliance engine around independently authored security controls.

The system should be capable of evaluating operating systems, applications, network devices, and infrastructure against multiple security frameworks.

Initial frameworks of interest:

- CIS Controls
- CIS Benchmarks
- NIST SP 800-53
- NIST SP 800-171
- NIST Cybersecurity Framework
- CMMC 2.0
- DISA STIG
- PCI DSS
- HIPAA Security Rule
- ISO 27001

The architecture must support adding additional frameworks without redesigning the compliance engine.

## 3. Intellectual Property and Licensing Requirements

This is a critical requirement.

Design the system to avoid unnecessary dependency on copyrighted benchmark publications.

Specifically:

1. Independently author security checks based on publicly documented technical requirements.
2. Do not copy CIS benchmark descriptions, rationale, remediation text, or explanatory material verbatim.
3. Do not import or redistribute licensed benchmark PDFs or their contents without appropriate authorization.
4. Do not assume that a publicly accessible benchmark is freely available for commercial redistribution.
5. Maintain attribution and licensing metadata where required.
6. Separate independently authored technical implementations from licensed framework content.
7. Support optional licensed content packages that can be installed separately.
8. Ensure the core compliance engine can operate without any licensed CIS content.
9. Maintain provenance for each security check, including its author, source references, and licensing status.
10. Flag controls that require legal or licensing review before commercial distribution.

Do not treat the GPL license of the software as overriding the licensing terms of third-party benchmark material.

## 4. Recommended Technical Architecture

I want a modular architecture with the following components:

### A. Compliance Engine

Responsible for:
- Executing security checks.
- Collecting system configuration data.
- Evaluating compliance.
- Recording pass/fail/not-applicable results.
- Generating evidence.
- Supporting automated and manual assessments.

### B. Security Control Library

A centralized collection of independently authored technical checks.

Each control should contain:

- Unique internal identifier.
- Framework mappings.
- Original control title.
- Original technical description.
- Technical implementation.
- Detection logic.
- Expected configuration.
- Original remediation instructions.
- Severity.
- Applicability conditions.
- References to authoritative public documentation.
- Source provenance.
- Licensing classification.

### C. Framework Mapping Layer

Allow a single technical security check to map to multiple compliance frameworks.

For example, one Windows password policy check could map to relevant requirements in:
- CIS Windows Benchmark.
- NIST SP 800-53.
- NIST SP 800-171.
- CMMC.
- DISA STIG.

Avoid duplicating technical checks simply because different frameworks reference the same security requirement.

Do not imply that satisfying one technical check automatically satisfies every mapped framework requirement. Preserve each framework's actual assessment criteria.

### D. Assessment Profiles

Allow administrators to select assessment profiles, such as:

- Windows 11 Security Baseline.
- Windows Server 2022 Security Baseline.
- Ubuntu Server Security Baseline.
- Debian Server Security Baseline.
- RHEL Security Baseline.
- Network Infrastructure Security Baseline.
- CMMC Level 2 Assessment.
- NIST 800-171 Assessment.

Profiles should be composed of reusable controls.

### E. Remediation Engine

Where technically possible, provide:
- Automated remediation.
- Manual remediation instructions.
- Before-and-after configuration checks.
- Rollback capabilities.
- Remediation logging.
- Approval workflows.

All remediation instructions must be independently authored or appropriately licensed.

## 5. Licensing-Aware Content Management

Implement a licensing metadata system.

Every control and associated content package should have a classification such as:

- ORIGINAL: Independently authored content.
- PUBLIC_DOMAIN: Verified public-domain content.
- OPEN_LICENSE: Content with an identified permissive license.
- ATTRIBUTION_REQUIRED: Content requiring attribution.
- NONCOMMERCIAL: Content restricted to non-commercial use.
- COMMERCIAL_LICENSE_REQUIRED: Content requiring additional permission.
- RESTRICTED: Content that cannot be redistributed without authorization.

The system should prevent restricted content from accidentally being included in commercial builds.

Support separate content packages so that customers who have their own CIS licensing can potentially import appropriately licensed material.

Do not assume that customer ownership of a benchmark license automatically permits us to redistribute its contents.

## 6. Research and Legal Validation

Before implementing CIS integration, investigate:

1. Current CIS Benchmark licensing terms.
2. CIS policies regarding machine-readable benchmark implementations.
3. Whether independently authored configuration checks can be distributed commercially.
4. Whether CIS identifiers and control references can be used in commercial software.
5. Whether CIS trademarks or certification claims create additional restrictions.
6. Whether Wazuh has publicly documented licensing permissions or agreements concerning its CIS-derived policies.
7. How other commercial compliance platforms handle framework content licensing.

Distinguish verified facts from assumptions.

Cite authoritative sources, preferably CIS licensing documentation and official Creative Commons documentation.

Do not make definitive legal conclusions where the applicable licensing terms require legal review.

## 7. Commercial Product Requirements

The architecture must support eventual commercial distribution.

We should be able to:

- Distribute our compliance engine commercially.
- Sell subscriptions to managed service providers.
- Provide compliance reporting to customers.
- Add new security checks without licensing an entire benchmark.
- Support optional third-party licensed content.
- Maintain a clean separation between our intellectual property and third-party content.

Avoid architectural decisions that unnecessarily force the entire project to inherit non-commercial licensing restrictions.

## 8. Expected Deliverables

Please provide:

1. An assessment of the CIS licensing implications.
2. A recommended architecture for the compliance engine.
3. A proposed security control data model.
4. A framework mapping model.
5. A licensing metadata model.
6. A content package architecture.
7. An example independently authored Windows security check.
8. An example independently authored Linux security check.
9. An example of mapping a technical check to CIS, NIST 800-171, and CMMC.
10. A commercial distribution strategy.
11. A list of licensing and legal risks requiring further review.

## 9. Important Development Instructions

Do not immediately begin implementing the entire system.

First analyze the existing project architecture and identify how these requirements should fit into it.

Preserve existing functionality and avoid unnecessary rewrites.

Present your recommended architecture, data models, and implementation plan before making structural changes.

The most important design principle is:

**We want to implement the security requirements of established frameworks through our own independently developed technical controls, rather than building a commercial product by copying and redistributing copyrighted benchmark publications.**

The result should be a commercially distributable, extensible, multi-framework compliance platform.
