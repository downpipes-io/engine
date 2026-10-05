// The compliance framework -> control knowledge base for the evidence packs, extracted faithfully
// from the website's reviewed compliance pages. It is PUBLIC, static reference data: control citations, faithful
// obligation paraphrases, the downpipes capability that supports each, and the posture check id(s)
// whose LIVE result evidences the control in a customer-specific signed pack (empty = a capability/
// obligation-only row, e.g. a customer filing duty or a legal deeming provision that no check attests).
//
// The framing is binding: downpipes SUPPORTS these obligations, it does not CERTIFY the customer.
// No row claims more than the compliance page already states. checkIds name the posture checks whose live
// result bears on the control (src/admin/posture.ts); a row with no check that attests it carries none. A
// check bound to a control it cannot fail for prints a pass the control has not earned, so a binding is
// a claim too: test/validate-framework-posture-claims.ts refuses the ones that were wrong.
//
// Node strip-types compatible: interfaces + const arrays, no enums.

// FrameworkControl is one control row: the citation, what it requires, how downpipes supports it, and
// the posture check id(s) that evidence it live.
export interface FrameworkControl {
  control: string;
  obligation: string;
  capability: string;
  checkIds: string[];
}

// COMPLIANCE_MODE_CONTROLS names the rows whose obligation binds a backup ADMINISTRATOR during retention, as
// "<framework id>/<control>". Only a compliance-mode lock does that, so the signed pack does not show the
// immutability check as met on these rows under governance mode (reports.ts buildEvidencePackReport). It is
// a list beside the rows rather than a field on them so the row text stays the mapping's alone.
export const COMPLIANCE_MODE_CONTROLS: ReadonlySet<string> = new Set([
  "essential-eight/ML3 admin immutability",
  "sec-17a-4/17a-4(f)(2)(i)(B)",
  "ism/ISM-1708",
]);

// Framework is one framework's pack: identity, the page title/description, the control rows and sources.
export interface Framework {
  id: string; // url-safe slug
  title: string;
  description: string;
  controls: FrameworkControl[];
  sources: { label: string; href: string }[];
}

// The shared no-custody scope statement every pack carries (the "supports not certifies" framing).
export const PACK_SCOPE_STATEMENT =
  "downpipes provides capabilities that support these obligations. Whether you meet them depends on your overall implementation, your environment and, where one applies, your assessment. This is not legal advice and not a certification. downpipes runs inside your own Cloudflare account; the vendor holds none of your data, keys or tokens.";

export const FRAMEWORKS: Framework[] = [
  {
    id: "apra-cps-230-234",
    title: "APRA CPS 234 & CPS 230",
    description:
      "How downpipes supports APRA-regulated entities: CPS 234 information security controls and testing, APRA's 2024 backup-adequacy findings, and CPS 230 tolerance levels for data loss.",
    controls: [
      { control: "CPS 234 para 20-21", obligation: "Classify information assets by criticality and sensitivity, with controls commensurate with both.", capability: "Per-dataset backup cadence and retention tier, so protection scales with criticality and sensitivity.", checkIds: ["destination-configured"] },
      { control: "CPS 234 para 27-28", obligation: "Test the effectiveness of information security controls through a systematic testing program.", capability: "Integrity verification at seal in either key posture, on for every run unless it is switched off, plus restore drills with an exportable evidence log: scheduled and unattended where an operational key is installed, attended with your break-glass key where it is not.", checkIds: ["seal-verification", "restore-test-enabled", "restore-test-recency", "audit-export-available"] },
      { control: "CPS 234 para 35-36", obligation: "Notify APRA of material incidents and control weaknesses within the statutory windows.", capability: "Tamper-evident audit logs speed the impact assessment; verified restorable copies mean the notification carries a recovery plan.", checkIds: ["audit-export-available", "seal-verification", "restore-test-recency"] },
      { control: "CPS 230 para 37(b)", obligation: "Set tolerance for the maximum extent of data loss accepted (the RPO) per critical operation.", capability: "Per-dataset cadence makes the achievable RPO a setting you choose and a number you can report.", checkIds: ["destination-configured", "failure-alerts"] },
      { control: "CPS 230 para 33(c)", obligation: "Maintain a credible business continuity plan, including disaster recovery for critical information assets.", capability: "Verified archives in storage you control (data and zone/account config), restore paths without the primary provider, and drill evidence.", checkIds: ["seal-verification", "restore-test-enabled", "restore-test-recency", "break-glass-present"] },
      { control: "CPS 230 para 42-43", obligation: "A systematic BCP testing program including severe-but-plausible scenarios and material-provider disruption.", capability: "The offline reader covers the provider-unavailable scenario: restore from your own storage with your own keys.", checkIds: ["break-glass-present", "restore-test-recency", "restore-test-enabled"] },
      { control: "CPS 230 para 53(b)", obligation: "Service provider agreements must address ownership and control of data.", capability: "Control of the backup copy is structural, not contractual: your storage, your keys, an open restore path.", checkIds: ["destination-configured", "break-glass-present"] },
      { control: "APRA backup letter (Jun 2024)", obligation: "Segregate production and backup; protect backups from unauthorised access or alteration; test recovery within tolerance.", capability: "Backups outside the production trust boundary when you choose an off-account destination; post-quantum encryption, RBAC, append-only archives, a signed run log, and a destination retention lock when you set one at a destination that enforces it; drills that verify the chain and decrypt a sample of records, with an evidence log.", checkIds: ["destination-configured", "dest-cred-encryption", "encryption-pq-hybrid", "access-enforced", "immutability", "seal-verification", "restore-test-recency"] },
    ],
    sources: [
      { label: "APRA, Prudential Standard CPS 234 Information Security (July 2019)", href: "https://www.apra.gov.au/sites/default/files/cps_234_july_2019_for_public_release.pdf" },
      { label: "APRA letter: Security and adequacy of backups (3 June 2024)", href: "https://www.apra.gov.au/security-and-adequacy-of-backups" },
      { label: "APRA, Prudential Standard CPS 230 Operational Risk Management (the version in force from 1 July 2026; CPS 230 first applied from 1 July 2025)", href: "https://handbook.apra.gov.au/standard/cps-230" },
      { label: "APRA, Prudential Practice Guide CPG 230 (June 2024)", href: "https://www.apra.gov.au/sites/default/files/2024-06/Prudential%20Practice%20Guide%20CPG%20230%20Operational%20Risk%20Management.pdf" },
    ],
  },
  {
    id: "iso-27001",
    title: "ISO/IEC 27001",
    description:
      "How downpipes maps to ISO/IEC 27001:2022 Annex A controls for backup, ICT readiness, cryptography and cloud exit, as a control an organisation deploys toward a certified ISMS.",
    controls: [
      { control: "A.8.13", obligation: "Information backup: maintain and regularly test backup copies in line with the backup policy.", capability: "Tested, tamper-evident, customer-keyed backups implement the control, held off-account when you choose an off-account destination.", checkIds: ["seal-verification", "restore-test-enabled", "restore-test-recency", "destination-configured", "encryption-pq-hybrid"] },
      { control: "A.8.14", obligation: "Redundancy of information processing facilities sufficient to meet availability requirements.", capability: "Copies at more than one destination, with failover between them, add redundant copies of the data; they are off-account when you choose an off-account destination.", checkIds: ["redundant-copies", "media-diversity"] },
      { control: "A.5.29", obligation: "Maintain information security at an appropriate level during a disruption.", capability: "Encryption and the integrity chain keep recovery data confidential and intact; the offline reader works without the vendor or network.", checkIds: ["encryption-pq-hybrid", "seal-verification", "break-glass-present"] },
      { control: "A.5.30", obligation: "ICT readiness for business continuity: plan, implement, maintain and test against continuity objectives.", capability: "Restore drills with a dated evidence log are the tested ICT recovery readiness.", checkIds: ["restore-test-enabled", "restore-test-recency", "audit-export-available"] },
      { control: "A.8.10", obligation: "Information deletion: delete information when no longer required.", capability: "Retention policy and a reviewed prune plan delete backup data on your schedule, once pruning is switched from its default dry run to enforce, with a disposal log.", checkIds: [] },
      { control: "A.5.33", obligation: "Protection of records: protect records from loss, destruction, falsification, unauthorised access and unauthorised release, in line with legislative, regulatory, contractual and business requirements.", capability: "A content-addressed, append-only copy under keys only you hold, off-account when you choose an off-account destination, guards against loss and unauthorised release. Per-record hashes with a signed run log make falsification detectable, and the anti-rollback high-water mark on the recovery sheet you hold, which the offline reader takes as --min-runlog-index, catches a rollback to an older log. Add destination retention locks where prevention, not just detection, is required.", checkIds: ["seal-verification", "encryption-pq-hybrid", "break-glass-present", "destination-configured"] },
      { control: "A.8.24", obligation: "Use of cryptography, including key management.", capability: "Hybrid post-quantum encryption and signatures; the break-glass key never leaves you; destination credentials are envelope-encrypted at rest when CONFIG_WRAP_KEY is set, and the deploy sets that key as a Worker secret on your engine.", checkIds: ["encryption-pq-hybrid", "break-glass-present", "dest-cred-encryption"] },
      { control: "A.5.23", obligation: "Information security for the use of cloud services, including exit.", capability: "Copies at a destination you choose, including one outside the source account, and an open, cloud-independent recovery path support a credible exit.", checkIds: ["destination-configured", "break-glass-present"] },
      { control: "A.8.16", obligation: "Monitoring activities: monitor systems for anomalous behaviour.", capability: "The signed run log and the freshness high-water mark you record on your recovery sheet are tamper-evident monitoring signals; the Security Centre also watches the running engine version against the last verified update, so an out-of-band redeploy is flagged.", checkIds: ["seal-verification", "failure-alerts", "audit-export-available", "update-version-drift"] },
    ],
    sources: [
      { label: "ISO/IEC 27001:2022, Information security management systems (Annex A)", href: "https://www.iso.org/standard/27001" },
      { label: "ISO/IEC 27002:2022, implementation guidance for the Annex A controls", href: "https://www.iso.org/standard/75652.html" },
    ],
  },
  {
    id: "essential-eight",
    title: "Essential Eight: Regular Backups",
    description:
      "Every Regular Backups requirement from Maturity Level One to Three, drawn from ASD's Essential Eight Maturity Model and mapped to downpipes capabilities.",
    controls: [
      { control: "ML1 perform/retain", obligation: "Backups performed and retained in accordance with business criticality and continuity requirements.", capability: "Scheduled per-source backups with per-downpipe retention policy set against your BCP.", checkIds: ["destination-configured", "failure-alerts"] },
      { control: "ML1 synchronise", obligation: "Backups synchronised to enable restoration to a common point in time.", capability: "Each source is captured on its own schedule. A restore can be pinned to a timestamp you nominate: for each source, downpipes resolves the latest successful run completed at or before that moment. A backup is consistent per record, not across the whole account at a single instant; D1 alone is exported as a sequentially-consistent snapshot.", checkIds: [] },
      { control: "ML1 secure/resilient", obligation: "Backups retained in a secure and resilient manner.", capability: "Post-quantum encrypted under customer keys, content-addressed, append-only, separate from production credentials.", checkIds: ["encryption-pq-hybrid", "immutability", "redundant-copies", "dest-cred-encryption"] },
      { control: "ML1 test restoration", obligation: "Restoration to a common point in time tested as part of disaster recovery exercises.", capability: "Drills verify the chain and restore sample data, in-account and unattended where an operational key is installed and attended with your break-glass key where it is not; the offline reader supports genuine DR; outcomes export to an evidence log.", checkIds: ["restore-test-enabled", "restore-test-recency", "seal-verification", "break-glass-present", "audit-export-available"] },
      { control: "ML1 access boundary", obligation: "Unprivileged user accounts cannot access, modify or delete backups.", capability: "SSO/passkey and RBAC separate from production accounts; Viewer, the role an identity with no grant receives, holds no capability that changes or deletes an archive.", checkIds: ["access-enforced", "immutability", "dest-cred-encryption"] },
      { control: "ML2 privileged boundary", obligation: "Privileged accounts (excluding backup administrators) cannot access, modify or delete backups.", capability: "Destinations bind to the engine, not users; an in-account bucket still sits inside the account it protects, so Cloudflare account administrators keep their own route to it. Within downpipes, disposal runs only through the retention planner, a dry run until an Operator or above switches it to enforce. A prune applied from the console always needs a second approver who is not the requester; the scheduled prune runs only where an operational key is installed, and a change to its policy needs a second approver only when configuration approval is on, which is off by default.", checkIds: ["access-enforced", "dest-cred-encryption", "immutability", "two-owners"] },
      { control: "ML3 own-backup boundary", obligation: "Unprivileged and privileged accounts cannot access their own backups.", capability: "A Cloudflare Access or passkey identity with no grant resolves to Viewer, and a native SSO sign-in with no grant, invite or mapped group is refused. Viewer can see configuration, reports, the audit log and a restore preview but cannot read any record value. Every higher role is an explicit grant keyed to the stable subject of the sign-in or to an IdP group you map, once the break-glass admin token is retired (the Security Centre reports it). A passkey sign-in has a subject that comes from the email the passkey is bound to. Viewer and Operator cannot read record values.", checkIds: ["access-enforced"] },
      { control: "ML3 admin immutability", obligation: "Backup administrators prevented from modifying or deleting backups during the retention period.", capability: "Append-only, content-addressed archives paired with a retention lock set in compliance mode at a destination that enforces one (S3 Object Lock, Google Cloud per-object retention or a locked Azure version-level immutability policy); governance mode can be lifted by a principal holding the bypass permission. Cloudflare R2 cannot enforce S3 Object Lock on any bucket, and downpipes neither sets nor reads R2's own bucket lock. The signed run log makes a rewrite within the log detectable; a wholesale rollback to an older, validly signed log is caught by the minimum-index pin from your recovery sheet.", checkIds: ["immutability", "seal-verification"] },
    ],
    sources: [
      { label: "ASD, Essential Eight Maturity Model (November 2023)", href: "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-maturity-model" },
      { label: "ASD, Essential Eight Assessment Process Guide (October 2024)", href: "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/essential-eight/essential-eight-assessment-process-guide" },
    ],
  },
  {
    id: "dora",
    title: "EU DORA",
    description:
      "How downpipes supports EU financial entities under the Digital Operational Resilience Act: the backup, recovery and integrity duties of Articles 9, 11 and 12, and recovery testing under Articles 24 to 26.",
    controls: [
      { control: "Art. 9(2)-(3)", obligation: "Protect availability, authenticity, integrity and confidentiality of data, including at rest.", capability: "Every archive encrypted at rest with hybrid post-quantum cryptography and sealed under a signature checked against a key you pinned; keys stay in your custody, and an optional operational key, if you install one, is held in your own Cloudflare account.", checkIds: ["encryption-pq-hybrid"] },
      { control: "Art. 11(4),(6)", obligation: "Maintain and periodically test continuity and response-and-recovery plans, at least yearly.", capability: "Restore drills with a dated evidence log, scheduled where an operational key is installed and attended where it is not; the offline reader covers the provider-unavailable scenario.", checkIds: ["restore-test-recency"] },
      { control: "Art. 12(1)", obligation: "Set backup policies specifying scope and minimum frequency by criticality, plus restoration procedures.", capability: "Per-dataset cadence and retention; the signed run log records what was backed up and when.", checkIds: ["destination-configured"] },
      { control: "Art. 12(2)", obligation: "Test backup, restoration and recovery periodically; activation must not jeopardise data.", capability: "Every restore is planned as a dry run first; a second approver can be required, which is optional and off by default; the integrity chain is verified before anything is trusted.", checkIds: ["restore-test-enabled"] },
      { control: "Art. 12(3)", obligation: "Restore using systems segregated from the source, protected from access and corruption.", capability: "Copies on an off-account destination sit outside the source account, in a region you choose, where the break-glass key never exists; an optional operational key, if you install one, is held in that account. A destination retention lock applies when you set one at a destination that enforces it. An in-account R2 bucket shares an account with the sources, so it is not the segregated copy.", checkIds: ["immutability"] },
      { control: "Art. 12(7)", obligation: "Build checks and reconciliations into recovery for the highest data integrity.", capability: "Each record SHA-384 hashed into a Merkle root and re-verified on the way back; a rollback to an older, validly signed run log is caught by the minimum-index pin from your recovery sheet.", checkIds: ["seal-verification"] },
      { control: "Art. 28(1),(3)", obligation: "Manage ICT third-party risk and maintain a register of contractual arrangements.", capability: "downpipes runs inside your account and holds nothing, so the deployed software is generally not an ongoing ICT service; you make that assessment.", checkIds: [] },
    ],
    sources: [
      { label: "Regulation (EU) 2022/2554 (DORA)", href: "https://eur-lex.europa.eu/eli/reg/2022/2554/oj/eng" },
      { label: "Commission Delegated Regulation (EU) 2024/1774 (RTS on ICT risk management)", href: "https://eur-lex.europa.eu/eli/reg_del/2024/1774/oj/eng" },
    ],
  },
  {
    id: "nis2",
    title: "EU NIS2",
    description:
      "How downpipes supports essential and important entities under the NIS2 Directive: the Article 21(2) risk-management measures, led by business continuity, backup management and disaster recovery.",
    controls: [
      { control: "Art. 21(2)(c)", obligation: "Business continuity, such as backup management and disaster recovery, and crisis management.", capability: "Verified restore drills with a dated evidence log, copies in a region you choose (off-account unless it is an in-account R2 bucket, and write-once where you set a destination retention lock), and an offline recovery path.", checkIds: ["restore-test-recency", "redundant-copies"] },
      { control: "Art. 21(2)(b)", obligation: "Incident handling.", capability: "A signed, append-only run log makes a rewrite, removal or fork within the log detectable, and a wholesale rollback to an older, validly signed log is caught by the minimum-index pin from your recovery sheet; the recovery path restores a clean copy.", checkIds: ["seal-verification"] },
      { control: "Art. 21(2)(d)", obligation: "Supply chain security, including the security of relationships with service providers.", capability: "Running in your account and holding nothing adds no data-holding supplier; the open reader removes any vendor recovery dependency; updates applied through the in-account update channel are verified against the release-signer key you pinned (UPDATE_SIGNER_PUBLIC) and the applied content hash is recorded in your own account; a deploy outside the channel is flagged by the version-drift check.", checkIds: ["break-glass-present", "update-apply-provenance"] },
      { control: "Art. 21(2)(f)", obligation: "Policies and procedures to assess the effectiveness of risk-management measures.", capability: "Repeatable recovery drills that verify the integrity chain and log the outcome.", checkIds: ["restore-test-enabled"] },
      { control: "Art. 21(2)(h)", obligation: "Policies and procedures on the use of cryptography and, where appropriate, encryption.", capability: "Archives sealed with hybrid post-quantum cryptography and signed against a key you pinned; keys stay in your custody.", checkIds: ["encryption-pq-hybrid"] },
      { control: "Art. 21(2)(i)", obligation: "Human resources security, access control policies and asset management.", capability: "Six-role RBAC. A prune applied from the console always needs a second approver; a second approver for a restore, or for a change to the scheduled prune policy, is optional and off by default.", checkIds: ["access-enforced", "two-owners"] },
      { control: "Art. 23", obligation: "Notify the CSIRT or competent authority of significant incidents within the timelines.", capability: "downpipes performs no regulatory notification; the tamper-evident logs help you evidence what happened.", checkIds: ["audit-export-available"] },
    ],
    sources: [{ label: "Directive (EU) 2022/2555 (NIS2)", href: "https://eur-lex.europa.eu/eli/dir/2022/2555/oj/eng" }],
  },
  {
    id: "eu-gdpr",
    title: "EU GDPR & data sovereignty",
    description:
      "How downpipes supports controllers and processors under GDPR Article 32 security of processing, and the data-sovereignty objective through in-region backups, customer-held keys and a no-custody design.",
    controls: [
      { control: "Art. 32(1)(c)", obligation: "Ensure the ability to restore availability and access to personal data in a timely manner after an incident.", capability: "Verified restore drills prove recovery, and the offline reader does it even when the platform is unreachable.", checkIds: ["restore-test-recency"] },
      { control: "Art. 32(1)(d)", obligation: "A process for regularly testing, assessing and evaluating the effectiveness of security measures.", capability: "Repeatable drills that verify the integrity chain and write a dated evidence log.", checkIds: ["restore-test-enabled"] },
      { control: "Art. 32(1)(b)", obligation: "Ensure ongoing confidentiality, integrity, availability and resilience of processing.", capability: "Per-record hashing into a signed Merkle root for integrity, and copies at a destination you choose for availability and resilience, off-account unless it is an in-account R2 bucket, write-once where you set a destination retention lock.", checkIds: ["immutability"] },
      { control: "Art. 32(1)(a)", obligation: "Pseudonymisation and encryption of personal data as appropriate to the risk.", capability: "Encryption at rest is hybrid post-quantum and on by default in every edition.", checkIds: ["encryption-pq-hybrid"] },
      { control: "Art. 5(1)(f)", obligation: "Protect against accidental loss, destruction or damage.", capability: "Encryption and customer-held keys protect confidentiality; the signed, content-addressed archive guards against accidental loss.", checkIds: ["dest-cred-encryption"] },
      { control: "Art. 5(1)(e)", obligation: "Storage limitation: keep personal data no longer than necessary.", capability: "Retention policy (keepRuns/keepDays) and a reviewed disposal log dispose of backup copies on the schedule you set, once pruning is switched from its default dry run to enforce.", checkIds: [] },
      { control: "Chapter V (Arts. 44-50)", obligation: "Lawful basis for transfers of personal data to a third country.", capability: "Backups can be pinned to an EU region you choose, so a backup copy need not become a third-country transfer.", checkIds: ["destination-configured"] },
      { control: "Art. 48", obligation: "A third-country disclosure order is recognisable only if based on an international agreement.", capability: "The vendor holds no data and no keys, so an order served on it returns nothing.", checkIds: [] },
    ],
    sources: [
      { label: "Regulation (EU) 2016/679 (GDPR)", href: "https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng" },
      { label: "Regulation (EU) 2019/881 (Cybersecurity Act)", href: "https://eur-lex.europa.eu/eli/reg/2019/881/oj/eng" },
    ],
  },
  {
    id: "nist-fedramp",
    title: "US NIST 800-53 & FedRAMP",
    description:
      "How downpipes supplies implementation evidence for NIST SP 800-53 Rev. 5 contingency-planning and data-protection controls, within a FedRAMP authorization boundary it does not replace.",
    controls: [
      { control: "CP-9", obligation: "System Backup: back up at the defined frequency and protect the confidentiality, integrity and availability of backups.", capability: "Encrypted backups at a destination you choose implement the control directly, off-account unless it is an in-account R2 bucket, write-once where you set a destination retention lock.", checkIds: ["destination-configured", "redundant-copies"] },
      { control: "CP-9(7)", obligation: "Dual Authorization for the deletion or destruction of backup information.", capability: "An attended prune applies only after a second authorised identity approves the exact plan. The scheduled prune runs only where an operational key is installed; arming Enforce for it is a configuration change, dual-controlled only when configuration approval is on, which is off by default.", checkIds: [] },
      { control: "CP-9(8)", obligation: "Cryptographic Protection to prevent unauthorised disclosure or modification of backups.", capability: "Hybrid post-quantum encryption protects from disclosure; a signature checked against a pinned key protects from modification.", checkIds: ["encryption-pq-hybrid"] },
      { control: "CP-10", obligation: "System Recovery and Reconstitution to a known state after disruption or compromise.", capability: "Verified recovery and the offline reader reconstitute data to a known-good, integrity-checked state.", checkIds: ["restore-test-enabled"] },
      { control: "CP-6", obligation: "Alternate Storage Site with controls equivalent to the primary site.", capability: "Copies land in a separate destination and region you choose; choose an off-account destination to keep them outside the source account.", checkIds: ["media-diversity"] },
      { control: "CP-4", obligation: "Contingency Plan Testing at the defined frequency.", capability: "Restore drills with a dated evidence log test the recovery step, scheduled where an operational key is installed and attended where it is not.", checkIds: ["restore-test-recency"] },
      { control: "AU-9", obligation: "Protection of Audit Information from unauthorised access, modification and deletion.", capability: "The signed, append-only run log, stored with the archive at your destination, makes modification or removal of the backup record detectable; a rollback to an older, validly signed log is caught by the minimum-index pin from your recovery sheet. The hash-chained audit log can be mirrored off-account.", checkIds: ["off-account-audit-mirror", "seal-verification"] },
      { control: "SC-28", obligation: "Protection of Information at Rest.", capability: "Backups are encrypted at rest with hybrid post-quantum cryptography; the integrity chain protects against silent alteration.", checkIds: ["encryption-pq-hybrid"] },
      { control: "SC-12", obligation: "Cryptographic Key Establishment and Management across the lifecycle.", capability: "Keys are generated on hardware you control, by the console ceremony in your browser or by the engine deploy on your own machine; the break-glass key stays offline with you; the vendor never holds it.", checkIds: ["break-glass-present"] },
    ],
    sources: [
      { label: "NIST SP 800-53 Rev. 5, Security and Privacy Controls", href: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final" },
      { label: "FedRAMP: scope of authorization", href: "https://www.fedramp.gov/docs/authority/scope/" },
    ],
  },
  {
    id: "sec-17a-4",
    title: "US SEC 17a-4",
    description:
      "How downpipes supports US broker-dealers under SEC Rule 17a-4: the retained WORM requirement and verified, producible, offline-readable records, and why the 2022 audit-trail alternative stays with you.",
    controls: [
      { control: "17a-4(f)(2)(i)(A)", obligation: "Audit-trail alternative: a complete, time-stamped record of every modification or deletion.", capability: "downpipes does not provide the audit-trail alternative for your records: it captures point-in-time copies at your cadence, not every change to a record. The signed run log records each run's creation time, record count and chain position, and keeps a pruned run's entry marked superseded; it does not record who pruned. The engine's hash-chained audit log names who changed configuration, ran a restore or pruned, and keeps the most recent 10,000 events.", checkIds: [] },
      { control: "17a-4(f)(2)(i)(B)", obligation: "WORM alternative: preserve records exclusively in a non-rewriteable, non-erasable format.", capability: "A destination retention lock set in compliance mode (S3 Object Lock, Google Cloud per-object retention or a locked Azure version-level immutability policy) over content-addressed, append-only archives. Governance mode does not meet this branch, because a principal holding the bypass permission can shorten or remove the window. Cloudflare R2 cannot enforce S3 Object Lock on any bucket, and downpipes neither sets nor reads R2's own bucket lock.", checkIds: ["immutability"] },
      { control: "17a-4(f)(2)(ii)", obligation: "Automatically verify the completeness and accuracy of the storage and retention processes.", capability: "Verification at seal is on unless it is switched off: each run's integrity chain is verified automatically and its seal checked against a key you pinned.", checkIds: ["seal-verification"] },
      { control: "17a-4(f)(2)(iv)", obligation: "Readily download and transfer a record and its audit trail in human-readable and electronic form.", capability: "The MIT-licensed reader reproduces records and the signed run log on any machine, human-readable and as the original bytes, using your break-glass key and the signer.pub from your recovery kit. While the signer that sealed a run is still current, the signer fingerprint from your recovery sheet can stand in for signer.pub.", checkIds: ["break-glass-present"] },
      { control: "17a-4(f)(2)(v)", obligation: "A backup recordkeeping system or other redundancy ensuring continued access.", capability: "Copies land at a destination you choose, off-account unless it is an in-account R2 bucket, and 3-2-1 failover keeps a redundant set.", checkIds: ["redundant-copies"] },
      { control: "17a-4(f)(3)(v)(A)", obligation: "File a signed undertaking with your examining authority to furnish records on request.", capability: "This is your filing duty, not the vendor's.", checkIds: [] },
      { control: "17a-4(a),(b)", obligation: "Retain the specified records for at least six years, or three years, as applicable.", capability: "Retention policy (keepRuns/keepDays) and a reviewed disposal log hold records for as long as you set. Pruning is a dry run until you switch it to enforce, so no run ages out of a retention window by default.", checkIds: [] },
    ],
    sources: [
      { label: "SEC Release No. 34-96034, Electronic Recordkeeping Requirements (87 FR 66412)", href: "https://www.govinfo.gov/content/pkg/FR-2022-11-03/html/2022-22670.htm" },
      { label: "17 CFR 240.17a-4, current text (eCFR)", href: "https://www.ecfr.gov/current/title-17/chapter-II/part-240/section-240.17a-4" },
    ],
  },
  {
    id: "soci-cirmp",
    title: "SOCI Act & CIRMP",
    description:
      "If your Cloudflare data stores hold business critical data, the SOCI Act deems them part of the critical asset itself: what that means for your CIRMP, recovery obligations and incident reporting.",
    controls: [
      { control: "CIRMP Rules s 8(4)", obligation: "Comply with a named cyber framework (Essential Eight ML1, ISO 27001, NIST CSF and others).", capability: "Implements the Regular Backups slice for KV, R2, D1, Secrets Store and configuration, with the mapping documented for your annual report.", checkIds: ["destination-configured"] },
      { control: "Enhanced CIRMP Rules 2026", obligation: "For nine specified asset classes only: a higher bar (Essential Eight ML2) plus explicit requirements to recover and restore critical systems, each deferred 24 months from the 10 June 2026 commencement, or from when the asset later comes into scope.", capability: "The ML2 access and modification controls are mapped; verified, off-platform, offline-restorable archives are recovery capability you can demonstrate.", checkIds: ["restore-test-enabled"] },
      { control: "SOCI Act s 9(7)", obligation: "A data storage system holding business critical data is taken to be part of the critical asset.", capability: "downpipes is the backup and recovery control you put against that in-scope estate.", checkIds: [] },
      { control: "CIRMP Rules s 6(f)", obligation: "Material risk to the availability, integrity, reliability or confidentiality of the data storage system.", capability: "Encrypted, integrity-verified, independently restorable backups mitigate exactly that risk.", checkIds: ["seal-verification"] },
      { control: "CIRMP Rules s 6(d)", obligation: "Material risk: the storage of sensitive operational information outside Australia.", capability: "You choose the destination, and its region is a setting of the bucket you create: an S3-compatible, Google Cloud or Azure Blob store in an Australian region keeps the copy in Australia. downpipes does not verify a destination's region.", checkIds: ["destination-configured"] },
      { control: "SOCI Act ss 30BC-30BD", obligation: "Report significant cyber incidents to ASD within 12 hours, others within 72 hours.", capability: "A verified restore point and a tamper-evident audit trail turn the report into evidence.", checkIds: ["restore-test-recency"] },
      { control: "SOCI Act s 30AG", obligation: "An annual, board-approved CIRMP report.", capability: "Drill evidence, retention status and run history export as-is.", checkIds: ["audit-export-available"] },
    ],
    sources: [
      { label: "Security of Critical Infrastructure Act 2018 (Cth)", href: "https://www.legislation.gov.au/C2018A00029/latest" },
      { label: "SOCI (Critical infrastructure risk management program) Rules (LIN 23/006)", href: "https://www.legislation.gov.au/F2023L00112/latest/text" },
    ],
  },
  {
    id: "ism",
    title: "ISM data backup & restoration controls",
    description:
      "The ISM's data backup and restoration controls and ASD's post-quantum cryptography controls, mapped to downpipes.",
    controls: [
      { control: "ISM-1547", obligation: "Data backup processes and supporting procedures are developed, implemented and maintained.", capability: "Declarative per-source configuration, scheduled runs, and operational runbooks you can hand to an assessor.", checkIds: ["destination-configured"] },
      { control: "ISM-1548", obligation: "Data restoration processes and supporting procedures are developed, implemented and maintained.", capability: "In-account restore, with a second approver when you turn that policy on (it is off by default), plus offline restore via the open reader; recovery instructions travel in the bucket.", checkIds: ["break-glass-present"] },
      { control: "ISM-1511", obligation: "Backups performed and retained in accordance with business criticality and continuity.", capability: "Per-source cadence and retention.", checkIds: ["restore-test-recency"] },
      { control: "ISM-1810", obligation: "Backups synchronised to enable restoration to a common point in time.", capability: "Each source is captured on its own schedule. A restore can be pinned to a timestamp you nominate: for each source, downpipes resolves the latest successful run completed at or before that moment. A backup is consistent per record, not across the whole account at a single instant.", checkIds: [] },
      { control: "ISM-1811", obligation: "Backups retained in a secure and resilient manner.", capability: "Post-quantum encryption under customer keys; content-addressed, append-only, isolated from production credentials.", checkIds: ["encryption-pq-hybrid"] },
      { control: "ISM-1812/1813", obligation: "Unprivileged accounts cannot access others' or their own backups.", capability: "A Cloudflare Access or passkey identity with no grant resolves to Viewer, which cannot read any record value, and a native SSO sign-in with no grant, invite or mapped group is refused; every higher role is an explicit grant behind SSO and passkeys, keyed to the stable subject of the sign-in (for a passkey, a subject that comes from its bound email) or to an IdP group you map, once the break-glass admin token is retired.", checkIds: ["access-enforced"] },
      { control: "ISM-1705/1706", obligation: "Privileged accounts (excluding backup administrators) cannot access others' or their own backups.", capability: "Credentials bind to the engine. The Viewer, Operator and Access admin roles carry no capability that reads a record value. Approver and Restore operator can apply a restore, which writes decrypted data to a target; turn on restore approval to make that need a second authorised identity (off by default). An in-account bucket still sits inside the account it protects, so Cloudflare account administrators keep their own route to it.", checkIds: ["dest-cred-encryption", "access-enforced"] },
      { control: "ISM-1814/1707", obligation: "Unprivileged and privileged accounts are prevented from modifying and deleting backups.", capability: "Within downpipes, disposal runs only through the retention planner, a dry run until an Operator or above switches it to enforce. A prune applied from the console always needs a second approver who is not the requester; the scheduled prune runs only where an operational key is installed, and a change to its policy needs a second approver only when configuration approval is on, which is off by default. Anyone with delete rights on the destination itself is outside downpipes' control; a compliance-mode retention lock prevents that deletion.", checkIds: ["access-enforced", "two-owners"] },
      { control: "ISM-1708", obligation: "Backup administrators are prevented from modifying and deleting backups during the retention period.", capability: "Append-only archives paired with a retention lock set in compliance mode at a destination that enforces one (S3 Object Lock, Google Cloud per-object retention or a locked Azure version-level immutability policy); governance mode can be lifted by a principal holding the bypass permission. Cloudflare R2 cannot enforce S3 Object Lock on any bucket, and downpipes neither sets nor reads R2's own bucket lock. The signed run log makes a rewrite within the log detectable; a wholesale rollback to an older, validly signed log is caught by the minimum-index pin from your recovery sheet.", checkIds: ["immutability"] },
      { control: "ISM-1515", obligation: "Restoration to a common point in time is tested as part of disaster recovery exercises.", capability: "Evidence-logged drills and real offline restore exercises that export into your DR records.", checkIds: ["restore-test-enabled"] },
      { control: "ISM-1917/1995/2073", obligation: "Support ML-DSA-87, ML-KEM-1024, SHA-384 and AES-256, and maintain a post-quantum transition plan.", capability: "Ships ML-DSA-87, ML-KEM-1024, SHA-384 and AES-256 today as the default and only mode; long-retention archives are sealed post-quantum now.", checkIds: ["encryption-pq-hybrid"] },
    ],
    sources: [
      { label: "ASD ISM, Guidelines for System Management (June 2026)", href: "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-system-management" },
      { label: "ASD ISM, Guidelines for Cryptography (June 2026)", href: "https://www.cyber.gov.au/business-government/asds-cyber-security-frameworks/ism/cyber-security-guidelines/guidelines-for-cryptography" },
    ],
  },
  {
    id: "privacy-act",
    title: "Privacy Act & APP 11",
    description:
      "APP 11 requires protecting personal information from loss and modification, and destroying it when no longer needed, including copies in backups. How downpipes supports both halves.",
    controls: [
      { control: "APP 11.1", obligation: "Take reasonable steps to protect personal information from loss and unauthorised access, modification or disclosure.", capability: "Encrypted, integrity-verified backups in storage you control are a demonstrable technical measure.", checkIds: ["encryption-pq-hybrid"] },
      { control: "APP 11.3 (Dec 2024)", obligation: "Reasonable steps include technical and organisational measures.", capability: "A governed backup capability: encryption, access control, audit logging and tested restoration.", checkIds: ["audit-export-available"] },
      { control: "APP 11.2", obligation: "Destroy or de-identify personal information once it is no longer needed.", capability: "Retention policy ages backup runs out on your schedule, once pruning is switched from its default dry run to enforce, with disposal that is planned and audit-logged; a prune applied from the console needs a second approver.", checkIds: [] },
      { control: "OAIC Guidelines para 11.39", obligation: "Destruction obligations cover all copies, including archived or back-up copies.", capability: "keepRuns/keepDays policy, a reviewable prune plan, and a log of what was disposed and when.", checkIds: [] },
      { control: "NDB scheme (Part IIIC)", obligation: "Assess suspected eligible data breaches within 30 days and notify where serious harm is likely.", capability: "Verified restore points bound the damage assessment; the audit chain evidences what happened and when.", checkIds: ["restore-test-recency"] },
    ],
    sources: [
      { label: "Privacy Act 1988 (Cth), Schedule 1: Australian Privacy Principles", href: "https://www.legislation.gov.au/C2004A03712/latest" },
      { label: "OAIC, APP Guidelines, Chapter 11: Security of personal information", href: "https://www.oaic.gov.au/privacy/australian-privacy-principles/australian-privacy-principles-guidelines/chapter-11-app-11-security-of-personal-information" },
    ],
  },
  {
    id: "uk-gdpr-caf",
    title: "UK GDPR & NCSC CAF",
    description:
      "How downpipes supports UK organisations under UK GDPR Article 32 and the NCSC Cyber Assessment Framework: restore-after-incident, regular testing, and the B5.c backups and D1 recovery outcomes.",
    controls: [
      { control: "Art. 32(1)(c)", obligation: "Restore availability and access to personal data in a timely manner after an incident.", capability: "Verified restore drills prove recovery; the offline reader restores from your own storage with your own key when the platform is unavailable.", checkIds: ["restore-test-recency"] },
      { control: "Art. 32(1)(d)", obligation: "Regularly test, assess and evaluate the effectiveness of security measures.", capability: "Drills verify the integrity chain and write a dated evidence log, scheduled where an operational key is installed and attended where it is not.", checkIds: ["restore-test-enabled"] },
      { control: "Art. 32(1)(b)", obligation: "Ensure ongoing confidentiality, integrity, availability and resilience.", capability: "A signed Merkle chain gives integrity; copies at a destination you choose give availability and resilience, off-account unless it is an in-account R2 bucket, write-once where you set a destination retention lock.", checkIds: ["seal-verification"] },
      { control: "Art. 5(1)(f)", obligation: "Protect against accidental loss, destruction or damage.", capability: "Encryption and customer-held keys, plus the signed, content-addressed archive.", checkIds: ["encryption-pq-hybrid"] },
      { control: "Art. 5(1)(e)", obligation: "Storage limitation: keep personal data no longer than necessary.", capability: "Retention policy and a reviewed disposal log dispose of backup copies on the schedule you set, once pruning is switched from its default dry run to enforce.", checkIds: [] },
      { control: "CAF B5.c", obligation: "Backups: accessible, secured, current, tested, documented and routinely reviewed.", capability: "Accessible, secured and tested backups with a documented recovery-drill log, at a destination you choose, off-account unless it is an in-account R2 bucket.", checkIds: ["redundant-copies"] },
      { control: "CAF B5.a", obligation: "Resilience preparation: be prepared to restore essential functions after an adverse impact.", capability: "The offline reader and the copies at your destination are the recovery capability the outcome depends on.", checkIds: ["break-glass-present"] },
      { control: "CAF B3.c", obligation: "Stored data protected from unauthorised access, modification or deletion.", capability: "Encryption and a tamper-evident run log that makes a change within it visible, with a destination retention lock when you set one at a destination that enforces it.", checkIds: ["immutability"] },
      { control: "CAF D1.b/D1.c", obligation: "Response and recovery capability, tested through exercises.", capability: "Trustworthy recoverable data and a clean restore path; recovery drills exercise and log the result.", checkIds: ["restore-test-enabled", "restore-test-recency"] },
      { control: "CAF D2.a", obligation: "Incident root cause analysis to inform remediation.", capability: "The signed, append-only run log is a tamper-evident record for the post-incident analysis.", checkIds: ["audit-export-available"] },
    ],
    sources: [
      { label: "UK GDPR (retained Regulation (EU) 2016/679), Article 32", href: "https://www.legislation.gov.uk/eur/2016/679/article/32" },
      { label: "NCSC Cyber Assessment Framework (CAF)", href: "https://www.ncsc.gov.uk/collection/cyber-assessment-framework" },
    ],
  },
  {
    id: "soc-2",
    title: "SOC 2",
    description:
      "How downpipes supports the Trust Services Criteria a service organisation evidences in a SOC 2 examination, for the backup and recovery of its Cloudflare data. downpipes is a control you operate; the SOC 2 report is yours to obtain.",
    controls: [
      { control: "CC6.1", obligation: "Logical access security over protected information assets.", capability: "SSO/passkey and role-based access control; Viewer/Operator tiers cannot read record values; destination credentials are envelope-encrypted at rest when CONFIG_WRAP_KEY is set, which the deploy installs.", checkIds: ["access-enforced", "dest-cred-encryption"] },
      { control: "CC6.7", obligation: "Restrict the transmission and movement of information to authorised users and processes.", capability: "Backups are sealed under customer keys before they leave the account; no plaintext on the wire.", checkIds: ["encryption-pq-hybrid"] },
      { control: "CC7.2", obligation: "Monitor for anomalies that could indicate security events.", capability: "A signed run log, failure alerts and the freshness high-water mark you record on your recovery sheet.", checkIds: ["seal-verification", "failure-alerts"] },
      { control: "A1.2", obligation: "Authorise, design and implement backup processes to meet availability objectives.", capability: "Scheduled backups with per-dataset cadence and retention, to a destination you choose, off-account unless it is an in-account R2 bucket.", checkIds: ["destination-configured", "redundant-copies"] },
      { control: "A1.3", obligation: "Test recovery-plan procedures supporting system recovery.", capability: "Restore drills with an exportable evidence log, scheduled where an operational key is installed and attended where it is not.", checkIds: ["restore-test-enabled", "restore-test-recency"] },
      { control: "C1.1 / C1.2", obligation: "Protect and dispose of confidential information per objectives.", capability: "Post-quantum encryption at rest, plus retention policy and audited disposal.", checkIds: ["encryption-pq-hybrid"] },
    ],
    sources: [{ label: "AICPA, Trust Services Criteria (2017, revised 2022)", href: "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services" }],
  },
];

// getFramework resolves a framework by id (the :framework path segment), or undefined when unknown.
export function getFramework(id: string): Framework | undefined {
  return FRAMEWORKS.find((f) => f.id === id);
}

// isFrameworkId is the runtime guard the route uses to reject an unknown framework id.
export function isFrameworkId(v: unknown): v is string {
  return typeof v === "string" && FRAMEWORKS.some((f) => f.id === v);
}

// frameworkIds lists every framework id (for the "all" pack and the console list).
export function frameworkIds(): string[] {
  return FRAMEWORKS.map((f) => f.id);
}
