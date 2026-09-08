// PROOF DIGEST-COVERAGE: every field an audit entry CARRIES is a field the chain hash COMMITS TO.
//
// WHAT WAS VACUOUS, AND IT WAS PROVEN BY PLANT RATHER THAN READ OFF THE PAGE. auditHash's own doc
// comment claims "the hashed object includes prevHash and every field except hash, so each entry
// commits to ... its own content (tamper-evidence)". It does not hash every field. It rebuilds a
// HAND-KEPT ALLOWLIST of nine fields plus two conditionals, and the comment beside it presents
// "stable even if AuditEvent gains a field later" as a FEATURE. A field added later is outside the
// digest, and verifyChain recomputes with that SAME allowlist, so the verifier cannot notice.
//
// The declared second opinion did not close it either. validate-audit-independent-oracle.ts exists
// precisely so that "a field silently dropped from the hashed set" cannot hide behind a writer and a
// verifier that share a bug, and it imports neither auditHash nor verifyChain nor the product's
// canonicalJSON. But its hashed-field set is a VERBATIM MIRROR of the product's allowlist, typed out
// by hand. TWO HAND-KEPT LISTS THAT AGREE ARE ONE LIST: the oracle is independent in its ALGORITHM
// and identical in its SCOPE, so it catches a changed digest and cannot catch an unhashed field.
//
// So an audit entry could carry a forensic field ("who approved this") that the tamper-evident chain
// does not commit to, and every audit validator in the repo would report the log intact after that
// field was edited in storage. The audit log is the compliance artefact; "tamper-evident" is a claim
// made to customers, so a false green here is expensive.
//
// HOW THIS CLOSES IT, AND WHY IT IS NOT A THIRD LIST. The coverage set is DERIVED FROM THE RUNTIME
// OBJECT (Object.keys of an event built by the one constructor), never from a list kept here. Every
// field the event actually carries, except `hash` itself, must change the digest when perturbed. A
// field added to AuditEvent in future is therefore covered the moment buildEvent stamps it, with no
// edit to this file: if it is not folded into the digest, this goes red.
//
// TWO-SIDED BY CONSTRUCTION, so it cannot read as "everything is covered":
//   - the POSITIVE control re-hashes the UNPERTURBED event and requires it to equal the stored hash,
//     so a rig whose hashing path was dead cannot pass the treatment cells by hashing nothing;
//   - the NEGATIVE control perturbs `hash` itself and requires the digest NOT to move, because the
//     hash field is excluded by design. An auditHash that hashed the whole object indiscriminately
//     would fail this cell, so the two cells cannot both pass by accident.
//
// AND THE POPULATION IS ASSERTED, which is the other half of the same lesson: "no field is unhashed"
// is also true of an event with no fields. The floor below requires a real event shape before any
// coverage cell is allowed to count.

import { auditHash, buildEvent, type AuditDraft, type AuditEvent } from "../src/admin/audit.ts";
import type { Ctx } from "./validate-audit-harness.ts";

// The fields whose ABSENCE from the digest is a deliberate, documented decision. `hash` is the digest
// itself and cannot commit to its own value. Anything else that appears on an event and does not move
// the digest is a finding, not an entry for this set.
const DELIBERATELY_UNHASHED = new Set(["hash"]);

/**
 * perturb returns a value that is JSON-distinct from `original` for every shape an audit field takes.
 * A per-field sentinel string is used for all shapes: canonicalJSON accepts strings everywhere, and a
 * string can never equal the original number, null, object or differing string, so the perturbation is
 * guaranteed to be a real change rather than a coincidental no-op. The guarantee is ASSERTED below
 * rather than assumed, because a perturbation that did not perturb would make every cell pass.
 */
function perturb(field: string, original: unknown): unknown {
  const sentinel = `vacuity-perturbed-${field}`;
  return original === sentinel ? `${sentinel}-2` : sentinel;
}

export async function runDigestCoverage(ctx: Ctx): Promise<void> {
  const { ok } = ctx;

  // A draft carrying BOTH optional fields, so actorSubject and advisory are present on the built
  // event and therefore enter the derived coverage set. An event built without them would silently
  // shrink the population this proof walks.
  const draft: AuditDraft = {
    actorSubject: "https://idp.example.test|subject-1",
    actorEmail: "owner@example.test",
    actorMethod: "access",
    sourceIp: "203.0.113.7",
    action: "restore-apply",
    outcome: "success",
    target: { kind: "run", runId: "01J0000000000000000000000A" },
    advisory: { acr: "urn:mace:incommon:iap:silver", amr: ["pwd", "otp"], authTime: 1786492800 },
  };
  const genesis = await buildEvent(
    { actorEmail: null, actorMethod: "engine", sourceIp: null, action: "engine-version-change", outcome: "success", target: { kind: "downpipe", id: "dp-vacuity" } },
    1,
    "2026-08-12T00:00:00.000Z",
    null,
  );
  const event = await buildEvent(draft, 2, "2026-08-12T00:00:01.000Z", genesis);

  // ---- POPULATION FLOOR ---------------------------------------------------------------------
  // Asserted before any coverage cell, because "no field is unhashed" holds over an event with no
  // fields. These are a floor on the SHAPE, not a list of the fields: they must not have to be
  // edited when AuditEvent gains a field, or this file becomes the third hand-kept list.
  const fields = Object.keys(event).sort();
  ok(`the built event carries a real field population (${fields.length} fields: ${fields.join(", ")})`, fields.length >= 10);
  ok("the built event carries its own chain fields (hash and prevHash)", fields.includes("hash") && fields.includes("prevHash"));
  ok("both OPTIONAL fields are present on this event, so the coverage walk reaches them", fields.includes("actorSubject") && fields.includes("advisory"));
  ok("the stored hash is a sha384 digest, so there is a real digest to move", /^sha384:[0-9a-f]{96}$/.test(event.hash));

  // ---- POSITIVE CONTROL: the rig's own hashing path is live ----------------------------------
  // Without this, an auditHash that threw or returned a constant would let every treatment cell
  // below pass while measuring nothing.
  const rehashed = await auditHash(event);
  ok("CONTROL: re-hashing the UNPERTURBED event reproduces its stored hash (the rig hashes for real)", rehashed === event.hash);

  // ---- NEGATIVE CONTROL: `hash` is excluded by design ----------------------------------------
  // The matched control for the treatment cells. If this FAILED, auditHash would be hashing the whole
  // object indiscriminately and the treatment cells would pass for the wrong reason.
  {
    const withMovedHash = { ...event, hash: `${event.hash.slice(0, -1)}${event.hash.endsWith("a") ? "b" : "a"}` } as AuditEvent;
    ok("CONTROL: perturbing `hash` itself does NOT move the digest (it is excluded by design)", (await auditHash(withMovedHash)) === event.hash);
  }

  // ---- TREATMENT: every field the event CARRIES must move the digest -------------------------
  // Derived from Object.keys(event), so a field added to AuditEvent later is walked automatically.
  let walked = 0;
  let uncommitted: string[] = [];
  for (const field of fields) {
    if (DELIBERATELY_UNHASHED.has(field)) continue;
    const original = (event as unknown as Record<string, unknown>)[field];
    const replacement = perturb(field, original);
    // A perturbation that did not perturb would make the cell pass while testing nothing.
    ok(
      `the perturbation of \`${field}\` is a real change (JSON-distinct from the original)`,
      JSON.stringify(replacement) !== JSON.stringify(original),
    );
    const mutated = { ...(event as unknown as Record<string, unknown>), [field]: replacement } as unknown as AuditEvent;
    const moved = (await auditHash(mutated)) !== event.hash;
    walked++;
    if (!moved) uncommitted.push(field);
    ok(`the chain hash COMMITS TO \`${field}\` (perturbing it moves the digest)`, moved);
  }

  // The walk itself must have happened. A loop over an empty field set would print no treatment cell
  // at all and leave the section looking clean, which is the exact shape this proof exists to refuse.
  ok(`the coverage walk examined every carried field except the excluded ones (${walked} walked, ${fields.length} carried, ${DELIBERATELY_UNHASHED.size} excluded)`, walked === fields.length - DELIBERATELY_UNHASHED.size && walked >= 9);
  ok(
    `NO field an audit entry carries is outside the tamper-evident digest${uncommitted.length === 0 ? "" : ` (uncommitted: ${uncommitted.join(", ")})`}`,
    uncommitted.length === 0,
  );
}
