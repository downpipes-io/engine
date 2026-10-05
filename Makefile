# Convenience targets for the engine. The authoritative gate is `npm run validate`; these wrap the
# additive test and demo entry points so they are discoverable and documented in one place.

.PHONY: demo validate test-runtime test-vitest test-property

# demo: the writer to reader end-to-end demo (the platform's moat, on real bytes). See docs/DEMO.md.
# Override the reader location with DOWNPIPE_REPO=/path/to/downpipe.
demo:
	bash scripts/e2e-writer-reader.sh

# validate: the authoritative cross-implementation validators (engine writer vs the Go vectors).
validate:
	npm run validate

# test-runtime: SchedulerDO concurrency invariants in a real workerd isolate (Miniflare).
test-runtime:
	npm run test:runtime

# test-vitest: the starter vitest-pool-workers suite exercising the Worker fetch entrypoint.
test-vitest:
	npm run test:vitest

# test-property: fast-check property tests over the crypto byte helpers and canonical JSON.
test-property:
	npm run test:property
