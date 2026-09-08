# Governance and licensing

## Licensing model

This repository is part of the downpipes platform and is licensed under the **Elastic License v2 (ELv2)**. ELv2 is source-available: you can read the source, modify it, and self-host it in your own Cloudflare account for free, including for commercial use. The single restriction is that you may not offer the platform to third parties as a hosted or managed service that competes with the maintainers. That suits downpipes exactly, because the product is built to run inside the customer's own account under the customer's own keys, not to be resold as someone else's backup service.

The separate offline reader and library (the `downpipe` repository) is **MIT**, deliberately and permanently. A customer has to be able to verify and restore their own backups with no dependency on the vendor or on any network, now or years from now. A permissive reader is what makes that recover-forever promise real, so it stays MIT even though the platform is ELv2.

This split is an intentional departure from a single AGPL licence. AGPL would not prevent a competing hosted service the way ELv2 does, and it would be the wrong choice for a reader that customers must be free to run forever.

## Code of conduct

Contributions are governed by the Contributor Covenant. See `CODE_OF_CONDUCT.md`.
