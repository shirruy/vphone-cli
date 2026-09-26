# Phase 5A Windows VM Runtime Foundation

Phase 5A establishes the native Windows runtime foundation contract.

It does not certify virtual iPhone guest boot.

Certified boundaries:

- Windows host architecture census
- ARM64 provider candidate census
- runtime provider contract
- fail-closed launch behavior
- Apple machine-model boundary
- inherited Phase 4 storage capability
- physical Windows Release build and tests
- exact-commit CI evidence

Until later Phase 5 work proves the guest runtime:

- boot_ready remains false
- Apple machine model remains unsupported
- launch remains fail-closed
- no Windows guest boot claim is permitted

Next gate:

Phase 5B ARM64 execution provider.