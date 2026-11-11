"""The database contract, versioned as one unit.

The three namespaces - traust (domain), traust_ops (operations),
traust_ledger (proof) - are mutually recursive (run_order references domain
tables; assessment references run_order), so they ship, upgrade and stamp
under a single db version. Each namespace owns its directory under
db/<version>/ and its loader module; this module owns the version itself.
"""

from __future__ import annotations

CONTRACT_VERSION = "v1"

#: Database schema revision, stamped on open. The previous projection model
#: was never released as a contract: its revisions died with it, and the
#: earlier standalone ledger went the same way. Databases created under
#: either are recreated, not migrated.
#: 1: baseline of the one-owner data model - traust, traust_ops, traust_ledger.
REVISION = 1
