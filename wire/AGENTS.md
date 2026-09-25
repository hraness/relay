# Contents

- `wire/` pins the versioned contract: envelope shapes, authority tuples,
  command lifecycle states, bounds, and canonical test vectors.

# Guidelines

- Every wire value parses from `unknown` with exact key sets; unknown
  fields and stale revisions are rejected.
- Identifiers carry the product namespace (`<product>.relay.<name>.v<n>`);
  bump the version rather than mutating a shipped shape.
- Bounds live here once — payload bytes, pending commands per device,
  devices per user — and every layer enforces the same constants.
- Cross-language test vectors are the compatibility contract; changing a
  crypto or envelope field means regenerating vectors and updating both
  consumers in the same change.
