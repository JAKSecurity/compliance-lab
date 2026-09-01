# Control Data Provenance

`nist-800-53-subset.yaml` is generated from the official NIST OSCAL catalog.  It contains the statement portions of 20 controls selected for this demonstration.  It is reference data for exercising retrieval and workflow behavior; it is not a complete control catalog, an overlay, an assessment procedure, or a compliance baseline.

## Pinned source

- Repository: `usnistgov/oscal-content`
- Tag: `v1.4.0`
- Commit: `bc8a528770033611df899b3d52703fb3dc91a20d`
- Catalog version: `5.2.0`
- OSCAL version: `1.1.3`
- Source XML SHA-256: `341f7dd2636b89b6d54b51fcf090e4cd18459b9e4ef4798f854f1a918023a650`
- Source path: `src/nist.gov/SP800-53/rev5/xml/NIST_SP-800-53_rev5_catalog.xml`
- Upstream license: NIST public domain and CC0 1.0

The generated YAML records the same provenance in its `source` mapping.  Organization-defined parameters are rendered as bracketed placeholders; the generator does not assign values to them.

## Rebuild

```bash
git clone --depth 1 --branch v1.4.0 https://github.com/usnistgov/oscal-content.git /tmp/oscal-content-v1.4.0
uv run python scripts/build_control_subset.py \
  /tmp/oscal-content-v1.4.0/src/nist.gov/SP800-53/rev5/xml/NIST_SP-800-53_rev5_catalog.xml \
  data/controls/nist-800-53-subset.yaml
```

The generator refuses to run if the source XML does not match the pinned SHA-256 digest.
