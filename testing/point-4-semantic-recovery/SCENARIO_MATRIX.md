# Point 4 Scenario Matrix

| Area | Scenario | Test |
| --- | --- | --- |
| Catalog completeness | Every vendored `env.json` host call resolves | `vendored_catalog_resolves_every_env_json_entry` |
| Catalog uniqueness | No duplicate `(module, name)` entries | `vendored_catalog_has_unique_module_name_pairs` |
| Catalog provenance | Version matches `soroban-env-common 26.1.2` | `catalog_version_tracks_vendored_source` |
| Core module coverage | Example calls from all 11 host modules resolve | `core_module_examples_cover_every_vendored_host_module` |
| Known matrix | 4096 deterministic known lookups resolve repeatedly | `deterministic_known_pair_matrix_resolves_repeatedly` |
| Unknown matrix | 4096 deterministic unknown pairs never false-positive | `deterministic_unknown_pair_matrix_does_not_false_positive` |
| Friendly IR rendering | Known host calls render friendly names | `dump_ir_renders_known_host_calls_as_friendly_names_and_unknown_as_raw` |
| Unknown IR fallback | Unknown host calls render raw `host:<module>:<name>` | `dump_ir_renders_known_host_calls_as_friendly_names_and_unknown_as_raw` |
| All-module IR rendering | One synthetic module exercises all 11 module examples | `dump_ir_renders_friendly_names_for_every_core_host_module_example` |
| Mixed scoring | 3 recognized of 5 host calls scores `0.6` | `coverage_json_scores_mixed_known_unknown_host_calls` |
| Unknown grouping | Repeated unknown pair is grouped with count `2` | `coverage_json_scores_mixed_known_unknown_host_calls` |
| All-known scoring | 11 recognized of 11 host calls scores `1.0` | `coverage_json_scores_all_core_module_examples_as_fully_recognized` |
| Text scoring | Text coverage lists unrecognized host calls and counts | `coverage_text_lists_unrecognized_host_calls_and_counts` |
| Zero denominator | No host calls yields JSON `ratio: null` | `coverage_json_uses_null_ratio_when_there_are_no_host_calls` |
| Local call separation | Local direct calls are excluded from host-call score | `coverage_json_scores_mixed_known_unknown_host_calls` |
