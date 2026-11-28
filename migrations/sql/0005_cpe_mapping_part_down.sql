-- Undo 0005. Without CASCADE: an object of another role that depends on the column blocks the downgrade.
-- The CNA names stay (they exist since 0001); only their content CHECKs and the CPE part go.
ALTER TABLE cpe_mapping
  DROP CONSTRAINT cpe_mapping_cna_product_check,
  DROP CONSTRAINT cpe_mapping_cna_vendor_check,
  DROP CONSTRAINT cpe_mapping_nvd_part_pair,
  DROP CONSTRAINT cpe_mapping_nvd_part_check,
  DROP COLUMN nvd_part;
