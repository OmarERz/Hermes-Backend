-- F15.9 (D-107, docs/datos/propuestas/cpe-mapping-parte-y-cna.md): the CPE part of the NVD pair (a application,
-- o operating system, h hardware) and content CHECKs on the CNA names, which exist since 0001 with their pair CHECKs.
-- One transaction: if a stored CNA name breaks the new CHECKs (the API never writes one), nothing is applied.

ALTER TABLE cpe_mapping ADD COLUMN nvd_part text;

-- Every mapping saved so far was rebuilt with part `a`; a CNA-only mapping has no NVD pair, so no part.
UPDATE cpe_mapping SET nvd_part = 'a' WHERE nvd_vendor IS NOT NULL;

ALTER TABLE cpe_mapping
  ADD CONSTRAINT cpe_mapping_nvd_part_check CHECK (nvd_part IN ('a', 'o', 'h')),
  ADD CONSTRAINT cpe_mapping_nvd_part_pair CHECK ((nvd_vendor IS NULL) = (nvd_part IS NULL)),
  -- 200: the limit the API applies (core.cpe.mapping.MAX_CNA_LENGTH)
  ADD CONSTRAINT cpe_mapping_cna_vendor_check CHECK (btrim(cna_vendor) <> '' AND char_length(cna_vendor) <= 200),
  ADD CONSTRAINT cpe_mapping_cna_product_check CHECK (btrim(cna_product) <> '' AND char_length(cna_product) <= 200);
