-- Trigger and helper functions resolve unqualified names at run time: pin a trusted search_path (temporary
-- schema last) so a session cannot redirect integrity checks to its own temporary tables.
ALTER FUNCTION check_formula_weights_of(uuid) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_formula_weights() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_activated_version() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION lock_formula_version() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_formula_levels_of(uuid,text) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_formula_levels() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_urgency_bands_of(uuid) SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_urgency_bands() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_finding_product() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_product_locked() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_ticket_finding_group() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION check_group_locked() SET search_path = pg_catalog, public, pg_temp;
ALTER FUNCTION normalize_text(text) SET search_path = pg_catalog, public, pg_temp;
