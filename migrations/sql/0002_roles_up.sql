-- Least-privilege grants on data model v1 (model v1 §16-§17, A-14). Runs as migrator, the owner of every
-- object created by 0001. The roles and the schema ownership come from migrations/provision.sql.

DO $$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['migrator', 'app', 'retention', 'slack_module'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      RAISE EXCEPTION 'role % is missing: run migrations/provision.sql first', r;
    ELSIF shobj_description((SELECT oid FROM pg_roles WHERE rolname = r), 'pg_authid') IS DISTINCT FROM 'hermes-managed' THEN
      RAISE EXCEPTION 'role % is not managed by Hermes', r;
    END IF;
  END LOOP;
END $$;

-- app (API and workers): CRUD on the model's tables only, read on its views
GRANT SELECT, INSERT, UPDATE, DELETE ON
  actor,
  actor_alias,
  alert,
  alert_asset,
  app_user,
  assessment,
  asset,
  asset_score,
  audit_log,
  calibration_proposal,
  claim,
  company_profile,
  correlation,
  correlation_match_type,
  cpe_mapping,
  cve,
  cve_affected_range,
  cve_analysis,
  cve_cwe,
  cve_reference,
  cve_reference_tag,
  cve_workaround,
  daily_metric,
  epss_score,
  error_queue,
  feedback,
  finding,
  finding_exclusion,
  finding_group,
  finding_status_change,
  formula_decay_step,
  formula_level,
  formula_reason_range,
  formula_urgency_band,
  formula_version,
  formula_weight,
  installed_software,
  ioc,
  ioc_cve,
  itop_outbox,
  judge_ladder_change,
  judge_reason,
  judge_reason_type,
  kev_entry,
  llm_review,
  mitigation_draft_step,
  news_actor_mention,
  news_analysis,
  news_attack_vector,
  news_cve_mention,
  news_product_mention,
  news_victim,
  notification_event,
  peer_company,
  peer_company_alias,
  person,
  profile_country,
  profile_sector,
  raw_article,
  review_package,
  run,
  sector,
  setting_definition,
  setting_option,
  setting_value,
  software_product,
  source,
  source_fetch,
  story,
  suppression,
  team,
  ticket,
  ticket_finding,
  ticket_update,
  verified_relationship
TO app;
GRANT SELECT ON
  actor_activity,
  asset_score_detail,
  data_mitigation,
  finding_current,
  finding_group_status,
  inventory_issue,
  judge_ladder_current,
  llm_usage_daily,
  remediation_time,
  setting_current,
  source_health,
  source_reliability,
  story_timeline,
  ticket_score
TO app;
-- append-only tables: no UPDATE or DELETE (retention excepted, through purge_retention)
REVOKE UPDATE, DELETE ON audit_log, finding_status_change, assessment, asset_score, llm_review, judge_reason FROM app;
-- deleting a package nulls llm_review.review_package_id (A-1): only the retention purge may do it
REVOKE DELETE ON review_package FROM app;

-- Functions of 0001: PUBLIC does not execute them; app needs them (triggers and index expressions).
REVOKE EXECUTE ON FUNCTION check_formula_weights_of(uuid), check_formula_weights(), check_activated_version(), lock_formula_version(), check_formula_levels_of(uuid,text), check_formula_levels(), check_urgency_bands_of(uuid), check_urgency_bands(), check_finding_product(), check_product_locked(), check_ticket_finding_group(), check_group_locked(), normalize_text(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION check_formula_weights_of(uuid), check_formula_weights(), check_activated_version(), lock_formula_version(), check_formula_levels_of(uuid,text), check_formula_levels(), check_urgency_bands_of(uuid), check_urgency_bands(), check_finding_product(), check_product_locked(), check_ticket_finding_group(), check_group_locked(), normalize_text(text) TO app;

-- retention (nightly job): only the operations of §16, through SECURITY DEFINER functions that
-- touch eligible rows only (delivered or finished, and older than the configured window).
-- Setting keys retention.* are proposed names; F0.6 seeds them in setting_definition.
CREATE FUNCTION retention_days(setting text, fallback int) RETURNS int LANGUAGE sql STABLE
RETURN COALESCE((SELECT (value #>> '{}')::int FROM setting_current WHERE setting_key = setting), fallback);

CREATE FUNCTION purge_retention() RETURNS TABLE (step text, affected bigint)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE n bigint;
BEGIN
  UPDATE raw_article SET clean_text = NULL
   WHERE clean_text IS NOT NULL AND captured_at < now() - make_interval(days => retention_days('retention.clean_text_days', 180));
  GET DIAGNOSTICS n = ROW_COUNT; step := 'raw_article.clean_text'; affected := n; RETURN NEXT;

  UPDATE llm_review SET calls = '[]'::jsonb
   WHERE calls <> '[]'::jsonb AND created_at < now() - make_interval(days => retention_days('retention.review_days', 365));
  GET DIAGNOSTICS n = ROW_COUNT; step := 'llm_review.calls'; affected := n; RETURN NEXT;

  DELETE FROM error_queue e USING review_package p
   WHERE e.review_package_id = p.id AND e.status IN ('resolved', 'gave_up')
     AND p.built_at < now() - make_interval(days => retention_days('retention.review_days', 365));
  -- a package still referenced by pending work (error_queue) is kept; everything else proceeds
  DELETE FROM review_package p
   WHERE p.built_at < now() - make_interval(days => retention_days('retention.review_days', 365))
     AND NOT EXISTS (SELECT 1 FROM error_queue e WHERE e.review_package_id = p.id);
  GET DIAGNOSTICS n = ROW_COUNT; step := 'review_package'; affected := n; RETURN NEXT;

  DELETE FROM notification_event
   WHERE status = 'delivered' AND delivered_at < now() - make_interval(days => retention_days('retention.delivered_days', 90));
  GET DIAGNOSTICS n = ROW_COUNT; step := 'notification_event'; affected := n; RETURN NEXT;

  DELETE FROM itop_outbox
   WHERE status = 'done' AND done_at < now() - make_interval(days => retention_days('retention.delivered_days', 90));
  GET DIAGNOSTICS n = ROW_COUNT; step := 'itop_outbox'; affected := n; RETURN NEXT;
END $$;
ALTER FUNCTION purge_retention() OWNER TO migrator;
ALTER FUNCTION retention_days(text, int) OWNER TO migrator;
REVOKE ALL ON FUNCTION purge_retention(), retention_days(text, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION purge_retention() TO retention;


-- slack_module: only its slack_* tables (outside this model) and the views the contract agrees on.
-- Nothing is granted yet.
