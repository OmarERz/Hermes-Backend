-- Undo 0004. Without CASCADE: an object of another role that depends on these columns blocks the downgrade.
-- Dropping a column drops its CHECKs, foreign key and index; dropping the table drops its grants.
ALTER TABLE installed_software
  DROP COLUMN software_licence_id,
  DROP COLUMN description,
  DROP COLUMN status,
  DROP COLUMN itop_class;

DROP TABLE software_licence;

ALTER TABLE asset
  DROP COLUMN ram,
  DROP COLUMN cpu;
