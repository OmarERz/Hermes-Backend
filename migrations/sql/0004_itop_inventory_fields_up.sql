-- F18.3 (D-088, docs/datos/propuestas/inventario-itop.md): CPU and RAM of hosts, the category, status,
-- description and licence of each software installation, and the iTop software licences (never their key).
-- Every new column accepts NULL: existing rows are left untouched and the next inventory sync fills them.

ALTER TABLE asset
  ADD COLUMN cpu text,
  ADD COLUMN ram text,
  ADD CONSTRAINT asset_cpu_check CHECK (btrim(cpu) <> '' AND char_length(cpu) <= 255),
  ADD CONSTRAINT asset_ram_check CHECK (btrim(ram) <> '' AND char_length(ram) <= 255);

CREATE TABLE software_licence (
  id uuid DEFAULT uuidv7() NOT NULL,
  itop_licence_id text NOT NULL,
  software_product_id uuid,
  name text NOT NULL,
  usage_limit text,
  start_date date,
  end_date date,
  perpetual boolean NOT NULL,
  synced_at timestamptz NOT NULL,
  removed_at timestamptz,
  CONSTRAINT software_licence_pkey PRIMARY KEY (id),
  CONSTRAINT software_licence_itop_licence_id_key UNIQUE (itop_licence_id),
  CONSTRAINT software_licence_software_product_id_fkey
    FOREIGN KEY (software_product_id) REFERENCES software_product (id),
  CONSTRAINT software_licence_name_check CHECK (btrim(name) <> '' AND char_length(name) <= 255),
  CONSTRAINT software_licence_usage_limit_check
    CHECK (btrim(usage_limit) <> '' AND char_length(usage_limit) <= 255)
);
-- Every foreign key has a full index (capa 2 convention of 0001)
CREATE INDEX software_licence_software_product_id_fkey_idx ON software_licence (software_product_id);

ALTER TABLE installed_software
  ADD COLUMN itop_class text,
  ADD COLUMN status text,
  ADD COLUMN description text,
  ADD COLUMN software_licence_id uuid,
  ADD CONSTRAINT installed_software_itop_class_check
    CHECK (itop_class IN ('DBServer', 'Middleware', 'OtherSoftware', 'PCSoftware', 'WebServer')),
  ADD CONSTRAINT installed_software_status_check CHECK (status IN ('active', 'inactive')),
  ADD CONSTRAINT installed_software_software_licence_id_fkey
    FOREIGN KEY (software_licence_id) REFERENCES software_licence (id);
CREATE INDEX installed_software_software_licence_id_fkey_idx ON installed_software (software_licence_id);

-- app: CRUD like the other inventory tables (model v1 §17); the sync itself only soft-deletes
GRANT SELECT, INSERT, UPDATE, DELETE ON software_licence TO app;
