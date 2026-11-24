ALTER TABLE notes ADD COLUMN created_at timestamptz NOT NULL DEFAULT now();
