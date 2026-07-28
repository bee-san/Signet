ALTER TABLE production_users
ADD COLUMN role TEXT NOT NULL DEFAULT 'approver'
CHECK (role IN ('owner', 'approver'));

-- Earlier schemas admitted only the configured owner, so every predecessor row
-- is an owner during this one-way upgrade.
UPDATE production_users SET role = 'owner';

CREATE UNIQUE INDEX production_users_single_owner
ON production_users(role)
WHERE role = 'owner';
