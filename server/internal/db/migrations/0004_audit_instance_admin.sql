-- Marks events performed through instance administration: admin endpoints, instance
-- administrators acting in an organization they are not a member of, and global API tokens.
-- Organization members see these with the actor's identity, IP address and client hidden.
ALTER TABLE audit_logs ADD COLUMN instance_admin BOOLEAN NOT NULL DEFAULT false;
