-- PostgreSQL's current_user keyword, which names the role a request acts as. Every request
-- of a deployment acting as one role reads the same name, so the rows the policy shows are
-- those whose manager is that role.

CREATE TABLE accounts (
    id SERIAL PRIMARY KEY,
    manager TEXT NOT NULL,
    company TEXT
);

ALTER TABLE accounts ENABLE ROW LEVEL SECURITY;

CREATE POLICY account_managers ON accounts
    FOR ALL TO PUBLIC
    USING (manager = current_user);
