-- A schema reached through the search path rather than by qualifying every name.
--
-- PostgreSQL resolves an unqualified reference through `search_path`, so a migration
-- that sets it once may then write bare names, and the policy target below is one.
-- The corpus carried no schema at all before this fixture, so nothing exercised that
-- resolution end to end.

CREATE SCHEMA app;
SET search_path TO app, public;

-- Unqualified, so the path puts it in `app`.
CREATE TABLE users (
    id UUID PRIMARY KEY,
    login TEXT NOT NULL UNIQUE
);

CREATE TABLE app.docs (
    id UUID PRIMARY KEY,
    owner_login TEXT NOT NULL REFERENCES app.users (login),
    title TEXT
);

-- A second schema holding a table of the same name, so resolution has to pick by path
-- order rather than by name alone.
CREATE SCHEMA archive;
CREATE TABLE archive.docs (
    id UUID PRIMARY KEY,
    owner_login TEXT
);

ALTER TABLE app.docs ENABLE ROW LEVEL SECURITY;
ALTER TABLE archive.docs ENABLE ROW LEVEL SECURITY;

-- The target is written bare. Only the path says which `docs` this guards, and it is
-- `app.docs` because `app` comes first.
CREATE POLICY docs_owner ON docs FOR SELECT USING (owner_login = current_setting('app.user_id'));

-- The other one is named in full, so both spellings appear in one schema.
CREATE POLICY archive_docs_owner ON archive.docs FOR SELECT
    USING (owner_login = current_setting('app.user_id'));
