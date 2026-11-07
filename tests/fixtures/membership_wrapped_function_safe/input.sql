CREATE TABLE docs (
  id UUID PRIMARY KEY,
  owner_id UUID
);

CREATE TABLE doc_members (
  doc_id UUID,
  user_id TEXT,
  member_id UUID,
  role TEXT
);

ALTER TABLE docs ENABLE ROW LEVEL SECURITY;

CREATE POLICY docs_wrapped_safe ON docs
FOR SELECT TO PUBLIC
USING (
  EXISTS (
    SELECT 1
    FROM doc_members dm
    WHERE dm.doc_id = docs.id
      AND dm.user_id = current_setting('app.user_id', true)
      AND lower(dm.role) = 'admin'
  )
);
