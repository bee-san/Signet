ALTER TABLE schema_cache
    ADD COLUMN present INTEGER NOT NULL DEFAULT 1 CHECK (present IN (0, 1));

CREATE INDEX schema_cache_presence_idx
    ON schema_cache(downstream_alias, present, review_state, tool_name);
