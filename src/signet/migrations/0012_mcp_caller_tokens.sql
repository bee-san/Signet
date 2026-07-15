CREATE TABLE mcp_caller_tokens (
    token_id TEXT PRIMARY KEY CHECK (
        length(token_id) = 16 AND
        token_id NOT GLOB '*[^A-Za-z0-9_-]*'
    ),
    origin_namespace TEXT NOT NULL CHECK (
        length(origin_namespace) BETWEEN 3 AND 160 AND
        origin_namespace NOT GLOB '*[^A-Za-z0-9:._-]*'
    ),
    verifier TEXT NOT NULL CHECK (
        length(verifier) = 71 AND
        substr(verifier, 1, 7) = 'sha256$' AND
        substr(verifier, 8) NOT GLOB '*[^0-9a-f]*'
    ),
    allowed_aliases_json TEXT NOT NULL CHECK (
        length(allowed_aliases_json) BETWEEN 5 AND 2048 AND
        json_valid(allowed_aliases_json) AND
        json_type(allowed_aliases_json) = 'array' AND
        json_array_length(allowed_aliases_json) BETWEEN 1 AND 16
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    revoked_at INTEGER CHECK (revoked_at IS NULL OR revoked_at >= created_at),
    rotation_of_token_id TEXT CHECK (
        rotation_of_token_id IS NULL OR rotation_of_token_id != token_id
    ),
    FOREIGN KEY (rotation_of_token_id) REFERENCES mcp_caller_tokens(token_id)
        ON DELETE RESTRICT
) STRICT;

CREATE INDEX mcp_caller_tokens_namespace_idx
    ON mcp_caller_tokens(origin_namespace, revoked_at, created_at, token_id);

CREATE UNIQUE INDEX mcp_caller_tokens_active_rotation_idx
    ON mcp_caller_tokens(rotation_of_token_id)
    WHERE rotation_of_token_id IS NOT NULL AND revoked_at IS NULL;

CREATE TRIGGER mcp_caller_tokens_validate_insert
BEFORE INSERT ON mcp_caller_tokens
FOR EACH ROW
WHEN
    EXISTS (
        SELECT 1 FROM json_each(NEW.allowed_aliases_json)
        WHERE type != 'text' OR
              length(value) NOT BETWEEN 1 AND 64 OR
              value NOT GLOB '[a-z]*' OR
              value GLOB '*[^a-z0-9_-]*'
    ) OR
    EXISTS (
        SELECT value FROM json_each(NEW.allowed_aliases_json)
        GROUP BY value HAVING count(*) != 1
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid MCP caller token aliases');
END;

CREATE TRIGGER mcp_caller_tokens_validate_rotation_insert
BEFORE INSERT ON mcp_caller_tokens
FOR EACH ROW
WHEN
    NEW.rotation_of_token_id IS NOT NULL AND
    NOT EXISTS (
        SELECT 1
        FROM mcp_caller_tokens AS parent
        WHERE parent.token_id = NEW.rotation_of_token_id AND
              parent.revoked_at IS NULL AND
              parent.origin_namespace = NEW.origin_namespace AND
              parent.allowed_aliases_json = NEW.allowed_aliases_json AND
              NEW.created_at >= parent.created_at
    )
BEGIN
    SELECT RAISE(ABORT, 'invalid MCP caller token rotation context');
END;

CREATE TRIGGER mcp_caller_tokens_immutable_identity
BEFORE UPDATE ON mcp_caller_tokens
FOR EACH ROW
WHEN
    OLD.token_id IS NOT NEW.token_id OR
    OLD.origin_namespace IS NOT NEW.origin_namespace OR
    OLD.verifier IS NOT NEW.verifier OR
    OLD.allowed_aliases_json IS NOT NEW.allowed_aliases_json OR
    OLD.created_at IS NOT NEW.created_at OR
    OLD.rotation_of_token_id IS NOT NEW.rotation_of_token_id OR
    (OLD.revoked_at IS NOT NULL AND OLD.revoked_at IS NOT NEW.revoked_at)
BEGIN
    SELECT RAISE(ABORT, 'MCP caller token identity is immutable');
END;

CREATE TRIGGER mcp_caller_tokens_no_delete
BEFORE DELETE ON mcp_caller_tokens
BEGIN
    SELECT RAISE(ABORT, 'MCP caller token records are retained');
END;
