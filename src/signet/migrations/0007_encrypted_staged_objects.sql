CREATE TABLE staged_objects (
    attachment_id TEXT PRIMARY KEY,
    adapter TEXT NOT NULL,
    account TEXT NOT NULL,
    filename TEXT NOT NULL,
    declared_mime TEXT NOT NULL,
    detected_mime TEXT NOT NULL,
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0),
    sha256 TEXT NOT NULL CHECK (length(sha256) = 64),
    storage_path TEXT UNIQUE,
    envelope_format TEXT NOT NULL,
    envelope_size INTEGER NOT NULL CHECK (envelope_size > 0),
    envelope_sha256 TEXT NOT NULL CHECK (length(envelope_sha256) = 64),
    encryption_key_ref TEXT,
    created_at INTEGER NOT NULL CHECK (created_at >= 0),
    consumed_request_id TEXT,
    consumed_at INTEGER,
    purged_at INTEGER,
    key_destroyed_at INTEGER,
    FOREIGN KEY (consumed_request_id) REFERENCES approval_requests(request_id)
        ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED,
    CHECK ((consumed_request_id IS NULL) = (consumed_at IS NULL)),
    CHECK ((storage_path IS NULL) = (purged_at IS NOT NULL)),
    CHECK (
        (key_destroyed_at IS NULL) OR
        (encryption_key_ref IS NULL AND storage_path IS NULL)
    ),
    CHECK (
        storage_path IS NULL OR
        (encryption_key_ref IS NOT NULL AND key_destroyed_at IS NULL)
    )
) STRICT;

CREATE INDEX staged_objects_consumption_idx
    ON staged_objects(consumed_request_id, purged_at, created_at);

CREATE TRIGGER attachments_require_encrypted_catalog
BEFORE INSERT ON attachments
FOR EACH ROW
WHEN NOT EXISTS (
    SELECT 1 FROM staged_objects AS staged
    WHERE staged.attachment_id = NEW.attachment_id
      AND staged.filename = NEW.filename
      AND staged.declared_mime = NEW.mime_type
      AND staged.size_bytes = NEW.size_bytes
      AND staged.sha256 = NEW.sha256
      AND staged.storage_path = NEW.storage_path
      AND staged.purged_at IS NULL
      AND staged.encryption_key_ref IS NOT NULL
)
BEGIN
    SELECT RAISE(ABORT, 'attachment encrypted catalog mismatch');
END;

CREATE TRIGGER attachments_enforce_single_request_owner
BEFORE INSERT ON attachments
FOR EACH ROW
WHEN EXISTS (
    SELECT 1 FROM staged_objects AS staged
    WHERE staged.attachment_id = NEW.attachment_id
      AND staged.consumed_request_id IS NOT NULL
      AND staged.consumed_request_id != NEW.request_id
)
BEGIN
    SELECT RAISE(ABORT, 'staged object is already consumed');
END;

CREATE TRIGGER attachments_claim_staged_object
AFTER INSERT ON attachments
FOR EACH ROW
BEGIN
    UPDATE staged_objects
    SET consumed_request_id = COALESCE(consumed_request_id, NEW.request_id),
        consumed_at = COALESCE(consumed_at, NEW.created_at)
    WHERE attachment_id = NEW.attachment_id;
END;

CREATE TRIGGER attachments_require_catalog_path_update
BEFORE UPDATE OF storage_path ON attachments
FOR EACH ROW
WHEN NEW.storage_path IS NOT NULL AND NOT EXISTS (
    SELECT 1 FROM staged_objects AS staged
    WHERE staged.attachment_id = NEW.attachment_id
      AND staged.storage_path = NEW.storage_path
      AND staged.purged_at IS NULL
)
BEGIN
    SELECT RAISE(ABORT, 'attachment encrypted catalog path mismatch');
END;

CREATE TRIGGER staged_objects_immutable_context
BEFORE UPDATE OF
    attachment_id, adapter, account, filename, declared_mime, detected_mime,
    size_bytes, sha256, envelope_format, envelope_size, envelope_sha256,
    created_at, consumed_request_id, consumed_at
ON staged_objects
FOR EACH ROW
WHEN
    OLD.attachment_id IS NOT NEW.attachment_id OR
    OLD.adapter IS NOT NEW.adapter OR
    OLD.account IS NOT NEW.account OR
    OLD.filename IS NOT NEW.filename OR
    OLD.declared_mime IS NOT NEW.declared_mime OR
    OLD.detected_mime IS NOT NEW.detected_mime OR
    OLD.size_bytes IS NOT NEW.size_bytes OR
    OLD.sha256 IS NOT NEW.sha256 OR
    OLD.envelope_format IS NOT NEW.envelope_format OR
    OLD.envelope_size IS NOT NEW.envelope_size OR
    OLD.envelope_sha256 IS NOT NEW.envelope_sha256 OR
    OLD.created_at IS NOT NEW.created_at OR
    NOT (
        (OLD.consumed_request_id IS NEW.consumed_request_id AND
         OLD.consumed_at IS NEW.consumed_at) OR
        (OLD.consumed_request_id IS NULL AND OLD.consumed_at IS NULL AND
         NEW.consumed_request_id IS NOT NULL AND NEW.consumed_at IS NOT NULL)
    )
BEGIN
    SELECT RAISE(ABORT, 'staged object immutable context changed');
END;

CREATE TRIGGER staged_objects_control_key_destruction
BEFORE UPDATE OF encryption_key_ref, key_destroyed_at ON staged_objects
FOR EACH ROW
WHEN NOT (
    (OLD.encryption_key_ref IS NEW.encryption_key_ref AND
     OLD.key_destroyed_at IS NEW.key_destroyed_at) OR
    (OLD.encryption_key_ref IS NOT NULL AND NEW.encryption_key_ref IS NULL AND
     OLD.key_destroyed_at IS NULL AND NEW.key_destroyed_at IS NOT NULL AND
     NEW.storage_path IS NULL AND NEW.purged_at IS NOT NULL)
)
BEGIN
    SELECT RAISE(ABORT, 'staged object key transition is invalid');
END;
