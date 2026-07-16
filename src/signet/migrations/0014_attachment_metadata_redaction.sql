CREATE TABLE attachment_metadata_privacy_maintenance (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    pending INTEGER NOT NULL CHECK (pending IN (0, 1))
) STRICT;

INSERT INTO attachment_metadata_privacy_maintenance(singleton, pending)
SELECT 1, EXISTS(
    SELECT 1 FROM staged_objects
    WHERE purged_at IS NOT NULL AND (
        adapter != '<redacted>' OR account != '<redacted>' OR
        filename != '<redacted>' OR declared_mime != 'application/octet-stream' OR
        detected_mime != 'application/octet-stream' OR size_bytes != 0 OR
        sha256 != printf('%064d', 0) OR envelope_size != 1 OR
        envelope_sha256 != printf('%064d', 0)
    )
) OR EXISTS(
    SELECT 1 FROM attachments
    WHERE purged_at IS NOT NULL AND (
        filename != '<redacted>' OR mime_type != 'application/octet-stream' OR
        size_bytes != 0 OR sha256 != printf('%064d', 0)
    )
);

DROP TRIGGER staged_objects_immutable_context;

CREATE TRIGGER staged_objects_immutable_context
BEFORE UPDATE OF
    attachment_id, adapter, account, filename, declared_mime, detected_mime,
    detection_source, size_bytes, sha256, envelope_format, envelope_size,
    envelope_sha256, created_at, consumed_request_id, consumed_at
ON staged_objects
FOR EACH ROW
WHEN NOT (
    (
        OLD.attachment_id IS NEW.attachment_id AND
        OLD.adapter IS NEW.adapter AND
        OLD.account IS NEW.account AND
        OLD.filename IS NEW.filename AND
        OLD.declared_mime IS NEW.declared_mime AND
        OLD.detected_mime IS NEW.detected_mime AND
        OLD.detection_source IS NEW.detection_source AND
        OLD.size_bytes IS NEW.size_bytes AND
        OLD.sha256 IS NEW.sha256 AND
        OLD.envelope_format IS NEW.envelope_format AND
        OLD.envelope_size IS NEW.envelope_size AND
        OLD.envelope_sha256 IS NEW.envelope_sha256 AND
        OLD.created_at IS NEW.created_at AND
        (
            (OLD.consumed_request_id IS NEW.consumed_request_id AND
             OLD.consumed_at IS NEW.consumed_at) OR
            (OLD.consumed_request_id IS NULL AND OLD.consumed_at IS NULL AND
             NEW.consumed_request_id IS NOT NULL AND NEW.consumed_at IS NOT NULL)
        )
    ) OR (
        OLD.storage_path IS NULL AND OLD.purged_at IS NOT NULL AND
        NEW.attachment_id IS OLD.attachment_id AND
        NEW.adapter = '<redacted>' AND NEW.account = '<redacted>' AND
        NEW.filename = '<redacted>' AND
        NEW.declared_mime = 'application/octet-stream' AND
        NEW.detected_mime = 'application/octet-stream' AND
        NEW.detection_source IS OLD.detection_source AND
        NEW.size_bytes = 0 AND NEW.sha256 = printf('%064d', 0) AND
        NEW.envelope_format IS OLD.envelope_format AND
        NEW.envelope_size = 1 AND NEW.envelope_sha256 = printf('%064d', 0) AND
        NEW.created_at IS OLD.created_at AND
        NEW.consumed_request_id IS OLD.consumed_request_id AND
        NEW.consumed_at IS OLD.consumed_at
    )
)
BEGIN
    SELECT RAISE(ABORT, 'staged object immutable context changed');
END;

UPDATE staged_objects
SET adapter = '<redacted>',
    account = '<redacted>',
    filename = '<redacted>',
    declared_mime = 'application/octet-stream',
    detected_mime = 'application/octet-stream',
    size_bytes = 0,
    sha256 = printf('%064d', 0),
    envelope_size = 1,
    envelope_sha256 = printf('%064d', 0)
WHERE purged_at IS NOT NULL;

UPDATE attachments
SET filename = '<redacted>',
    mime_type = 'application/octet-stream',
    size_bytes = 0,
    sha256 = printf('%064d', 0)
WHERE purged_at IS NOT NULL;
