DROP TRIGGER payload_versions_immutable_fields;

CREATE TRIGGER payload_versions_immutable_fields
BEFORE UPDATE ON payload_versions
WHEN
    OLD.request_id IS NOT NEW.request_id OR
    OLD.version IS NOT NEW.version OR
    OLD.payload_hash IS NOT NEW.payload_hash OR
    OLD.canonical_size IS NOT NEW.canonical_size OR
    OLD.policy_version IS NOT NEW.policy_version OR
    OLD.adapter_version IS NOT NEW.adapter_version OR
    OLD.schema_version IS NOT NEW.schema_version OR
    OLD.editor_actor IS NOT NEW.editor_actor OR
    OLD.created_at IS NOT NEW.created_at OR
    (
        OLD.encrypted_payload IS NOT NEW.encrypted_payload AND NOT (
            OLD.encrypted_payload IS NOT NULL AND
            NEW.encrypted_payload IS NULL AND
            NEW.purged_at IS NOT NULL
        )
    ) OR
    (
        OLD.encryption_key_ref IS NOT NEW.encryption_key_ref AND NOT (
            OLD.encryption_key_ref IS NOT NULL AND
            NEW.encryption_key_ref IS NULL AND
            NEW.purged_at IS NOT NULL AND
            NEW.key_destroyed_at IS NOT NULL
        )
    ) OR
    (OLD.purged_at IS NOT NULL AND OLD.purged_at IS NOT NEW.purged_at) OR
    (
        OLD.key_destroyed_at IS NOT NULL AND
        OLD.key_destroyed_at IS NOT NEW.key_destroyed_at
    )
BEGIN
    SELECT RAISE(ABORT, 'payload versions are immutable except for one-way purge');
END;
