ALTER TABLE staged_objects
ADD COLUMN detection_source TEXT NOT NULL DEFAULT 'legacy_filename_unverified'
CHECK (detection_source IN ('legacy_filename_unverified', 'content_signature_v1'));

DROP TRIGGER staged_objects_immutable_context;

CREATE TRIGGER staged_objects_immutable_context
BEFORE UPDATE OF
    attachment_id, adapter, account, filename, declared_mime, detected_mime,
    detection_source, size_bytes, sha256, envelope_format, envelope_size,
    envelope_sha256, created_at, consumed_request_id, consumed_at
ON staged_objects
FOR EACH ROW
WHEN
    OLD.attachment_id IS NOT NEW.attachment_id OR
    OLD.adapter IS NOT NEW.adapter OR
    OLD.account IS NOT NEW.account OR
    OLD.filename IS NOT NEW.filename OR
    OLD.declared_mime IS NOT NEW.declared_mime OR
    OLD.detected_mime IS NOT NEW.detected_mime OR
    OLD.detection_source IS NOT NEW.detection_source OR
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

CREATE TEMP TABLE legacy_decision_events(
    event_id INTEGER PRIMARY KEY,
    request_id TEXT NOT NULL,
    occurred_at INTEGER NOT NULL,
    version INTEGER NOT NULL,
    payload_hash TEXT NOT NULL,
    decision_action INTEGER NOT NULL
) STRICT;

INSERT INTO legacy_decision_events(
    event_id, request_id, occurred_at, version, payload_hash, decision_action
)
SELECT event_id, request_id, occurred_at, version, payload_hash,
       action = 'denied' OR action IN ('approved_via_web', 'approved_via_mcp')
FROM request_events
WHERE CASE
    WHEN safe_details_json IS NULL THEN
        action = 'denied' OR action IN ('approved_via_web', 'approved_via_mcp')
    WHEN NOT json_valid(safe_details_json) THEN 1
    WHEN json_type(safe_details_json) != 'object' THEN 1
    WHEN (SELECT count(*) FROM json_tree(request_events.safe_details_json)
          WHERE key IS NOT NULL) !=
         (SELECT count(*) FROM (
              SELECT path, key FROM json_tree(request_events.safe_details_json)
              WHERE key IS NOT NULL GROUP BY path, key
          )) THEN 1
    WHEN action IN ('approved_via_web', 'approved_via_mcp') THEN CASE
        WHEN (SELECT count(*) FROM json_each(request_events.safe_details_json)
              WHERE key = 'decision_note') != 1 THEN 1
        ELSE COALESCE(
            json_type(safe_details_json, '$.decision_note') != 'text'
            OR json_extract(safe_details_json, '$.decision_note') NOT IN (
                'exact_request_approved', 'expected_and_authorized',
                'mcp_chat_confirmation', 'authenticated_exact_review',
                'legacy_unstructured_reason'
            ),
            1
        )
    END
    WHEN action = 'denied' THEN CASE
        WHEN (SELECT count(*) FROM json_each(request_events.safe_details_json)
              WHERE key = 'decision_note') != 1 THEN 1
        ELSE COALESCE(
            json_type(safe_details_json, '$.decision_note') != 'text'
            OR json_extract(safe_details_json, '$.decision_note') NOT IN (
                'wrong_destination', 'unexpected_content_or_scope', 'duplicate_request',
                'unsafe_or_disallowed', 'insufficient_authority',
                'request_no_longer_needed', 'authenticated_denial',
                'legacy_unstructured_reason'
            ),
            1
        )
    END
    ELSE (SELECT count(*) FROM json_each(request_events.safe_details_json)
          WHERE key = 'decision_note') != 0
END;

CREATE TEMP TABLE legacy_decision_drafts(
    challenge_id TEXT PRIMARY KEY
) STRICT;

INSERT INTO legacy_decision_drafts(challenge_id)
SELECT challenge_id
FROM web_action_drafts
WHERE CASE
    WHEN policy_change = 1 THEN decision_note IS NOT NULL
    WHEN action = 'approve' THEN COALESCE(decision_note NOT IN (
        'exact_request_approved', 'expected_and_authorized'
    ), 1)
    WHEN action = 'deny' THEN COALESCE(decision_note NOT IN (
        'wrong_destination', 'unexpected_content_or_scope', 'duplicate_request',
        'unsafe_or_disallowed', 'insufficient_authority', 'request_no_longer_needed'
    ), 1)
    ELSE decision_note IS NOT NULL
END;

CREATE TABLE privacy_maintenance(
    maintenance_name TEXT PRIMARY KEY CHECK (
        maintenance_name = 'structured_decision_reasons'
    ),
    pending INTEGER NOT NULL CHECK (pending IN (0, 1))
) STRICT;

INSERT INTO privacy_maintenance(maintenance_name, pending)
SELECT 'structured_decision_reasons',
       EXISTS(SELECT 1 FROM legacy_decision_events)
       OR EXISTS(SELECT 1 FROM legacy_decision_drafts);

DELETE FROM web_action_drafts
WHERE challenge_id IN (SELECT challenge_id FROM legacy_decision_drafts);

UPDATE auth_challenges
SET invalidated_at = COALESCE(invalidated_at, created_at)
WHERE consumed_at IS NULL
  AND challenge_id IN (SELECT challenge_id FROM legacy_decision_drafts);

DROP TRIGGER request_events_no_update;

UPDATE request_events
SET safe_details_json = CASE
    WHEN event_id IN (
        SELECT event_id FROM legacy_decision_events WHERE decision_action = 1
    ) THEN json_object('decision_note', 'legacy_unstructured_reason')
    ELSE NULL
END
WHERE event_id IN (SELECT event_id FROM legacy_decision_events);

CREATE TRIGGER request_events_no_update
BEFORE UPDATE ON request_events
BEGIN
    SELECT RAISE(ABORT, 'request_events are append-only');
END;

INSERT INTO request_events(
    request_id, actor, action, occurred_at, version, payload_hash, safe_details_json
)
SELECT request_id,
       'migration:0013',
       'legacy_decision_reason_sanitized',
       max(occurred_at, unixepoch()),
       version,
       payload_hash,
       json_object('sanitized_event_id', event_id)
FROM legacy_decision_events;

CREATE TRIGGER web_action_drafts_structured_reason_insert
BEFORE INSERT ON web_action_drafts
FOR EACH ROW
WHEN CASE
    WHEN NEW.policy_change = 1 THEN NEW.decision_note IS NOT NULL
    WHEN NEW.action = 'approve' THEN COALESCE(NEW.decision_note NOT IN (
        'exact_request_approved', 'expected_and_authorized'
    ), 1)
    WHEN NEW.action = 'deny' THEN COALESCE(NEW.decision_note NOT IN (
        'wrong_destination', 'unexpected_content_or_scope', 'duplicate_request',
        'unsafe_or_disallowed', 'insufficient_authority', 'request_no_longer_needed'
    ), 1)
    ELSE NEW.decision_note IS NOT NULL
END
BEGIN
    SELECT RAISE(ABORT, 'invalid structured web decision reason');
END;

CREATE TRIGGER request_events_structured_reason_insert
BEFORE INSERT ON request_events
FOR EACH ROW
WHEN CASE
    WHEN NEW.safe_details_json IS NULL THEN
        NEW.action = 'denied' OR NEW.action IN ('approved_via_web', 'approved_via_mcp')
    WHEN NOT json_valid(NEW.safe_details_json) THEN 1
    WHEN json_type(NEW.safe_details_json) != 'object' THEN 1
    WHEN (SELECT count(*) FROM json_tree(NEW.safe_details_json)
          WHERE key IS NOT NULL) !=
         (SELECT count(*) FROM (
              SELECT path, key FROM json_tree(NEW.safe_details_json)
              WHERE key IS NOT NULL GROUP BY path, key
          )) THEN 1
    WHEN NEW.action IN ('approved_via_web', 'approved_via_mcp') THEN CASE
        WHEN (SELECT count(*) FROM json_each(NEW.safe_details_json)
              WHERE key = 'decision_note') != 1 THEN 1
        ELSE COALESCE(json_extract(NEW.safe_details_json, '$.decision_note') NOT IN (
            'exact_request_approved', 'expected_and_authorized',
            'mcp_chat_confirmation', 'authenticated_exact_review'
        ), 1)
    END
    WHEN NEW.action = 'denied' THEN CASE
        WHEN (SELECT count(*) FROM json_each(NEW.safe_details_json)
              WHERE key = 'decision_note') != 1 THEN 1
        ELSE COALESCE(json_extract(NEW.safe_details_json, '$.decision_note') NOT IN (
            'wrong_destination', 'unexpected_content_or_scope', 'duplicate_request',
            'unsafe_or_disallowed', 'insufficient_authority',
            'request_no_longer_needed', 'authenticated_denial'
        ), 1)
    END
    ELSE (SELECT count(*) FROM json_each(NEW.safe_details_json)
          WHERE key = 'decision_note') != 0
END
BEGIN
    SELECT RAISE(ABORT, 'invalid structured request decision reason');
END;

DROP TABLE legacy_decision_drafts;
DROP TABLE legacy_decision_events;
