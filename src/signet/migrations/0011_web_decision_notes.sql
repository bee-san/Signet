ALTER TABLE web_action_drafts
ADD COLUMN decision_note TEXT CHECK (
    decision_note IS NULL OR (
        action IN ('approve', 'deny') AND
        length(decision_note) BETWEEN 1 AND 1000 AND
        length(CAST(decision_note AS BLOB)) <= 4000
    )
);
