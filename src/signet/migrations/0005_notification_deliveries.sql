CREATE TABLE notification_outbox_deliveries (
    outbox_id TEXT NOT NULL,
    subscription_id TEXT NOT NULL CHECK (length(subscription_id) BETWEEN 1 AND 256),
    delivered_at INTEGER NOT NULL,
    PRIMARY KEY (outbox_id, subscription_id),
    FOREIGN KEY (outbox_id) REFERENCES notification_outbox(outbox_id) ON DELETE RESTRICT
) STRICT;

CREATE INDEX notification_outbox_deliveries_time_idx
    ON notification_outbox_deliveries(delivered_at, outbox_id);
