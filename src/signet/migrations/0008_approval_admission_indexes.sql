CREATE INDEX approval_requests_tool_admission_idx
    ON approval_requests(
        downstream_alias, tool_name, state, expires_at, created_at
    );

CREATE INDEX approval_requests_tool_rate_idx
    ON approval_requests(downstream_alias, tool_name, created_at);
