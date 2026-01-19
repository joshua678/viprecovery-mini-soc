-- Event volume by Zeek log type
SELECT event_type, COUNT(*) AS n
FROM events
GROUP BY event_type
ORDER BY n DESC;

-- Top destination IP:port pairs (all events that have resp_h/resp_p)
SELECT resp_h, resp_p, COUNT(*) AS n
FROM events
WHERE resp_h IS NOT NULL AND resp_p IS NOT NULL
GROUP BY resp_h, resp_p
ORDER BY n DESC
LIMIT 25;

-- If you imported Suricata alerts, this will work:
-- SELECT severity, rule_id, COUNT(*) AS n
-- FROM alerts
-- GROUP BY severity, rule_id
-- ORDER BY severity DESC, n DESC;
