-- Maltrail
-- plugin_id: 90090

DELETE FROM plugin WHERE id="90090";
DELETE FROM plugin_sid WHERE plugin_id="90090";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (90090, 1, 'maltrail', 'Maltrail');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES
(90090, 1, 15,171, NULL, 'Maltrail: IP or DNS: known attacker', 1, 2),
(90090, 2, 15,171, NULL, 'Maltrail: IP or DNS: malware distribution', 1, 3),
(90090, 3, 15,171, NULL, 'Maltrail: IP or DNS: malware', 1, 4),
(90090, 4, 15,171, NULL, 'Maltrail: IP or DNS: potential malware site', 1, 3),
(90090, 5, 15,171, NULL, 'Maltrail: IP or DNS: crawler', 1, 3),
(90090, 6, 15,171, NULL, 'Maltrail: IP or DNS: http spammer', 1, 3),
(90090, 7, 15,171, NULL, 'Maltrail: IP or DNS: malicious', 1, 3),
(90090, 8, 15,171, NULL, 'Maltrail: IP or DNS: bad reputation', 1, 3),
(90090, 9, 15,171, NULL, 'Maltrail: IP or DNS: mass scanner', 1, 2),
(90090, 10, 15,171, NULL, 'Maltrail: IP or DNS: parking site (suspicious)', 1, 3),
(90090, 11, 15,171, NULL, 'Maltrail: IP or DNS: spammer', 1, 3),
(90090, 12, 15,171, NULL, 'Maltrail: IP or DNS: proxy (suspicious)', 1, 3),
(90090, 13, 15,171, NULL, 'Maltrail: IP or DNS: tor exit node (suspicious)', 1, 3),
(90090, 14, 15,171, NULL, 'Maltrail: IP or DNS: bitcoin node (bad reputation)', 1, 3),
(90090, 15, 15,171, NULL, 'Maltrail: IP or DNS: potential port scanning', 1, 3),
(90090, 16, 15,171, NULL, 'Maltrail: IP or DNS: sinkhole response (malware)', 1, 3),
(90090, 17, 15,171, NULL, 'Maltrail: IP or DNS: seized domain (suspicious)', 1, 3),
(90090, 18, 15,171, NULL, 'Maltrail: IP or DNS: anonymous proxy (suspicious)', 1, 3),
(90090, 19, 15,171, NULL, 'Maltrail: IP or DNS: compromised (suspicious)', 1, 3),
(90090, 98, 15,171, NULL, 'Maltrail: IP: malware (static)', 1, 4),
(90090, 99, 15,171, NULL, 'Maltrail: IP: Generic', 1, 3),

(90090, 101, 15,171, NULL, 'Maltrail: DNS: browser hijacking (suspicious)', 1, 3),
(90090, 102, 15,171, NULL, 'Maltrail: DNS: bad history (suspicious)', 1, 3),
(90090, 103, 15,171, NULL, 'Maltrail: DNS: potential dns exhaustion (suspicious)', 1, 3),
(90090, 104, 15,171, NULL, 'Maltrail: DNS: consonant threshold no such domain (suspicious)', 1, 3),
(90090, 105, 15,171, NULL, 'Maltrail: DNS: excessive no such domain (suspicious)', 1, 3),
(90090, 106, 15,171, NULL, 'Maltrail: DNS: long domain (suspicious)', 1, 3),
(90090, 107, 15,171, NULL, 'Maltrail: DNS: domain (suspicious)', 1, 3),
(90090, 108, 15,171, NULL, 'Maltrail: DNS: parked site (suspicious)', 1, 3),
(90090, 109, 15,171, NULL, 'Maltrail: DNS: entropy threshold no such domain (suspicious)', 1, 3),
(90090, 110, 15,171, NULL, 'Maltrail: DNS: free web hosting (suspicious)', 1, 3),
(90090, 111, 15,171, NULL, 'Maltrail: DNS: pup (suspicious)', 1, 3),
(90090, 112, 15,171, NULL, 'Maltrail: DNS: malware', 1, 4),
(90090, 113, 15,171, NULL, 'Maltrail: DNS: ipinfo (suspicious)', 1, 3),
(90090, 114, 15,171, NULL, 'Maltrail: DNS: dynamic domain (suspicious)', 1, 3),
(90090, 115, 15,171, NULL, 'Maltrail: DNS: onion (suspicious)', 1, 3),
(90090, 116, 15,171, NULL, 'Maltrail: DNS: anonymous web proxy (suspicious)', 1, 3),
(90090, 117, 15,171, NULL, 'Maltrail: DNS: suspicious', 1, 3),
(90090, 118, 15,171, NULL, 'Maltrail: DNS: phishing', 1, 3),
(90090, 195, 15,171, NULL, 'Maltrail: DNS: known attacker', 1, 3),
(90090, 196, 15,171, NULL, 'Maltrail: DNS: parking site (suspicious)', 1, 3),
(90090, 197, 15,171, NULL, 'Maltrail: DNS: sinkholed by malware (static)', 1, 3),
(90090, 198, 15,171, NULL, 'Maltrail: DNS: malware (static)', 1, 4),
(90090, 199, 15,171, NULL, 'Maltrail: DNS: Generic', 1, 3),

(90090, 201, 15,171, NULL, 'Maltrail: HTTP: potential proxy probe (suspicious)', 1, 3),
(90090, 202, 15,171, NULL, 'Maltrail: HTTP: missing host header (suspicious)', 1, 3),
(90090, 299, 15,171, NULL, 'Maltrail: HTTP: Generic', 1, 3),

(90090, 301, 15,171, NULL, 'Maltrail: URL: potential web shell (suspicious)', 1, 3),
(90090, 397, 15,171, NULL, 'Maltrail: URL: direct file download (suspicious)', 1, 3),
(90090, 398, 15,171, NULL, 'Maltrail: URL: malware (static)', 1, 4),
(90090, 399, 15,171, NULL, 'Maltrail: URL: Generic', 1, 3),

(90090, 401, 15,171, NULL, 'Maltrail: HTTP or URL: potential sql injection (suspicious)', 1, 4),
(90090, 402, 15,171, NULL, 'Maltrail: HTTP or URL: potential xml injection (suspicious)', 1, 4),
(90090, 403, 15,171, NULL, 'Maltrail: HTTP or URL: potential php injection (suspicious)', 1, 4),
(90090, 404, 15,171, NULL, 'Maltrail: HTTP or URL: potential ldap injection (suspicious)', 1, 4),
(90090, 405, 15,171, NULL, 'Maltrail: HTTP or URL: potential xss injection (suspicious)', 1, 4),
(90090, 406, 15,171, NULL, 'Maltrail: HTTP or URL: potential xxe injection (suspicious)', 1, 4),
(90090, 407, 15,171, NULL, 'Maltrail: HTTP or URL: potential data leakage (suspicious)', 1, 4),
(90090, 408, 15,171, NULL, 'Maltrail: HTTP or URL: config file access (suspicious)', 1, 4),
(90090, 409, 15,171, NULL, 'Maltrail: HTTP or URL: potential remote code execution (suspicious)', 1, 4),
(90090, 410, 15,171, NULL, 'Maltrail: HTTP or URL: potential directory traversal (suspicious)', 1, 4),
(90090, 411, 15,171, NULL, 'Maltrail: HTTP or URL: potential web scan (suspicious)', 1, 4),
(90090, 412, 15,171, NULL, 'Maltrail: HTTP or URL: non-existent page (suspicious)', 1, 4),

(90090, 501, 15,171, NULL, 'Maltrail: UA: user agent (suspicious)', 1, 3),
(90090, 599, 15,171, NULL, 'Maltrail: UA: Generic', 1, 3),

(90090, 999, 15,171, NULL, 'Maltrail: Generic', 1, 3);
