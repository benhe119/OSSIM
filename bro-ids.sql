-- Bro IDS
-- plugin_id: 1568

DELETE FROM plugin WHERE id="1568";
DELETE FROM plugin_sid WHERE plugin_id="1568";

INSERT IGNORE INTO plugin (id, type, name, description) VALUES (1568, 1, 'bro-ids', 'Bro-IDS');

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1, 15,171, NULL, 'Bro-IDS: Address dropped', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 2, 15,171, NULL, 'Bro-IDS: Port scan', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 3, 15,171, NULL, 'Bro-IDS: Notice::Invalid Server Cert', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 4, 15,171, NULL, 'Bro-IDS: Notice::Address Scan', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 5, 15,171, NULL, 'Bro-IDS: Notice::Port Scan', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 6, 15,171, NULL, 'Bro-IDS: Notice::SQL Injection Attacker', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 7, 15,171, NULL, 'Bro-IDS: Notice::SQL Injection Victim', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 8, 15,171, NULL, 'Bro-IDS: Notice::SYN after partial', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 9, 15,171, NULL, 'Bro-IDS: Notice::Traceroute', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 10, 15,171, NULL, 'Bro-IDS: Notice::SSH::Password Guessing', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 11, 15,171, NULL, 'Bro-IDS: Notice::SIP::Scan', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 12, 15,171, NULL, 'Bro-IDS: Notice::Virus', 1, 5);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 13, 15,171, NULL, 'Bro-IDS: Notice::Heartbleed Attack', 1, 5);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 14, 15,171, NULL, 'Bro-IDS: Notice::Heartbleed Attack (Probable)', 1, 5);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 15, 15,171, NULL, 'Bro-IDS: Notice::SIP::Bruteforce', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 16, 15,171, NULL, 'Bro-IDS: Notice::HTTP::New WPAD', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 17, 15,171, NULL, 'Bro-IDS: Notice::DNS::New WPAD', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 18, 15,171, NULL, 'Bro-IDS: Notice::DHCP::Unauthorized DHCP ack', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 19, 15,171, NULL, 'Bro-IDS: Notice::DHCP::Unauthorized DHCP offers', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 20, 15,171, NULL, 'Bro-IDS: Notice::DHCP::Suspicious DHCP router list', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 21, 15,171, NULL, 'Bro-IDS: Notice::SSH::Server versionl long', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 22, 15,171, NULL, 'Bro-IDS: Notice::SSH::Client versionl long', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 23, 15,171, NULL, 'Bro-IDS: Notice::Meterpreter detected', 1, 5);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 99, 15,171, NULL, 'Bro-IDS: Notice::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 101, 15,171, NULL, 'Bro-IDS: File::HTTP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 102, 15,171, NULL, 'Bro-IDS: File::SMTP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 103, 15,171, NULL, 'Bro-IDS: File::FTP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 104, 15,171, NULL, 'Bro-IDS: File::SSL', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 199, 15,171, NULL, 'Bro-IDS: File::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 201, 15,171, NULL, 'Bro-IDS: SMTP-Message', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 301, 15,171, NULL, 'Bro-IDS: SSH-connection', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 401, 15,171, NULL, 'Bro-IDS: DNS', 1, 1);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 501, 15,171, NULL, 'Bro-IDS: Weird::DNS unmatched reply', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 502, 15,171, NULL, 'Bro-IDS: Weird::NUL in line', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 503, 15,171, NULL, 'Bro-IDS: Weird::Data before established', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 504, 15,171, NULL, 'Bro-IDS: Weird::Possible split routing', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 505, 15,171, NULL, 'Bro-IDS: Weird::Window recision', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 506, 15,171, NULL, 'Bro-IDS: Weird::Unescaped special URI char', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 507, 15,171, NULL, 'Bro-IDS: Weird::Active connection reuse', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 508, 15,171, NULL, 'Bro-IDS: Weird::SYN seq jump', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 509, 15,171, NULL, 'Bro-IDS: Weird::SYN inside connection', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 510, 15,171, NULL, 'Bro-IDS: Weird::Above hole data without any acks', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 511, 15,171, NULL, 'Bro-IDS: Weird::Premature connection reuse', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 599, 15,171, NULL, 'Bro-IDS: Weird::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 601, 15,171, NULL, 'Bro-IDS: SOFTWARE::UNKNOWN', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 602, 15,171, NULL, 'Bro-IDS: SOFTWARE::OS::WINDOWS', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 603, 15,171, NULL, 'Bro-IDS: SOFTWARE::FTP::CLIENT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 604, 15,171, NULL, 'Bro-IDS: SOFTWARE::FTP::SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 605, 15,171, NULL, 'Bro-IDS: SOFTWARE::HTTP::WEB_APPLICATION', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 606, 15,171, NULL, 'Bro-IDS: SOFTWARE::HTTP::BROWSER_PLUGIN', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 607, 15,171, NULL, 'Bro-IDS: SOFTWARE::HTTP::SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 608, 15,171, NULL, 'Bro-IDS: SOFTWARE::HTTP::APPSERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 609, 15,171, NULL, 'Bro-IDS: SOFTWARE::HTTP::BROWSER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 610, 15,171, NULL, 'Bro-IDS: SOFTWARE::MySQL::SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 611, 15,171, NULL, 'Bro-IDS: SOFTWARE::SMTP::MAIL_CLIENT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 612, 15,171, NULL, 'Bro-IDS: SOFTWARE::SMTP::MAIL_SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 613, 15,171, NULL, 'Bro-IDS: SOFTWARE::SMTP::WEBMAIL_SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 614, 15,171, NULL, 'Bro-IDS: SOFTWARE::SSH::SERVER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 615, 15,171, NULL, 'Bro-IDS: SOFTWARE::SSH::CLIENT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 699, 15,171, NULL, 'Bro-IDS: SOFTWARE::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 701, 15,171, NULL, 'Bro-IDS: DPD::SSL::Invalid version in TLS', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 702, 15,171, NULL, 'Bro-IDS: DPD::SSL::Invalid headers in SSL', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 703, 15,171, NULL, 'Bro-IDS: DPD::HTTP::Not a http line', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 704, 15,171, NULL, 'Bro-IDS: DPD::SMTP::Reply code out of range', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 705, 15,171, NULL, 'Bro-IDS: DPD::FTP::Non-numeric reply code', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 706, 15,171, NULL, 'Bro-IDS: DPD::DTLS::Invalid version', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 707, 15,171, NULL, 'Bro-IDS: DPD::SSL::Invalid version in SSL client hello', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 708, 15,171, NULL, 'Bro-IDS: DPD::IRC::Line too short', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 709, 15,171, NULL, 'Bro-IDS: DPD::SNMP::Binpac exception', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 710, 15,171, NULL, 'Bro-IDS: DPD::SIP::Binpac exception', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 711, 15,171, NULL, 'Bro-IDS: DPD::RADIUS::Binpac exception', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 712, 15,171, NULL, 'Bro-IDS: DPD::IRC::Invalid reply number', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 799, 15,171, NULL, 'Bro-IDS: DPD::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 801, 15,171, NULL, 'Bro-IDS: FTP::APPE', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 802, 15,171, NULL, 'Bro-IDS: FTP::DELE', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 803, 15,171, NULL, 'Bro-IDS: FTP::RETR', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 804, 15,171, NULL, 'Bro-IDS: FTP::STOR', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 805, 15,171, NULL, 'Bro-IDS: FTP::STOU', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 806, 15,171, NULL, 'Bro-IDS: FTP::ACCT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 807, 15,171, NULL, 'Bro-IDS: FTP::PORT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 808, 15,171, NULL, 'Bro-IDS: FTP::PASV', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 809, 15,171, NULL, 'Bro-IDS: FTP::EPRT', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 810, 15,171, NULL, 'Bro-IDS: FTP::EPSV', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 899, 15,171, NULL, 'Bro-IDS: FTP::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 901, 15,171, NULL, 'Bro-IDS: SIP::CANCEL', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 902, 15,171, NULL, 'Bro-IDS: SIP::INVITE', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 903, 15,171, NULL, 'Bro-IDS: SIP::ACK', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 904, 15,171, NULL, 'Bro-IDS: SIP::OPTIONS', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 905, 15,171, NULL, 'Bro-IDS: SIP::BYE', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 906, 15,171, NULL, 'Bro-IDS: SIP::REGISTER', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 907, 15,171, NULL, 'Bro-IDS: SIP::Unknown', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 999, 15,171, NULL, 'Bro-IDS: SIP::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1001, 15,171, NULL, 'Bro-IDS: RDP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1002, 15,171, NULL, 'Bro-IDS: RDP::Info', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1099, 15,171, NULL, 'Bro-IDS: RDP::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1101, 15,171, NULL, 'Bro-IDS: SNMP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1199, 15,171, NULL, 'Bro-IDS: SNMP::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1201, 15,171, NULL, 'Bro-IDS: Tunnel::DISCOVER', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1202, 15,171, NULL, 'Bro-IDS: Tunnel::CLOSE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1203, 15,171, NULL, 'Bro-IDS: Tunnel::EXPIRE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1299, 15,171, NULL, 'Bro-IDS: Tunnel::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1301, 15,171, NULL, 'Bro-IDS: Kerberos::Success', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1302, 15,171, NULL, 'Bro-IDS: Kerberos::Unknown', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1303, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_NONE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1304, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_NAME_EXP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1305, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SERVICE_EXP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1306, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_BAD_PVNO', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1307, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_C_OLD_MAST_KVNO', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1308, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_S_OLD_MAST_KVNO', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1309, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_C_PRINCIPAL_UNKNOWN', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1310, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_S_PRINCIPAL_UNKNOWN', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1311, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_PRINCIPAL_NOT_UNIQUE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1312, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_NULL_KEY', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1313, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_CANNOT_POSTDATE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1314, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_NEVER_VALID', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1315, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_POLICY', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1316, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_BADOPTION', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1317, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_ETYPE_NOTSUPP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1318, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SUMTYPE_NOSUPP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1319, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_PADATA_TYPE_NOSUPP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1320, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_TRTYPE_NO_SUPP', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1321, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_CLIENT_REVOKED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1322, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SERVICE_REVOKED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1323, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_TGT_REVOKED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1324, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_CLIENT_NOTYET', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1325, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SERVICE_NOTYET', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1326, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_KEY_EXPIRED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1327, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_PREAUTH_FAILED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1328, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_PREAUTH_REQUIRED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1329, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SERVER_NOMATCH', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1330, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_SVC_UNAVAILABLE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1331, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BAD_INTEGRITY', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1332, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_TKT_EXPIRED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1333, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_TKT_NYV', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1334, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_REPEAT', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1335, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_NOT_US', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1336, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADMATCH', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1337, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_SKEW', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1338, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADADDR', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1339, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADVERSION', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1340, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_MSG_TYPE', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1341, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_MODIFIED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1342, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADORDER', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1343, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADKEYVER', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1344, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_NOKEY', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1345, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_MUT_FAIL', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1346, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADDIRECTION', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1347, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_METHOD', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1348, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_BADSEQ', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1349, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_INAPP_CKSUM', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1350, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_PATH_NOT_ACCEPTED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1351, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_ERR_RESPONSE_TOO_BIG', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1352, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_ERR_GENERIC', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1353, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_ERR_FIELD_TOOLONG', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1354, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_CLIENT_NOT_TRUSTED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1355, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_KDC_NOT_TRUSTED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1356, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_INVALID_SIG', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1357, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_KEY_TOO_WEAK', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1358, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_USER_TO_USER_REQUIRED', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1359, 15,171, NULL, 'Bro-IDS: Kerberos::KRB_AP_ERR_NO_TGT', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1360, 15,171, NULL, 'Bro-IDS: Kerberos::KDC_ERR_WRONG_REALM', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1399, 15,171, NULL, 'Bro-IDS: Kerberos::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1401, 15,171, NULL, 'Bro-IDS: Socks::OK', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1402, 15,171, NULL, 'Bro-IDS: Socks::Credentials::OK', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1403, 15,171, NULL, 'Bro-IDS: Socks::Not OK', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1404, 15,171, NULL, 'Bro-IDS: Socks::Credentials::Not OK', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1499, 15,171, NULL, 'Bro-IDS: Socks::Generic', 1, 3);

INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1501, 15,171, NULL, 'Bro-IDS: HTTP', 1, 1);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1502, 15,171, NULL, 'Bro-IDS: HTTP::Credentials', 1, 3);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1503, 15,171, NULL, 'Bro-IDS: HTTP::SQL Injection', 1, 4);
INSERT IGNORE INTO plugin_sid (plugin_id, sid, category_id, subcategory_id, class_id, name, priority, reliability) VALUES (1568, 1599, 15,171, NULL, 'Bro-IDS: HTTP::Generic', 1, 3);