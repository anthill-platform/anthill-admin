CREATE TABLE `audit_log` (
  `action_id` int(11) unsigned NOT NULL AUTO_INCREMENT,
  `gamespace_id` int(10) unsigned NOT NULL,
  `service_name` varchar(64) NOT NULL DEFAULT '',
  `service_action` varchar(64) NOT NULL DEFAULT '',
  `action_icon` varchar(64) NOT NULL DEFAULT '',
  `action_message` varchar(255) NOT NULL DEFAULT '',
  `action_payload` json NOT NULL,
  `action_date` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `action_author` int(11) NOT NULL,
  PRIMARY KEY (`action_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;