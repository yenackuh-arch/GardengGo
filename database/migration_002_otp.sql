
USE gardengo;


ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0 AFTER is_active;


UPDATE users SET email_verified = 1 WHERE id > 0;


CREATE TABLE IF NOT EXISTS email_otps (
  id         INT UNSIGNED     NOT NULL AUTO_INCREMENT,
  user_id    INT UNSIGNED     NOT NULL,
  purpose    ENUM('verify_email','admin_login') NOT NULL,
  code_hash  CHAR(64)         NOT NULL,
  attempts   TINYINT UNSIGNED NOT NULL DEFAULT 0,        
  sent_at    DATETIME         NOT NULL,
  expires_at DATETIME         NOT NULL,
  used_at    DATETIME         NULL,                      
  PRIMARY KEY (id),
  KEY idx_otps_lookup (user_id, purpose, id),
  CONSTRAINT fk_otps_user FOREIGN KEY (user_id) REFERENCES users (id)
    ON UPDATE CASCADE ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
