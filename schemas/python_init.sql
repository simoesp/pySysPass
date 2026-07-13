-- sysPass Python - PHP-Compatible Database Schema
-- This creates all tables with the exact same structure as the PHP version

-- Users table
CREATE TABLE IF NOT EXISTS `User` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `userGroupId` mediumint(8) unsigned NOT NULL,
  `username` varchar(50) NOT NULL,
  `email` varchar(255) NOT NULL,
  `pass` varbinary(500) NOT NULL,
  `mPass` varbinary(2000) DEFAULT NULL,
  `mKey` varbinary(2000) DEFAULT NULL,
  `hashSalt` varbinary(255) NOT NULL,
  `tempPassword` varbinary(255) DEFAULT NULL,
  `isProfileMaster` tinyint(1) DEFAULT 0,
  `isUserAdmin` tinyint(1) DEFAULT 0,
  `isUserEnabled` tinyint(1) DEFAULT 1,
  `isUserForcePwdChange` tinyint(1) DEFAULT 0,
  `lastLogin` datetime DEFAULT NULL,
  `lastIP` varchar(50) DEFAULT NULL,
  `twoFactorAuth` tinyint(1) DEFAULT 0,
  `twoFactorSecret` varbinary(255) DEFAULT NULL,
  `twoFactorBackupCodes` text DEFAULT NULL,
  `avatar` mediumblob DEFAULT NULL,
  `locale` varchar(10) DEFAULT 'en_US',
  `timezone` varchar(50) DEFAULT 'UTC',
  `dateCreate` datetime NOT NULL,
  `dateUpdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_User_01` (`username`),
  UNIQUE KEY `uk_User_02` (`email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- UserGroup table
CREATE TABLE IF NOT EXISTS `UserGroup` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `description` varchar(255) DEFAULT NULL,
  `isProfileMaster` tinyint(1) DEFAULT 0,
  `isUserAdmin` tinyint(1) DEFAULT 0,
  `isUserEnabled` tinyint(1) DEFAULT 1,
  `isUserForcePwdChange` tinyint(1) DEFAULT 0,
  `dateCreate` datetime NOT NULL,
  `dateUpdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_UserGroup_01` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- UserProfile table
CREATE TABLE IF NOT EXISTS `UserProfile` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `userId` mediumint(8) unsigned NOT NULL,
  `name` varchar(100) NOT NULL,
  `isProfileMaster` tinyint(1) DEFAULT 0,
  `isUserAdmin` tinyint(1) DEFAULT 0,
  `isUserEnabled` tinyint(1) DEFAULT 1,
  `isUserForcePwdChange` tinyint(1) DEFAULT 0,
  `dateCreate` datetime NOT NULL,
  `dateUpdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_UserProfile_01` (`userId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Category table
CREATE TABLE IF NOT EXISTS `Category` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `icon` varchar(50) DEFAULT 'folder',
  `dateCreate` datetime NOT NULL,
  `dateUpdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_Category_01` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Client table
CREATE TABLE IF NOT EXISTS `Client` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(100) NOT NULL,
  `contact` varchar(255) DEFAULT NULL,
  `notes` text DEFAULT NULL,
  `dateCreate` datetime NOT NULL,
  `dateUpdate` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_Client_01` (`name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Account table (main table)
CREATE TABLE IF NOT EXISTS `Account` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `userGroupId` mediumint(8) unsigned NOT NULL,
  `userId` mediumint(8) unsigned NOT NULL,
  `userEditId` mediumint(8) unsigned NOT NULL,
  `clientId` mediumint(8) unsigned NOT NULL,
  `name` varchar(100) NOT NULL,
  `categoryId` mediumint(8) unsigned NOT NULL,
  `login` varchar(50) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `pass` varbinary(2000) NOT NULL,
  `key` varbinary(2000) NOT NULL,
  `notes` text DEFAULT NULL,
  `countView` int(10) unsigned NOT NULL DEFAULT 0,
  `countDecrypt` int(10) unsigned NOT NULL DEFAULT 0,
  `dateAdd` datetime NOT NULL,
  `dateEdit` datetime DEFAULT NULL,
  `otherUserGroupEdit` tinyint(1) DEFAULT 0,
  `otherUserEdit` tinyint(1) DEFAULT 0,
  `isPrivate` tinyint(1) DEFAULT 0,
  `isPrivateGroup` tinyint(1) DEFAULT 0,
  `passDate` int(11) unsigned DEFAULT NULL,
  `passDateChange` int(11) unsigned DEFAULT NULL,
  `parentId` mediumint(8) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_Account_01` (`categoryId`),
  KEY `idx_Account_02` (`userGroupId`,`userId`),
  KEY `idx_Account_03` (`clientId`),
  KEY `idx_Account_04` (`parentId`),
  CONSTRAINT `fk_Account_categoryId` FOREIGN KEY (`categoryId`) REFERENCES `Category` (`id`),
  CONSTRAINT `fk_Account_clientId` FOREIGN KEY (`clientId`) REFERENCES `Client` (`id`),
  CONSTRAINT `fk_Account_userEditId` FOREIGN KEY (`userEditId`) REFERENCES `User` (`id`),
  CONSTRAINT `fk_Account_userGroupId` FOREIGN KEY (`userGroupId`) REFERENCES `UserGroup` (`id`),
  CONSTRAINT `fk_Account_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountHistory table
CREATE TABLE IF NOT EXISTS `AccountHistory` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `accountId` mediumint(8) unsigned NOT NULL,
  `userGroupId` mediumint(8) unsigned NOT NULL,
  `userId` mediumint(8) unsigned NOT NULL,
  `userEditId` mediumint(8) unsigned NOT NULL,
  `clientId` mediumint(8) unsigned NOT NULL,
  `name` varchar(255) NOT NULL,
  `categoryId` mediumint(8) unsigned NOT NULL,
  `login` varchar(50) DEFAULT NULL,
  `url` varchar(255) DEFAULT NULL,
  `pass` varbinary(2000) NOT NULL,
  `key` varbinary(2000) NOT NULL,
  `notes` text NOT NULL,
  `countView` int(10) unsigned NOT NULL DEFAULT 0,
  `countDecrypt` int(10) unsigned NOT NULL DEFAULT 0,
  `dateAdd` datetime NOT NULL,
  `dateEdit` datetime DEFAULT NULL,
  `isModify` tinyint(1) DEFAULT 0,
  `isDeleted` tinyint(1) DEFAULT 0,
  `mPassHash` varbinary(255) NOT NULL,
  `otherUserEdit` tinyint(1) DEFAULT 0,
  `otherUserGroupEdit` tinyint(1) DEFAULT 0,
  `passDate` int(10) unsigned DEFAULT NULL,
  `passDateChange` int(10) unsigned DEFAULT NULL,
  `parentId` mediumint(8) unsigned DEFAULT NULL,
  `isPrivate` tinyint(1) DEFAULT 0,
  `isPrivateGroup` tinyint(1) DEFAULT 0,
  PRIMARY KEY (`id`),
  KEY `idx_AccountHistory_01` (`accountId`),
  CONSTRAINT `fk_AccountHistory_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Tag table
CREATE TABLE IF NOT EXISTS `Tag` (
  `id` mediumint(8) unsigned NOT NULL AUTO_INCREMENT,
  `name` varchar(50) NOT NULL,
  `color` varchar(7) DEFAULT '#000000',
  `userId` mediumint(8) unsigned DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_Tag_01` (`userId`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountToTag junction table
CREATE TABLE IF NOT EXISTS `AccountToTag` (
  `accountId` mediumint(8) unsigned NOT NULL,
  `tagId` mediumint(8) unsigned NOT NULL,
  PRIMARY KEY (`accountId`,`tagId`),
  CONSTRAINT `fk_AccountToTag_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_AccountToTag_tagId` FOREIGN KEY (`tagId`) REFERENCES `Tag` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountToFavorite junction table
CREATE TABLE IF NOT EXISTS `AccountToFavorite` (
  `accountId` mediumint(8) unsigned NOT NULL,
  `userId` mediumint(8) unsigned NOT NULL,
  PRIMARY KEY (`accountId`,`userId`),
  CONSTRAINT `fk_AccountToFavorite_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_AccountToFavorite_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountToUser (shared access) table
CREATE TABLE IF NOT EXISTS `AccountToUser` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `accountId` mediumint(8) unsigned NOT NULL,
  `userId` mediumint(8) unsigned NOT NULL,
  `actionId` smallint(5) DEFAULT 1,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_AccountToUser_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_AccountToUser_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountToUserGroup (shared access) table
CREATE TABLE IF NOT EXISTS `AccountToUserGroup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `accountId` mediumint(8) unsigned NOT NULL,
  `userGroupId` mediumint(8) unsigned NOT NULL,
  `actionId` smallint(5) DEFAULT 1,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_AccountToUserGroup_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_AccountToUserGroup_userGroupId` FOREIGN KEY (`userGroupId`) REFERENCES `UserGroup` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AuthToken table
CREATE TABLE IF NOT EXISTS `AuthToken` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` mediumint(8) unsigned NOT NULL,
  `token` varbinary(255) NOT NULL,
  `hash` varbinary(500) DEFAULT NULL,
  `ip` varchar(50) DEFAULT NULL,
  `userAgent` varchar(255) DEFAULT NULL,
  `dateAdd` datetime NOT NULL,
  `dateExpire` datetime DEFAULT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_AuthToken_01` (`token`),
  CONSTRAINT `fk_AuthToken_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Notification table
CREATE TABLE IF NOT EXISTS `Notification` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` mediumint(8) unsigned NOT NULL,
  `type` varchar(50) NOT NULL,
  `message` text NOT NULL,
  `isRead` tinyint(1) DEFAULT 0,
  `dateAdd` datetime NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_Notification_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- PublicLink table
CREATE TABLE IF NOT EXISTS `PublicLink` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `accountId` mediumint(8) unsigned NOT NULL,
  `hash` varbinary(255) NOT NULL,
  `expire` int(11) unsigned DEFAULT NULL,
  `password` varbinary(255) DEFAULT NULL,
  `dateAdd` datetime NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_PublicLink_01` (`hash`),
  CONSTRAINT `fk_PublicLink_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- ItemPreset table
CREATE TABLE IF NOT EXISTS `ItemPreset` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `type` varchar(25) NOT NULL,
  `userId` mediumint(8) unsigned DEFAULT NULL,
  `userGroupId` mediumint(8) unsigned DEFAULT NULL,
  `userProfileId` mediumint(8) unsigned DEFAULT NULL,
  `fixed` tinyint(1) unsigned NOT NULL DEFAULT 0,
  `priority` tinyint(3) unsigned NOT NULL DEFAULT 0,
  `data` blob DEFAULT NULL,
  `hash` varbinary(40) NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_ItemPreset_01` (`hash`),
  CONSTRAINT `fk_ItemPreset_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ItemPreset_userGroupId` FOREIGN KEY (`userGroupId`) REFERENCES `UserGroup` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_ItemPreset_userProfileId` FOREIGN KEY (`userProfileId`) REFERENCES `UserProfile` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- UserToUserGroup table
CREATE TABLE IF NOT EXISTS `UserToUserGroup` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `userId` mediumint(8) unsigned NOT NULL,
  `userGroupId` mediumint(8) unsigned NOT NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_UserToUserGroup_01` (`userId`,`userGroupId`),
  CONSTRAINT `fk_UserToUserGroup_userId` FOREIGN KEY (`userId`) REFERENCES `User` (`id`) ON DELETE CASCADE,
  CONSTRAINT `fk_UserToUserGroup_userGroupId` FOREIGN KEY (`userGroupId`) REFERENCES `UserGroup` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- AccountFile table
CREATE TABLE IF NOT EXISTS `AccountFile` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `accountId` mediumint(8) unsigned NOT NULL,
  `name` varchar(100) NOT NULL,
  `type` varchar(100) NOT NULL,
  `size` int(11) NOT NULL,
  `content` mediumblob NOT NULL,
  `extension` varchar(10) NOT NULL,
  `thumb` mediumblob DEFAULT NULL,
  `dateAdd` datetime NOT NULL,
  PRIMARY KEY (`id`),
  CONSTRAINT `fk_AccountFile_accountId` FOREIGN KEY (`accountId`) REFERENCES `Account` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8 COLLATE=utf8_unicode_ci;

-- Insert default master user group
INSERT IGNORE INTO `UserGroup` (`id`, `name`, `description`, `isProfileMaster`, `isUserAdmin`, `isUserEnabled`, `dateCreate`) 
VALUES (1, 'Master', 'Master user group with full privileges', 1, 1, 1, NOW());

-- Insert default categories
INSERT IGNORE INTO `Category` (`id`, `name`, `icon`, `dateCreate`) VALUES 
(1, 'General', 'folder', NOW()),
(2, 'Social Media', 'globe', NOW()),
(3, 'Finance', 'dollar', NOW()),
(4, 'Work', 'briefcase', NOW()),
(5, 'Personal', 'user', NOW());

-- Insert default client
INSERT IGNORE INTO `Client` (`id`, `name`, `dateCreate`) VALUES (1, 'General', NOW());
