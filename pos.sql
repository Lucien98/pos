/*
Navicat MySQL Data Transfer

Source Server         : localmysql
Source Server Version : 50726
Source Host           : localhost:3306
Source Database       : pos

Target Server Type    : MYSQL
Target Server Version : 50726
File Encoding         : 65001

Date: 2020-07-21 16:49:31
*/

SET FOREIGN_KEY_CHECKS=0;

-- ----------------------------
-- Table structure for block
-- ----------------------------
DROP TABLE IF EXISTS `block`;
CREATE TABLE `block` (
  `height` int(11) NOT NULL,
  `prevhash` varchar(64) DEFAULT NULL,
  `vrf_pk` varchar(66) DEFAULT NULL,
  `vrf_hash` varchar(64) DEFAULT NULL,
  `vrf_proof` varchar(162) DEFAULT NULL,
  `merkle_root` varchar(64) DEFAULT NULL,
  `signature` varchar(149) DEFAULT NULL,
  `tx` longtext,
  `hash` varchar(64) DEFAULT NULL,
  PRIMARY KEY (`height`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;

-- ----------------------------
-- Table structure for stakeholder
-- ----------------------------
DROP TABLE IF EXISTS `stakeholder`;
CREATE TABLE `stakeholder` (
  `id` int(5) NOT NULL,
  `pk` varchar(255) DEFAULT NULL,
  `sk` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=MyISAM DEFAULT CHARSET=utf8;
