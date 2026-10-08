<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Schema {

	const DB_VERSION = '1.0.0';

	const ERROR_TYPE_CF_BYPASS = 1;

	const ERROR_TYPE_PROBING = 2;

	const ERROR_TYPE_DIRECT_PHP = 3;

	const ERROR_TYPE_XMLRPC = 4;

	const ERROR_TYPE_SUSPICIOUS_UA = 5;

	public static function get_table_name( $suffix ) {
		global $wpdb;

		return $wpdb->prefix . 'attacklog_' . $suffix;
	}

	public static function create_or_upgrade() {
		$installed_version = get_option( 'attacklog_db_version', '' );

		if ( self::DB_VERSION === $installed_version ) {
			return;
		}

		require_once ABSPATH . 'wp-admin/includes/upgrade.php';

		foreach ( self::get_schema_sql() as $table_sql ) {
			dbDelta( $table_sql );
		}

		self::seed_error_types();

		update_option( 'attacklog_db_version', self::DB_VERSION );
	}

	public static function get_schema_sql() {
		global $wpdb;

		$charset_collate = $wpdb->get_charset_collate();

		$request_types_table  = self::get_table_name( 'request_types' );
		$error_types_table    = self::get_table_name( 'error_types' );
		$requests_table       = self::get_table_name( 'requests' );
		$request_errors_table = self::get_table_name( 'request_errors' );
		$user_agents_table    = self::get_table_name( 'user_agents' );

		$statements = array();

		$statements[] = "CREATE TABLE {$request_types_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			http_method VARCHAR(10) NOT NULL,
			request_path VARCHAR(2048) NOT NULL,
			path_hash CHAR(40) NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			hit_count INT UNSIGNED NOT NULL DEFAULT 1,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_hash (path_hash),
			KEY idx_last_seen (last_seen)
		) {$charset_collate};";

		$statements[] = "CREATE TABLE {$error_types_table} (
			id TINYINT UNSIGNED NOT NULL,
			name VARCHAR(50) NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_name (name)
		) {$charset_collate};";

		$statements[] = "CREATE TABLE {$user_agents_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			user_agent VARCHAR(512) NOT NULL,
			ua_hash CHAR(40) NOT NULL,
			first_seen DATETIME NOT NULL,
			last_seen DATETIME NOT NULL,
			PRIMARY KEY  (id),
			UNIQUE KEY uq_ua_hash (ua_hash)
		) {$charset_collate};";

		$statements[] = "CREATE TABLE {$requests_table} (
			id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
			request_type_id BIGINT UNSIGNED NOT NULL,
			return_code SMALLINT UNSIGNED NOT NULL,
			cf_ray VARCHAR(64) NULL,
			cf_ipcountry CHAR(2) NULL,
			cf_visitor VARCHAR(64) NULL,
			client_ip VARBINARY(16) NULL,
			remote_addr VARBINARY(16) NULL,
			user_agent_id BIGINT UNSIGNED NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (id),
			KEY idx_created (created_at),
			KEY idx_req (request_type_id),
			KEY idx_ip (client_ip, created_at),
			KEY idx_ua (user_agent_id)
		) {$charset_collate};";

		$statements[] = "CREATE TABLE {$request_errors_table} (
			request_id BIGINT UNSIGNED NOT NULL,
			error_type_id TINYINT UNSIGNED NOT NULL,
			detail VARCHAR(255) NULL,
			created_at DATETIME NOT NULL,
			PRIMARY KEY  (request_id, error_type_id),
			KEY idx_type_time (error_type_id, created_at, request_id)
		) {$charset_collate};";

		return $statements;
	}

	public static function seed_error_types() {
		global $wpdb;

		$table = self::get_table_name( 'error_types' );

		foreach ( self::get_error_type_ids() as $name => $id ) {
			$wpdb->query(
				$wpdb->prepare(
					"INSERT IGNORE INTO {$table} (id, name) VALUES (%d, %s)",
					$id,
					$name
				)
			);
		}
	}

	public static function get_error_type_ids() {
		return array(
			'Cloudflare Bypass'     => self::ERROR_TYPE_CF_BYPASS,
			'Probing'               => self::ERROR_TYPE_PROBING,
			'Direct PHP Access'     => self::ERROR_TYPE_DIRECT_PHP,
			'XML-RPC'               => self::ERROR_TYPE_XMLRPC,
			'Suspicious User Agent' => self::ERROR_TYPE_SUSPICIOUS_UA,
		);
	}
}