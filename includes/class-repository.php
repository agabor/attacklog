<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Repository {

	public function upsert_request_type( $http_method, $request_path ) {
		global $wpdb;

		$table        = Schema::get_table_name( 'request_types' );
		$path_hash    = sha1( $http_method . ' ' . $request_path );
		$current_time = gmdate( 'Y-m-d H:i:s' );

		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (http_method, request_path, path_hash, first_seen, last_seen, hit_count) VALUES (%s, %s, %s, %s, %s, 1) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), last_seen = %s, hit_count = hit_count + 1",
				$http_method,
				$request_path,
				$path_hash,
				$current_time,
				$current_time,
				$current_time
			)
		);

		return (int) $wpdb->insert_id;
	}

	public function upsert_user_agent( $user_agent ) {
		global $wpdb;

		if ( null === $user_agent ) {
			return null;
		}

		$table        = Schema::get_table_name( 'user_agents' );
		$ua_hash      = sha1( $user_agent );
		$current_time = gmdate( 'Y-m-d H:i:s' );

		$wpdb->query(
			$wpdb->prepare(
				"INSERT INTO {$table} (user_agent, ua_hash, first_seen, last_seen) VALUES (%s, %s, %s, %s) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id), last_seen = %s",
				$user_agent,
				$ua_hash,
				$current_time,
				$current_time,
				$current_time
			)
		);

		return (int) $wpdb->insert_id;
	}

	public function get_error_type_id( $error_type_name ) {
		$error_type_map = $this->get_error_type_map();

		return isset( $error_type_map[ $error_type_name ] ) ? $error_type_map[ $error_type_name ] : null;
	}

	private function get_error_type_map() {
		global $wpdb;

		$cached_map = wp_cache_get( 'error_type_map', 'attacklog' );

		if ( false !== $cached_map ) {
			return $cached_map;
		}

		$table = Schema::get_table_name( 'error_types' );
		$rows  = $wpdb->get_results( "SELECT id, name FROM {$table}" );

		$error_type_map = array();

		foreach ( $rows as $row ) {
			$error_type_map[ $row->name ] = (int) $row->id;
		}

		wp_cache_set( 'error_type_map', $error_type_map, 'attacklog' );

		return $error_type_map;
	}

	public function insert_request( array $request_data ) {
		global $wpdb;

		$table = Schema::get_table_name( 'requests' );

		$wpdb->insert(
			$table,
			array(
				'request_type_id' => $request_data['request_type_id'],
				'return_code'     => $request_data['return_code'],
				'cf_ray'          => $request_data['cf_ray'],
				'cf_ipcountry'    => $request_data['cf_ipcountry'],
				'cf_visitor'      => $request_data['cf_visitor'],
				'client_ip'       => $request_data['client_ip'],
				'remote_addr'     => $request_data['remote_addr'],
				'user_agent_id'   => $request_data['user_agent_id'],
				'created_at'      => $request_data['created_at'],
			),
			array( '%d', '%d', '%s', '%s', '%s', '%s', '%s', '%d', '%s' )
		);

		return (int) $wpdb->insert_id;
	}

	public function insert_request_errors( $request_id, array $error_type_ids_with_details ) {
		global $wpdb;

		if ( empty( $error_type_ids_with_details ) ) {
			return;
		}

		$table        = Schema::get_table_name( 'request_errors' );
		$current_time = gmdate( 'Y-m-d H:i:s' );

		foreach ( $error_type_ids_with_details as $error_type_id => $detail ) {
			$wpdb->insert(
				$table,
				array(
					'request_id'    => $request_id,
					'error_type_id' => $error_type_id,
					'detail'        => $detail,
					'created_at'    => $current_time,
				),
				array( '%d', '%d', '%s', '%s' )
			);
		}
	}
}