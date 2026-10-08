<?php
/**
 * Database access layer for Attack Log data.
 *
 * @package AttackLog
 */

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

/**
 * Provides all SQL operations used to write and read logged requests,
 * their deduplicated request types and user agents, and their error
 * type associations.
 */
class Repository {

	/**
	 * Upserts a (method, path) pair into the request_types table.
	 *
	 * @param string $http_method   HTTP method of the request.
	 * @param string $request_path  Normalized request path.
	 *
	 * @return int Request type ID.
	 */
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

	/**
	 * Upserts a User-Agent string into the user_agents table.
	 *
	 * @param string|null $user_agent Sanitized User-Agent string, or null when missing.
	 *
	 * @return int|null User agent ID, or null when $user_agent is null.
	 */
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

	/**
	 * Looks up an error type ID by name, using a cached map of all
	 * error types to avoid repeated queries.
	 *
	 * @param string $error_type_name Error type name, e.g. 'Probing'.
	 *
	 * @return int|null Error type ID, or null when the name is unknown.
	 */
	public function get_error_type_id( $error_type_name ) {
		$error_type_map = $this->get_error_type_map();

		return isset( $error_type_map[ $error_type_name ] ) ? $error_type_map[ $error_type_name ] : null;
	}

	/**
	 * Returns the cached name => id map of all error types, querying and
	 * caching it on first use.
	 *
	 * @return array
	 */
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

	/**
	 * Inserts a single logged request.
	 *
	 * @param array $request_data {
	 *     Request data to store.
	 *
	 *     @type int         $request_type_id Request type ID.
	 *     @type int         $return_code     Final HTTP status code.
	 *     @type string|null $cf_ray          CF-Ray header value.
	 *     @type string|null $cf_ipcountry    CF-IPCountry header value.
	 *     @type string|null $cf_visitor      CF-Visitor header value.
	 *     @type string|null $client_ip       Binary client IP.
	 *     @type string|null $remote_addr     Binary remote address.
	 *     @type int|null    $user_agent_id   User agent ID.
	 *     @type string      $created_at      UTC datetime.
	 * }
	 *
	 * @return int Inserted request ID.
	 */
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

	/**
	 * Inserts the matched error type rows for a logged request.
	 *
	 * @param int   $request_id                  Request ID the error types belong to.
	 * @param array $error_type_ids_with_details  Map of error_type_id => detail (string or null).
	 *
	 * @return void
	 */
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