<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Repository {

	const BATCH_SIZE = 5000;

	const CACHE_GROUP = 'attacklog';

	const CACHE_LIFETIME = 60;

	public function upsert_request_type( $http_method, $request_path ) {
		global $wpdb;

		$table        = Schema::get_table_name( 'request_types' );
		$path_hash    = sha1( $http_method . ' ' . $request_path );
		$current_time = gmdate( 'Y-m-d H:i:s' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to a custom plugin table; an upsert cannot be cached and read caches are versioned and invalidated separately.
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

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Write to a custom plugin table; an upsert cannot be cached and read caches are versioned and invalidated separately.
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

	public function insert_request( array $request_data ) {
		global $wpdb;

		$table = Schema::get_table_name( 'requests' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Write to a custom plugin table; no core API exists for it.
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

	public function insert_request_errors( $request_id, array $error_type_ids_with_details, $created_at ) {
		global $wpdb;

		if ( empty( $error_type_ids_with_details ) ) {
			return;
		}

		$table = Schema::get_table_name( 'request_errors' );

		foreach ( $error_type_ids_with_details as $error_type_id => $detail ) {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Write to a custom plugin table; the cache is invalidated after the inserts.
			$wpdb->insert(
				$table,
				array(
					'request_id'    => (int) $request_id,
					'error_type_id' => (int) $error_type_id,
					'detail'        => $detail,
					'created_at'    => $created_at,
				),
				array( '%d', '%d', '%s', '%s' )
			);
		}

		$this->invalidate_cache();
	}

	public function get_tab_counts(): array {
		global $wpdb;

		$cache_key    = $this->build_cache_key( 'tab_counts' );
		$cached_value = wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached_value ) {
			return $cached_value;
		}

		$requests_table = Schema::get_table_name( 'requests' );
		$errors_table   = Schema::get_table_name( 'request_errors' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table; the result is cached with wp_cache_set() below.
		$tab_counts = array( 'all' => (int) $wpdb->get_var( "SELECT COUNT(*) FROM {$requests_table}" ) );

		foreach ( Schema::get_error_type_ids() as $error_type_id ) {
			$tab_counts[ $error_type_id ] = 0;
		}

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table; the result is cached with wp_cache_set() below.
		$count_rows = $wpdb->get_results( "SELECT error_type_id, COUNT(*) AS total FROM {$errors_table} GROUP BY error_type_id" );

		foreach ( $count_rows as $count_row ) {
			$tab_counts[ (int) $count_row->error_type_id ] = (int) $count_row->total;
		}

		wp_cache_set( $cache_key, $tab_counts, self::CACHE_GROUP, self::CACHE_LIFETIME );

		return $tab_counts;
	}

	public function count_requests( $error_type_id ): int {
		$tab_counts = $this->get_tab_counts();
		$count_key  = null === $error_type_id ? 'all' : (int) $error_type_id;

		return isset( $tab_counts[ $count_key ] ) ? (int) $tab_counts[ $count_key ] : 0;
	}

	public function get_requests( $error_type_id, $orderby, $order, $page, $per_page ): array {
		$error_type_id   = null === $error_type_id ? null : (int) $error_type_id;
		$order_direction = 'ASC' === strtoupper( (string) $order ) ? 'ASC' : 'DESC';
		$page_number     = max( 1, (int) $page );
		$page_size       = max( 1, (int) $per_page );
		$offset          = ( $page_number - 1 ) * $page_size;

		$cache_key    = $this->build_cache_key(
			'requests_' . md5( wp_json_encode( array( $error_type_id, $orderby, $order_direction, $page_number, $page_size ) ) )
		);
		$cached_value = wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached_value ) {
			return $cached_value;
		}

		if ( null === $error_type_id ) {
			$rows = $this->query_all_requests( $orderby, $order_direction, $page_size, $offset );
		} else {
			$rows = $this->query_requests_by_error_type( $error_type_id, $orderby, $order_direction, $page_size, $offset );
		}

		if ( ! is_array( $rows ) ) {
			return array();
		}

		wp_cache_set( $cache_key, $rows, self::CACHE_GROUP, self::CACHE_LIFETIME );

		return $rows;
	}

	private function get_request_columns_sql(): string {
		return 'r.id, r.return_code, r.cf_ray, r.cf_ipcountry, r.cf_visitor, r.client_ip, r.remote_addr, r.created_at, t.http_method, t.request_path, ua.user_agent';
	}

	private function get_request_joins_sql(): string {
		$request_types_table = Schema::get_table_name( 'request_types' );
		$user_agents_table   = Schema::get_table_name( 'user_agents' );

		return "INNER JOIN {$request_types_table} t ON t.id = r.request_type_id LEFT JOIN {$user_agents_table} ua ON ua.id = r.user_agent_id";
	}

	private function query_all_requests( $orderby, $order_direction, $page_size, $offset ) {
		global $wpdb;

		$requests_table   = Schema::get_table_name( 'requests' );
		$selected_columns = $this->get_request_columns_sql();
		$shared_joins     = $this->get_request_joins_sql();
		$order_column     = 'return_code' === $orderby ? 'r.return_code' : 'r.created_at';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin tables; the only caller, get_requests(), caches the result.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$selected_columns}, NULL AS detail FROM {$requests_table} r {$shared_joins} ORDER BY {$order_column} {$order_direction}, r.id {$order_direction} LIMIT %d OFFSET %d",
				$page_size,
				$offset
			)
		);
	}

	private function query_requests_by_error_type( $error_type_id, $orderby, $order_direction, $page_size, $offset ) {
		global $wpdb;

		$requests_table   = Schema::get_table_name( 'requests' );
		$errors_table     = Schema::get_table_name( 'request_errors' );
		$selected_columns = $this->get_request_columns_sql();
		$shared_joins     = $this->get_request_joins_sql();
		$order_column     = 'return_code' === $orderby ? 'r.return_code' : 'e.created_at';

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Custom plugin tables; the only caller, get_requests(), caches the result.
		return $wpdb->get_results(
			$wpdb->prepare(
				"SELECT {$selected_columns}, e.detail AS detail FROM {$errors_table} e INNER JOIN {$requests_table} r ON r.id = e.request_id {$shared_joins} WHERE e.error_type_id = %d ORDER BY {$order_column} {$order_direction}, r.id {$order_direction} LIMIT %d OFFSET %d",
				$error_type_id,
				$page_size,
				$offset
			)
		);
	}

	public function get_error_types_for_requests( array $request_ids ): array {
		global $wpdb;

		$request_ids = array_values( array_unique( array_map( 'intval', $request_ids ) ) );

		if ( empty( $request_ids ) ) {
			return array();
		}

		$cache_key    = $this->build_cache_key( 'error_types_' . md5( implode( ',', $request_ids ) ) );
		$cached_value = wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached_value ) {
			return $cached_value;
		}

		$errors_table = Schema::get_table_name( 'request_errors' );
		$placeholders = implode( ',', array_fill( 0, count( $request_ids ), '%d' ) );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table; the result is cached with wp_cache_set() below.
		$rows = $wpdb->get_results(
			$wpdb->prepare(
				"SELECT request_id, error_type_id, detail FROM {$errors_table} WHERE request_id IN ({$placeholders})",
				$request_ids
			)
		);

		$error_types_by_request = array();

		foreach ( (array) $rows as $row ) {
			$error_types_by_request[ (int) $row->request_id ][ (int) $row->error_type_id ] = $row->detail;
		}

		wp_cache_set( $cache_key, $error_types_by_request, self::CACHE_GROUP, self::CACHE_LIFETIME );

		return $error_types_by_request;
	}

	public function get_clear_type_impact( $error_type_id ): array {
		global $wpdb;

		$error_type_id = (int) $error_type_id;
		$cache_key     = $this->build_cache_key( 'clear_impact_' . $error_type_id );
		$cached_value  = wp_cache_get( $cache_key, self::CACHE_GROUP );

		if ( false !== $cached_value ) {
			return $cached_value;
		}

		$errors_table = Schema::get_table_name( 'request_errors' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table; the result is cached with wp_cache_set() below.
		$total_requests = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(*) FROM {$errors_table} WHERE error_type_id = %d",
				$error_type_id
			)
		);

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery -- Custom plugin table; the result is cached with wp_cache_set() below.
		$shared_requests = (int) $wpdb->get_var(
			$wpdb->prepare(
				"SELECT COUNT(DISTINCT e.request_id) FROM {$errors_table} e INNER JOIN {$errors_table} o ON o.request_id = e.request_id AND o.error_type_id <> e.error_type_id WHERE e.error_type_id = %d",
				$error_type_id
			)
		);

		$impact = array(
			'total'   => $total_requests,
			'shared'  => $shared_requests,
			'deleted' => $total_requests - $shared_requests,
		);

		wp_cache_set( $cache_key, $impact, self::CACHE_GROUP, self::CACHE_LIFETIME );

		return $impact;
	}

	public function delete_error_type( $error_type_id ): int {
		global $wpdb;

		$errors_table  = Schema::get_table_name( 'request_errors' );
		$error_type_id = (int) $error_type_id;
		$total_deleted = 0;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched delete on a custom plugin table; the cache is invalidated in cleanup_orphans().
			$deleted_rows = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$errors_table} WHERE error_type_id = %d LIMIT %d",
					$error_type_id,
					self::BATCH_SIZE
				)
			);

			$deleted_rows   = (int) $deleted_rows;
			$total_deleted += $deleted_rows;
		} while ( self::BATCH_SIZE === $deleted_rows );

		$this->cleanup_orphans();

		return $total_deleted;
	}

	public function delete_requests_older_than( int $keep_days ): int {
		global $wpdb;

		$requests_table = Schema::get_table_name( 'requests' );
		$errors_table   = Schema::get_table_name( 'request_errors' );
		$cutoff         = gmdate( 'Y-m-d H:i:s', time() - $keep_days * DAY_IN_SECONDS );
		$total_requests = 0;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh data is required to select rows for deletion; the cache is invalidated in cleanup_orphans().
			$request_ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT id FROM {$requests_table} WHERE created_at < %s LIMIT %d",
					$cutoff,
					self::BATCH_SIZE
				)
			);

			if ( empty( $request_ids ) ) {
				break;
			}

			$id_placeholders = implode( ',', array_fill( 0, count( $request_ids ), '%d' ) );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched delete on a custom plugin table; the cache is invalidated in cleanup_orphans().
			$wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$errors_table} WHERE request_id IN ({$id_placeholders})",
					$request_ids
				)
			);

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched delete on a custom plugin table; the cache is invalidated in cleanup_orphans().
			$deleted_requests = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$requests_table} WHERE id IN ({$id_placeholders})",
					$request_ids
				)
			);

			if ( ! $deleted_requests ) {
				break;
			}

			$batch_size      = count( $request_ids );
			$total_requests += $batch_size;
		} while ( self::BATCH_SIZE === $batch_size );

		if ( $total_requests > 0 ) {
			$this->cleanup_orphans();
		}

		return $total_requests;
	}

	public function delete_requests_by_ip( string $binary_ip, array $error_type_ids ): int {
		global $wpdb;

		$prepared_condition_sql = $wpdb->prepare(
			'((r.cf_ray IS NOT NULL AND r.cf_ipcountry IS NOT NULL AND r.cf_visitor IS NOT NULL AND r.client_ip = %s) OR ((r.cf_ray IS NULL OR r.cf_ipcountry IS NULL OR r.cf_visitor IS NULL) AND r.remote_addr = %s))',
			$binary_ip,
			$binary_ip
		);

		return $this->delete_error_rows_for_matching_requests( $prepared_condition_sql, $error_type_ids );
	}

	public function delete_requests_by_user_agent( string $user_agent, array $error_type_ids ): int {
		global $wpdb;

		$user_agents_table = Schema::get_table_name( 'user_agents' );

		$prepared_condition_sql = $wpdb->prepare(
			"r.user_agent_id IN (SELECT ua.id FROM {$user_agents_table} ua WHERE BINARY ua.user_agent = %s)",
			$user_agent
		);

		return $this->delete_error_rows_for_matching_requests( $prepared_condition_sql, $error_type_ids );
	}

	private function delete_error_rows_for_matching_requests( string $prepared_condition_sql, array $error_type_ids ): int {
		global $wpdb;

		$requests_table = Schema::get_table_name( 'requests' );
		$errors_table   = Schema::get_table_name( 'request_errors' );
		$select_filter  = $this->build_error_type_filter( 'e.error_type_id', $error_type_ids );
		$delete_filter  = $this->build_error_type_filter( 'error_type_id', $error_type_ids );
		$limit_clause   = $wpdb->prepare( 'LIMIT %d', self::BATCH_SIZE );
		$total_requests = 0;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Fresh data is required to select rows for deletion; all interpolated fragments were already prepared; the cache is invalidated in cleanup_orphans().
			$request_ids = $wpdb->get_col(
				"SELECT DISTINCT r.id FROM {$requests_table} r INNER JOIN {$errors_table} e ON e.request_id = r.id WHERE {$prepared_condition_sql} {$select_filter} {$limit_clause}"
			);

			if ( empty( $request_ids ) ) {
				break;
			}

			$id_placeholders = implode( ',', array_fill( 0, count( $request_ids ), '%d' ) );
			$id_clause       = $wpdb->prepare( "request_id IN ({$id_placeholders})", $request_ids );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching, WordPress.DB.PreparedSQL.NotPrepared -- Batched delete on a custom plugin table; all interpolated fragments were already prepared; the cache is invalidated in cleanup_orphans().
			$wpdb->query( "DELETE FROM {$errors_table} WHERE {$id_clause} {$delete_filter}" );

			$total_requests += count( $request_ids );
		} while ( count( $request_ids ) === self::BATCH_SIZE );

		if ( $total_requests > 0 ) {
			$this->cleanup_orphans();
		}

		return $total_requests;
	}

	private function build_error_type_filter( string $column_name, array $error_type_ids ): string {
		global $wpdb;

		$error_type_ids = array_values( array_unique( array_map( 'intval', $error_type_ids ) ) );

		if ( empty( $error_type_ids ) ) {
			return '';
		}

		$placeholders = implode( ',', array_fill( 0, count( $error_type_ids ), '%d' ) );

		return $wpdb->prepare( "AND {$column_name} IN ({$placeholders})", $error_type_ids );
	}

	public function delete_all(): void {
		$this->delete_all_rows_in_batches( Schema::get_table_name( 'request_errors' ) );
		$this->delete_all_rows_in_batches( Schema::get_table_name( 'requests' ) );
		$this->delete_all_rows_in_batches( Schema::get_table_name( 'request_types' ) );
		$this->delete_all_rows_in_batches( Schema::get_table_name( 'user_agents' ) );

		$this->invalidate_cache();
	}

	private function delete_all_rows_in_batches( $table ) {
		global $wpdb;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched delete on a custom plugin table; the cache is invalidated in delete_all().
			$deleted_rows = (int) $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$table} LIMIT %d",
					self::BATCH_SIZE
				)
			);
		} while ( self::BATCH_SIZE === $deleted_rows );
	}

	private function cleanup_orphans(): void {
		$requests_table      = Schema::get_table_name( 'requests' );
		$request_types_table = Schema::get_table_name( 'request_types' );
		$user_agents_table   = Schema::get_table_name( 'user_agents' );
		$errors_table        = Schema::get_table_name( 'request_errors' );

		$this->delete_orphaned_rows( $requests_table, $errors_table, 'request_id' );
		$this->delete_orphaned_rows( $request_types_table, $requests_table, 'request_type_id' );
		$this->delete_orphaned_rows( $user_agents_table, $requests_table, 'user_agent_id' );

		$this->recompute_hit_counts();
		$this->invalidate_cache();
	}

	private function delete_orphaned_rows( $parent_table, $child_table, $child_column ) {
		global $wpdb;

		do {
			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Fresh data is required to find orphans on custom plugin tables; the cache is invalidated in cleanup_orphans().
			$orphan_ids = $wpdb->get_col(
				$wpdb->prepare(
					"SELECT p.id FROM {$parent_table} p LEFT JOIN {$child_table} c ON c.{$child_column} = p.id WHERE c.{$child_column} IS NULL LIMIT %d",
					self::BATCH_SIZE
				)
			);

			if ( empty( $orphan_ids ) ) {
				return;
			}

			$placeholders = implode( ',', array_fill( 0, count( $orphan_ids ), '%d' ) );

			// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Batched delete on a custom plugin table; the cache is invalidated in cleanup_orphans().
			$deleted_rows = $wpdb->query(
				$wpdb->prepare(
					"DELETE FROM {$parent_table} WHERE id IN ({$placeholders})",
					$orphan_ids
				)
			);

			if ( ! $deleted_rows ) {
				return;
			}
		} while ( count( $orphan_ids ) === self::BATCH_SIZE );
	}

	private function recompute_hit_counts() {
		global $wpdb;

		$requests_table      = Schema::get_table_name( 'requests' );
		$request_types_table = Schema::get_table_name( 'request_types' );

		// phpcs:ignore WordPress.DB.DirectDatabaseQuery.DirectQuery, WordPress.DB.DirectDatabaseQuery.NoCaching -- Maintenance update on a custom plugin table; the cache is invalidated in cleanup_orphans().
		$wpdb->query(
			"UPDATE {$request_types_table} t INNER JOIN (SELECT request_type_id, COUNT(*) AS total FROM {$requests_table} GROUP BY request_type_id) c ON c.request_type_id = t.id SET t.hit_count = c.total WHERE t.hit_count <> c.total"
		);
	}

	private function build_cache_key( $name ) {
		return $name . '_' . $this->get_cache_version();
	}

	private function get_cache_version() {
		$cache_version = wp_cache_get( 'cache_version', self::CACHE_GROUP );

		if ( false === $cache_version ) {
			$cache_version = $this->generate_cache_version();
			wp_cache_set( 'cache_version', $cache_version, self::CACHE_GROUP );
		}

		return $cache_version;
	}

	private function generate_cache_version() {
		return uniqid( '', true );
	}

	private function invalidate_cache(): void {
		wp_cache_set( 'cache_version', $this->generate_cache_version(), self::CACHE_GROUP );
	}
}