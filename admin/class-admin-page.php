<?php

namespace AttackLog\Admin;

use AttackLog\Cf_Detector;
use AttackLog\Ip_Resolver;
use AttackLog\Repository;
use AttackLog\Schema;

defined( 'ABSPATH' ) || exit;

class Admin_Page {

	const PAGE_SLUG = 'attack-log';

	const NONCE_ACTION = 'attacklog_admin';

	const LAST_TAB_META_KEY = 'attacklog_last_tab';

	const PER_PAGE = 50;

	private $repository;

	private $ip_resolver;

	private $page_hook = '';

	public function __construct( Repository $repository ) {
		$this->repository  = $repository;
		$this->ip_resolver = new Ip_Resolver();
	}

	public function register_hooks(): void {
		add_action( 'admin_menu', array( $this, 'register_menu' ) );
		add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_assets' ) );
	}

	public function register_menu(): void {
		$page_hook = add_menu_page(
			__( 'Attack Log', 'attack-log' ),
			__( 'Attack Log', 'attack-log' ),
			'manage_options',
			self::PAGE_SLUG,
			array( $this, 'render_page' ),
			'dashicons-shield-alt'
		);

		if ( ! is_string( $page_hook ) ) {
			return;
		}

		$this->page_hook = $page_hook;

		add_action( 'load-' . $page_hook, array( $this, 'on_load_page' ) );
	}

	public function on_load_page(): void {
		Cf_Detector::maybe_auto_set_on_first_admin_visit();
	}

	public function enqueue_assets( $hook_suffix ): void {
		if ( '' === $this->page_hook || $this->page_hook !== $hook_suffix ) {
			return;
		}

		wp_enqueue_style(
			'attacklog-admin',
			ATTACKLOG_PLUGIN_URL . 'assets/css/admin.css',
			array(),
			ATTACKLOG_VERSION
		);

		wp_enqueue_script(
			'attacklog-admin',
			ATTACKLOG_PLUGIN_URL . 'assets/js/admin.js',
			array(),
			ATTACKLOG_VERSION,
			true
		);

		wp_localize_script(
			'attacklog-admin',
			'attacklogAdmin',
			array(
				'ajaxUrl'               => admin_url( 'admin-ajax.php' ),
				'nonce'                 => wp_create_nonce( self::NONCE_ACTION ),
				'requestHasAllCfHeaders' => Cf_Detector::request_has_all_cf_headers() ? '1' : '0',
				'strings'               => array(
					'confirmEnableWithoutCloudflare' => __( 'This request did not come through Cloudflare. If the site is not really behind Cloudflare, every front-end request will be logged as a Cloudflare Bypass. Turn detection on anyway?', 'attack-log' ),
					'confirmDisable'                 => __( 'Requests that reach your server directly will no longer be logged as Cloudflare Bypass. Turn detection off?', 'attack-log' ),
					'clearAllPrompt'                 => __( 'This deletes the entire log, including entries in all other tabs. Type CLEAR to confirm.', 'attack-log' ),
					'clearAllMismatch'               => __( 'The log was not cleared because the confirmation text did not match.', 'attack-log' ),
					'genericError'                   => __( 'Something went wrong. Please try again.', 'attack-log' ),
				),
			)
		);
	}

	public function render_page(): void {
		if ( ! current_user_can( 'manage_options' ) ) {
			wp_die( esc_html__( 'You do not have permission to access this page.', 'attack-log' ) );
		}

		$attacklog_view = $this->get_log_view_data();

		require ATTACKLOG_PLUGIN_DIR . 'admin/views/log.php';
	}

	public function get_tab_definitions(): array {
		return array(
			array(
				'slug'          => 'all',
				'label'         => __( 'All', 'attack-log' ),
				'error_type_id' => null,
				'badge_class'   => 'attacklog-badge--all',
				'empty_message' => __( 'No suspicious requests have been logged yet.', 'attack-log' ),
			),
			array(
				'slug'          => 'cloudflare-bypass',
				'label'         => __( 'Cloudflare Bypass', 'attack-log' ),
				'error_type_id' => Schema::ERROR_TYPE_CF_BYPASS,
				'badge_class'   => 'attacklog-badge--cloudflare-bypass',
				'empty_message' => __( 'Requests that reach your server without the headers Cloudflare always adds appear here.', 'attack-log' ),
			),
			array(
				'slug'          => 'probing',
				'label'         => __( 'Probing', 'attack-log' ),
				'error_type_id' => Schema::ERROR_TYPE_PROBING,
				'badge_class'   => 'attacklog-badge--probing',
				'empty_message' => __( 'Requests that end in a 404 and look for files scanners hunt for, such as .env or backup.sql, appear here.', 'attack-log' ),
			),
			array(
				'slug'          => 'direct-php',
				'label'         => __( 'Direct PHP Access', 'attack-log' ),
				'error_type_id' => Schema::ERROR_TYPE_DIRECT_PHP,
				'badge_class'   => 'attacklog-badge--direct-php',
				'empty_message' => __( 'Requests for PHP files inside wp-includes or the uploads folder appear here.', 'attack-log' ),
			),
			array(
				'slug'          => 'xmlrpc',
				'label'         => __( 'XML-RPC', 'attack-log' ),
				'error_type_id' => Schema::ERROR_TYPE_XMLRPC,
				'badge_class'   => 'attacklog-badge--xmlrpc',
				'empty_message' => __( 'Requests to xmlrpc.php appear here.', 'attack-log' ),
			),
			array(
				'slug'          => 'suspicious-ua',
				'label'         => __( 'Suspicious User Agent', 'attack-log' ),
				'error_type_id' => Schema::ERROR_TYPE_SUSPICIOUS_UA,
				'badge_class'   => 'attacklog-badge--suspicious-ua',
				'empty_message' => __( 'Requests with a missing, malformed, HTTP library or scanner User-Agent appear here.', 'attack-log' ),
			),
		);
	}

	public function get_error_type_label( $error_type_id ): string {
		foreach ( $this->get_tab_definitions() as $tab_definition ) {
			if ( null !== $tab_definition['error_type_id'] && (int) $error_type_id === $tab_definition['error_type_id'] ) {
				return $tab_definition['label'];
			}
		}

		return '';
	}

	public function get_current_tab(): string {
		$valid_slugs = wp_list_pluck( $this->get_tab_definitions(), 'slug' );
		$user_id     = get_current_user_id();
		$stored_slug = (string) get_user_meta( $user_id, self::LAST_TAB_META_KEY, true );

		$requested_slug = isset( $_GET['type'] ) ? sanitize_key( wp_unslash( $_GET['type'] ) ) : '';

		if ( in_array( $requested_slug, $valid_slugs, true ) ) {
			if ( $requested_slug !== $stored_slug ) {
				update_user_meta( $user_id, self::LAST_TAB_META_KEY, $requested_slug );
			}

			return $requested_slug;
		}

		if ( in_array( $stored_slug, $valid_slugs, true ) ) {
			return $stored_slug;
		}

		return 'all';
	}

	public function build_tab_url( $tab_slug, $page = 1 ): string {
		return $this->build_page_url(
			array(
				'type'  => $tab_slug,
				'paged' => max( 1, (int) $page ),
			)
		);
	}

	private function build_page_url( array $query_arguments ): string {
		return add_query_arg(
			array_merge( array( 'page' => self::PAGE_SLUG ), $query_arguments ),
			admin_url( 'admin.php' )
		);
	}

	public function get_log_view_data(): array {
		$current_slug             = $this->get_current_tab();
		$current_tab              = $this->find_tab_by_slug( $current_slug );
		$current_error_type_id    = $current_tab['error_type_id'];
		$bypass_detection_enabled = Cf_Detector::is_bypass_detection_enabled();
		$sort                     = $this->read_sort();

		$total_items  = $this->repository->count_requests( $current_error_type_id );
		$total_pages  = max( 1, (int) ceil( $total_items / self::PER_PAGE ) );
		$current_page = min( $this->read_requested_page(), $total_pages );

		$requests = $this->repository->get_requests(
			$current_error_type_id,
			$sort['orderby'],
			$sort['order'],
			$current_page,
			self::PER_PAGE
		);

		$error_types_by_request = $this->repository->get_error_types_for_requests( wp_list_pluck( $requests, 'id' ) );

		$tabs                    = $this->build_tab_view_models( $current_slug, $bypass_detection_enabled );
		$tabs_by_error_type_id   = $this->index_tabs_by_error_type_id( $tabs );
		$cloudflare_status       = Cf_Detector::get_status();

		$rows = array();

		foreach ( $requests as $request_row ) {
			$row_error_types = isset( $error_types_by_request[ (int) $request_row->id ] ) ? $error_types_by_request[ (int) $request_row->id ] : array();

			$rows[] = $this->build_row_view_model( $request_row, $row_error_types, $current_error_type_id, $tabs_by_error_type_id );
		}

		$pagination_base_url = $this->build_page_url(
			array(
				'type'    => $current_slug,
				'orderby' => $sort['orderby_param'],
				'order'   => $sort['order_param'],
			)
		);

		return array(
			'tabs'               => $tabs,
			'current_tab'        => $current_tab,
			'sort'               => $this->build_sort_view_model( $current_slug, $sort ),
			'page'               => $current_page,
			'per_page'           => self::PER_PAGE,
			'total_items'        => $total_items,
			'total_pages'        => $total_pages,
			'pagination_base'    => add_query_arg( 'paged', '%#%', $pagination_base_url ),
			'badge_column_label' => null === $current_error_type_id ? __( 'Types', 'attack-log' ) : __( 'Also flagged', 'attack-log' ),
			'rows'               => $rows,
			'cloudflare'         => array(
				'enabled'     => $bypass_detection_enabled,
				'live_note'   => Cf_Detector::get_live_note(),
				'hint'        => Cf_Detector::get_switch_hint(),
				'description' => $this->describe_cf_set_by( $cloudflare_status ),
			),
		);
	}

	public function describe_cf_set_by( array $status ): string {
		$set_by = isset( $status['set_by'] ) ? $status['set_by'] : null;

		if ( 'activation' === $set_by ) {
			return __( 'Set automatically at activation', 'attack-log' );
		}

		if ( 'first_admin_visit' === $set_by ) {
			return __( 'Set automatically on first visit', 'attack-log' );
		}

		if ( 'user' !== $set_by ) {
			return __( 'Not set yet', 'attack-log' );
		}

		$user         = ! empty( $status['user_id'] ) ? get_userdata( (int) $status['user_id'] ) : false;
		$display_name = $user ? $user->display_name : __( 'unknown user', 'attack-log' );
		$set_date     = ! empty( $status['set_at'] )
			? mysql2date( get_option( 'date_format' ), get_date_from_gmt( $status['set_at'] ) )
			: '';

		if ( ! empty( $status['enabled'] ) ) {
			return sprintf(
				/* translators: 1: user display name, 2: date. */
				__( 'Turned on by %1$s, %2$s', 'attack-log' ),
				$display_name,
				$set_date
			);
		}

		return sprintf(
			/* translators: 1: user display name, 2: date. */
			__( 'Turned off by %1$s, %2$s', 'attack-log' ),
			$display_name,
			$set_date
		);
	}

	private function find_tab_by_slug( $tab_slug ): array {
		$tab_definitions = $this->get_tab_definitions();

		foreach ( $tab_definitions as $tab_definition ) {
			if ( $tab_slug === $tab_definition['slug'] ) {
				return $tab_definition;
			}
		}

		return $tab_definitions[0];
	}

	private function read_requested_page(): int {
		return isset( $_GET['paged'] ) ? max( 1, absint( wp_unslash( $_GET['paged'] ) ) ) : 1;
	}

	private function read_sort(): array {
		$orderby_param = 'time';
		$order_param   = 'desc';

		if ( isset( $_GET['orderby'] ) && 'code' === sanitize_key( wp_unslash( $_GET['orderby'] ) ) ) {
			$orderby_param = 'code';
		}

		if ( isset( $_GET['order'] ) && 'asc' === sanitize_key( wp_unslash( $_GET['order'] ) ) ) {
			$order_param = 'asc';
		}

		return array(
			'orderby_param' => $orderby_param,
			'order_param'   => $order_param,
			'orderby'       => 'code' === $orderby_param ? 'return_code' : 'created_at',
			'order'         => 'asc' === $order_param ? 'ASC' : 'DESC',
		);
	}

	private function build_sort_view_model( $current_slug, array $sort ): array {
		$sort_view_model = array();

		foreach ( array( 'time', 'code' ) as $column_name ) {
			$is_active_column = $column_name === $sort['orderby_param'];
			$next_order       = $is_active_column && 'desc' === $sort['order_param'] ? 'asc' : 'desc';
			$indicator        = '';

			if ( $is_active_column ) {
				$indicator = 'desc' === $sort['order_param'] ? '↓' : '↑';
			}

			$sort_view_model[ $column_name . '_url' ]       = $this->build_page_url(
				array(
					'type'    => $current_slug,
					'orderby' => $column_name,
					'order'   => $next_order,
				)
			);
			$sort_view_model[ $column_name . '_indicator' ] = $indicator;
		}

		return $sort_view_model;
	}

	private function build_tab_view_models( $current_slug, $bypass_detection_enabled ): array {
		$tab_counts = $this->repository->get_tab_counts();
		$tabs       = array();

		foreach ( $this->get_tab_definitions() as $tab_definition ) {
			$count_key = null === $tab_definition['error_type_id'] ? 'all' : $tab_definition['error_type_id'];

			$tabs[] = array(
				'slug'            => $tab_definition['slug'],
				'label'           => $tab_definition['label'],
				'error_type_id'   => $tab_definition['error_type_id'],
				'badge_class'     => $tab_definition['badge_class'],
				'empty_message'   => $tab_definition['empty_message'],
				'count'           => isset( $tab_counts[ $count_key ] ) ? (int) $tab_counts[ $count_key ] : 0,
				'url'             => $this->build_tab_url( $tab_definition['slug'] ),
				'is_active'       => $current_slug === $tab_definition['slug'],
				'is_detection_off' => Schema::ERROR_TYPE_CF_BYPASS === $tab_definition['error_type_id'] && ! $bypass_detection_enabled,
				'tooltip'         => null === $tab_definition['error_type_id']
					? __( 'Counts each request once, even if it was logged under several types, so it can be lower than the sum of the other tabs.', 'attack-log' )
					: '',
			);
		}

		return $tabs;
	}

	private function index_tabs_by_error_type_id( array $tabs ): array {
		$indexed_tabs = array();

		foreach ( $tabs as $tab ) {
			if ( null !== $tab['error_type_id'] ) {
				$indexed_tabs[ $tab['error_type_id'] ] = $tab;
			}
		}

		return $indexed_tabs;
	}

	private function build_row_view_model( $request_row, array $row_error_types, $current_error_type_id, array $tabs_by_error_type_id ): array {
		$client_ip   = $this->format_ip( $request_row->client_ip );
		$remote_addr = $this->format_ip( $request_row->remote_addr );
		$status_code = (int) $request_row->return_code;

		return array(
			'id'               => (int) $request_row->id,
			'time'             => get_date_from_gmt( $request_row->created_at, 'Y-m-d H:i:s' ),
			'method'           => (string) $request_row->http_method,
			'path'             => (string) $request_row->request_path,
			'status_code'      => $status_code,
			'status_class'     => $this->get_status_class( $status_code ),
			'client_ip'        => $client_ip,
			'remote_addr'      => $remote_addr,
			'addresses_differ' => '' !== $remote_addr && $client_ip !== $remote_addr,
			'second_line'      => $this->build_second_line( $request_row, $row_error_types, $current_error_type_id ),
			'badges'           => $this->build_row_badges( $row_error_types, $current_error_type_id, $tabs_by_error_type_id ),
		);
	}

	private function build_row_badges( array $row_error_types, $current_error_type_id, array $tabs_by_error_type_id ): array {
		ksort( $row_error_types );

		$badges = array();

		foreach ( array_keys( $row_error_types ) as $error_type_id ) {
			if ( $error_type_id === $current_error_type_id || ! isset( $tabs_by_error_type_id[ $error_type_id ] ) ) {
				continue;
			}

			$badges[] = array(
				'label'       => $tabs_by_error_type_id[ $error_type_id ]['label'],
				'badge_class' => $tabs_by_error_type_id[ $error_type_id ]['badge_class'],
				'url'         => $tabs_by_error_type_id[ $error_type_id ]['url'],
			);
		}

		return $badges;
	}

	private function build_second_line( $request_row, array $row_error_types, $current_error_type_id ): string {
		if ( null !== $current_error_type_id && ! empty( $request_row->detail ) ) {
			return (string) $request_row->detail;
		}

		if ( null === $current_error_type_id ) {
			ksort( $row_error_types );

			foreach ( $row_error_types as $detail ) {
				if ( ! empty( $detail ) ) {
					return (string) $detail;
				}
			}
		}

		if ( null === $request_row->user_agent || '' === $request_row->user_agent ) {
			return __( '— missing —', 'attack-log' );
		}

		return (string) $request_row->user_agent;
	}

	private function get_status_class( $status_code ): string {
		if ( $status_code >= 200 && $status_code < 300 ) {
			return 'attacklog-status--success';
		}

		if ( $status_code >= 400 && $status_code < 500 ) {
			return 'attacklog-status--warning';
		}

		if ( $status_code >= 500 ) {
			return 'attacklog-status--danger';
		}

		return 'attacklog-status--neutral';
	}

	private function format_ip( $binary_ip ): string {
		if ( ! is_string( $binary_ip ) || ! in_array( strlen( $binary_ip ), array( 4, 16 ), true ) ) {
			return '';
		}

		$readable_ip = $this->ip_resolver->to_readable( $binary_ip );

		return null === $readable_ip ? '' : $readable_ip;
	}
}