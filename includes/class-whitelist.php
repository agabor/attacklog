<?php

namespace AttackLog;

defined( 'ABSPATH' ) || exit;

class Whitelist {

	const OPTION_NAME = 'attacklog_whitelist';

	const TYPE_IP = 'ip';

	const TYPE_UA = 'ua';

	const CATEGORY_ALL = 'all';

	const NOTE_MAX_LENGTH = 255;

	const ID_LENGTH = 12;

	private static $cached_entries = null;

	private $ip_resolver;

	public function __construct() {
		$this->ip_resolver = new Ip_Resolver();
	}

	public function get_entries(): array {
		if ( null !== self::$cached_entries ) {
			return self::$cached_entries;
		}

		$stored_entries = get_option( self::OPTION_NAME, array() );
		$entries        = array();

		if ( is_array( $stored_entries ) ) {
			foreach ( $stored_entries as $stored_entry ) {
				$entry = $this->normalize_stored_entry( $stored_entry );

				if ( null !== $entry ) {
					$entries[] = $entry;
				}
			}
		}

		self::$cached_entries = $entries;

		return $entries;
	}

	public function add_entry( array $input, int $user_id ) {
		$sanitized_input = $this->sanitize_input( $input );

		if ( is_wp_error( $sanitized_input ) ) {
			return $sanitized_input;
		}

		$entry = array_merge(
			array(
				'id' => $this->generate_id(),
			),
			$sanitized_input,
			array(
				'created_at' => gmdate( 'Y-m-d H:i:s' ),
				'created_by' => $user_id,
			)
		);

		$entries   = $this->get_entries();
		$entries[] = $entry;

		$this->save_entries( $entries );

		return $entry;
	}

	public function update_entry( string $id, array $input ) {
		$entries     = $this->get_entries();
		$entry_index = $this->find_entry_index( $entries, $id );

		if ( null === $entry_index ) {
			return $this->build_not_found_error();
		}

		$sanitized_input = $this->sanitize_input( $input, $id );

		if ( is_wp_error( $sanitized_input ) ) {
			return $sanitized_input;
		}

		$updated_entry = array_merge( $entries[ $entry_index ], $sanitized_input );

		$entries[ $entry_index ] = $updated_entry;

		$this->save_entries( $entries );

		return $updated_entry;
	}

	public function delete_entry( string $id ): bool {
		$entries     = $this->get_entries();
		$entry_index = $this->find_entry_index( $entries, $id );

		if ( null === $entry_index ) {
			return false;
		}

		unset( $entries[ $entry_index ] );

		$this->save_entries( $entries );

		return true;
	}

	public function sanitize_input( array $input, string $ignore_id = '' ) {
		$type = isset( $input['type'] ) ? sanitize_key( (string) $input['type'] ) : '';

		if ( ! in_array( $type, array( self::TYPE_IP, self::TYPE_UA ), true ) ) {
			return new \WP_Error( 'attacklog_whitelist_invalid_type', __( 'Choose IP or User-Agent as the entry type.', 'attacklog' ) );
		}

		$raw_value = isset( $input['value'] ) ? (string) $input['value'] : '';
		$value     = $this->normalize_value( $type, $raw_value );

		if ( null === $value ) {
			return new \WP_Error( 'attacklog_whitelist_invalid_value', $this->get_invalid_value_message( $type ) );
		}

		$categories = $this->parse_categories( isset( $input['categories'] ) ? $input['categories'] : self::CATEGORY_ALL );

		if ( ! $this->are_categories_valid( $categories ) ) {
			return new \WP_Error( 'attacklog_whitelist_invalid_categories', __( 'Choose at least one valid category.', 'attacklog' ) );
		}

		if ( $this->is_duplicate( $type, $value, $ignore_id ) ) {
			return new \WP_Error( 'attacklog_whitelist_duplicate', __( 'This entry is already on the whitelist.', 'attacklog' ) );
		}

		return array(
			'type'       => $type,
			'value'      => $value,
			'categories' => $categories,
			'note'       => $this->sanitize_note( isset( $input['note'] ) ? (string) $input['note'] : '' ),
		);
	}

	public function parse_categories( $raw ) {
		$raw_items = is_array( $raw ) ? $raw : explode( ',', (string) $raw );
		$items     = array();

		foreach ( $raw_items as $raw_item ) {
			$item = strtolower( trim( (string) $raw_item ) );

			if ( '' !== $item ) {
				$items[] = $item;
			}
		}

		if ( in_array( self::CATEGORY_ALL, $items, true ) ) {
			return self::CATEGORY_ALL;
		}

		$error_type_ids = array();

		foreach ( $items as $item ) {
			$error_type_ids[] = ctype_digit( $item ) ? (int) $item : 0;
		}

		$error_type_ids = array_values( array_unique( $error_type_ids ) );

		sort( $error_type_ids );

		return $error_type_ids;
	}

	public function resolve_ip_for_matching( Request_Context $context ): string {
		return $context->is_cloudflare_trusted() ? $context->get_client_ip() : $context->get_remote_addr();
	}

	public function get_suppressed_error_type_ids( Request_Context $context ): array {
		$request_binary_ip = $this->get_request_binary_ip( $context );
		$request_agent     = $context->get_user_agent();
		$suppressed_ids    = array();

		foreach ( $this->get_entries() as $entry ) {
			if ( ! $this->entry_matches_request( $entry, $request_binary_ip, $request_agent ) ) {
				continue;
			}

			foreach ( array_values( Schema::get_error_type_ids() ) as $error_type_id ) {
				if ( $this->entry_applies_to_type( $entry, $error_type_id ) ) {
					$suppressed_ids[ $error_type_id ] = $error_type_id;
				}
			}
		}

		return array_values( $suppressed_ids );
	}

	public function entry_applies_to_type( array $entry, int $error_type_id ): bool {
		if ( self::CATEGORY_ALL === $entry['categories'] ) {
			return true;
		}

		return is_array( $entry['categories'] )
			&& in_array( $error_type_id, array_map( 'intval', $entry['categories'] ), true );
	}

	public function flush_cache(): void {
		self::$cached_entries = null;
	}

	private function get_request_binary_ip( Request_Context $context ): ?string {
		$request_ip = $this->resolve_ip_for_matching( $context );

		if ( '' === $request_ip ) {
			return null;
		}

		return $this->ip_resolver->to_binary( $request_ip );
	}

	private function entry_matches_request( array $entry, ?string $request_binary_ip, ?string $request_agent ): bool {
		if ( self::TYPE_IP === $entry['type'] ) {
			return null !== $request_binary_ip && $request_binary_ip === $this->ip_resolver->to_binary( $entry['value'] );
		}

		if ( self::TYPE_UA === $entry['type'] ) {
			return null !== $request_agent && $request_agent === $entry['value'];
		}

		return false;
	}

	private function normalize_stored_entry( $stored_entry ): ?array {
		if ( ! is_array( $stored_entry ) ) {
			return null;
		}

		if ( empty( $stored_entry['id'] ) || empty( $stored_entry['type'] ) || ! isset( $stored_entry['value'] ) ) {
			return null;
		}

		return wp_parse_args(
			$stored_entry,
			array(
				'categories' => self::CATEGORY_ALL,
				'note'       => '',
				'created_at' => '',
				'created_by' => 0,
			)
		);
	}

	private function normalize_value( string $type, string $raw_value ): ?string {
		if ( self::TYPE_IP === $type ) {
			return $this->normalize_ip_value( $raw_value );
		}

		return Request_Context::sanitize_user_agent( $raw_value );
	}

	private function normalize_ip_value( string $raw_value ): ?string {
		$binary_ip = $this->ip_resolver->to_binary( trim( sanitize_text_field( $raw_value ) ) );

		if ( null === $binary_ip ) {
			return null;
		}

		return $this->ip_resolver->to_readable( $binary_ip );
	}

	private function get_invalid_value_message( string $type ): string {
		if ( self::TYPE_IP === $type ) {
			return __( 'Enter a valid IPv4 or IPv6 address.', 'attacklog' );
		}

		return __( 'Enter a User-Agent. A missing User-Agent cannot be whitelisted.', 'attacklog' );
	}

	private function are_categories_valid( $categories ): bool {
		if ( self::CATEGORY_ALL === $categories ) {
			return true;
		}

		if ( ! is_array( $categories ) || empty( $categories ) ) {
			return false;
		}

		$valid_error_type_ids = array_values( Schema::get_error_type_ids() );

		foreach ( $categories as $error_type_id ) {
			if ( ! in_array( $error_type_id, $valid_error_type_ids, true ) ) {
				return false;
			}
		}

		return true;
	}

	private function sanitize_note( string $raw_note ): string {
		return mb_substr( sanitize_text_field( $raw_note ), 0, self::NOTE_MAX_LENGTH );
	}

	private function is_duplicate( string $type, string $value, string $ignore_id ): bool {
		foreach ( $this->get_entries() as $entry ) {
			if ( '' !== $ignore_id && $ignore_id === $entry['id'] ) {
				continue;
			}

			if ( $type === $entry['type'] && $value === $entry['value'] ) {
				return true;
			}
		}

		return false;
	}

	private function find_entry_index( array $entries, string $id ): ?int {
		foreach ( $entries as $entry_index => $entry ) {
			if ( $id === $entry['id'] ) {
				return $entry_index;
			}
		}

		return null;
	}

	private function build_not_found_error(): \WP_Error {
		return new \WP_Error( 'attacklog_whitelist_not_found', __( 'Whitelist entry not found.', 'attacklog' ) );
	}

	private function generate_id(): string {
		return wp_generate_password( self::ID_LENGTH, false );
	}

	private function save_entries( array $entries ): void {
		update_option( self::OPTION_NAME, array_values( $entries ), false );

		$this->flush_cache();
	}
}