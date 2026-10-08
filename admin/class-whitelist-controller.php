<?php

namespace AttackLog\Admin;

use AttackLog\Ip_Resolver;
use AttackLog\Repository;
use AttackLog\Request_Context;
use AttackLog\Whitelist;

defined( 'ABSPATH' ) || exit;

class Whitelist_Controller {

	private $repository;

	private $whitelist;

	private $ip_resolver;

	public function __construct( Repository $repository ) {
		$this->repository  = $repository;
		$this->whitelist   = new Whitelist();
		$this->ip_resolver = new Ip_Resolver();
	}

	public function register_hooks(): void {
		add_action( 'wp_ajax_attacklog_whitelist_add', array( $this, 'ajax_whitelist_add' ) );
		add_action( 'wp_ajax_attacklog_whitelist_update', array( $this, 'ajax_whitelist_update' ) );
		add_action( 'wp_ajax_attacklog_whitelist_delete', array( $this, 'ajax_whitelist_delete' ) );
	}

	public function verify_request(): void {
		check_ajax_referer( Admin_Page::NONCE_ACTION, 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'You are not allowed to do this.', 'attack-log' ) ),
				403
			);
		}
	}

	public function ajax_whitelist_add(): void {
		$this->verify_request();

		$posted_input = $this->read_input();
		$entry        = $this->whitelist->add_entry( $posted_input, get_current_user_id() );

		$this->send_entry_response( $entry, $posted_input['delete_existing'] );
	}

	public function ajax_whitelist_update(): void {
		$this->verify_request();

		$posted_input = $this->read_input();
		$entry        = $this->whitelist->update_entry( $this->read_entry_id(), $posted_input );

		$this->send_entry_response( $entry, $posted_input['delete_existing'] );
	}

	public function ajax_whitelist_delete(): void {
		$this->verify_request();

		if ( ! $this->whitelist->delete_entry( $this->read_entry_id() ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Whitelist entry not found.', 'attack-log' ) ),
				404
			);
		}

		wp_send_json_success();
	}

	private function send_entry_response( $entry, bool $delete_existing ): void {
		if ( is_wp_error( $entry ) ) {
			wp_send_json_error(
				array( 'message' => $entry->get_error_message() ),
				400
			);
		}

		$deleted_requests = $delete_existing ? $this->purge_existing_rows( $entry ) : 0;

		wp_send_json_success(
			array(
				'entry'   => $entry,
				'deleted' => $deleted_requests,
			)
		);
	}

	private function read_entry_id(): string {
		return isset( $_POST['id'] ) ? sanitize_text_field( wp_unslash( $_POST['id'] ) ) : '';
	}

	private function read_input(): array {
		return array(
			'type'            => isset( $_POST['type'] ) ? sanitize_key( wp_unslash( $_POST['type'] ) ) : '',
			'value'           => $this->read_value(),
			'categories'      => isset( $_POST['categories'] ) ? sanitize_text_field( wp_unslash( $_POST['categories'] ) ) : Whitelist::CATEGORY_ALL,
			'note'            => isset( $_POST['note'] ) ? sanitize_text_field( wp_unslash( $_POST['note'] ) ) : '',
			'delete_existing' => isset( $_POST['delete_existing'] ) && '1' === sanitize_text_field( wp_unslash( $_POST['delete_existing'] ) ),
		);
	}

	private function read_value(): string {
		if ( ! isset( $_POST['value'] ) ) {
			return '';
		}

		$sanitized_value = Request_Context::sanitize_user_agent( wp_unslash( $_POST['value'] ) );

		return null === $sanitized_value ? '' : $sanitized_value;
	}

	private function purge_existing_rows( array $entry ): int {
		$error_type_ids = Whitelist::CATEGORY_ALL === $entry['categories']
			? array()
			: array_map( 'intval', (array) $entry['categories'] );

		if ( Whitelist::TYPE_IP === $entry['type'] ) {
			$binary_ip = $this->ip_resolver->to_binary( $entry['value'] );

			return null === $binary_ip ? 0 : $this->repository->delete_requests_by_ip( $binary_ip, $error_type_ids );
		}

		return $this->repository->delete_requests_by_user_agent( $entry['value'], $error_type_ids );
	}
}