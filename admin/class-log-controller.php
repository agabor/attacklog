<?php

namespace AttackLog\Admin;

use AttackLog\Cf_Detector;
use AttackLog\Repository;
use AttackLog\Schema;

defined( 'ABSPATH' ) || exit;

class Log_Controller {

	private $repository;

	public function __construct( Repository $repository ) {
		$this->repository = $repository;
	}

	public function register_hooks(): void {
		add_action( 'wp_ajax_attacklog_toggle_cf', array( $this, 'ajax_toggle_cf' ) );
		add_action( 'wp_ajax_attacklog_clear_impact', array( $this, 'ajax_clear_impact' ) );
		add_action( 'wp_ajax_attacklog_clear_type', array( $this, 'ajax_clear_type' ) );
		add_action( 'wp_ajax_attacklog_clear_all', array( $this, 'ajax_clear_all' ) );
	}

	public function verify_request(): void {
		check_ajax_referer( 'attacklog_admin', 'nonce' );

		if ( ! current_user_can( 'manage_options' ) ) {
			wp_send_json_error(
				array( 'message' => __( 'You are not allowed to do this.', 'attack-log' ) ),
				403
			);
		}
	}

	public function ajax_toggle_cf(): void {
		$this->verify_request();

		$posted_value = isset( $_POST['enabled'] ) ? sanitize_text_field( wp_unslash( $_POST['enabled'] ) ) : '';
		$enabled      = in_array( strtolower( $posted_value ), array( '1', 'true', 'on' ), true );

		Cf_Detector::set_status( $enabled, 'user', get_current_user_id() );

		$admin_page = new Admin_Page( $this->repository );

		wp_send_json_success(
			array(
				'enabled'     => $enabled,
				'set_by_text' => $admin_page->describe_cf_set_by( Cf_Detector::get_status() ),
			)
		);
	}

	public function ajax_clear_impact(): void {
		$this->verify_request();

		$error_type_id = $this->get_valid_error_type_id();

		wp_send_json_success( $this->repository->get_clear_type_impact( $error_type_id ) );
	}

	public function ajax_clear_type(): void {
		$this->verify_request();

		$error_type_id = $this->get_valid_error_type_id();

		wp_send_json_success(
			array( 'deleted' => $this->repository->delete_error_type( $error_type_id ) )
		);
	}

	public function ajax_clear_all(): void {
		$this->verify_request();

		$confirmation = isset( $_POST['confirmation'] ) ? sanitize_text_field( wp_unslash( $_POST['confirmation'] ) ) : '';

		if ( 'CLEAR' !== $confirmation ) {
			wp_send_json_error(
				array( 'message' => __( 'Confirmation text did not match.', 'attack-log' ) ),
				400
			);
		}

		$this->repository->delete_all();

		wp_send_json_success();
	}

	public function get_valid_error_type_id(): int {
		$error_type_id = isset( $_POST['error_type_id'] ) ? (int) sanitize_text_field( wp_unslash( $_POST['error_type_id'] ) ) : 0;

		if ( ! in_array( $error_type_id, array_values( Schema::get_error_type_ids() ), true ) ) {
			wp_send_json_error(
				array( 'message' => __( 'Invalid error type.', 'attack-log' ) ),
				400
			);
		}

		return $error_type_id;
	}
}