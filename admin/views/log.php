<?php

defined( 'ABSPATH' ) || exit;

$tabs                   = $view_data['tabs'];
$active_tab_slug        = $view_data['active_tab'];
$active_tab             = $tabs[ $active_tab_slug ];
$rows                   = $view_data['rows'];
$error_types_by_request = $view_data['error_types_by_request'];
$second_lines           = $view_data['second_lines'];
$ip_details             = $view_data['ips'];
$total_pages            = (int) $view_data['total_pages'];
$current_page           = (int) $view_data['page'];
$cf_status              = $view_data['cf_status'];
$cf_live_note           = $view_data['cf_live_note'];
$cf_hint                = $view_data['cf_hint'];
$cf_set_by_text         = $view_data['cf_set_by_text'];

$detection_enabled = ! empty( $cf_status['enabled'] );
$is_all_tab        = null === $active_tab['error_type_id'];

$tabs_by_error_type_id = array();

foreach ( $tabs as $tab_definition ) {
	if ( null !== $tab_definition['error_type_id'] ) {
		$tabs_by_error_type_id[ (int) $tab_definition['error_type_id'] ] = $tab_definition;
	}
}

$stored_settings = get_option( 'attacklog_settings', array() );
$keep_days       = is_array( $stored_settings ) && ! empty( $stored_settings['keep_days'] ) ? (int) $stored_settings['keep_days'] : 30;

$live_note_icons = array(
	'full'    => '✓',
	'partial' => '⚠',
	'none'    => '○',
);
$live_note_icon  = isset( $live_note_icons[ $cf_live_note['status'] ] ) ? $live_note_icons[ $cf_live_note['status'] ] : '○';

$pagination_base = str_replace( '999999999', '%#%', $this->build_tab_url( $active_tab_slug, 999999999 ) );
?>
<div class="wrap attacklog-wrap">
	<h1 class="attacklog-title"><?php esc_html_e( 'Attack Log', 'attack-log' ); ?></h1>

	<div class="attacklog-card attacklog-cf-card">
		<p class="attacklog-cf-note attacklog-cf-note--<?php echo esc_attr( $cf_live_note['status'] ); ?>">
			<span class="attacklog-cf-note__icon" aria-hidden="true"><?php echo esc_html( $live_note_icon ); ?></span>
			<span class="attacklog-cf-note__text"><?php echo esc_html( $cf_live_note['message'] ); ?></span>
		</p>

		<?php if ( ! empty( $cf_hint ) ) : ?>
			<p class="attacklog-cf-hint"><?php echo esc_html( $cf_hint ); ?></p>
		<?php endif; ?>

		<div class="attacklog-cf-switch">
			<span class="attacklog-cf-switch__label" id="attacklog-cf-switch-label"><?php esc_html_e( 'Cloudflare bypass detection', 'attack-log' ); ?></span>
			<button
				type="button"
				class="attacklog-switch<?php echo $detection_enabled ? ' is-on' : ''; ?>"
				id="attacklog-cf-switch"
				role="switch"
				aria-checked="<?php echo $detection_enabled ? 'true' : 'false'; ?>"
				aria-labelledby="attacklog-cf-switch-label"
				data-enabled="<?php echo $detection_enabled ? '1' : '0'; ?>"
			>
				<span class="attacklog-switch__knob"></span>
				<span class="attacklog-switch__state"><?php echo $detection_enabled ? esc_html__( 'On', 'attack-log' ) : esc_html__( 'Off', 'attack-log' ); ?></span>
			</button>
		</div>

		<p class="attacklog-cf-footer" id="attacklog-cf-set-by"><?php echo esc_html( $cf_set_by_text ); ?></p>
	</div>

	<nav class="attacklog-tabs" aria-label="<?php esc_attr_e( 'Error types', 'attack-log' ); ?>">
		<?php foreach ( $tabs as $tab_slug => $tab_definition ) : ?>
			<?php
			$is_active_tab      = $tab_slug === $active_tab_slug;
			$is_detection_muted = \AttackLog\Schema::ERROR_TYPE_CF_BYPASS === $tab_definition['error_type_id'] && ! $detection_enabled;
			$tab_classes        = 'attacklog-tab';

			if ( $is_active_tab ) {
				$tab_classes .= ' is-active';
			}

			if ( $is_detection_muted ) {
				$tab_classes .= ' is-muted';
			}
			?>
			<a
				class="<?php echo esc_attr( $tab_classes ); ?>"
				href="<?php echo esc_url( $this->build_tab_url( $tab_slug, 1 ) ); ?>"
				<?php echo $is_active_tab ? 'aria-current="page"' : ''; ?>
			>
				<span class="attacklog-tab__label"><?php echo esc_html( $tab_definition['label'] ); ?></span>
				<?php if ( null === $tab_definition['error_type_id'] ) : ?>
					<span class="attacklog-tab__count" title="<?php esc_attr_e( 'A request flagged with several types is counted once here, so this number can be lower than the sum of the other tabs.', 'attack-log' ); ?>"><?php echo esc_html( number_format_i18n( (int) $tab_definition['count'] ) ); ?></span>
				<?php else : ?>
					<span class="attacklog-tab__count"><?php echo esc_html( number_format_i18n( (int) $tab_definition['count'] ) ); ?></span>
				<?php endif; ?>
				<?php if ( $is_detection_muted ) : ?>
					<span class="attacklog-tab__note"><?php esc_html_e( 'detection off', 'attack-log' ); ?></span>
				<?php endif; ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<div class="attacklog-card attacklog-log-card">
		<?php if ( empty( $rows ) ) : ?>
			<p class="attacklog-empty"><?php echo esc_html( $active_tab['empty_message'] ); ?></p>
		<?php else : ?>
			<div class="attacklog-table-scroll">
				<table class="attacklog-table">
					<thead>
						<tr>
							<th scope="col"><?php esc_html_e( 'Time', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Method', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Path', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Code', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'IP', 'attack-log' ); ?></th>
							<th scope="col"><?php echo $is_all_tab ? esc_html__( 'Types', 'attack-log' ) : esc_html__( 'Also flagged', 'attack-log' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<?php
							$request_id    = (int) $row->id;
							$row_types     = isset( $error_types_by_request[ $request_id ] ) ? $error_types_by_request[ $request_id ] : array();
							$second_line   = isset( $second_lines[ $request_id ] ) ? (string) $second_lines[ $request_id ] : '';
							$row_ip        = isset( $ip_details[ $request_id ] ) ? $ip_details[ $request_id ] : array();
							$client_ip     = ! empty( $row_ip['client_ip'] ) ? $row_ip['client_ip'] : '';
							$remote_addr   = ! empty( $row_ip['remote_addr'] ) ? $row_ip['remote_addr'] : '';
							$ip_differs    = ! empty( $row_ip['differs'] );
							$code_class    = 'attacklog-code attacklog-code--' . (int) floor( (int) $row->return_code / 100 ) . 'xx';
							$visible_types = array();

							foreach ( array_keys( $row_types ) as $row_type_id ) {
								if ( ! isset( $tabs_by_error_type_id[ $row_type_id ] ) ) {
									continue;
								}

								if ( ! $is_all_tab && (int) $active_tab['error_type_id'] === $row_type_id ) {
									continue;
								}

								$visible_types[] = $tabs_by_error_type_id[ $row_type_id ];
							}
							?>
							<tr>
								<td class="attacklog-cell attacklog-cell--time"><?php echo esc_html( get_date_from_gmt( $row->created_at, 'M j, H:i:s' ) ); ?></td>
								<td class="attacklog-cell attacklog-cell--method"><?php echo esc_html( $row->http_method ); ?></td>
								<td class="attacklog-cell attacklog-cell--path">
									<span class="attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $row->request_path ); ?>"><?php echo esc_html( $row->request_path ); ?></span>
									<?php if ( '' !== $second_line ) : ?>
										<span class="attacklog-second-line attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $second_line ); ?>"><?php echo esc_html( $second_line ); ?></span>
									<?php else : ?>
										<span class="attacklog-second-line attacklog-second-line--missing"><?php esc_html_e( '— missing —', 'attack-log' ); ?></span>
									<?php endif; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--code"><span class="<?php echo esc_attr( $code_class ); ?>"><?php echo esc_html( (string) (int) $row->return_code ); ?></span></td>
								<td class="attacklog-cell attacklog-cell--ip">
									<span class="attacklog-mono"><?php echo '' !== $client_ip ? esc_html( $client_ip ) : '—'; ?></span>
									<?php if ( $ip_differs && '' !== $remote_addr ) : ?>
										<span class="attacklog-remote-addr attacklog-mono is-different" title="<?php esc_attr_e( 'Actual connecting address differs from the client IP', 'attack-log' ); ?>"><?php echo esc_html( $remote_addr ); ?></span>
									<?php endif; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--types">
									<?php foreach ( $visible_types as $visible_type ) : ?>
										<?php if ( $is_all_tab ) : ?>
											<span class="attacklog-badge <?php echo esc_attr( $visible_type['badge_class'] ); ?>"><?php echo esc_html( $visible_type['label'] ); ?></span>
										<?php else : ?>
											<a class="attacklog-badge <?php echo esc_attr( $visible_type['badge_class'] ); ?>" href="<?php echo esc_url( $this->build_tab_url( $visible_type['slug'], 1 ) ); ?>"><?php echo esc_html( $visible_type['label'] ); ?></a>
										<?php endif; ?>
									<?php endforeach; ?>
								</td>
							</tr>
						<?php endforeach; ?>
					</tbody>
				</table>
			</div>
		<?php endif; ?>

		<?php if ( $total_pages > 1 ) : ?>
			<div class="attacklog-pagination">
				<?php
				echo wp_kses_post(
					paginate_links(
						array(
							'base'      => $pagination_base,
							'format'    => '',
							'current'   => $current_page,
							'total'     => $total_pages,
							'prev_text' => '‹',
							'next_text' => '›',
							'type'      => 'plain',
						)
					)
				);
				?>
			</div>
		<?php endif; ?>

		<div class="attacklog-footer">
			<p class="attacklog-footer__count">
				<?php
				echo esc_html(
					sprintf(
						_n( '%s request', '%s requests', (int) $active_tab['count'], 'attack-log' ),
						number_format_i18n( (int) $active_tab['count'] )
					)
				);
				?>
			</p>

			<div class="attacklog-footer__actions">
				<?php if ( ! $is_all_tab ) : ?>
					<button
						type="button"
						class="button attacklog-clear-type"
						data-type-id="<?php echo esc_attr( (string) (int) $active_tab['error_type_id'] ); ?>"
						data-label="<?php echo esc_attr( $active_tab['label'] ); ?>"
					>
						<?php
						echo esc_html(
							sprintf(
								__( 'Clear %s', 'attack-log' ),
								$active_tab['label']
							)
						);
						?>
					</button>
				<?php endif; ?>
				<button type="button" class="button button-link-delete attacklog-clear-all"><?php esc_html_e( 'Clear all', 'attack-log' ); ?></button>
			</div>

			<p class="attacklog-footer__autoclean">
				<?php
				echo esc_html(
					sprintf(
						_n(
							'Auto-clean: entries older than %s day are removed daily.',
							'Auto-clean: entries older than %s days are removed daily.',
							$keep_days,
							'attack-log'
						),
						number_format_i18n( $keep_days )
					)
				);
				?>
			</p>
		</div>
	</div>
</div>