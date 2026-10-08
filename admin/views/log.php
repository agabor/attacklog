<?php

defined( 'ABSPATH' ) || exit;

$tabs               = $view_data['tabs'];
$current_tab        = $view_data['current_tab'];
$sort               = $view_data['sort'];
$current_page       = (int) $view_data['page'];
$total_pages        = (int) $view_data['total_pages'];
$total_items        = (int) $view_data['total_items'];
$pagination_base    = $view_data['pagination_base'];
$badge_column_label = $view_data['badge_column_label'];
$rows               = $view_data['rows'];
$cloudflare         = $view_data['cloudflare'];

$cf_live_note      = $cloudflare['live_note'];
$cf_hint           = $cloudflare['hint'];
$cf_set_by_text    = $cloudflare['description'];
$detection_enabled = ! empty( $cloudflare['enabled'] );
$is_all_tab        = null === $current_tab['error_type_id'];

$stored_settings = get_option( 'attacklog_settings', array() );
$keep_days       = is_array( $stored_settings ) && ! empty( $stored_settings['keep_days'] ) ? (int) $stored_settings['keep_days'] : 30;

$live_note_icons = array(
	'full'    => '✓',
	'partial' => '⚠',
	'none'    => '○',
);
$live_note_icon  = isset( $live_note_icons[ $cf_live_note['status'] ] ) ? $live_note_icons[ $cf_live_note['status'] ] : '○';

$whitelist_button_labels = array(
	'ip' => __( 'IP', 'attack-log' ),
	'ua' => __( 'UA', 'attack-log' ),
);
?>
<div class="wrap attacklog-wrap">
	<h1 class="attacklog-title"><?php esc_html_e( 'Attack Log', 'attack-log' ); ?></h1>

	<?php require ATTACKLOG_PLUGIN_DIR . 'admin/views/section-nav.php'; ?>

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
		<?php foreach ( $tabs as $tab ) : ?>
			<?php
			$tab_classes = 'attacklog-tab';

			if ( ! empty( $tab['is_active'] ) ) {
				$tab_classes .= ' is-active';
			}

			if ( ! empty( $tab['is_detection_off'] ) ) {
				$tab_classes .= ' is-muted';
			}
			?>
			<a
				class="<?php echo esc_attr( $tab_classes ); ?>"
				href="<?php echo esc_url( $tab['url'] ); ?>"
				<?php echo ! empty( $tab['is_active'] ) ? 'aria-current="page"' : ''; ?>
			>
				<span class="attacklog-tab__label"><?php echo esc_html( $tab['label'] ); ?></span>
				<span class="attacklog-tab__count"<?php echo '' !== $tab['tooltip'] ? ' title="' . esc_attr( $tab['tooltip'] ) . '"' : ''; ?>><?php echo esc_html( number_format_i18n( (int) $tab['count'] ) ); ?></span>
				<?php if ( ! empty( $tab['is_detection_off'] ) ) : ?>
					<span class="attacklog-tab__note"><?php esc_html_e( 'detection off', 'attack-log' ); ?></span>
				<?php endif; ?>
			</a>
		<?php endforeach; ?>
	</nav>

	<div class="attacklog-card attacklog-log-card">
		<?php if ( empty( $rows ) ) : ?>
			<p class="attacklog-empty"><?php echo esc_html( $current_tab['empty_message'] ); ?></p>
		<?php else : ?>
			<div class="attacklog-table-scroll">
				<table class="attacklog-table">
					<thead>
						<tr>
							<th scope="col">
								<a class="attacklog-sort" href="<?php echo esc_url( $sort['time_url'] ); ?>">
									<?php esc_html_e( 'Time', 'attack-log' ); ?>
									<span class="attacklog-sort__indicator" aria-hidden="true"><?php echo esc_html( $sort['time_indicator'] ); ?></span>
								</a>
							</th>
							<th scope="col"><?php esc_html_e( 'Method', 'attack-log' ); ?></th>
							<th scope="col"><?php esc_html_e( 'Path', 'attack-log' ); ?></th>
							<th scope="col">
								<a class="attacklog-sort" href="<?php echo esc_url( $sort['code_url'] ); ?>">
									<?php esc_html_e( 'Code', 'attack-log' ); ?>
									<span class="attacklog-sort__indicator" aria-hidden="true"><?php echo esc_html( $sort['code_indicator'] ); ?></span>
								</a>
							</th>
							<th scope="col"><?php esc_html_e( 'IP', 'attack-log' ); ?></th>
							<th scope="col"><?php echo esc_html( $badge_column_label ); ?></th>
							<th scope="col"><?php esc_html_e( 'Whitelist', 'attack-log' ); ?></th>
						</tr>
					</thead>
					<tbody>
						<?php foreach ( $rows as $row ) : ?>
							<tr>
								<td class="attacklog-cell attacklog-cell--time"><?php echo esc_html( $row['time'] ); ?></td>
								<td class="attacklog-cell attacklog-cell--method"><?php echo esc_html( $row['method'] ); ?></td>
								<td class="attacklog-cell attacklog-cell--path">
									<span class="attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $row['path'] ); ?>"><?php echo esc_html( $row['path'] ); ?></span>
									<span class="attacklog-second-line attacklog-mono attacklog-ellipsis" title="<?php echo esc_attr( $row['second_line'] ); ?>"><?php echo esc_html( $row['second_line'] ); ?></span>
								</td>
								<td class="attacklog-cell attacklog-cell--code"><span class="attacklog-code <?php echo esc_attr( $row['status_class'] ); ?>"><?php echo esc_html( (string) $row['status_code'] ); ?></span></td>
								<td class="attacklog-cell attacklog-cell--ip">
									<span class="attacklog-mono"><?php echo '' !== $row['client_ip'] ? esc_html( $row['client_ip'] ) : '—'; ?></span>
									<?php if ( ! empty( $row['addresses_differ'] ) ) : ?>
										<span class="attacklog-remote-addr attacklog-mono is-different" title="<?php esc_attr_e( 'Actual connecting address differs from the client IP', 'attack-log' ); ?>"><?php echo esc_html( $row['remote_addr'] ); ?></span>
									<?php endif; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--types">
									<?php foreach ( $row['badges'] as $badge ) : ?>
										<a class="attacklog-badge <?php echo esc_attr( $badge['badge_class'] ); ?>" href="<?php echo esc_url( $badge['url'] ); ?>"><?php echo esc_html( $badge['label'] ); ?></a>
									<?php endforeach; ?>
								</td>
								<td class="attacklog-cell attacklog-cell--whitelist">
									<?php foreach ( $whitelist_button_labels as $button_kind => $button_label ) : ?>
										<?php $whitelist_button = $row['whitelist'][ $button_kind ]; ?>
										<button
											type="button"
											class="button button-small attacklog-wl-row-button<?php echo ! empty( $whitelist_button['exists'] ) ? ' is-existing' : ''; ?>"
											data-kind="<?php echo esc_attr( $button_kind ); ?>"
											data-prefill="<?php echo esc_attr( $whitelist_button['prefill_json'] ); ?>"
											data-existing="<?php echo esc_attr( $whitelist_button['existing_json'] ); ?>"
											title="<?php echo esc_attr( $whitelist_button['title'] ); ?>"
											<?php disabled( ! empty( $whitelist_button['disabled'] ) ); ?>
										><?php echo esc_html( ( ! empty( $whitelist_button['exists'] ) ? '✓ ' : '+ ' ) . $button_label ); ?></button>
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
						/* translators: %s: number of logged requests. */
						_n( '%s request', '%s requests', $total_items, 'attack-log' ),
						number_format_i18n( $total_items )
					)
				);
				?>
			</p>

			<div class="attacklog-footer__actions">
				<?php if ( ! $is_all_tab ) : ?>
					<button
						type="button"
						class="button attacklog-clear-type"
						data-type-id="<?php echo esc_attr( (string) (int) $current_tab['error_type_id'] ); ?>"
						data-label="<?php echo esc_attr( $current_tab['label'] ); ?>"
					>
						<?php
						echo esc_html(
							sprintf(
								/* translators: %s: error type name. */
								__( 'Clear %s', 'attack-log' ),
								$current_tab['label']
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
						/* translators: %s: number of days. */
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

	<?php
	$whitelist_form_is_modal = true;

	require ATTACKLOG_PLUGIN_DIR . 'admin/views/whitelist-form.php';
	?>
</div>