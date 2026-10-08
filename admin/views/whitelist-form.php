<?php

defined( 'ABSPATH' ) || exit;

$category_options = $view_data['category_options'];
$ua_hint          = $view_data['ua_hint'];
$is_modal         = ! empty( $whitelist_form_is_modal );
?>
<?php if ( $is_modal ) : ?>
<div class="attacklog-wl-modal" id="attacklog-wl-modal" role="dialog" aria-modal="true" aria-labelledby="attacklog-wl-title" hidden>
	<div class="attacklog-wl-modal__backdrop"></div>
<?php endif; ?>
	<form class="attacklog-card attacklog-wl-form" id="attacklog-wl-form"<?php echo $is_modal ? '' : ' hidden'; ?>>
		<h2 class="attacklog-wl-form-title" id="attacklog-wl-title"><?php esc_html_e( 'Add whitelist entry', 'attack-log' ); ?></h2>

		<input type="hidden" id="attacklog-wl-id" value="">

		<div class="attacklog-wl-field">
			<label class="attacklog-wl-field__label" for="attacklog-wl-type"><?php esc_html_e( 'Type', 'attack-log' ); ?></label>
			<select id="attacklog-wl-type">
				<option value="ip"><?php esc_html_e( 'IP', 'attack-log' ); ?></option>
				<option value="ua"><?php esc_html_e( 'User-Agent', 'attack-log' ); ?></option>
			</select>
		</div>

		<div class="attacklog-wl-field">
			<label class="attacklog-wl-field__label" for="attacklog-wl-value"><?php esc_html_e( 'Value (exact match)', 'attack-log' ); ?></label>
			<input type="text" class="regular-text attacklog-mono" id="attacklog-wl-value" maxlength="512" autocomplete="off">
			<p class="attacklog-wl-field__hint"><?php echo esc_html( $ua_hint ); ?></p>
		</div>

		<fieldset class="attacklog-wl-field attacklog-wl-categories">
			<legend class="attacklog-wl-field__label"><?php esc_html_e( 'Applies to', 'attack-log' ); ?></legend>
			<label class="attacklog-wl-check">
				<input type="checkbox" class="attacklog-wl-category" data-category="all" checked>
				<?php esc_html_e( 'All categories', 'attack-log' ); ?>
			</label>
			<?php foreach ( $category_options as $category_option ) : ?>
				<label class="attacklog-wl-check">
					<input type="checkbox" class="attacklog-wl-category" data-category="<?php echo esc_attr( (string) $category_option['id'] ); ?>">
					<?php echo esc_html( $category_option['label'] ); ?>
				</label>
			<?php endforeach; ?>
		</fieldset>

		<div class="attacklog-wl-field">
			<label class="attacklog-wl-field__label" for="attacklog-wl-note"><?php esc_html_e( 'Note', 'attack-log' ); ?></label>
			<input type="text" class="regular-text" id="attacklog-wl-note" maxlength="255">
		</div>

		<div class="attacklog-wl-field">
			<label class="attacklog-wl-check">
				<input type="checkbox" id="attacklog-wl-delete-existing">
				<?php esc_html_e( 'Also delete existing matching rows', 'attack-log' ); ?>
			</label>
		</div>

		<p class="attacklog-wl-error" id="attacklog-wl-error" role="alert" hidden></p>

		<div class="attacklog-wl-form-actions">
			<button type="submit" class="button button-primary" id="attacklog-wl-save"><?php esc_html_e( 'Save', 'attack-log' ); ?></button>
			<button type="button" class="button" id="attacklog-wl-cancel"><?php esc_html_e( 'Cancel', 'attack-log' ); ?></button>
		</div>
	</form>
<?php if ( $is_modal ) : ?>
</div>
<?php endif; ?>