( function () {
	'use strict';

	const config = window.attacklogAdmin || {};
	const strings = config.strings || {};

	const defaultStrings = {
		confirmEnable: 'Turn on Cloudflare bypass detection?',
		confirmEnableWithoutCloudflare: 'This request did not come through Cloudflare. If the site is not really behind Cloudflare, every front-end request will be logged as a Cloudflare Bypass. Turn on bypass detection anyway?',
		confirmDisable: 'Turn off Cloudflare bypass detection? Requests that go directly to the origin server will no longer be logged.',
		confirmClearType: 'Remove %1$s from %2$s requests? %3$s of them also have other types and stay in those tabs; the other %4$s are deleted. This can\'t be undone.',
		clearAllPrompt: 'This deletes the whole log, all types. Type CLEAR to confirm.',
		errorGeneric: 'Something went wrong. Please try again.',
		on: 'On',
		off: 'Off'
	};

	function getString( key ) {
		return strings[ key ] || defaultStrings[ key ];
	}

	function formatString( template, values ) {
		return template.replace( /%(\d+)\$s/g, function ( match, position ) {
			const value = values[ Number( position ) - 1 ];
			return undefined === value ? match : String( value );
		} );
	}

	function getErrorMessage( response ) {
		if ( response && response.data && response.data.message ) {
			return response.data.message;
		}

		return getString( 'errorGeneric' );
	}

	function postAjax( action, data ) {
		const body = new window.FormData();

		body.append( 'action', action );
		body.append( 'nonce', config.nonce );

		Object.keys( data || {} ).forEach( function ( key ) {
			body.append( key, data[ key ] );
		} );

		return window
			.fetch( config.ajaxUrl, {
				method: 'POST',
				credentials: 'same-origin',
				body: body
			} )
			.then( function ( response ) {
				return response.json();
			} );
	}

	function requestHasCloudflareHeaders() {
		return '1' === config.requestHasAllCfHeaders;
	}

	function renderSwitchState( switchButton, enabled ) {
		const stateLabel = switchButton.querySelector( '.attacklog-switch__state' );

		switchButton.classList.toggle( 'is-on', enabled );
		switchButton.setAttribute( 'aria-checked', enabled ? 'true' : 'false' );
		switchButton.setAttribute( 'data-enabled', enabled ? '1' : '0' );

		if ( stateLabel ) {
			stateLabel.textContent = enabled ? getString( 'on' ) : getString( 'off' );
		}
	}

	function getSwitchConfirmMessage( turningOn ) {
		if ( ! turningOn ) {
			return getString( 'confirmDisable' );
		}

		if ( ! requestHasCloudflareHeaders() ) {
			return getString( 'confirmEnableWithoutCloudflare' );
		}

		return getString( 'confirmEnable' );
	}

	function initCloudflareSwitch() {
		const switchButton = document.getElementById( 'attacklog-cf-switch' );
		const setByElement = document.getElementById( 'attacklog-cf-set-by' );

		if ( ! switchButton ) {
			return;
		}

		switchButton.addEventListener( 'click', function () {
			const currentlyEnabled = '1' === switchButton.getAttribute( 'data-enabled' );
			const turningOn = ! currentlyEnabled;

			if ( ! window.confirm( getSwitchConfirmMessage( turningOn ) ) ) {
				return;
			}

			switchButton.disabled = true;

			postAjax( 'attacklog_toggle_cf', { enabled: turningOn ? '1' : '0' } )
				.then( function ( response ) {
					if ( ! response || ! response.success ) {
						renderSwitchState( switchButton, currentlyEnabled );
						window.alert( getErrorMessage( response ) );
						return;
					}

					renderSwitchState( switchButton, Boolean( response.data.enabled ) );

					if ( setByElement && response.data.set_by_text ) {
						setByElement.textContent = response.data.set_by_text;
					}
				} )
				.catch( function () {
					renderSwitchState( switchButton, currentlyEnabled );
					window.alert( getString( 'errorGeneric' ) );
				} )
				.then( function () {
					switchButton.disabled = false;
				} );
		} );
	}

	function clearTypeAfterConfirmation( button, errorTypeId, impact, label ) {
		const message = formatString( getString( 'confirmClearType' ), [
			label,
			impact.total,
			impact.shared,
			impact.deleted
		] );

		if ( ! window.confirm( message ) ) {
			button.disabled = false;
			return Promise.resolve();
		}

		return postAjax( 'attacklog_clear_type', { error_type_id: errorTypeId } ).then( function ( response ) {
			if ( ! response || ! response.success ) {
				button.disabled = false;
				window.alert( getErrorMessage( response ) );
				return;
			}

			window.location.reload();
		} );
	}

	function initClearType() {
		const button = document.querySelector( '.attacklog-clear-type' );

		if ( ! button ) {
			return;
		}

		button.addEventListener( 'click', function () {
			const errorTypeId = button.getAttribute( 'data-type-id' );
			const label = button.getAttribute( 'data-label' );

			button.disabled = true;

			postAjax( 'attacklog_clear_impact', { error_type_id: errorTypeId } )
				.then( function ( response ) {
					if ( ! response || ! response.success ) {
						button.disabled = false;
						window.alert( getErrorMessage( response ) );
						return undefined;
					}

					return clearTypeAfterConfirmation( button, errorTypeId, response.data, label );
				} )
				.catch( function () {
					button.disabled = false;
					window.alert( getString( 'errorGeneric' ) );
				} );
		} );
	}

	function initClearAll() {
		const button = document.querySelector( '.attacklog-clear-all' );

		if ( ! button ) {
			return;
		}

		button.addEventListener( 'click', function () {
			const confirmation = window.prompt( getString( 'clearAllPrompt' ) );

			if ( null === confirmation ) {
				return;
			}

			if ( 'CLEAR' !== confirmation.trim() ) {
				window.alert( getString( 'errorGeneric' ) );
				return;
			}

			button.disabled = true;

			postAjax( 'attacklog_clear_all', { confirmation: 'CLEAR' } )
				.then( function ( response ) {
					if ( ! response || ! response.success ) {
						button.disabled = false;
						window.alert( getErrorMessage( response ) );
						return;
					}

					window.location.reload();
				} )
				.catch( function () {
					button.disabled = false;
					window.alert( getString( 'errorGeneric' ) );
				} );
		} );
	}

	function init() {
		initCloudflareSwitch();
		initClearType();
		initClearAll();
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );