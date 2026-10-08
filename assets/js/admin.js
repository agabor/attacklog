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
		off: 'Off',
		confirmDeleteEntry: 'Remove this entry from the whitelist?',
		addEntryTitle: 'Add whitelist entry',
		editEntryTitle: 'Edit whitelist entry',
		noCurrentIp: 'Your current IP address could not be determined.',
		ipPlaceholder: '203.0.113.7',
		uaPlaceholder: 'Mozilla/5.0 (compatible; MyMonitor/1.0)'
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

	function parseJsonAttribute( button, attributeName ) {
		try {
			return JSON.parse( button.getAttribute( attributeName ) );
		} catch ( parseError ) {
			return null;
		}
	}

	function parseEntryData( button ) {
		return parseJsonAttribute( button, 'data-entry' );
	}

	function initWhitelist() {
		const form = document.getElementById( 'attacklog-wl-form' );

		if ( ! form ) {
			return;
		}

		const modalElement = document.getElementById( 'attacklog-wl-modal' );
		const container = modalElement || form;
		const isModal = Boolean( modalElement );
		const titleElement = document.getElementById( 'attacklog-wl-title' );
		const idField = document.getElementById( 'attacklog-wl-id' );
		const typeField = document.getElementById( 'attacklog-wl-type' );
		const valueField = document.getElementById( 'attacklog-wl-value' );
		const noteField = document.getElementById( 'attacklog-wl-note' );
		const deleteExistingField = document.getElementById( 'attacklog-wl-delete-existing' );
		const errorElement = document.getElementById( 'attacklog-wl-error' );
		const saveButton = document.getElementById( 'attacklog-wl-save' );
		const cancelButton = document.getElementById( 'attacklog-wl-cancel' );
		const addButton = document.getElementById( 'attacklog-wl-add' );
		const addCurrentIpButton = document.getElementById( 'attacklog-wl-add-current-ip' );
		const categoryBoxes = Array.prototype.slice.call( form.querySelectorAll( '.attacklog-wl-category' ) );

		function showFormError( message ) {
			errorElement.textContent = message;
			errorElement.hidden = false;
		}

		function clearFormError() {
			errorElement.textContent = '';
			errorElement.hidden = true;
		}

		function updateValuePlaceholder() {
			valueField.placeholder = 'ua' === typeField.value ? getString( 'uaPlaceholder' ) : getString( 'ipPlaceholder' );
		}

		function applyCategories( categories ) {
			const selectedIds = Array.isArray( categories ) ? categories.map( String ) : [];
			const allSelected = ! Array.isArray( categories );

			categoryBoxes.forEach( function ( box ) {
				const category = box.getAttribute( 'data-category' );

				box.checked = 'all' === category ? allSelected : selectedIds.indexOf( category ) !== -1;
			} );
		}

		function syncAllCategoryCheckbox( changedBox ) {
			if ( ! changedBox.checked ) {
				return;
			}

			const changedIsAll = 'all' === changedBox.getAttribute( 'data-category' );

			categoryBoxes.forEach( function ( box ) {
				const boxIsAll = 'all' === box.getAttribute( 'data-category' );

				if ( box !== changedBox && boxIsAll === changedIsAll ) {
					return;
				}

				if ( box !== changedBox ) {
					box.checked = false;
				}
			} );
		}

		function openWhitelistForm( mode, entry ) {
			const entryData = entry || {};

			titleElement.textContent = 'edit' === mode ? getString( 'editEntryTitle' ) : getString( 'addEntryTitle' );
			idField.value = 'edit' === mode && entryData.id ? entryData.id : '';
			typeField.value = 'ua' === entryData.type ? 'ua' : 'ip';
			valueField.value = entryData.value || '';
			noteField.value = entryData.note || '';
			deleteExistingField.checked = false;
			applyCategories( Array.isArray( entryData.categories ) ? entryData.categories : 'all' );
			updateValuePlaceholder();
			clearFormError();
			saveButton.disabled = false;

			container.hidden = false;

			if ( isModal ) {
				document.body.classList.add( 'modal-open' );
			}

			valueField.focus();
		}

		function closeWhitelistForm() {
			container.hidden = true;
			clearFormError();

			if ( isModal ) {
				document.body.classList.remove( 'modal-open' );
			}
		}

		function collectWhitelistFormData() {
			const checkedCategories = categoryBoxes
				.filter( function ( box ) {
					return box.checked;
				} )
				.map( function ( box ) {
					return box.getAttribute( 'data-category' );
				} );

			const data = {
				type: typeField.value,
				value: valueField.value,
				categories: checkedCategories.indexOf( 'all' ) !== -1 ? 'all' : checkedCategories.join( ',' ),
				note: noteField.value,
				delete_existing: deleteExistingField.checked ? '1' : '0'
			};

			if ( '' !== idField.value ) {
				data.id = idField.value;
			}

			return data;
		}

		function submitWhitelistForm( event ) {
			event.preventDefault();

			const data = collectWhitelistFormData();
			const action = data.id ? 'attacklog_whitelist_update' : 'attacklog_whitelist_add';

			clearFormError();
			saveButton.disabled = true;

			postAjax( action, data )
				.then( function ( response ) {
					if ( ! response || ! response.success ) {
						saveButton.disabled = false;
						showFormError( getErrorMessage( response ) );
						return;
					}

					window.location.reload();
				} )
				.catch( function () {
					saveButton.disabled = false;
					showFormError( getString( 'errorGeneric' ) );
				} );
		}

		function handleAddCurrentIp() {
			const currentIp = addCurrentIpButton.getAttribute( 'data-current-ip' );

			if ( ! currentIp ) {
				window.alert( getString( 'noCurrentIp' ) );
				return;
			}

			openWhitelistForm( 'add', { type: 'ip', value: currentIp, categories: 'all' } );
		}

		function handleDeleteEntry( button ) {
			const entry = parseEntryData( button );

			if ( ! entry || ! window.confirm( getString( 'confirmDeleteEntry' ) ) ) {
				return;
			}

			button.disabled = true;

			postAjax( 'attacklog_whitelist_delete', { id: entry.id } )
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
		}

		function handleEditEntry( button ) {
			const entry = parseEntryData( button );

			if ( entry ) {
				openWhitelistForm( 'edit', entry );
			}
		}

		function handleRowWhitelistButton( button ) {
			if ( '' !== ( button.getAttribute( 'data-existing' ) || '' ) ) {
				const existingEntry = parseJsonAttribute( button, 'data-existing' );

				if ( existingEntry ) {
					openWhitelistForm( 'edit', existingEntry );
					return;
				}
			}

			const prefillEntry = parseJsonAttribute( button, 'data-prefill' );

			if ( prefillEntry ) {
				openWhitelistForm( 'add', prefillEntry );
			}
		}

		function handleContainerClick( event ) {
			const clickedBackdrop = event.target === container || event.target.classList.contains( 'attacklog-wl-modal__backdrop' );

			if ( isModal && clickedBackdrop ) {
				closeWhitelistForm();
			}
		}

		function handleEscapeKey( event ) {
			if ( isModal && 'Escape' === event.key && ! container.hidden ) {
				closeWhitelistForm();
			}
		}

		if ( addButton ) {
			addButton.addEventListener( 'click', function () {
				openWhitelistForm( 'add', {} );
			} );
		}

		if ( addCurrentIpButton ) {
			addCurrentIpButton.addEventListener( 'click', handleAddCurrentIp );
		}

		if ( cancelButton ) {
			cancelButton.addEventListener( 'click', closeWhitelistForm );
		}

		typeField.addEventListener( 'change', updateValuePlaceholder );
		form.addEventListener( 'submit', submitWhitelistForm );
		container.addEventListener( 'click', handleContainerClick );
		document.addEventListener( 'keydown', handleEscapeKey );

		categoryBoxes.forEach( function ( box ) {
			box.addEventListener( 'change', function () {
				syncAllCategoryCheckbox( box );
			} );
		} );

		Array.prototype.forEach.call( document.querySelectorAll( '.attacklog-wl-edit' ), function ( button ) {
			button.addEventListener( 'click', function () {
				handleEditEntry( button );
			} );
		} );

		Array.prototype.forEach.call( document.querySelectorAll( '.attacklog-wl-delete' ), function ( button ) {
			button.addEventListener( 'click', function () {
				handleDeleteEntry( button );
			} );
		} );

		Array.prototype.forEach.call( document.querySelectorAll( '.attacklog-wl-row-button' ), function ( button ) {
			if ( button.disabled ) {
				return;
			}

			button.addEventListener( 'click', function () {
				handleRowWhitelistButton( button );
			} );
		} );

		updateValuePlaceholder();
	}

	function init() {
		initCloudflareSwitch();
		initClearType();
		initClearAll();
		initWhitelist();
	}

	if ( 'loading' === document.readyState ) {
		document.addEventListener( 'DOMContentLoaded', init );
	} else {
		init();
	}
}() );