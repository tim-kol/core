(function () {
	var SetPassword = {
		init : function() {
			$('#set-password #submit').click(this.onClickSetPassword);
		},

		onClickSetPassword : function(event){
			event.preventDefault();
			var passwordObj = $('#password');
			if (passwordObj.val()){
				$.post(
					passwordObj.parents('form').attr('action'),
					{password : passwordObj.val()}
				).done(function (result) {
					OC.User.SetPassword._resetDone(result);
				}).fail(function (result) {
					OC.User.SetPassword._onSetPasswordFail(result);
				});
			}
		},

		_onSetPasswordFail: function(result) {
			var responseObj = JSON.parse(result.responseText);
			var errorObject = $('#error-message');
			var showErrorMessage = false;

			var errorMessage;
			errorMessage = responseObj.message;

			if (errorMessage) {
				errorObject.text(errorMessage);
				errorObject.show();
				$('#submit').prop('disabled', true);
			}
		},

		_resetDone : function(result){
			if (result && result.status === 'success') {
				var getRootPath = OC.getRootPath();
				if (getRootPath === '') {
					/**
					 * If owncloud is not run inside subfolder, the getRootPath
					 * will return empty string
					 */
					getRootPath = "/";
				}
				OC.redirect(getRootPath);
			}
		}
	};

	if (!OC.User) {
		OC.User = {};
	}
	OC.User.SetPassword = SetPassword;
})();

$(document).ready(function () {
	OC.User.SetPassword.init();
});