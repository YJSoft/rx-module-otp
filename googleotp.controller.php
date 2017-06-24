<?php
class googleotpController extends googleotp
{
	function init()
	{
	}

	function procGoogleotpUserConfig()
	{
		if(!Context::get("is_logged")) return new Object(-1,"로그인해주세요");

		$oGoogleOTPModel = getModel('googleotp');

		if(!$oGoogleOTPModel->checkUserConfig(Context::get('logged_info')->member_srl)) {
			$oGoogleOTPModel->insertNewConfig(Context::get('logged_info')->member_srl);
		}

		$cond = new stdClass();
		$cond->srl=Context::get('logged_info')->member_srl;
		$cond->use = Context::get("use") === "Y" ? "Y" : "N";
		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return new Object(-1,"ERROR");

		// alert a message
		if(Context::get('xeVirtualRequestMethod') !== 'xml')
		{
			$this->setMessage('success_updated');
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}

	function triggerHijackLogin(&$obj) {
		if(!Context::get("is_logged") || $obj->act === "dispMemberLogout") {
			unset($_SESSION['googleotp_passed']);
			return;
		}

		$oGoogleOTPModel = getModel('googleotp');
		$userconfig = $oGoogleOTPModel->getUserConfig(Context::get('logged_info')->member_srl);
		if($userconfig->use === "Y") {
			$allowedact = array("dispGoogleotpInputotp","procGoogleotpInputotp","procMemberLogin","dispMemberLogout");
			if(!in_array($obj->act,$allowedact) && !$_SESSION['googleotp_passed'])
			{
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpInputotp'));
				Context::close();
				die();
			}
		}
	}
}
