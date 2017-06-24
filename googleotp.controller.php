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
}
