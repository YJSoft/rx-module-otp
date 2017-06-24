<?php
require_once(_XE_PATH_.'modules/googleotp/libs/GoogleAuthenticator.php');

class googleotpView extends googleotp
{
	function init()
	{
		$this->setTemplatePath($this->module_path . 'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispGoogleotp', '', $this->act)));
	}

	function dispGoogleotpUserConfig()
	{
		if(!Context::get('logged_info') || Context::get('logged_info')->member_srl == 0) return new Object(-1,"로그인해주세요");

		$oGoogleOTPModel = getModel('googleotp');
		$ga = new PHPGangsta_GoogleAuthenticator();

		if(!$oGoogleOTPModel->checkUserConfig(Context::get('logged_info')->member_srl)) {
			$oGoogleOTPModel->insertNewConfig(Context::get('logged_info')->member_srl);
		}
		$userconfig = $oGoogleOTPModel->getUserConfig(Context::get('logged_info')->member_srl);
		$userconfig->qrcode = $ga->getQRCodeGoogleUrl(Context::get('logged_info')->user_id, $userconfig->key);; //user_id
		Context::set("user_config",$userconfig);
	}
}
