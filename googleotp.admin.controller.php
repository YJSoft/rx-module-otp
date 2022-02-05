<?php
class googleotpAdminController extends googleotp
{
	function init()
	{
	}

	public function procGoogleotpAdminInsertConfig()
	{
		// 현재 설정 상태 불러오기
		$config = $this->getConfig();

		// 제출받은 데이터 불러오기
		$vars = Context::getRequestVars();

		$config->skins = $vars->skins;
		$config->allow_issue_type = $vars->allow_issue_type;
		$config->auth_retry_hour = $vars->auth_retry_hour;
		$config->auth_retry_limit = $vars->auth_retry_limit;
		$config->use_captcha = $vars->use_captcha ? 'Y' : 'N';
		
		$output = $this->setConfig($config);
		if (!$output->toBool())
		{
			return $output;
		}

		// 설정 화면으로 리다이렉트
		$this->setMessage('success_registed');
		$this->setRedirectUrl(Context::get('success_return_url'));
	}
	
	public function procGoogleotpAdminUpdateConfig()
	{
		$obj = Context::getRequestVars();
		$args = new stdClass();
		$args->srl = $obj->srl;
		$args->use = $obj->use;
		$args->issue_type = $obj->issue_type;
		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $args);
		if(!$output->toBool())
		{
			return $output;
		}
		$this->setMessage('success_registed');
		$this->setRedirectUrl(Context::get('success_return_url'));
	}
}
