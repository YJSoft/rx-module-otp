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
		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $args);
		if(!$output->toBool())
		{
			return $output;
		}
		$this->setMessage('success_registed');
		$this->setRedirectUrl(Context::get('success_return_url'));
	}
}
