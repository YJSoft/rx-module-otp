<?php

/**
 * @class googleotpAdminView
 * @author Lastorder-DC
 * @brief Google OTP 2차 인증 모듈의 관리자 뷰 클래스
 */
class googleotpAdminView extends googleotp
{
	/**
	 * 관리자 뷰 초기화 함수.
	 *
	 * 관리자 템플릿 경로를 설정한다.
	 *
	 * @return void
	 */
	function init()
	{
		$this->setTemplatePath($this->module_path.'tpl');
		$this->setTemplateFile(strtolower(str_replace('dispGoogleotpAdmin', '', $this->act)));
	}

	/**
	 * 관리자 설정 화면을 출력하는 함수.
	 *
	 * @return void
	 */
	public function dispGoogleotpAdminConfig()
	{
		// 현재 설정 상태 불러오기
		$config = $this->getConfig();

		$oModuleModel = moduleModel::getInstance();
		$skin_list = $oModuleModel->getSkins($this->module_path);

		// Context에 세팅
		Context::set('googleotp_config', $config);
		Context::set('skin_list',$skin_list);

		// 스킨 파일 지정
		$this->setTemplateFile('config');
	}
	
	/**
	 * OTP 사용 회원 목록을 출력하는 함수.
	 *
	 * @return void
	 */
	public function dispGoogleotpAdminMemberList()
	{
		$oMemberModel = memberModel::getInstance();
		
		$args = new stdClass;
		$args->page = Context::get('page'); ///< 페이지
		$args->list_count = 20; ///< 한페이지에 보여줄 기록 수
		$args->page_count = 10; ///< 페이지 네비게이션에 나타날 페이지의 수
		$args->order_type = 'desc';
		$output = executeQueryArray('googleotp.getGoogleotpMemberList', $args);

		foreach ($output->data as $key => $datum)
		{
			$output->data[$key]->member_info = $oMemberModel->getMemberInfoByMemberSrl($datum->srl);
		}

		Context::set('total_count', $output->total_count);
		Context::set('total_page', $output->total_page);
		Context::set('page', $output->page);
		Context::set('page_navigation', $output->page_navigation);
		Context::set('otp_list', $output->data);
	}
	
	/**
	 * 개별 회원의 OTP 설정을 관리하는 화면을 출력하는 함수.
	 *
	 * @return void
	 */
	public function dispGoogleotpAdminMemberSetup()
	{
		$userOtpConfig = googleotpModel::getInstance()->getUserConfig(Context::get('srl'));
		
		Context::set('user_config', $userOtpConfig);

		$config = $this->getConfig();
		Context::set('googleotp_config', $config);
	}

	/**
	 * OTP 인증 시도 로그 목록을 출력하는 함수.
	 *
	 * @return void
	 */
	public function dispGoogleotpAdminAuthList()
	{
		$oMemberModel = memberModel::getInstance();
		
		$args = new stdClass;
		$args->page = Context::get('page'); ///< 페이지
		$args->list_count = 20; ///< 한페이지에 보여줄 기록 수
		$args->page_count = 10; ///< 페이지 네비게이션에 나타날 페이지의 수
		$args->order_type = 'desc';
		$output = executeQueryArray('googleotp.getGoogleotpauthlogList', $args);

		foreach ($output->data as $key => $datum)
		{
			$output->data[$key]->member_info = $oMemberModel->getMemberInfoByMemberSrl($datum->srl);
		}

		Context::set('total_count', $output->total_count);
		Context::set('total_page', $output->total_page);
		Context::set('page', $output->page);
		Context::set('page_navigation', $output->page_navigation);
		Context::set('auth_list', $output->data);
	}

	/**
	 * 인증 발송(이메일/SMS) 로그 목록을 출력하는 함수.
	 *
	 * @return void
	 */
	public function dispGoogleotpAdminAuthSendList()
	{
		$oMemberModel = memberModel::getInstance();
		
		$args = new stdClass;
		$args->page = Context::get('page'); ///< 페이지
		$args->list_count = 20; ///< 한페이지에 보여줄 기록 수
		$args->page_count = 10; ///< 페이지 네비게이션에 나타날 페이지의 수
		$args->order_type = 'desc';
		$output = executeQueryArray('googleotp.getAuthSendLogList', $args);

		foreach ($output->data as $key => $datum)
		{
			$output->data[$key]->member_info = $oMemberModel->getMemberInfoByMemberSrl($datum->member_srl);
		}

		Context::set('total_count', $output->total_count);
		Context::set('total_page', $output->total_page);
		Context::set('page', $output->page);
		Context::set('page_navigation', $output->page_navigation);
		Context::set('authsend_list', $output->data);
	}
}
