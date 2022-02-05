<?php
require_once(_XE_PATH_.'modules/googleotp/libs/GoogleAuthenticator.php');

class googleotpModel extends googleotp
{
	function init()
	{
	}

	function insertNewConfig($member_srl)
	{
		if($this->checkUserConfig($member_srl)) return FALSE;

		$ga = new PHPGangsta_GoogleAuthenticator();
		$cond = new stdClass();
		$cond->srl=$member_srl;
		$cond->otp_id = $ga->createSecret();
		$cond->use = "N";
		$output = executeQuery('googleotp.insertGoogleotpuserconfig', $cond);
		return $output->toBool();
	}
	
	function insertAuthlog($member_srl,$number,$issuccess) {
	    if(!$this->checkUserConfig($member_srl)) return FALSE;

		$cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->number = $number;
		$cond->issuccess = $issuccess;
		$cond->time = time();
		$output = executeQuery('googleotp.insertGoogleotpauthlog', $cond);
		return $output;
	}

	function checkUserConfig($member_srl)
	{
		$cond = new stdClass();
		$cond->srl = $member_srl;
		$output = executeQuery('googleotp.getGoogleotpuserconfigbySrl', $cond);
		if(!isset($output->data->otp_id)) return FALSE;
		else return TRUE;
	}
	
	function checkUsedNumber($member_srl,$number) {
	    // 5분전 입력한 인증코드 이후만 조회함
	    $cond = new stdClass();
		$cond->srl = $member_srl;
		$cond->number = $number;
		$cond->issuccess = "Y";
		$cond->time = time() - 300;
		
		$output = executeQueryArray('googleotp.getGoogleotpauthlogbySrl', $cond);
		if(!isset($output->data[0])) return TRUE;
		else return FALSE;
	}

	function generateQRCode($member_srl,$key)
	{
		$ga = new PHPGangsta_GoogleAuthenticator();
		return $ga->getQRCodeGoogleUrl($member_srl, $key);
	}

	function generateNewOTP($member_srl)
	{
		if(!$this->checkUserConfig($member_srl)) {
			return FALSE;
		} else {
			$ga = new PHPGangsta_GoogleAuthenticator();

			$cond = new stdClass();
			$cond->srl=$member_srl;
			$cond->otp_id = $ga->createSecret();
			$output = executeQuery('googleotp.updateGoogleotpkeybySrl', $cond);
			return $output->toBool();
		}
	}

	function checkOTPNumber($member_srl,$number)
	{
		$config = $this->getUserConfig($member_srl);
		$ga = new PHPGangsta_GoogleAuthenticator();
		return $ga->verifyCode($config->otp_id, $number, 2);
	}

	function getUserConfig($member_srl)
	{
		//srl로 회원 조회
		$cond = new stdClass();
		$cond->srl = $member_srl;
		$output = executeQuery('googleotp.getGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return FALSE;
		else return $output->data;
	}

	public function AvailableToSendEmail($member_srl)
	{
		$config = $this->getConfig();

		// 이메일 최대 발송 횟수 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'email';
		$args->time = time() - ($config->auth_retry_hour * 3600);
		$output = executeQuery('googleotp.getAuthSendLogCount', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->count >= $config->auth_retry_limit) return FALSE;

		// 최종 이메일 발송 시간으로부터 1분이 지났는지 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'email';
		$output = executeQuery('googleotp.getLastSentTime', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->time > time() - (60)) return FALSE;

		return TRUE;
	}

	public function AvailableToSendSMS($member_srl)
	{
		$config = $this->getConfig();

		// SMS 최대 발송 횟수 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'sms';
		$args->time = time() - ($config->auth_retry_hour * 3600);
		$output = executeQuery('googleotp.getAuthSendLogCount', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->count >= $config->auth_retry_limit) return FALSE;

		// 최종 SMS 발송 시간으로부터 1분이 지났는지 확인
		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->issue_type = 'sms';
		$output = executeQuery('googleotp.getLastSentTime', $args);
		if(!$output->toBool()) return FALSE;
		if($output->data->time > time() - (60)) return FALSE;

		return TRUE;
	}

	public static function sendAuthEmail($member_srl, $auth_number)
	{
		$oMemberModel = getModel('member');
		$member_info = $oMemberModel->getMemberInfoByMemberSrl($member_srl);

		$mail_address = $member_info->email_address;
		$mail_title = "2차 인증 메일입니다.";
		$mail_content = "2차 인증 번호는 [".$auth_number."] 입니다.";

		// @todo 메일 발송

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->number = $auth_number;
		$args->issue_type = 'email';
		$args->address = $member_info->email_address;
		$args->time = time();
		$output = executeQuery('googleotp.insertAuthSendLog', $args);

		return true;
	}

	public static function sendAuthSMS($member_srl, $auth_number)
	{
		$oMemberModel = getModel('member');
		$member_info = $oMemberModel->getMemberInfoByMemberSrl($member_srl);

		$sms_address = $member_info->phone_number;
		$sms_content = "2차 인증 번호는 [".$auth_number."] 입니다.";

		// @todo SMS 발송

		$args = new stdClass();
		$args->member_srl = $member_srl;
		$args->number = $auth_number;
		$args->issue_type = 'sms';
		$args->address = $member_info->phone_number;
		$args->time = time();
		$output = executeQuery('googleotp.insertAuthSendLog', $args);

		return true;
	}
}
