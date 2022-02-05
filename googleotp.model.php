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
}
