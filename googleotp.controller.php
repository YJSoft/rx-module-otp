<?php
class googleotpController extends googleotp
{
	function init()
	{
	}

	function procGoogleotpUserConfig()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1, "로그인해주세요");

		$oGoogleOTPModel = getModel('googleotp');

		if(!$oGoogleOTPModel->checkUserConfig(Context::get('logged_info')->member_srl)) {
			$oGoogleOTPModel->insertNewConfig(Context::get('logged_info')->member_srl);
		}

		$cond = new stdClass();
		$cond->srl = Context::get('logged_info')->member_srl;
		$cond->use = Context::get("use") === "Y" ? "Y" : "N";
		$cond->issue_type = Context::get("issue_type") ?: 'none';

		if($cond->use == 'Y' && !in_array($cond->issue_type, array('otp', 'email'))) {
			return $this->createObject(-1, "2차 인증 방식을 선택해주세요.");
		}

		$output = executeQuery('googleotp.updateGoogleotpuserconfigbySrl', $cond);
		if(!$output->toBool()) return $this->createObject(-1, "ERROR #1 : 관리자에게 문의하세요.");

		if($cond->use === "Y")
		{
			$_SESSION['googleotp_passed'] = TRUE;
		}

		// alert a message
		if(Context::get('xeVirtualRequestMethod') !== 'xml')
		{
			$this->setMessage('success_updated');
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpUserConfig'));
		}
	}

	function procGoogleotpInputotp()
	{
		if(!Context::get("is_logged")) return $this->createObject(-1,"로그인하지 않았습니다.");
		if($_SESSION['googleotp_passed']) return $this->createObject(-1,"이미 인증했습니다.");
		
		$otpnumber = Context::get("otpinput");
		
		// change 111 111 to 111111
	    $otpnumber = explode(" ",$otpnumber);
	    $otpnumber = implode("",$otpnumber);
	    
		$member_srl = Context::get('logged_info')->member_srl;

		$oGoogleOTPModel = getModel('googleotp');
		$config = $oGoogleOTPModel->getUserConfig($member_srl);
		
		if($oGoogleOTPModel->checkOTPNumber($member_srl,$otpnumber))
		{
		    if(!$oGoogleOTPModel->checkUsedNumber($member_srl,$otpnumber))
		    {
		        return $this->createObject(-1,"이미 인증에 사용된 OTP 번호입니다. 다른 번호를 사용해주세요.");
		    }
		    else
		    {
		        $oGoogleOTPModel->insertAuthlog($member_srl,$otpnumber,"Y");
			    $_SESSION['googleotp_passed'] = TRUE;
			    $this->setRedirectUrl($_SESSION['beforeaddress']);
		    }
		}
		else
		{
		    $oGoogleOTPModel->insertAuthlog($member_srl,$otpnumber,"N");
			$this->setMessage("잘못된 OTP 번호입니다");
			$this->setRedirectUrl(getNotEncodedUrl('', 'act', 'dispGoogleotpInputotp'));
		}
	}

	function triggerAddMemberMenu()
	{
		$logged_info = Context::get('logged_info');
		if(!Context::get('is_logged')) return $this->createObject();

		$oMemberController = getController('member');
		$oMemberController->addMemberMenu('dispGoogleotpUserConfig', "로그인 2차 인증 설정");
		if($logged_info->is_admin== 'Y')
		{
			$target_srl = Context::get('target_srl');

			$url = getUrl('','act','dispGoogleotpUserConfig','member_srl',$target_srl);
			$oMemberController->addMemberPopupMenu($url, '유저 로그인 2차 인증 관리', '');
		}
		return $this->createObject();
	}

	function triggerHijackLogin($obj) {
		if(!Context::get("is_logged") || $obj->act === "dispMemberLogout") {
			unset($_SESSION['googleotp_passed']);
			return;
		}

		$oGoogleOTPModel = getModel('googleotp');
		$userconfig = $oGoogleOTPModel->getUserConfig(Context::get('logged_info')->member_srl);
		if($userconfig->use === "Y") {
			$allowedact = array("dispGoogleotpInputotp","procGoogleotpInputotp","procMemberLogin","dispMemberLogout");
			if(!in_array($obj->act, $allowedact) && !$_SESSION['googleotp_passed'])
			{
				$_SESSION['beforeaddress'] = getNotEncodedUrl();
				header("Location: " . getNotEncodedUrl('act','dispGoogleotpInputotp'));
				Context::close();
				die();
			}
		}
	}
}
