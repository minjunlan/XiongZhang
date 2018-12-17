<?php

use Exception;
/**
 * 百度熊掌号
 * 仿微信公众号 https://github.com/dodgepudding/wechat-php-sdk/blob/master/wechat.class.php
 */
class XiongZhang extends XzhBase {
    private $token;
	private $encodingAesKey;
	private $encrypt_type;
	private $client_id;
	private $client_secret;
    private $access_token;
    private $packType;
    private $postxml;
    public $logcallback;

    private $_msg;
	private $_funcflag = false;
	private $_receive;
	private $_text_filter = true;

	const MSGTYPE_TEXT = 'text';
	const MSGTYPE_IMAGE = 'image';
	const MSGTYPE_LOCATION = 'location';
	const MSGTYPE_LINK = 'link';
	const MSGTYPE_EVENT = 'event';
	const MSGTYPE_MUSIC = 'music';
	const MSGTYPE_NEWS = 'news';
	const MSGTYPE_VOICE = 'voice';
	const MSGTYPE_VIDEO = 'video';
	const MSGTYPE_SHORTVIDEO = 'shortvideo';
	const EVENT_SUBSCRIBE = 'subscribe';       //订阅
	const EVENT_UNSUBSCRIBE = 'unsubscribe';   //取消订阅
	const EVENT_SCAN = 'SCAN';                 //扫描带参数二维码
	const EVENT_LOCATION = 'LOCATION';         //上报地理位置
	const EVENT_MENU_VIEW = 'VIEW';                     //菜单 - 点击菜单跳转链接
	const EVENT_MENU_CLICK = 'CLICK';                   //菜单 - 点击菜单拉取消息
	const EVENT_MENU_SCAN_PUSH = 'scancode_push';       //菜单 - 扫码推事件(客户端跳URL)
	const EVENT_MENU_SCAN_WAITMSG = 'scancode_waitmsg'; //菜单 - 扫码推事件(客户端不跳URL)
	const EVENT_MENU_PIC_SYS = 'pic_sysphoto';          //菜单 - 弹出系统拍照发图
	const EVENT_MENU_PIC_PHOTO = 'pic_photo_or_album';  //菜单 - 弹出拍照或者相册发图
	const EVENT_MENU_PIC_WEIXIN = 'pic_weixin';         //菜单 - 弹出微信相册发图器
	const EVENT_MENU_LOCATION = 'location_select';      //菜单 - 弹出地理位置选择器
	const EVENT_SEND_MASS = 'MASSSENDJOBFINISH';        //发送结果 - 高级群发完成
	const EVENT_SEND_TEMPLATE = 'TEMPLATESENDJOBFINISH';//发送结果 - 模板消息发送结果
	const EVENT_KF_SEESION_CREATE = 'kfcreatesession';  //多客服 - 接入会话
	const EVENT_KF_SEESION_CLOSE = 'kfclosesession';    //多客服 - 关闭会话
	const EVENT_KF_SEESION_SWITCH = 'kfswitchsession';  //多客服 - 转接会话
	const EVENT_CARD_PASS = 'card_pass_check';          //卡券 - 审核通过
	const EVENT_CARD_NOTPASS = 'card_not_pass_check';   //卡券 - 审核未通过
	const EVENT_CARD_USER_GET = 'user_get_card';        //卡券 - 用户领取卡券
	const EVENT_CARD_USER_DEL = 'user_del_card';        //卡券 - 用户删除卡券
	const EVENT_MERCHANT_ORDER = 'merchant_order';        //微信小店 - 订单付款通知

    public function __construct($options)
	{
		$this->token = isset($options['token'])?$options['token']:'';
        $this->encodingAesKey = isset($options['encodingAesKey'])?$options['encodingAesKey']:'';
		$this->client_id = isset($options['client_id'])?$options['client_id']:'';
        $this->client_secret = isset($options['client_secret'])?$options['client_secret']:'';
        $this->packType = isset($options['packType'])?$options['packType']:'xml';
		$this->debug = isset($options['debug'])?$options['debug']:false;
        $this->logcallback = isset($options['logcallback'])?$options['logcallback']:false;
    }
    
    /**
	 * For server validation
	 */
	private function checkSignature($str='')
	{
        $signature = isset($_GET["signature"])?$_GET["signature"]:'';
	    $signature = isset($_GET["msg_signature"])?$_GET["msg_signature"]:$signature; //如果存在加密验证则用加密验证段
        $timestamp = isset($_GET["timestamp"])?$_GET["timestamp"]:'';
        $nonce = isset($_GET["nonce"])?$_GET["nonce"]:'';
		$token = $this->token;
		$tmpArr = array($token, $timestamp, $nonce,$str);
		sort($tmpArr, SORT_STRING);
		$tmpStr = implode( $tmpArr );
		$tmpStr = sha1( $tmpStr );
		if( $tmpStr == $signature ){
			return true;
		}else{
			return false;
		}
    }
    
    /**
	 * For weixin server validation
	 * @param bool $return 是否返回
	 */
	public function valid($return=false)
    {
        $encryptStr="";
        if ($_SERVER['REQUEST_METHOD'] == "POST") {
            $postStr = file_get_contents("php://input");
            $array = $this->getPostArr($postStr);
            $this->encrypt_type = isset($_GET["encrypt_type"]) ? $_GET["encrypt_type"]: '';
            if ($this->encrypt_type == 'aes') { //aes加密
                $this->log($postStr);
            	$encryptStr = $array['Encrypt'];
                $pc = new Prpcrypt($this->encodingAesKey);
                $array = $pc->decrypt($encryptStr,$this->client_id);
            	if (!isset($array[0]) || ($array[0] != 0)) {
            	    if (!$return) {
            	        die('decrypt error!');
            	    } else {
            	        return false;
            	    }
            	}
            	$this->postxml = $array[1];
            	if (!$this->client_id)
            	    $this->client_id = $array[2];//为了没有client_id的订阅号。
            } else {
                $this->postxml = $postStr;
            }
            $this->log("postxml:".$this->postxml);
        } elseif (isset($_GET["echostr"])) {
        	$echoStr = $_GET["echostr"];
        	if ($return) {
        		if ($this->checkSignature())
        			return $echoStr;
        		else
        			return false;
        	} else {
        		if ($this->checkSignature())
        			die($echoStr);
        		else
        			die('no access');
        	}
        }
        if (!$this->checkSignature($encryptStr)) {
        	if ($return)
        		return false;
        	else
        		die('no access');
        }
        return true;
    }

    /**
     * 获取微信服务器发来的信息
     */
	public function getRev()
	{
		if ($this->_receive) return $this;
		$postStr = !empty($this->postxml)?$this->postxml:file_get_contents("php://input");
		//兼顾使用明文又不想调用valid()方法的情况
		$this->log($postStr);
		if (!empty($postStr)) {
            $this->_receive = $this->getPostArr($postStr);
			//$this->_receive = (array)simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
		}
		return $this;
	}
	/**
	 * 获取微信服务器发来的信息
	 */
	public function getRevData()
	{
		return $this->_receive;
	}
	/**
	 * 获取消息发送者
	 */
	public function getRevFrom() {
		if (isset($this->_receive['FromUserName']))
			return $this->_receive['FromUserName'];
		else
			return false;
	}
	/**
	 * 获取消息接受者
	 */
	public function getRevTo() {
		if (isset($this->_receive['ToUserName']))
			return $this->_receive['ToUserName'];
		else
			return false;
	}
	/**
	 * 获取接收消息的类型
	 */
	public function getRevType() {
		if (isset($this->_receive['MsgType']))
			return $this->_receive['MsgType'];
		else
			return false;
	}
	
	/**
	 * 获取消息ID
	 */
	public function getRevID() {
		if (isset($this->_receive['MsgId']))
			return $this->_receive['MsgId'];
		else
			return false;
	}
	/**
	 * 获取消息发送时间
	 */
	public function getRevCtime() {
		if (isset($this->_receive['CreateTime']))
			return $this->_receive['CreateTime'];
		else
			return false;
	}
	/**
	 * 获取接收消息内容正文
	 */
	public function getRevContent(){
		if (isset($this->_receive['Content']))
			return $this->_receive['Content'];
		else if (isset($this->_receive['Recognition'])) //获取语音识别文字内容，需申请开通
			return $this->_receive['Recognition'];
		else
			return false;
    }
    
/**
	 * 获取接收消息图片
	 */
	public function getRevPic(){
		if (isset($this->_receive['PicUrl']))
			return array(
				'mediaid'=>$this->_receive['MediaId'],
				'picurl'=>(string)$this->_receive['PicUrl'],    //防止picurl为空导致解析出错
			);
		else
			return false;
	}
	/**
	 * 获取接收消息链接
	 */
	public function getRevLink(){
		if (isset($this->_receive['Url'])){
			return array(
				'url'=>$this->_receive['Url'],
				'title'=>$this->_receive['Title'],
				'description'=>$this->_receive['Description']
			);
		} else
			return false;
	}
	/**
	 * 获取接收地理位置
	 */
	public function getRevGeo(){
		if (isset($this->_receive['Location_X'])){
			return array(
				'x'=>$this->_receive['Location_X'],
				'y'=>$this->_receive['Location_Y'],
				'scale'=>$this->_receive['Scale'],
				'label'=>$this->_receive['Label']
			);
		} else
			return false;
	}
	/**
	 * 获取上报地理位置事件
	 */
	public function getRevEventGeo(){
        	if (isset($this->_receive['Latitude'])){
        		 return array(
				'x'=>$this->_receive['Latitude'],
				'y'=>$this->_receive['Longitude'],
				'precision'=>$this->_receive['Precision'],
			);
		} else
			return false;
	}
	/**
	 * 获取接收事件推送
	 */
	public function getRevEvent(){
		if (isset($this->_receive['Event'])){
			$array['event'] = $this->_receive['Event'];
		}
		if (isset($this->_receive['EventKey'])){
			$array['key'] = $this->_receive['EventKey'];
		}
		if (isset($array) && count($array) > 0) {
			return $array;
		} else {
			return false;
		}
	}

    /**
	 * 获取自定义菜单的扫码推事件信息
	 *
	 * 事件类型为以下两种时则调用此方法有效
	 * Event	 事件类型，scancode_push
	 * Event	 事件类型，scancode_waitmsg
	 *
	 * @return: array | false
	 * array (
	 *     'ScanType'=>'qrcode',
	 *     'ScanResult'=>'123123'
	 * )
	 */
	public function getRevScanInfo(){
		if (isset($this->_receive['ScanCodeInfo'])){
		    if (!is_array($this->_receive['ScanCodeInfo'])) {
		        $array=(array)$this->_receive['ScanCodeInfo'];
		        $this->_receive['ScanCodeInfo']=$array;
		    }else {
		        $array=$this->_receive['ScanCodeInfo'];
		    }
		}
		if (isset($array) && count($array) > 0) {
			return $array;
		} else {
			return false;
		}
	}
	/**
	 * 获取自定义菜单的图片发送事件信息
	 *
	 * 事件类型为以下三种时则调用此方法有效
	 * Event	 事件类型，pic_sysphoto        弹出系统拍照发图的事件推送
	 * Event	 事件类型，pic_photo_or_album  弹出拍照或者相册发图的事件推送
	 * Event	 事件类型，pic_weixin          弹出微信相册发图器的事件推送
	 *
	 * @return: array | false
	 * array (
	 *   'Count' => '2',
	 *   'PicList' =>array (
	 *         'item' =>array (
	 *             0 =>array ('PicMd5Sum' => 'aaae42617cf2a14342d96005af53624c'),
	 *             1 =>array ('PicMd5Sum' => '149bd39e296860a2adc2f1bb81616ff8'),
	 *         ),
	 *   ),
	 * )
	 *
	 */
	public function getRevSendPicsInfo(){
		if (isset($this->_receive['SendPicsInfo'])){
		    if (!is_array($this->_receive['SendPicsInfo'])) {
		        $array=(array)$this->_receive['SendPicsInfo'];
		        if (isset($array['PicList'])){
		            $array['PicList']=(array)$array['PicList'];
		            $item=$array['PicList']['item'];
		            $array['PicList']['item']=array();
		            foreach ( $item as $key => $value ){
		                $array['PicList']['item'][$key]=(array)$value;
		            }
		        }
		        $this->_receive['SendPicsInfo']=$array;
		    } else {
		        $array=$this->_receive['SendPicsInfo'];
		    }
		}
		if (isset($array) && count($array) > 0) {
			return $array;
		} else {
			return false;
		}
	}
	/**
	 * 获取自定义菜单的地理位置选择器事件推送
	 *
	 * 事件类型为以下时则可以调用此方法有效
	 * Event	 事件类型，location_select        弹出地理位置选择器的事件推送
	 *
	 * @return: array | false
	 * array (
	 *   'Location_X' => '33.731655000061',
	 *   'Location_Y' => '113.29955200008047',
	 *   'Scale' => '16',
	 *   'Label' => '某某市某某区某某路',
	 *   'Poiname' => '',
	 * )
	 *
	 */
	public function getRevSendGeoInfo(){
	    if (isset($this->_receive['SendLocationInfo'])){
	        if (!is_array($this->_receive['SendLocationInfo'])) {
	            $array=(array)$this->_receive['SendLocationInfo'];
	            if (empty($array['Poiname'])) {
	                $array['Poiname']="";
	            }
	            if (empty($array['Label'])) {
	                $array['Label']="";
	            }
	            $this->_receive['SendLocationInfo']=$array;
	        } else {
	            $array=$this->_receive['SendLocationInfo'];
	        }
	    }
	    if (isset($array) && count($array) > 0) {
	        return $array;
	    } else {
	        return false;
	    }
	}
	/**
	 * 获取接收语音推送
	 */
	public function getRevVoice(){
		if (isset($this->_receive['MediaId'])){
			return array(
				'mediaid'=>$this->_receive['MediaId'],
				'format'=>$this->_receive['Format'],
			);
		} else
			return false;
	}
	/**
	 * 获取接收视频推送
	 */
	public function getRevVideo(){
		if (isset($this->_receive['MediaId'])){
			return array(
					'mediaid'=>$this->_receive['MediaId'],
					'thumbmediaid'=>$this->_receive['ThumbMediaId']
			);
		} else
			return false;
	}

    public static function xmlSafeStr($str)
	{
		return '<![CDATA['.preg_replace("/[\\x00-\\x08\\x0b-\\x0c\\x0e-\\x1f]/",'',$str).']]>';
	}
	/**
	 * 数据XML编码
	 * @param mixed $data 数据
	 * @return string
	 */
	public static function data_to_xml($data) {
	    $xml = '';
	    foreach ($data as $key => $val) {
	        is_numeric($key) && $key = "item id=\"$key\"";
	        $xml    .=  "<$key>";
	        $xml    .=  ( is_array($val) || is_object($val)) ? self::data_to_xml($val)  : self::xmlSafeStr($val);
	        list($key, ) = explode(' ', $key);
	        $xml    .=  "</$key>";
	    }
	    return $xml;
	}
	/**
	 * XML编码
	 * @param mixed $data 数据
	 * @param string $root 根节点名
	 * @param string $item 数字索引的子节点名
	 * @param string $attr 根节点属性
	 * @param string $id   数字索引子节点key转换的属性名
	 * @param string $encoding 数据编码
	 * @return string
	*/
	public function xml_encode($data, $root='xml', $item='item', $attr='', $id='id', $encoding='utf-8') {
	    if ($this->packType == 'json') {
			return json_encode($data);
		} else {
			if(is_array($attr)){
				$_attr = array();
				foreach ($attr as $key => $value) {
					$_attr[] = "{$key}=\"{$value}\"";
				}
				$attr = implode(' ', $_attr);
			}
			$attr   = trim($attr);
			$attr   = empty($attr) ? '' : " {$attr}";
			$xml   = "<{$root}{$attr}>";
			$xml   .= self::data_to_xml($data, $item, $id);
			$xml   .= "</{$root}>";
			return $xml;
		}
	}
	/**
	 * 过滤文字回复\r\n换行符
	 * @param string $text
	 * @return string|mixed
	 */
	private function _auto_text_filter($text) {
		if (!$this->_text_filter) return $text;
		return str_replace("\r\n", "\n", $text);
    }
    
    /**
	 * 设置发送消息
	 * @param array $msg 消息数组
	 * @param bool $append 是否在原消息数组追加
	 */
    public function Message($msg = '',$append = false){
        if (is_null($msg)) {
            $this->_msg =array();
        }elseif (is_array($msg)) {
            if ($append)
                $this->_msg = array_merge($this->_msg,$msg);
            else
                $this->_msg = $msg;
            return $this->_msg;
        } else {
            return $this->_msg;
        }
    }

	/**
	 * 设置回复消息
	 * Example: $obj->text('hello')->reply();
	 * @param string $text
	 */
	public function text($text='')
	{
		$FuncFlag = $this->_funcflag ? 1 : 0;
		$msg = array(
			'ToUserName' => $this->getRevFrom(),
			'FromUserName'=>$this->getRevTo(),
			'MsgType'=>self::MSGTYPE_TEXT,
			'Content'=>$this->_auto_text_filter($text),
			'CreateTime'=>time(),
			'FuncFlag'=>$FuncFlag
		);
		
		$this->Message($msg);
		return $this;
	}

	/**
	 * 设置图片回复消息
	 * Example: $obj->image('media_id')->reply();
	 * @param string $mediaid
	 */
	public function image($mediaid='')
	{
		$FuncFlag = $this->_funcflag ? 1 : 0;
		$msg = array(
			'ToUserName' => $this->getRevFrom(),
			'FromUserName'=>$this->getRevTo(),
			'MsgType'=>self::MSGTYPE_IMAGE,
			'Image'=>array('MediaId'=>$mediaid),
			'CreateTime'=>time(),
			'FuncFlag'=>$FuncFlag
		);
		$this->Message($msg);
		return $this;
	}

	/**
	 * 设置回复图文
	 * @param array $newsData
	 * 数组结构:
	 *  array(
	 *  	"0"=>array(
	 *  		'Title'=>'msg title',
	 *  		'Description'=>'summary text',
	 *  		'PicUrl'=>'http://www.domain.com/1.jpg',
	 *  		'Url'=>'http://www.domain.com/1.html'
	 *  	),
	 *  	"1"=>....
	 *  )
	 */
	public function kf_news($newsData=array())
	{
		if ($this->checkAuth()) {
			$params = [
				'access_token' => $this->access_token,
			];
			$data['touser'] =  $this->getRevFrom();
			$data['msgtype'] = "news";
			$data['news'] = [
				"articles" => $newsData
			];
			$this->log($newsData);
			$rs = $this->postInvoke(XzhConst::URI_REST_PREFIXS."/message/custom_send",json_encode($data),$params);
			$this->log($rs);
		}
		exit;
	}

	/**
	 * 设置回复消息
	 * Example: $obj->voice('media_id')->reply();
	 * @param string $mediaid
	 */
	public function voice($mediaid='')
	{
		$FuncFlag = $this->_funcflag ? 1 : 0;
		$msg = array(
			'ToUserName' => $this->getRevFrom(),
			'FromUserName'=>$this->getRevTo(),
			'MsgType'=>self::MSGTYPE_VOICE,
			'Voice'=>array('MediaId'=>$mediaid),
			'CreateTime'=>time(),
			'FuncFlag'=>$FuncFlag
		);
		$this->Message($msg);
		return $this;
	}

	/**
	 * 获取access_token
	 * @param string $client_id 如在类初始化时已提供，则可为空
	 * @param string $client_secret 如在类初始化时已提供，则可为空
	 * @param string $token 手动指定access_token，非必要情况不建议用
	 */
	public function checkAuth($client_id='',$client_secret='',$token=''){
		if (!$client_id || !$client_secret) {
			$client_id = $this->client_id;
			$client_secret = $this->client_secret;
		}
		if ($token) { //手动指定token，优先使用
		    $this->access_token=$token;
		    return $this->access_token;
		}
		$authname = 'baidu_access_token'.$client_id;
		if ($rs = $this->getCache($authname))  {
			$this->access_token = $rs;
			return $rs;
		}

		$params = [
            'grant_type' => XzhConst::TOKEN_GRANT_TYPE,
            'client_id' => $client_id,
            'client_secret' => $client_secret,
        ];

        $result = $this->getInvoke(XzhConst::URI_OAUTH_TOKEN, $params);
		//$result = $this->http_get(self::API_URL_PREFIX.self::AUTH_URL.'client_id='.$client_id.'&secret='.$client_secret);
		if ($result)
		{
			$json = json_decode($result,true);
			if (!$json || isset($json['error'])) {
				$this->errCode = $json['error'];
				$this->errMsg = $json['error_description'];
				return false;
			}
			$this->access_token = $json['access_token'];
			$expire = $json['expires_in'] ? intval($json['expires_in'])-100 : 3600;
			$this->setCache($authname,$this->access_token,$expire);
			return $this->access_token;
		}
		return false;
	}
	
    protected function getPostArr($postStr){
        if ($this->packType == "json") {
            $array = (array)json_decode($postStr,1);
        } else {
            $array = (array)simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
        }
        return $array;
    }


	/**
	 *
	 * 回复微信服务器, 此函数支持链式操作
	 * Example: $this->text('msg tips')->reply();
	 * @param string $msg 要发送的信息, 默认取$this->_msg
	 * @param bool $return 是否返回信息而不抛出到浏览器 默认:否
	 */
	public function reply($msg=array(),$return = false)
	{
		if (empty($msg)) {
		    if (empty($this->_msg))   //防止不先设置回复内容，直接调用reply方法导致异常
		        return false;
			$msg = $this->_msg;
		}
		
		$xmldata=  $this->xml_encode($msg);
		$this->log($xmldata);
		if ($this->encrypt_type == 'aes') { //如果来源消息为加密方式
		    $pc = new Prpcrypt($this->encodingAesKey);
		    $array = $pc->encrypt($xmldata, $this->client_id);
		    $ret = $array[0];
		    if ($ret != 0) {
		        $this->log('encrypt err!');
		        return false;
		    }
		    $timestamp = time();
		    $nonce = rand(77,999)*rand(605,888)*rand(11,99);
		    $encrypt = $array[1];
		    $tmpArr = array($this->token, $timestamp, $nonce,$encrypt);//比普通公众平台多了一个加密的密文
		    sort($tmpArr, SORT_STRING);
		    $signature = implode($tmpArr);
		    $signature = sha1($signature);
		    $xmldata = $this->generate($encrypt, $signature, $timestamp, $nonce);
		    $this->log($xmldata);
		}
		if ($return)
			return $xmldata;
		else
			echo $xmldata;
	}
    /**
     * xml格式加密，仅请求为加密方式时再用
     */
	private function generate($encrypt, $signature, $timestamp, $nonce)
	{
		if ($this->packType == 'json') {
			$format['Encrypt'] = $encrypt;
			$format['MsgSignature'] = $signature;
			$format['TimeStamp'] = $timestamp;
			$format['Nonce'] = $nonce;
			return json_encode($format);
		} else {
			//格式化加密信息
			$format = "<xml>
<Encrypt><![CDATA[%s]]></Encrypt>
<MsgSignature><![CDATA[%s]]></MsgSignature>
<TimeStamp>%s</TimeStamp>
<Nonce><![CDATA[%s]]></Nonce>
</xml>";
			return sprintf($format, $encrypt, $signature, $timestamp, $nonce);
		}
		

	   
	}

	/**
	 * 设置缓存，按需重载
	 * @param string $cachename
	 * @param mixed $value
	 * @param int $expired
	 * @return boolean
	 */
	protected function setCache($cachename,$value,$expired){
		//TODO: set cache implementation
		return false;
	}
	/**
	 * 获取缓存，按需重载
	 * @param string $cachename
	 * @return mixed
	 */
	protected function getCache($cachename){
		//TODO: get cache implementation
		return false;
	}
	/**
	 * 清除缓存，按需重载
	 * @param string $cachename
	 * @return boolean
	 */
	protected function removeCache($cachename){
		//TODO: remove cache implementation
		return false;
	}

    /**
     * 日志记录，可被重载。
     * @param mixed $log 输入日志
     * @return mixed
     */
    protected function log($log){
        if ($this->debug && function_exists($this->logcallback)) {
            if (is_array($log)) $log = print_r($log,true);
            return call_user_func($this->logcallback,$log);
        }
    }

}


/**
 * PKCS7Encoder class
 *
 * 提供基于PKCS7算法的加解密接口.
 */
class PKCS7Encoder
{
    public static $block_size = 32;
    /**
     * 对需要加密的明文进行填充补位
     * @param $text 需要进行填充补位操作的明文
     * @return 补齐明文字符串
     */
    function encode($text)
    {
        $block_size = PKCS7Encoder::$block_size;
        $text_length = strlen($text);
        //计算需要填充的位数
        $amount_to_pad = PKCS7Encoder::$block_size - ($text_length % PKCS7Encoder::$block_size);
        if ($amount_to_pad == 0) {
            $amount_to_pad = PKCS7Encoder::block_size;
        }
        //获得补位所用的字符
        $pad_chr = chr($amount_to_pad);
        $tmp = "";
        for ($index = 0; $index < $amount_to_pad; $index++) {
            $tmp .= $pad_chr;
        }
        return $text . $tmp;
    }
    /**
     * 对解密后的明文进行补位删除
     * @param decrypted 解密后的明文
     * @return 删除填充补位后的明文
     */
    function decode($text)
    {
        $pad = ord(substr($text, -1));
        if ($pad < 1 || $pad > PKCS7Encoder::$block_size) {
            $pad = 0;
        }
        return substr($text, 0, (strlen($text) - $pad));
    }
}

/**
 * Prpcrypt class
 *
 * 提供接收和推送给公众平台消息的加解密接口.
 */
class Prpcrypt
{
    public $key;
    function __construct($k) {
        $this->key = base64_decode($k . "=");
    }
    /**
     * 兼容老版本php构造函数，不能在 __construct() 方法前边，否则报错
     */
    function Prpcrypt($k)
    {
        $this->key = base64_decode($k . "=");
    }
  /**
   * 对明文进行加密
   * @param string $text 需要加密的明文
   * @return string 加密后的密文
   */
  public function encrypt($text, $client_id){
    try {
      //获得16位随机字符串，填充到明文之前
      $random = $this->getRandomStr();
      $text = $random . pack("N", strlen($text)) . $text . $client_id;

      $iv = substr($this->key, 0, 16);
      $pkc_encoder = new PKCS7Encoder;
      $text = $pkc_encoder->encode($text);
      $encrypted = openssl_encrypt($text,'AES-256-CBC',substr($this->key, 0, 32),OPENSSL_ZERO_PADDING,$iv);
      return array(ErrorCode::$OK, $encrypted);
    } catch (Exception $e) {
      //print $e;
      return array(ErrorCode::$EncryptAESError, null);
    }
  }
  /**
   * 对密文进行解密
   * @param string $encrypted 需要解密的密文
   * @return string 解密得到的明文
   */
  public function decrypt($encrypted, $client_id){
    try {
      $iv = substr($this->key, 0, 16);
      $decrypted = openssl_decrypt($encrypted,'AES-256-CBC',substr($this->key, 0, 32),OPENSSL_ZERO_PADDING,$iv);
    } catch (Exception $e) {
      return array(ErrorCode::$DecryptAESError, null);
    }
    try {
      //去除补位字符
      $pkc_encoder = new PKCS7Encoder;
      $result = $pkc_encoder->decode($decrypted);
      
      //去除16位随机字符串,网络字节序和client_id
      if (strlen($result) < 16)
        return "";
      $content = substr($result, 16, strlen($result));
      $len_list = unpack("N", substr($content, 0, 4));
      $xml_len = $len_list[1];
      $xml_content = substr($content, 4, $xml_len);
      $from_client_id = substr($content, $xml_len + 4);
      if (!$client_id)
        $client_id = $from_client_id;
      //如果传入的client_id是空的，则认为是订阅号，使用数据中提取出来的client_id
    } catch (Exception $e) {
      //print $e;
      return array(ErrorCode::$IllegalBuffer, null);
    }
    if ($from_client_id != $client_id)
      return array(ErrorCode::$Validateclient_idError, null);
    //不注释上边两行，避免传入client_id是错误的情况

    return array(0, $xml_content, $from_client_id);
    //增加client_id，为了解决后面加密回复消息的时候没有client_id的订阅号会无法回复
  }
    /**
     * 随机生成16位字符串
     * @return string 生成的字符串
     */
    function getRandomStr()
    {
        $str = "";
        $str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        $max = strlen($str_pol) - 1;
        for ($i = 0; $i < 16; $i++) {
            $str .= $str_pol[mt_rand(0, $max)];
        }
        return $str;
    }
}


/**
 * error code
 * 仅用作类内部使用，不用于官方API接口的errCode码
 */
class ErrorCode
{
    public static $OK = 0;
    public static $ValidateSignatureError = 40001;
    public static $ParseXmlError = 40002;
    public static $ComputeSignatureError = 40003;
    public static $IllegalAesKey = 40004;
    public static $Validateclient_idError = 40005;
    public static $EncryptAESError = 40006;
    public static $DecryptAESError = 40007;
    public static $IllegalBuffer = 40008;
    public static $EncodeBase64Error = 40009;
    public static $DecodeBase64Error = 40010;
    public static $GenReturnXmlError = 40011;
    public static $errCode=array(
            '0' => '处理成功',
            '40001' => '校验签名失败',
            '40002' => '解析xml失败',
            '40003' => '计算签名失败',
            '40004' => '不合法的AESKey',
            '40005' => '校验client_id失败',
            '40006' => 'AES加密失败',
            '40007' => 'AES解密失败',
            '40008' => '公众平台发送的xml不合法',
            '40009' => 'Base64编码失败',
            '40010' => 'Base64解码失败',
            '40011' => '公众帐号生成回包xml失败'
    );
    public static function getErrText($err) {
        if (isset(self::$errCode[$err])) {
            return self::$errCode[$err];
        }else {
            return false;
        };
    }
}

class XzhConst
{
    /**
     * 获取凭证获取token URI
     */
    const URI_OAUTH_TOKEN = 'https://openapi.baidu.com/oauth/2.0/token';
    /**
     * 获取授权码code URI
     */
    const URI_AUTHORIZE = 'https://openapi.baidu.com/oauth/2.0/authorize';
    /**
     * 熊掌号Rest服务 URI
     */
    const URI_REST_PREFIXS = 'https://openapi.baidu.com/rest/2.0/cambrian';
    /**
     * TP授权 URI
     */
    const URI_AUTH_TP = 'https://openapi.baidu.com/oauth/2.0/tp/login_page';

    /**
     * 熊掌号授权类型
     */
    const TOKEN_GRANT_TYPE = 'client_credentials';
    /**
     * tp授权类型
     */
    const TP_TOKEN_GRANT_TYPE = 'tp_credentials';


    /**
     * 网页授权-返回授权码code
     */
    const RESPONSE_TYPE = 'code';
    /**
     * 网页授权-授权码
     */
    const AUTHORIZATION_CODE = 'authorization_code';
    /**
     * 代熊掌号发起网页授权-授权码
     */
    const TP_AUTHORIZATION_CODE = 'tp_authorization_code';
    /**
     * 更新AccessToken
     */
    const REFRESH_CODE = 'refresh_token';
    /**
     * 代熊掌号发起网页授权-更新AccessToken
     */
    const TP_REFRESH_CODE = 'tp_refresh_token';

    /**
     * 网页授权-获取网页授权用户信息 API
     */
    const OPENAPI_SNS_USERINFO = 'sns/userinfo';

    /**
     * 熊掌号授权-获取预授权码 API
     */
    const OPENAPI_TP_API_CREATE_PREAUTHCODE = 'tp/api_create_preauthcode';
    /**
     * 熊掌号授权-获取熊掌号调用凭据 API
     */
    const OPENAPI_TP_API_QUERYAUTH = 'tp/api_query_auth';
    /**
     * 熊掌号授权-refresh_token刷新接口调用凭据 API
     */
    const OPENAPI_TP_API_AUTHORIZER_TOKEN= 'tp/api_authorizer_token';
    /**
     * 熊掌号授权-获取熊掌号信息 API
     */
    const OPENAPI_TP_AUTHORIZER_INFO= 'tp/api_get_authorizer_info';
}

class XzhBase
{

    /**
     * @param $path
     * @param $params
     * @param array $headers
     * @param int $connectTimeout
     * @param int $socketTimeout
     * @return array
     * @throws XzhException
     */
    protected function getInvoke($path, $params, $headers=array(), $connectTimeout = 6000, $socketTimeout = 6000)
    {
        try {
            $httpClient = new XzhHttpClient($connectTimeout, $socketTimeout);
            $get = $httpClient->get($path, $params, $headers);
            return $get['content'];
        } catch (Exception $e) {
            throw new XzhException(XzhError::getCusXzhError(XzhError::REQUEST_EXCEPTION_ERROR, $e->getMessage()));
        }
    }

    /**
     * @param $path
     * @param $data
     * @param $params
     * @param int $connectTimeout
     * @param int $socketTimeout
     * @param array $headers
     * @return array
     * @throws XzhException
     */
    protected function postInvoke($path, $data, $params, $headers=array(), $connectTimeout = 6000, $socketTimeout = 6000)
    {
        try {
            $httpClient = new XzhHttpClient($connectTimeout, $socketTimeout);
			$post = $httpClient->post($path, $data, $params, $headers);
            return $post['content'];
        } catch (Exception $e) {
            throw new XzhException(XzhError::getCusXzhError(XzhError::REQUEST_EXCEPTION_ERROR, $e->getMessage()));
        }
    }

}

class XzhHttpClient
{
    private $connectTimeout;
    private $socketTimeout;
    private $headers;

    /**
     * XzhHttpClient constructor.
     * @param int $connectTimeout
     * @param int $socketTimeout
     * @param array $headers
     */
    public function __construct($connectTimeout = 6000, $socketTimeout = 6000, $headers = array())
    {
        $this->connectTimeout = $connectTimeout;
        $this->socketTimeout = $socketTimeout;
        $this->headers = $headers;
    }

    /**
     * 连接超时
     * @param $ms
     */
    public function setConnectionTimeoutInMillis($ms)
    {
        $this->connectTimeout = $ms;
    }

    /**
     * 响应超时
     * @param $ms
     */
    public function setSocketTimeoutInMillis($ms)
    {
        $this->socketTimeout = $ms;
    }

    /**
     * @param $url
     * @param array $data
     * @param array $params
     * @param array $headers
     * @return array
     * @throws Exception
     */
    public function post($url, $data=array(), $params=array(), $headers=array())
    {
        $url = $this->buildUrl($url, $params);
		$headers = array_merge($this->headers, $this->buildHeaders($headers));
		
		$ch = curl_init();
        if (class_exists('CURLFile')) {
            curl_setopt($ch, CURLOPT_SAFE_UPLOAD, true);
        } else {
            if (defined('CURLOPT_SAFE_UPLOAD')) {
                curl_setopt($ch, CURLOPT_SAFE_UPLOAD, false);
            }
		}
		
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, 1);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
		curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

		curl_setopt($ch, CURLOPT_POSTFIELDS, $data);
		
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->socketTimeout);
		curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $this->connectTimeout);
		
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
		
        if($code === 0) {
            throw new Exception(curl_error($ch));
        }

        curl_close($ch);
        return array(
            'code' => $code,
            'content' => $content,
        );
    }

    /**
     * @param $url
     * @param array $params
     * @param array $headers
     * @return array
     * @throws Exception
     */
    public function get($url, $params=array(), $headers=array())
    {
        $url = $this->buildUrl($url, $params);
        $headers = array_merge($this->headers, $this->buildHeaders($headers));

        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_HEADER, false);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_TIMEOUT_MS, $this->socketTimeout);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT_MS, $this->connectTimeout);
        $content = curl_exec($ch);
        $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        if($code === 0) {
            throw new Exception(curl_error($ch));
        }

        curl_close($ch);
        return array(
            'code' => $code,
            'content' => $content,
        );
    }

    /**
     * @param $headers
     * @return array
     */
    private function buildHeaders($headers)
    {
        $result = array();
        if(empty($headers)) {
            return $result;
        }

        foreach($headers as $k => $v){
            $result[] = sprintf('%s:%s', $k, $v);
        }

        return $result;
    }

    /**
     * @param $url
     * @param $params
     * @return string
     */
    private function buildUrl($url, $params)
    {
        if(!empty($params)) {
            $str = http_build_query($params);
            return $url . (strpos($url, '?') === false ? '?' : '&') . $str;
        } else {
            return $url;
        }
    }
}

class XzhException extends Exception
{

    /**
     * XzhException constructor.
     * @param XzhError $error
     */
    public function __construct(XzhError $error)
    {
        parent::__construct($error->getErrorMsg(), $error->getErrorCode());
    }

}

class XzhError
{

    /**
     * 错误码
     */
    const PARAMS_ERROR = 'SDK1000';
    const REQUEST_EXCEPTION_ERROR = 'SDK1001';
    const AES_ENCRYPT_ERROR = 'SDK1002';
    const AES_DECRYPT_ERROR = 'SDK1003';
    const AES_DECRYPT_XML_ILLEGAL_ERROR = 'SDK1004';
    const AES_DECRYPT_CLIENTID_ERROR = 'SDK1005';

    /**
     * 错误码说明，关系对
     * @var array
     */
    private static $xzhErrors = [
        self::PARAMS_ERROR => '参数错误',
        self::REQUEST_EXCEPTION_ERROR => '请求发生异常错误',
        self::AES_ENCRYPT_ERROR => 'AES签名错误',
        self::AES_DECRYPT_CLIENTID_ERROR => 'AesEncryptUtil 校验ClientID失败;'
    ];

    /**
     * 错误码属性
     * @var
     */
    private $errorCode;

    /**
     * 错误说明属性
     * @var
     */
    private $errorMsg;

    /**
     * XzhError constructor.
     * @param $errorCode
     * @param $errorMsg
     */
    public function __construct($errorCode, $errorMsg)
    {
        $this->errorCode = $errorCode;
        $this->errorMsg = $errorMsg;
    }

    /**
     * @param $code
     * @return mixed
     */
    public static function getXzhError($code)
    {
        $errorMsg = '';
        if (isset(self::$xzhErrors[$code])) {
            $errorMsg = self::$xzhErrors[$code];
        }
        return new XzhError($code, $errorMsg);
    }

    /**
     * @param $code
     * @param $cusErrorMsg
     * @return XzhError
     */
    public static function getCusXzhError($code, $cusErrorMsg)
    {
        return new XzhError($code, $cusErrorMsg);
    }

    /**
     * @return mixed
     */
    public function getErrorCode()
    {
        return $this->errorCode;
    }

    /**
     * @return mixed
     */
    public function getErrorMsg()
    {
        return $this->errorMsg;
    }
}
