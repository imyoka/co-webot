getRawBody= require 'raw-body'
xml2js= require 'xml2js'
crypto= require 'crypto'
ejs= require 'ejs'
WXBizMsgCrypt= require 'wechat-crypto'

wechat= (config)->
	unless @ instanceof wechat then new wechat config
	@setToken config

wechat::setToken= (config)->
	if 'string' is typeof config then @token= config
	else if 'object' is typeof config and config.token
		@token= config.token
		@appid= config.appid or ''
		@encodingAESKey= config.encodingAESKey or ''
	else throw new Error 'Plz check ur config'

getSignature= (timestamp, nonce, token)->
	s= [token, timestamp, nonce].sort()
								.join('')
	crypto.createHash 'sha1'
		.update s
		.digest 'hex'

parseXML= (xml)-> (done)-> xml2js.parseString xml, {trim: true}, done

# 将xml2js解析出来的对象转换成直接可访问的对象
formatMessage= (result)->
	message= {}
	if 'object' is typeof result
		for key, val of result
			if (not val instanceof Array) or (val.length is 0) then continue
			if val.length is 1
				val= val[0]
				if 'object' is typeof val then message[key]= formatMessage val
				else message[key]= (val or '').trim()
			else
				message[key]= []
				result[key].forEach (item)-> message[key].push formatMessage(item)
	message

tpl = [
	'<xml>',
		'<ToUserName><![CDATA[<%-toUsername%>]]></ToUserName>',
		'<FromUserName><![CDATA[<%-fromUsername%>]]></FromUserName>',
		'<CreateTime><%=createTime%></CreateTime>',
		'<MsgType><![CDATA[<%=msgType%>]]></MsgType>',
		'<% if (msgType === "news") { %>',
		'<ArticleCount><%=content.length%></ArticleCount>',
		'<Articles>',
		'<% content.forEach(function(item){ %>',
		'<item>',
		'<Title><![CDATA[<%-item.title%>]]></Title>',
		'<Description><![CDATA[<%-item.description%>]]></Description>',
		'<PicUrl><![CDATA[<%-item.picUrl || item.picurl || item.pic %>]]></PicUrl>',
		'<Url><![CDATA[<%-item.url%>]]></Url>',
		'</item>',
		'<% }); %>',
		'</Articles>',
		'<% } else if (msgType === "music") { %>',
		'<Music>',
		'<Title><![CDATA[<%-content.title%>]]></Title>',
		'<Description><![CDATA[<%-content.description%>]]></Description>',
		'<MusicUrl><![CDATA[<%-content.musicUrl || content.url %>]]></MusicUrl>',
		'<HQMusicUrl><![CDATA[<%-content.hqMusicUrl || content.hqUrl %>]]></HQMusicUrl>',
		'</Music>',
		'<% } else if (msgType === "voice") { %>',
		'<Voice>',
		'<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
		'</Voice>',
		'<% } else if (msgType === "image") { %>',
		'<Image>',
		'<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
		'</Image>',
		'<% } else if (msgType === "video") { %>',
		'<Video>',
		'<MediaId><![CDATA[<%-content.mediaId%>]]></MediaId>',
		'<Title><![CDATA[<%-content.title%>]]></Title>',
		'<Description><![CDATA[<%-content.description%>]]></Description>',
		'</Video>',
		'<% } else if (msgType === "transfer_customer_service") { %>',
		'<% if (content && content.kfAccount) { %>',
		'<TransInfo>',
		'<KfAccount><![CDATA[<%-content.kfAccount%>]]></KfAccount>',
		'</TransInfo>',
		'<% } %>',
		'<% } else { %>',
		'<Content><![CDATA[<%-content%>]]></Content>',
		'<% } %>',
	'</xml>'].join('')

# 编译过后的模版
compiled = ejs.compile(tpl)

wrapTpl = '<xml>' +
	'<Encrypt><![CDATA[<%-encrypt%>]]></Encrypt>' +
	'<MsgSignature><![CDATA[<%-signature%>]]></MsgSignature>' +
	'<TimeStamp><%-timestamp%></TimeStamp>' +
	'<Nonce><![CDATA[<%-nonce%>]]></Nonce>' +
	'</xml>'

encryptWrap = ejs.compile(wrapTpl)

# 将内容回复给微信的封装方法
reply= (content, fromUsername, toUsername)->
	info= {}
	type= 'text'
	info.content= content or ''
	if Array.isArray content then type= 'new'
	else if 'object' is typeof content
		if content.hasOwnProperty 'type'
			if content.type is 'customerService' then return reply2CustomerService fromUsername, toUsername, content.kfAccount
			type= content.type
			info.content= content.content
		else type= 'music'

	info.msgType= type
	info.createTime= new Date().getTime()
	info.toUsername= toUsername
	info.fromUsername= fromUsername
	compiled info

reply2CustomerService= (fromUsername, toUsername, kfAccount)->
	info= {}
	info.msgType= 'transfer_customer_service'
	info.createTime= new Date().getTime()
	info.toUsername= toUsername
	info.fromUsername= fromUsername
	info.content= {}
	if 'string' is kfAccount then info.content.kfAccount= kfAccount
	compiled info

wechat::middleware= (handle)->
	that= @
	if @encodingAESKey then @crypto= new WXBizMsgCrypt @token, @encodingAESKey, @appid
	(next)->
		query= @query
		# 加密模式
		encrypted= !!(query.encrypt_type and query.encrypt_type is 'aes' and query.msg_signature)
		timestamp= query.timestamp
		nonce= query.nonce
		echostr= query.echostr

		if 'GET' is @method
			valid= false
			if encrypted
				signature= query.msg_signature
				valid= signature= that.crypto.getSignature timestamp, nonce, echostr
			else
				valid= signature= getSignature timestamp, nonce, that.token

			unless valid
				@status= 401
				@body= 'Invalid signature'
			else
				if encrypted
					decrypted= that.crypto.decrypt echostr
					# 检查appId的正确性
					@body= decrypted.message
				else
					@body= echostr
		if 'POST' is @method
			unless encrypted
				# 校验
				if query.signature isnt getSignature timestamp, nonce, that.token
					@status= 401
					@body= 'Invalid signature'
			# 取原始数据
			xml= yield getRawBody @req, {
					length: @length
					limit: '1mb'
					encoding: @charset
				}
			@weixin_xml= xml
			# 解析xml
			result= yield parseXML xml
			formated= formatMessage result.xml
			if encrypted
				encryptMessage= formated.Encrypt
				if query.msg_signature isnt that.cryptor.getSignature timestamp, nonce, encryptMessage
					@status= 401
					@body= 'Invalid signature'
					return
				decryptedXML= that.cryptor.decrypt encryptMessage
				messageWrapXml= decryptedXML.message
				if messageWrapXml is ''
					@status= 401
					@body= 'Invalid signature'
					return
				decodedXML= yield parseXML messageWrapXml
				formated= formatMessage decodedXML.xml
			# 挂载处理后的微信消息
			@weixin= formated

			# 取session数据
			if @sessionStore
				@wxSessionId= formated.FromUserName
				@wxsession= yield @sessionStore.get @wxSessionId
				unless @wxsession
					@wxsession= {}
					@wxsession.cookie= @session.cookie

			# 业务逻辑处理
			yield from handle.call @

			# 更新session
			if @sessionStore
				unless @wxsession
				if @wxSessionId then yield @sessionStore.destory @wxSessionId
				else yield @sessionStore.set @wxSessionId, @wxsession

			# 假如服务器无法保证五秒内处理并回复，可以直接回复空串
			# 微信服务器不会对此做任何处理，并且不会发起重试
			if @body is '' then return
			replyMessageXml= reply @body, formated.ToUserName, formated.FromUserName

			if !query.encrypt_type or query.encrypt_type is 'raw' then @body= replyMessageXml
			else
				wrap= {}
				wrap.encrypt= that.cryptor.encrypt replyMessageXml
				wrap.nonce= ~~(Math.random()* 100000000000), 10
				wrap.timestamp= new Date().getTime()
				wrap.signature= that.cryptor.getSignature wrap.timestamp, wrap.nonce, wrap.encrypt
				@body= encryptWrap wrap

			@type= 'application/xml'	
		else
			@status= 501
			@body= 'Not Implemented'

module.exports = wechat