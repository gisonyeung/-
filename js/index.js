(function() {

	var $ = document.querySelector.bind(document);


	/* 凯撒密码 生成密文 */
	$('#submit1-1').onclick = function() {

		var content = getText('#input1-1', '#input1-2');  

		if ( !content[0] ) {
			return false;
		}

		var result = caesar(content[0], content[1] || 0);

		setText('#result1-1', result);


	};



	/*
		凯撒密码
		@description 根据加密内容和口令加密
		@param { String } plaintext 明文
		@param { number-like String } key 偏移量
		@return { String } 密文
	*/
	function caesar(plaintext, key) {

		var _result = '';

		key = parseInt(key, 10) % 26; // 防止超出26

		for (var i = 0; i < plaintext.length; i++) {

			var _char = plaintext[i].charCodeAt();

			if ( _char >= 97 && _char <= 123 ) { // 小写变大写

				var _charToSecret = 65 + (_char + key) % 97 % 26;
				_result += String.fromCharCode(_charToSecret);

			} else if ( _char >= 65 && _char <= 91 ) { // 大写变小写

				var _charToSecret = 97 + (_char + key) % 65 % 26;
				_result += String.fromCharCode(_charToSecret);

			} else { // 不是字母则原样输出
				_result += plaintext[i];
			}

		}

		return _result;

	}


	/*
		@description 用于获取输入框文本，输入选择器，输出文本数组
		@param { selector String } 输入框对应的选择器
		@return [ input.value, input.value , ... ]
	*/
	function getText() {
		
		var _result = [];

		for(var i = 0; i < arguments.length; i++) {
			_result.push( $(arguments[i]).value || $(arguments[i]).innerText );
		}

		return _result;
	}

	/*
		@description 用于输出文本至特定选择器
		@param { selector String } selector 对应容器的选择器
		@param { String } text 文本内容
	*/
	function setText(selector, text) {
		$(selector).innerText = text;
	}

})();