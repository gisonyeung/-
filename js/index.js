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

	/* playfiar密码 生成密文 */
	$('#submit2-1').onclick = function() {

		var content = getText('#input2-1', '#input2-2');  

		var playfiar = new Playfiar(content[1]); // 传入密钥

		var _cipherText = '';

		if ( playfiar.error ) { // 密钥格式错误则会返回错误原因

			_cipherText = playfiar.error;

		} else {

			// 获取密钥对应的字母矩阵二维数组，并绘制为 DOM
			drawLetterMatrix('#letterMatrix1', playfiar.getLetterMatrix());

			_cipherText = playfiar.encrypt(content[0]); // 传入明文

		}

		setText('#result2-1', _cipherText);

		// 释放对象
		playfiar = null;

	};

	/* playfiar密码 生成明文 */
	$('#submit2-2').onclick = function() {

		var content = getText('#input2-3', '#input2-4');  

		var playfiar = new Playfiar(content[1]); // 传入密钥

		var _plainText = '';

		if ( playfiar.error ) { // 密钥格式错误则会返回错误原因

			_plainText = playfiar.error;

		} else {

			// 获取密钥对应的字母矩阵二维数组，并绘制为 DOM
			drawLetterMatrix('#letterMatrix2', playfiar.getLetterMatrix());

			_plainText = playfiar.decrypt(content[0]); // 传入密文

		}

		setText('#result2-2', _plainText);

		// 释放对象
		playfiar = null;

	};

	/* hill 密码 生成密钥矩阵 */
	var hill;
	$('#submit3-1').onclick = function() {

		var content = getText('#input3-1');  

		if ( !content[0] || content[0] < 26 ) {
			$('#input3-1').value = 26;
		} else if ( content[0] > 50 ) {
			$('#input3-1').value = 50;
		}

		hill = new Hill(content[0]); // 传入密钥

		// 获取密钥对应的字母矩阵二维数组，并绘制为 DOM
		drawLetterMatrix('#codeMatrix1', hill.getSKMatrix().one);
		drawLetterMatrix('#codeMatrix2', hill.getSKMatrix().one);

		// var _cipherText = hill.encrypt(content[1]); // 传入明文

		setText('#result3-1', '-');

	};

	/* hill 密码 生成密文 */
	$('#submit3-2').onclick = function() {

		var content = getText('#input3-1', '#input3-2');  

		// 还没生成过 hill 对象
		if ( !hill ) {

			$('#submit3-1').click();

		} else {
		
			var _cipherText = hill.encrypt(content[1]); // 传入明文

			setText('#result3-1', _cipherText);

		}

	};

	/* hill 密码 生成逆矩阵 */
	$('#submit3-3').onclick = function() {

		// 还没生成过 hill 对象
		if ( !hill ) {
			
			$('#submit3-1').click();

		}

		drawLetterMatrix('#codeMatrix3', hill.getInverseMartrix().one);
		
	};

	/* hill 密码 生成明文 */
	$('#submit3-4').onclick = function() {

		// 还没生成过 hill 对象
		if ( !hill ) {
			return false;
		}

		var content = getText('#input3-3');  

		if ( !content[0] ) {
			return false;
		}

		var _plainText = hill.decrypt(content[0]); // 传入明文
		setText('#result3-2', $('#input3-2').value.toUpperCase() || '-');
		
	};

	function drawLetterMatrix(selector, letterMatrix) {
		var $letterMatrix_ul = $(selector);

		var letterMatrix_li_tpl = '<li>{{letter}}</li>';

		var _html = '';

		letterMatrix.forEach(function(val, index) {
			_html += letterMatrix_li_tpl.replace(/{{letter}}/, val);
		});

		$letterMatrix_ul.innerHTML = _html;
	}

	var rsa;

	/* RSA 使用该质数 */
	$('#submit4-1-1').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa ) {
			rsa = new RSA();
		}

		var content = getText('#input4-1', '#input4-2');  

		// [p, q, n, $n]
		var result = rsa.setPairPrimeNum(content[0], content[1]);

		// 重复按钮
		if ( !result ) {
			return false;
		}

		// 质数不符合条件
		if (result.error) {
			setText('#result4-1', result.error);
			setText('#result4-2', '-');
			// 重置公钥相关信息
			resetPublicMsg()
			return false;
		}

		setValue('#input4-1', result[0] || '');
		setValue('#input4-2', result[1] || '');
		setText('#result4-1', result[2] || '-');
		setText('#result4-2', result[3] || '-');

		// 重置公钥相关信息
		resetPublicMsg();
		
	};

	/* RSA 随机生成质数 */
	$('#submit4-1-2').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa ) {
			rsa = new RSA();
		}

		// [p, q, n, $n]
		var result = rsa.getPairPrimeNum();

		setValue('#input4-1', result[0] || '');
		setValue('#input4-2', result[1] || '');
		setText('#result4-1', result[2] || '-');
		setText('#result4-2', result[3] || '-');

		// 重置公钥相关信息
		resetPublicMsg();
	};

	/* RSA 使用该公钥 */
	$('#submit4-2-1').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa ) {
			return false;			
		}

		var content = getText('#input4-3');  

		// { error, e d, publicKey, privateKey }
		var result = rsa.setPublicKey(content[0]);

		if ( !result ) {
			return false;
		}

		if ( result.error ) {
			setText('#result4-3', result.error);
			setText('#result4-4', '-');
			setText('#result4-5', '-');
			return false;
		}

		setValue('#input4-3', result.e || '');
		setText('#result4-3', result.d || '-');
		setText('#result4-4', result.publicKey || '-');
		setText('#result4-5', result.privateKey || '-');
		
	};

	/* RSA 随机生成公钥 */
	$('#submit4-2-2').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa ) {
			return false;			
		}

		// { e d, publicKey, privateKey }
		var result = rsa.getRandomPublicKey();

		setValue('#input4-3', result.e || '');
		setText('#result4-3', result.d || '-');
		setText('#result4-4', result.publicKey || '-');
		setText('#result4-5', result.privateKey || '-');
		
	};

	/* RSA 加密 */
	$('#submit4-3').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa ) {
			return false;			
		}

		var content = getText('#input4-4');

		if ( !content[0] ) {
			return false;
		}

		var _c = rsa.encrypt(content[0]);


		setText('#result4-6', _c || '-');
		
	};

	function resetPublicMsg() {
		// 重置公钥相关信息
		setValue('#input4-3', '');
		setText('#result4-3', '-');
		setText('#result4-4', '-');
		setText('#result4-5', '-');
		setText('#result4-6', '-');
	}

	/* RSA 解密 */
	var rsa2;
	$('#submit4-4').onclick = function() {

		// 还没生成过 rsa 对象
		if ( !rsa2 ) {
			rsa2 = new RSA();		
		}

		var content = getText('#input4-5', '#input4-6', '#input4-7');

		if ( !content[0] || !content[1] || !content[2] ) {
			return false;
		}

		var _c = rsa2.decrypt(content[2], content[0], content[1]);

		setText('#result4-7', _c || '-');

		
	};



	/* 工具函数 */

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

	/*
		@description 用于输出文本至特定输入框
		@param { selector String } selector 对应输入框选择器
		@param { String } text 文本内容
	*/
	function setValue(selector, text) {
		$(selector).value = text;
	}





	/* 页面操作逻辑相关代码 */


	/*
		切换面板
	*/
	$('.project-list').addEventListener('click', function(e) {

		var ev = ev || window.event;
		var target = ev.target || ev.srcElement;


		// 监听 li
		if (target.nodeName.toLowerCase() == 'li') {

			// 已选中则取消执行后续动作
			if ( /active/.test(target.className) ) {
				return false;
			}

			var panel = target.getAttribute('data-target');

			// 未指定面板，则取消执行后续动作
			if ( !panel ) {
				return false;
			}

			// 切换标签选中
			$('.p-item.active').className = $('.p-item.active').className.replace(/\s*active\s*/, '');
			target.className += ' active';

			// 切换面板显隐
			$('.panel.open').className = $('.panel.open').className.replace(/\s*open\s*/, '');
			$(panel).className += ' open';

			
		}

	});
	








})();