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

			// 传入密钥
			hill = new Hill(content[0]);
			// 获取密钥对应的字母矩阵二维数组，并绘制为 DOM
			drawLetterMatrix('#codeMatrix1', hill.getSKMatrix().one);
			drawLetterMatrix('#codeMatrix2', hill.getSKMatrix().one);

		} else {
		
			var _cipherText = hill.encrypt(content[1]); // 传入明文

			setText('#result3-1', _cipherText);

		}

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

		// 去除空格
		plaintext = plaintext.replace(/\s/, '');

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
		playfair 密码
		@description 根据加密内容和口令加密
		@用法：

		var playfiar = new Playfir('code') // 传入密钥
		var _cipherText = '',
			letterMatrix;

		if ( playfiar.error ) { // 密钥格式错误则会返回错误原因
			_cipherText = playfiar.error;
		} else {

			// 获取密钥对应的字母矩阵一维数组 length:25
			letterMatrix = playfiar.getLetterMatrix(); 

			_cipherText = playfiar.encrypt('test'); // 传入明文
		}

		// todo with `letterMatrix` & `_ciphertext`

	*/
	var Playfiar = function(secretKey) {

		// 将密钥转换为大写并去掉所有空格	
		secretKey = secretKey
					.toUpperCase()
					.replace(/\s/g, "");

		// 密钥格式验证
		if ( !secretKey.length ) {
			return {
				error: '密钥不能为空',
			}
		} else if ( /[^A-Za-z\s]/g.test(secretKey) ) {
			return {
				error: '密钥只能由字母组成',
			}
		}

		// 生成字母矩阵
		this.createMatrix = function(secretKey) {
			var secretKeyLen = secretKey.length; //获取密钥关键字的长度
			var keys =[];
			//格式化用户输入的密钥关键字并存入keys数组
			for ( var i = 0; i < secretKeyLen; i++ ) {
				if ( keys.indexOf(secretKey[i]) == -1 ) {
					if ( secretKey[i] == 'I' || secretKey[i] == 'J' ) {
						if (keys.indexOf("I") == -1) {
							keys.push("I");
						}
					} else {
						keys.push(secretKey[i]);
					}
				}
			}

			// 生成完整的字母矩阵
			var letterChar;
			for (var letter = 65; letter <= 90; letter++) {
				letterChar = String.fromCharCode(letter);
				if (keys.indexOf(letterChar) == -1 && letterChar != 'J') {
					if (letterChar == 'I') {
						keys.push("I");
						letter++; //跳过字母J
					} else {
						keys.push(letterChar);
					}
				}
			}

			return keys;
		}

		// 字母矩阵
		this.letterMatrix = this.createMatrix(secretKey);

		this.getLetterMatrix = function() {
			return this.letterMatrix;
		}

		// 根据明文生成密文
		this.encrypt = function(plaintext) {

			plaintext = plaintext
						.toUpperCase()
						.replace(/\s/g, "");

			var plaintextLen = plaintext.length,
				textGroup = '', // 用于记录分组明文
				cipherText = ''; // 密文

			var letterMatrix = this.getLetterMatrix();

			// 明文格式验证
			if ( !plaintextLen ) {
				return '明文不能为空';
			} else if ( /[^A-Za-z\s]/g.test(plaintext) ) {
				return '明文只能由字母组成';
			}

			// 将明文分组
			for (var i = 0; i < plaintextLen;) {
				if ( i == (plaintextLen - 1) ) {
					textGroup = textGroup + plaintext[i];
					i++;
				} else if (plaintext[i] != plaintext[i + 1]) {
					textGroup = textGroup + plaintext[i] + plaintext[i + 1];
					i += 2;
				} else {
					textGroup = textGroup + plaintext[i] + "K";
					i++;
				}
			}

			if (textGroup.length % 2) { //判断最后一组是否只有一个字母，如果是则补充字母K
				textGroup += "K";
			}

			// 转换密文
			var textGroupLen = textGroup.length;
			var letterA, letterB, remainderA, remainderB, discussA, discussB;
			for (i = 0; i < textGroupLen; i += 2) {
				letterA = letterMatrix.indexOf(textGroup[i]);
				letterB = letterMatrix.indexOf(textGroup[i + 1]);
				remainderA = letterA % 5;
				remainderB = letterB % 5;
				discussA = Math.floor(letterA / 5);
				discussB = Math.floor(letterB / 5);
				if ( discussA == discussB ) {
					//如果明文字母在矩阵中同行，则
					letterA++;
					letterB++;
					if (letterA % 5 == 0) {
						letterA -= 5;
					}
					if (letterB % 5 == 0) {
						letterB -= 5;
					}
					cipherText += letterMatrix[letterA] + letterMatrix[letterB];
					continue;
				} else if ( remainderA == remainderB ) {
					//如果明文字母在矩阵中同列，则
					letterA += 5;
					letterB += 5;
					if (letterA > 24) {
						letterA -= 25;
					}
					if (letterB > 24) {
						letterB -= 25;
					}
					cipherText += letterMatrix[letterA] + letterMatrix[letterB];
					continue;
				} else {
					//如果明文字母在矩阵中既不同行又不同列，则
					letterA = letterA - remainderA + remainderB;
					letterB = letterB - remainderB + remainderA;
					cipherText += letterMatrix[letterA] + letterMatrix[letterB];
				}
			}

			// 返回密文
			return cipherText;

		}

		// 根据密文生成明文
		this.decrypt = function(cipherText) {

			cipherText = cipherText
						.toUpperCase()
						.replace(/\s/g, "");

			var cipherTextLen = cipherText.length,
				textGroup = '', // 用于记录分组明文
				plaintext = ''; // 明文

			// 密文格式验证
			if ( !cipherTextLen || /[^A-IK-Za-ik-z\s]/g.test(cipherText) ) {
				return '密文不合法';
			}
			
			var letterMatrix = this.getLetterMatrix();			

			//转换明文
			var letterA, letterB, remainderA, remainderB, discussA, discussB;
			for (i = 0; i < cipherTextLen; i += 2) {
				letterA = letterMatrix.indexOf(cipherText[i]);
				letterB = letterMatrix.indexOf(cipherText[i + 1]);
				remainderA = letterA % 5;
				remainderB = letterB % 5;
				discussA = Math.floor(letterA / 5);
				discussB = Math.floor(letterB / 5);
				if (discussA == discussB) {
					//如果密文字母在矩阵中同行，则
					letterA--;
					letterB--;
					if ((letterA + 1) % 5 == 0) {
						letterA += 5;
					}
					if ((letterB + 1) % 5 == 0) {
						letterB += 5;
					}
					textGroup = textGroup + letterMatrix[letterA] + letterMatrix[letterB];
					continue;
				} else if (remainderA == remainderB) {
					//如果密文字母在矩阵中同列，则
					letterA -= 5;
					letterB -= 5;
					if (letterA < 0) {
						letterA += 25;
					}
					if (letterB < 0) {
						letterB += 25;
					}
					textGroup = textGroup + letterMatrix[letterA] + letterMatrix[letterB];
					continue;
				} else {
					//如果密文字母在矩阵中既不同行又不同列，则
					letterA = letterA - remainderA + remainderB;
					letterB = letterB - remainderB + remainderA;
					textGroup = textGroup + letterMatrix[letterA] + letterMatrix[letterB];
				}
			}

			//去“K”
			var textGroupLen = textGroup.length;
			for (i = 0; i < (textGroupLen - 2); i += 2) {
				if (textGroup[i] == textGroup[i + 2] && textGroup[i + 1] == 'K') {
					plaintext = plaintext + textGroup[i];
				} else {
					plaintext = plaintext + textGroup[i] + textGroup[i + 1];
				}
			}
			if (textGroup[i] != 'K' && textGroup[i + 1] == 'K') { //末尾处理
				plaintext = plaintext + textGroup[i] + "(K)";
			} else if (textGroup[i] == 'K' && textGroup[i + 1] == 'K') {
				plaintext = plaintext + textGroup[i];
			} else {
				plaintext = plaintext + textGroup[i] + textGroup[i + 1];
			}

			return plaintext;
		}

		return this;

	}


	/*
		hill 密码
		@description 根据加密内容和口令加密
		@用法：

		var playfiar = new Playfir('code') // 传入密钥
		var _cipherText = '',
			letterMatrix;

		if ( playfiar.error ) { // 密钥格式错误则会返回错误原因
			_cipherText = playfiar.error;
		} else {

			// 获取密钥对应的字母矩阵一维数组 length:25
			letterMatrix = playfiar.getLetterMatrix(); 

			_cipherText = playfiar.encrypt('test'); // 传入明文
		}

		// todo with `letterMatrix` & `_ciphertext`
	*/
	function Hill(secretKeyRange) {

		secretKeyRange = parseInt(secretKeyRange, 10) || 26;

		if ( secretKeyRange > 50 ) {
			secretKeyRange = 50;
		} else if ( secretKeyRange < 26 ) {
			secretKeyRange = 26;
		}

		this.createSKMatrix = function(secretKeyRange) {
			var one = [], // 一维表示
				two = []; // 二维表示

			for( var i = 0; i < 3; i++ ) {
				two[i] = [];
		        for( var j = 0; j < 3; j++ ) {
		        	var _random = 1 + Math.round(Math.random() * (secretKeyRange - 1));
		            one.push(_random);
		            two[i][j] = _random;
		        }
		    }

		    return {
		    	one: one,
		    	two: two,
		    }
		};

		this.SKMatrix = this.createSKMatrix(secretKeyRange);

		this.getSKMatrix = function() {
			return this.SKMatrix;
		};

		this.createGroup = function(plaintext) {
			plaintext = plaintext
						.toUpperCase()
						.replace(/\s/g, "");

			var plaintextLen = plaintext.length;
			var one = [], // 一维表示
				two = []; // 二维表示

			// 处理明文并存入 one
			for ( var i = 0; i < plaintextLen; i++ )  {
				one.push(plaintext.charCodeAt(i) - 65);
			}

			if (one.length % 3 == 1) { // 判断最后一组是否只有1个字母
				one.push(23);
				one.push(23);
			} else if (one.length % 3 == 2) { // 判断最后一组是否只有2个字母
				one.push(23);
			}

			var row = 0, col = 0;
			one.forEach(function(val, index) {

				if ( col == 0 ) {
					two[row] = [];
				}

				two[row].push(val);
				col++;

				if ( col == 3 ) {
					col = 0;
					row++;
				}

			});

			return {
				one: one,
				two: two,
			};
		};

		this.encrypt = function(plaintext) {

			plaintext = plaintext
						.toUpperCase()
						.replace(/\s/g, "");

			var plaintextLen = plaintext.length,
				cipherText = ''; // 密文

			// 明文格式验证
			if ( !plaintextLen ) {
				return '明文不能为空';
			} else if ( /[^A-Za-z\s]/g.test(plaintext) ) {
				return '明文只能由字母组成';
			}

			// 密钥矩阵
			var SKMatrix = this.getSKMatrix().two;
			// 明文分组，二维数组
			var group = this.createGroup(plaintext).two;

			var K = $M(SKMatrix);
			var P = $M(group);

			var rowsLen = P.rows(),
				cipherMatrix = [];

			for ( var i = 1; i <= rowsLen; i++ ) {
				cipherMatrix.push(K.x( P.row(i) ));
			}

			cipherMatrix.forEach(function(row) {

				row.elements.forEach(function(val, index) {
					cipherText += String.fromCharCode( val % 26 + 65 );
				});

			});

			return cipherText;

		};



	}
















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