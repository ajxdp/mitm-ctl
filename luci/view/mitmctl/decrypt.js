'use strict';
'require view';

/* mitm-ctl 的 解密内容（请求 / 返回正文）。
   内嵌本机 7690 端口的页面 —— 那套界面是独立前端（原生 JS、零构建），
   在 LuCI 之外也能直接用，这里只是给它一个入口。 */
return view.extend({
	render: function() {
		var host = window.location.hostname;
		var url = 'http://' + host + ':7690/body';
		return E('div', { 'class': 'cbi-map' }, [
			E('h2', {}, _('解密内容（请求 / 返回正文）')),
			E('div', { 'class': 'cbi-map-descr' }, [
				_('服务端口 7690。页面空白说明服务没起来，去看系统日志；'),
				' ',
				E('a', { href: url, target: '_blank', style: 'font-weight:600' },
					_('在新窗口打开 ↗'))
			]),
			E('iframe', {
				src: url,
				style: 'width:100%;min-height:720px;border:1px solid #ddd;' +
				       'border-radius:4px;background:#fff;resize:vertical'
			})
		]);
	},
	handleSaveApply: null,
	handleSave: null,
	handleReset: null
});
