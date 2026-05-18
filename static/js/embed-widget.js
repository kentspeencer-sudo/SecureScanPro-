/* SecureScan Pro - SEO CMS Embeddable Widget */
(function() {
    var host = document.currentScript.getAttribute('data-host') || '';
    var container = document.createElement('div');
    container.id = 'securescan-widget';
    container.style.cssText = 'max-width:600px;margin:20px auto;';

    var iframe = document.createElement('iframe');
    iframe.src = host + '/embed';
    iframe.width = '100%';
    iframe.height = '600';
    iframe.frameBorder = '0';
    iframe.style.cssText = 'border:1px solid #2d3a50;border-radius:12px;';
    iframe.title = 'SecureScan Pro - Security Scanner';
    iframe.setAttribute('allow', 'clipboard-write');

    container.appendChild(iframe);

    if (document.currentScript.parentNode) {
        document.currentScript.parentNode.insertBefore(container, document.currentScript.nextSibling);
    } else {
        document.body.appendChild(container);
    }
})();
