var _logBuf = [];
var _flushing = false;

function _flushLogs() {
    if (_flushing || _logBuf.length === 0) return;
    _flushing = true;
    var batch = _logBuf.join('\n');
    _logBuf = [];
    try {
        var xhr = new XMLHttpRequest();
        xhr.open('POST', '/log', true);
        xhr.setRequestHeader('Content-Type', 'text/plain; charset=utf-8');
        xhr.onloadend = function() { _flushing = false; _flushLogs(); };
        xhr.send(batch);
    } catch(e) { _flushing = false; }
}

// Flush when event loop is free (at await points)
setInterval(_flushLogs, 50);

print = function(msg) {
    if (document.body) document.body.innerText += msg + '\n';
    _logBuf.push(msg);
};
