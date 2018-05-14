'use strict';

const LineReader = require('./line-reader');
const net = require('net');
const npmlog = require('npmlog');
const path = require('path');
const os = require('os');
const fs = require('fs');
const crypto = require('crypto');

class AvastClient {
    constructor(options) {
        options = options || {};

        this.connection = false;
        this._connecting = false;
        this.initialized = false;

        this._commandQueue = [];

        this.lineReader = false;
        this._lineReaderEnded = false;

        this._quitting = false;

        this._processing = false;
        this._current = false;

        this._data = false; // if true then expects data lines

        this._initializeCallback = false;

        this.address = path.join(options.address || '/var/run/avast/scan.sock');
        this.tmpdir = options.tmpdir || os.tmpdir();

        this.logger = options.logger || npmlog;
    }

    run(command, callback) {
        if (this._quitting) {
            return callback(new Error('QUIT called'));
        } else if (command === 'QUIT') {
            this._quitting = true;
        }

        this._commandQueue.push({
            command,
            prefix: command
                .toString()
                .split(/\s/)
                .shift()
                .toUpperCase(),
            response: [],
            callback
        });

        if (!this._processing) {
            this._sendCommand();
        }
    }

    _parseFlagsResponse(value) {
        let response = {};
        [].concat(value || []).forEach(str => {
            (str || '')
                .toString()
                .trim()
                .split(/\s+/)
                .forEach(entry => {
                    if (!entry) {
                        return;
                    }

                    let sign = entry.charAt(0);
                    let key = entry.substr(1).toLowerCase();

                    if (!key) {
                        return;
                    }

                    if (sign === '-') {
                        response[key] = false;
                    } else if (sign === '+') {
                        response[key] = true;
                    }
                });
        });
        return response;
    }

    _sendCommand(continueProcessing) {
        if (this._processing && !continueProcessing) {
            return;
        }

        if (!this._commandQueue.length) {
            this._processing = false;
            return;
        }

        if (this._quitting && this._commandQueue[0].command === 'QUIT') {
            let quitter = this._commandQueue.shift();

            // return errors for all queued requests
            while (this._commandQueue.length) {
                let cur = this._commandQueue.shift();
                setImmediate(() => cur.callback(new Error('QUIT called')));
            }

            if (!this.connection) {
                // nothing to do here
                return quitter.callback();
            }

            // put the QUIT command back to the queue
            this._commandQueue.unshift(quitter);
        }

        this._processing = true;
        let getConnection = done => {
            if (this.connection) {
                return done();
            }
            this._connect(done);
        };

        let tryCount = 0;
        let tryConnect = () => {
            getConnection(err => {
                if (err) {
                    tryCount++;
                    if (tryCount < 5) {
                        return setTimeout(tryConnect, tryCount * 100);
                    }

                    // return errors for all queued requests
                    while (this._commandQueue.length) {
                        let cur = this._commandQueue.shift();
                        setImmediate(() => cur.callback(err));
                    }
                    return;
                }

                this._current = this._commandQueue.shift();

                let command = this._current.command;
                this.logger.verbose('Avast', 'C: %s', this._current.command.toString().trim());

                if (typeof command === 'string') {
                    command = Buffer.from(command + '\n');
                } else if (command && Buffer.isBuffer(command)) {
                    command = Buffer.concat([command, Buffer.from('\n')]);
                }

                try {
                    this.connection.write(command);
                } catch (E) {
                    this.logger.error('Avast', E);
                }
            });
        };
        tryConnect();
    }

    _connect(callback) {
        let returned = false;
        let timer = false;
        let done = (...args) => {
            clearTimeout(timer);
            this._initializeCallback = false;
            if (returned) {
                return;
            }
            returned = true;
            callback(...args);
        };

        this._connecting = true;
        this.initialized = false;

        this._initializeCallback = done;

        this.logger.info('Avast', 'Connecting to %s', this.address);
        let connection = (this.connection = net.createConnection(this.address, () => {
            if (returned) {
                // already returned
                try {
                    connection.end();
                } catch (E) {
                    // ignore
                }
                return;
            }

            this.logger.info('Avast', 'Connection established to %s', this.address);

            this._connecting = false;
            this._lineReader = new LineReader((line, done) => this.readLine(line, done));
            this._lineReaderEnded = false;
            connection.pipe(this._lineReader);
        }));

        connection.once('error', err => {
            this.logger.error('Avast', 'Connection error. %s', err.message);
            this.connection = false;
            done(err);
        });

        connection.once('end', () => {
            this.logger.info('Avast', 'Connection closed to %s', this.address);
            this.connection = false;
            if (!returned) {
                return done(new Error('Unexpected connection close'));
            }
        });

        timer = setTimeout(() => {
            done(new Error('TIMEOUT'));
        }, 10 * 1000);
    }

    _closeLineReader() {
        if (this._lineReader && !this._lineReaderEnded) {
            this._lineReaderEnded = true;
            try {
                this._lineReader.end();
            } catch (E) {
                // ignore
            }
        }
    }

    quit(callback) {
        callback = callback || (() => false);
        this.run('QUIT', err => {
            if (err) {
                return callback(err);
            }
            return callback();
        });
    }

    scan(filename, data, callback) {
        this._getFile(filename, data, (err, file) => {
            if (err) {
                return callback(err);
            }

            let fpath = file.path;
            this.run('SCAN ' + this._escapeParam(fpath), (err, response) => {
                fs.unlink(file.path, err => {
                    if (err) {
                        this.logger.error('Avast', 'DELERR path=%s size=%s error=%s', file.path, file.size, err.message);
                    }
                });

                if (err) {
                    return callback(err);
                }

                return setImmediate(() => callback(null, this._parseScanResponse(response)));
            });
        });
    }

    _parseScanResponse(list) {
        let response = {};
        let infection = false;

        (list || []).forEach(row => {
            let tabPos = row.indexOf('\t');
            if (tabPos < 0) {
                // ???
                return;
            }

            let filename = row.substr(0, tabPos);
            let status = this._parseScanStatus(row.substr(tabPos + 1));

            filename = this._unescapeParam(filename);
            let subParts = filename.split('|>');
            subParts.shift();

            response[subParts.join('/') || '.'] = status;

            if (!infection && status && status.status === 'infected') {
                infection = status;
                if (subParts.length) {
                    status.path = subParts.join('/');
                }
            }
        });

        if (infection) {
            return infection;
        }

        return response['.'] || { status: false };
    }

    _parseScanStatus(str) {
        let match = (str || '')
            .toString()
            .trim()
            .match(/^\[(.)\]\s*([\d.]+)(?:\s+(0|Error\s+\d+)\s+(.*))?/);

        if (!match) {
            return { status: false };
        }

        switch (match[1]) {
            case '+':
                return { status: 'clean' };
            case 'E':
                return { status: 'error', code: (match[3] && Number(match[3].substr(6))) || 0, message: this._unescapeParam(match[4] || '') };
            case 'L':
                return { status: 'infected', message: this._unescapeParam(match[4] || '') };
            default:
                return { status: false };
        }
    }

    _getFile(filename, data, callback) {
        filename = (filename || '').toString().trim();
        let extension = (filename && path.parse(filename).ext) || '.bin';

        let tmpfile = path.join(this.tmpdir, Date.now() + crypto.randomBytes(12).toString('hex')) + extension;
        if (typeof data === 'string') {
            data = Buffer.from(data);
        }

        if (Buffer.isBuffer(data)) {
            return fs.writeFile(tmpfile, data, err => {
                if (err) {
                    return callback(err);
                }
                callback(null, { path: tmpfile, size: data.length });
            });
        }

        if (data && typeof data === 'object' && typeof data.pipe === 'function') {
            // seems like a stream
            let returned = false;

            let targetFile = fs.createWriteStream(tmpfile);
            targetFile.once('error', err => {
                if (returned) {
                    return;
                }
                returned = true;
                callback(err);
            });
            targetFile.once('finish', () => {
                if (returned) {
                    return;
                }
                returned = true;
                callback(null, { path: tmpfile, size: -1 });
            });
            data.once('error', err => {
                targetFile.emit('error', err);
            });
            data.pipe(targetFile);
            return;
        }

        return setImmediate(() => callback(new Error('Invalid input')));
    }

    _unescapeParam(str) {
        return (str || '').toString().replace(/\\(.)/g, (m, c) => {
            switch (c) {
                case ' ':
                    return ' ';
                case 'n':
                    return '\n';
                case 'r':
                    return '\r';
                case 't':
                    return '\t';
                case 'b':
                    return '\b';
            }
            return m;
        });
    }

    _escapeParam(str) {
        return (str || '').toString().replace(/\s/g, c => {
            switch (c) {
                case '\r':
                    return '\\r';
                case '\n':
                    return '\\n';
                case '\t':
                    return '\\t';
                case ' ':
                    return '\\ ';
                default:
                    return '';
            }
        });
    }

    _getFlagLike(command, callback) {
        this.run((command || '').toUpperCase().trim(), (err, response) => {
            if (err) {
                return callback(err);
            }
            return callback(null, this._parseFlagsResponse(response));
        });
    }

    _setFlagLike(command, values, callback) {
        let paramsEntry = [];
        Object.keys(values || {}).forEach(key => {
            let sign = values[key];
            key = (key || '')
                .toString()
                .toLowerCase()
                .replace(/\s+/g, '');
            if (key && sign) {
                paramsEntry.push((sign ? '+' : '-') + key);
            }
        });

        this.run((command || '').toUpperCase().trim() + (paramsEntry.length ? ' ' + paramsEntry.join(' ') : ''), (err, response) => {
            if (err) {
                if (err.status === 501) {
                    let error = new Error('Invalid argument for ' + (command || '').toUpperCase().trim());
                    error.status = err.status;
                    return callback(error);
                }
                return callback(err);
            }
            return callback(null, this._parseFlagsResponse(response));
        });
    }

    getFlags(callback) {
        this._getFlagLike('FLAGS', callback);
    }

    setFlags(flags, callback) {
        this._setFlagLike('FLAGS', flags, callback);
    }

    getSensitivity(callback) {
        this._getFlagLike('SENSITIVITY', callback);
    }

    setSensitivity(sensitivities, callback) {
        this._setFlagLike('SENSITIVITY', sensitivities, callback);
    }

    getPack(callback) {
        this._getFlagLike('PACK', callback);
    }

    setPack(packers, callback) {
        this._setFlagLike('PACK', packers, callback);
    }

    getVPS(callback) {
        this.run('VPS', (err, response) => {
            if (err) {
                return callback(err);
            }
            let version = (response && response.length && response[0]) || false;
            return callback(null, version);
        });
    }

    checkUrl(url, callback) {
        this.run('CHECKURL ' + this._escapeParam(url), (err, response) => {
            if (err) {
                return callback(err);
            }
            return callback(null, response !== 520);
        });
    }

    readLine(line, done) {
        if (!line || !line.length) {
            return done();
        }
        line = line.toString();

        this.logger.verbose('Avast', 'S: %s', line);

        if (!this.initialized) {
            if (line.indexOf('220 DAEMON') === 0) {
                this.initialized = true;
                this._initializeCallback();
                return setImmediate(done);
            } else {
                this._initializeCallback(new Error(line));
            }
        }

        if (/^\d{3} /.test(line)) {
            // done
            if (this._current) {
                let cur = this._current;
                let statusCode = Number(line.substr(0, 3));
                if (statusCode === 210) {
                    this._data = true;
                    // expecting further data
                    return done();
                }
                this._data = false;

                if (statusCode === 520) {
                    // url blocked
                    this._current = false;
                    setImmediate(() => cur.callback(null, 520));
                    setImmediate(() => this._sendCommand(true));
                    return done();
                }

                if ((statusCode < 200 || statusCode >= 300) && !(cur.command.indexOf('SCAN') === 0 && statusCode === 451)) {
                    let error = new Error(line.replace(/^\d{3}( [^\s]+\s)?/, ''));
                    error.status = statusCode;
                    setImmediate(() => cur.callback(error));
                } else {
                    setImmediate(() => cur.callback(null, cur.response));
                }
                this._current = false;
                setImmediate(() => this._sendCommand(true));
            }
            return done();
        }

        if (this._data) {
            // waiting for data
            let spacePos = line.indexOf(' ');
            let prefix;
            if (spacePos >= 0) {
                prefix = line.substr(0, spacePos).toUpperCase();
                line = line.substr(spacePos + 1).trim();
            } else {
                prefix = line;
                line = '';
            }

            if (prefix === this._current.prefix && line) {
                this._current.response.push(line);
            }
        }

        done();
    }
}

module.exports = AvastClient;
