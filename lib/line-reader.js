'use strict';

const { Writable } = require('stream');

class LineReader extends Writable {
    constructor(lineHandler, options) {
        options = options || {};
        options.writableObjectMode = false;
        options.readableObjectMode = true;
        super(options);

        this.lineHandler = lineHandler;
        this.lineNum = 0;
        this.readBuffer = [];
        this.lineBuffer = [];
        this.readPos = 0;
    }

    finalizeLine(final) {
        if (final && this.lineBuffer.length) {
            let line = Buffer.concat(this.lineBuffer);
            this.lineBuffer = [];
            return line;
        }

        return false;
    }

    readLine(final) {
        if (!this.readBuffer.length) {
            return this.finalizeLine(final);
        }

        let reading = true;
        let curBuf = this.readBuffer[0];
        let curBufLen = curBuf.length;
        let startPos = this.readPos;
        while (reading) {
            if (this.readPos >= curBufLen) {
                // reached end of one chunk
                if (startPos) {
                    // part of the chunk
                    this.lineBuffer.push(curBuf.slice(startPos));
                } else {
                    // entire chunk
                    this.lineBuffer.push(curBuf);
                }

                this.readBuffer.shift();
                this.readPos = 0;
                if (!this.readBuffer.length) {
                    // nothing more to read but still not end of line
                    return this.finalizeLine(final);
                }
                curBuf = this.readBuffer[0];
                continue;
            }

            let c = curBuf[this.readPos++];
            if (c === 0x0a) {
                // line break!
                this.lineBuffer.push(curBuf.slice(startPos, this.readPos));
                let line = Buffer.concat(this.lineBuffer);
                this.lineBuffer = [];
                return line;
            }
        }
    }

    readLines(final, callback) {
        let readNextLine = () => {
            let line = this.readLine(final);
            if (!line) {
                return callback();
            }

            let nl = 0;
            if (line.length >= 1 && line[line.length - 1] === 0x0a) {
                nl++;
                if (line.length >= 2 && line[line.length - 2] === 0x0d) {
                    nl++;
                }
            }

            if (nl) {
                line = line.slice(0, line.length - nl);
            }

            this.lineHandler(line, err => {
                if (err) {
                    return this.emit('error', err);
                }
                setImmediate(readNextLine);
            });
        };

        readNextLine();
    }

    _write(chunk, encoding, callback) {
        this.readBuffer.push(chunk);
        this.readLines(false, callback);
    }

    _final(callback) {
        this.readLines(true, callback);
    }
}

module.exports = LineReader;
