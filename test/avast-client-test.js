/* eslint no-console: 0 */

'use strict';

const AvastClient = require('../lib/avast-client');
const npmlog = require('npmlog');

npmlog.level = 'silly';

// run in app root assuming example.com has Avast Core running:
//   rm -rf scan.sock  && ssh -nNT -L ./scan.sock:/var/run/avast/scan.sock example.com
// NB! tunneling the socket does not work for scanning as the file needs to be written to server
const SOCKET_ADDR = __dirname + '/../scan.sock';

let ac = new AvastClient({ address: SOCKET_ADDR });
ac.setFlags({ allfiles: true }, console.log);
ac.getFlags(console.log);

ac.checkUrl('http://www.neti.ee/', console.log);
ac.checkUrl('http://www.avast.com/eng/test-url-blocker.html', console.log);

ac.setSensitivity({ pup: true }, console.log);
ac.getSensitivity(console.log);

ac.setPack({ zip: true, kriips: true }, console.log);
ac.getPack(console.log);

ac.getVPS(console.log);

ac.scan('message.eml', 'tere', console.log);
