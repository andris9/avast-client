# avast-client

Connects to [Avast scanner daemon](https://www.avast.com/linux-server-antivirus) and scans files for viruses.

```
const AvastClient = require('avast-client');
const scanner = new AvastClient();
scanner.scan('virus.exe', fs.readFileSync('virus.exe'), (err, response)=>{
    console.log(err || response);
    // you can keep using the same scanner instance until you call quit()
    scanner.quit();
});
```

## Methods

### getFlags

Return current flags as an object with key:value pairs where key is a flag and value is a boolean indicating if the flag is set or not

```javascript
scanner.getFlags((err, flags) => {
    console.log(flags);
});
```

Example response

```javascript
{ fullfiles: false, allfiles: true, scandevices: false }
```

### setFlags

Allows to change flags. Returns current flags as an object with key:value pairs where key is a flag and value is a boolean indicating if the flag is set or not

```javascript
scanner.setFlags({ allfiles: false, fullfiles: true }, (err, flags) => {
    console.log(flags);
});
```

Example response

```javascript
{ fullfiles: true, allfiles: false, scandevices: false }
```

### getSensitivity

Return current sensitvity as an object with key:value pairs where key is an option and value is a boolean indicating if the sensitivity option is set or not

```javascript
scanner.getSensitivity((err, opts) => {
    console.log(opts);
});
```

Example response

```javascript
{ worm: true,
  trojan: true,
  adware: true,
  spyware: true,
  dropper: true,
  kit: true,
  joke: true,
  dangerous: true,
  dialer: true,
  rootkit: true,
  exploit: true,
  pup: true,
  suspicious: true,
  pube: true }
```

### setSensitivity

Allows to change sensitvity options. Return current sensitvity as an object with key:value pairs where key is an option and value is a boolean indicating if the sensitivity option is set or no

```javascript
scanner.setSensitivity({ dialer: false }, (err, opts) => {
    console.log(opts);
});
```

Example response

```javascript
{ worm: true,
  trojan: true,
  adware: true,
  spyware: true,
  dropper: true,
  kit: true,
  joke: true,
  dangerous: true,
  dialer: false,
  rootkit: true,
  exploit: true,
  pup: true,
  suspicious: true,
  pube: true }
```

### getPack

Return current packer settings as an object with key:value pairs where key is an option and value is a boolean indicating if the packer option is set or not

```javascript
scanner.getPack((err, opts) => {
    console.log(opts);
});
```

Example response

```javascript
{ mime: true,
  zip: true,
  arj: true,
  rar: true,
  cab: true,
  tar: true,
  gz: true,
  bzip2: true,
  ace: true,
  arc: true,
  zoo: true,
  lharc: true,
  chm: true,
  cpio: true,
  rpm: true,
  '7zip': true,
  iso: true,
  tnef: true,
  dbx: true,
  sys: true,
  ole: true,
  exec: true,
  winexec: true,
  install: true,
  dmg: true }
```

### setPack

Allows to change packer options. Return current packer settings as an object with key:value pairs where key is an option and value is a boolean indicating if the packer option is set or not

```javascript
scanner.setPack({ mime: false }, (err, opts) => {
    console.log(opts);
});
```

Example response

```javascript
{ mime: false,
  zip: true,
  arj: true,
  rar: true,
  cab: true,
  tar: true,
  gz: true,
  bzip2: true,
  ace: true,
  arc: true,
  zoo: true,
  lharc: true,
  chm: true,
  cpio: true,
  rpm: true,
  '7zip': true,
  iso: true,
  tnef: true,
  dbx: true,
  sys: true,
  ole: true,
  exec: true,
  winexec: true,
  install: true,
  dmg: true }
```

### checkUrl

Allows to check if an url is blacklisted or not

```javascript
scanner.checkUrl('http://www.google.com/', (err, status) => {
    if (status) {
        console.log('URL is OK');
    } else {
        console.log('URL is blacklisted');
    }
});
```

### getVPS

Get current virus definitions version. Return the version number as a string.

```javascript
scanner.getVPS((err, version) => {
    console.log(version);
});
```

### scan

Scans a buffer or a stream and returns scan result

    scanner.scan(filename, data, callback)

Where

*   **filename** is a name of the file. This is not real path, it just indicates the type of the data to be scanned
*   **data** is file contents, either a Buffer, a String (ascii or utf8) or a Stream
*   **callback** (_err_, _response_) is the function to run once scanning is complete
    *   **err** is the error respone if scanning failed for some system error
    *   **response** is scan response object
        *   **status** is either 'clean', 'infected' or 'error'
        *   **message** is either the injection or error message
        *   **path** is set if the infected file was found from a container, eg the scanned file was a zip file

```javascript
scanner.scan('message.eml', fs.readFileSync('/var/mail/message.eml'), (err, result) => {
    console.log(result);
});
```

Example response

```javascript
{ status: 'infected', message: 'Win32:Malware-gen' }
```

### quit

Closes the socket to the daemon and does not allow to use this instance anymore.

## License

**MIT**
