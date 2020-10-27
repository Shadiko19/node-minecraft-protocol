const crypto = require('crypto')
const request = require('request')

function joinServer(options, callback) {
    const serverhash = mcHexDigest(crypto.createHash('sha1')
        .update(options.serverid)
        .update(options.sharedsecret)
        .update(options.serverkey)
        .digest())

    const reqOptions = {
        uri: options.uri || 'https://auth.mcleaks.net/v1/joinserver',
        method: 'POST',
        json: {
            session: options.session,
            mcname: options.mcname,
            serverhash: options.serverhash || serverhash,
            server: options.server
        }
    }

    request(reqOptions, function (err, response, body) {
        if(!err && !body.success) {
            err = new Error(`MCLeaks responded '${body.errorMessage}'`)
        }
        callback(err, body)
    })
}

function mcHexDigest(hash) {
    if (!(hash instanceof Buffer)) { hash = Buffer.from(hash, encoding) }
    // check for negative hashes
    const negative = hash.readInt8(0) < 0
    if (negative) performTwosCompliment(hash)
    return (negative ? '-' : '') + hash.toString('hex').replace(/^0+/g, '')
}

function performTwosCompliment(buffer) {
    let carry = true;
    let i, newByte, value;
    for (i = buffer.length - 1; i >= 0; --i) {
        value = buffer.readUInt8(i);
        newByte = ~value & 0xff;
        if (carry) {
            carry = newByte === 0xff;
            buffer.writeUInt8(newByte + 1, i);
        } else {
            buffer.writeUInt8(newByte, i);
        }
    }
}

module.exports = {
    joinServer
};